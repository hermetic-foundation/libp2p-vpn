//! Connection-local packet authority for one browser swarm and network.
//! The caller owns durable membership, capability validation, and transport
//! admission. A relay hop is never a member connection.

use std::{collections::HashMap, time::Duration};

use libp2p::{PeerId, request_response::OutboundRequestId, swarm::ConnectionId};
use web_time::Instant;

use crate::net::MIN_IPV4_MTU;

const DRAIN_LIMIT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    pub(super) peer: PeerId,
    pub(super) connection: ConnectionId,
}

/// Classify an established connection by its local dial or reservation
/// ownership, not by the remote peer ID alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Established {
    DirectMember,
    CircuitMember,
    RelayHop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StreamMtu(u16);

impl StreamMtu {
    /// Negotiate only after the capability payload passes VPN authorization.
    pub(super) fn negotiate(local: u16, remote: u16) -> Option<Self> {
        let mtu = local.min(remote);
        (mtu >= MIN_IPV4_MTU).then_some(Self(mtu))
    }

    pub(super) fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Selected {
    pub(super) binding: Binding,
    pub(super) mtu: StreamMtu,
    pub(super) path: Established,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProbeOutcome {
    Ignored,
    CloseCandidate(Binding),
    Promoted { draining: Binding, until: Instant },
}

#[derive(Clone, Copy)]
enum Authority {
    Unverified,
    Waiting(OutboundRequestId),
    Authorized(StreamMtu),
}

#[derive(Clone, Copy)]
enum CandidatePhase {
    Capabilities(Authority),
    Payload(StreamMtu),
    Probe {
        request: OutboundRequestId,
        mtu: StreamMtu,
    },
}

#[derive(Clone, Copy)]
struct Candidate {
    fallback: ConnectionId,
    path: Established,
    deadline: Instant,
    phase: CandidatePhase,
}

#[derive(Clone, Copy)]
enum Phase {
    Primary {
        path: Established,
        authority: Authority,
    },
    Candidate(Candidate),
    Draining {
        successor: ConnectionId,
        until: Instant,
        mtu: StreamMtu,
    },
}

struct Entry {
    peer: PeerId,
    phase: Phase,
}

pub(super) struct MemberSessions {
    // At most one primary and one candidate or drain per member. The caller
    // still bounds pending transport dials and relay infrastructure separately.
    paths: HashMap<ConnectionId, Entry>,
    max_members: usize,
}

impl MemberSessions {
    pub(super) fn new(max_members: usize) -> Self {
        Self {
            paths: HashMap::new(),
            max_members,
        }
    }

    pub(super) fn set_limit(&mut self, limit: usize) {
        self.max_members = limit;
    }

    /// Called only for an authenticated transport connection admitted by the
    /// caller's membership or explicit checkpoint bootstrap policy. This does
    /// not grant packet authority, even to an already known member.
    pub(super) fn attach(&mut self, binding: Binding, path: Established) -> bool {
        if path == Established::RelayHop
            || self.paths.contains_key(&binding.connection)
            || self.paths.values().any(|entry| entry.peer == binding.peer)
            || self
                .paths
                .values()
                .filter(|entry| matches!(entry.phase, Phase::Primary { .. }))
                .count()
                >= self.max_members
        {
            return false;
        }
        self.paths.insert(
            binding.connection,
            Entry {
                peer: binding.peer,
                phase: Phase::Primary {
                    path,
                    authority: Authority::Unverified,
                },
            },
        );
        true
    }

    pub(super) fn stage_direct(
        &mut self,
        candidate: Binding,
        path: Established,
        fallback: Binding,
        deadline: Instant,
    ) -> bool {
        if path != Established::DirectMember {
            return false;
        }
        self.stage_replacement(candidate, path, fallback, deadline)
    }

    pub(super) fn stage_replacement(
        &mut self,
        candidate: Binding,
        path: Established,
        fallback: Binding,
        deadline: Instant,
    ) -> bool {
        if path == Established::RelayHop
            || candidate.peer != fallback.peer
            || self.paths.contains_key(&candidate.connection)
            || self
                .paths
                .iter()
                .any(|(id, entry)| entry.peer == fallback.peer && *id != fallback.connection)
            || !matches!(
                self.phase(fallback),
                Some(Phase::Primary {
                    path: Established::CircuitMember,
                    authority: Authority::Authorized(_),
                })
            )
        {
            return false;
        }
        self.paths.insert(
            candidate.connection,
            Entry {
                peer: candidate.peer,
                phase: Phase::Candidate(Candidate {
                    fallback: fallback.connection,
                    path,
                    deadline,
                    phase: CandidatePhase::Capabilities(Authority::Unverified),
                }),
            },
        );
        true
    }

    /// Register the ID returned by a capability request sent on this exact
    /// connection. Retrying replaces the outstanding request, not its authority.
    pub(super) fn expect_capabilities(
        &mut self,
        binding: Binding,
        request: OutboundRequestId,
    ) -> bool {
        let Some(authority) = self.authority_mut(binding) else {
            return false;
        };
        if matches!(authority, Authority::Authorized(_)) {
            return false;
        }
        *authority = Authority::Waiting(request);
        true
    }

    /// Check this before validating a response or processing its membership
    /// side effects. A control-only checkpoint exchange is not packet proof.
    pub(super) fn awaits_capabilities(
        &self,
        binding: Binding,
        request: OutboundRequestId,
        now: Instant,
    ) -> bool {
        match self.phase(binding) {
            Some(Phase::Primary {
                authority: Authority::Waiting(id),
                ..
            }) => id == request,
            Some(Phase::Candidate(Candidate {
                deadline,
                phase: CandidatePhase::Capabilities(Authority::Waiting(id)),
                ..
            })) => now < deadline && id == request,
            _ => false,
        }
    }

    /// Complete the exact exchange after validating the response against the
    /// current committed authority. Pass None for rejection or transport failure.
    pub(super) fn finish_capabilities(
        &mut self,
        binding: Binding,
        request: OutboundRequestId,
        mtu: Option<StreamMtu>,
        now: Instant,
    ) -> bool {
        if !self.awaits_capabilities(binding, request, now) {
            return false;
        }
        *self
            .authority_mut(binding)
            .expect("matching capability exchange") =
            mtu.map_or(Authority::Unverified, Authority::Authorized);
        true
    }

    pub(super) fn expect_probe(
        &mut self,
        binding: Binding,
        request: OutboundRequestId,
        now: Instant,
    ) -> bool {
        let Some(Phase::Candidate(Candidate {
            fallback,
            deadline,
            phase:
                CandidatePhase::Capabilities(Authority::Authorized(mtu)) | CandidatePhase::Payload(mtu),
            ..
        })) = self.phase(binding)
        else {
            return false;
        };
        if now >= deadline
            || !self.has_outbound(
                Binding {
                    connection: fallback,
                    ..binding
                },
                mtu,
            )
        {
            return false;
        }
        let Phase::Candidate(candidate) = self.phase_mut(binding).expect("matching candidate")
        else {
            unreachable!("matching candidate");
        };
        candidate.phase = CandidatePhase::Probe { request, mtu };
        true
    }

    pub(super) fn allow_candidate_payload(&mut self, binding: Binding) -> bool {
        if let Some(Phase::Candidate(Candidate {
            path: Established::CircuitMember,
            phase: phase @ CandidatePhase::Capabilities(Authority::Authorized(_)),
            ..
        })) = self.phase_mut(binding)
        {
            let CandidatePhase::Capabilities(Authority::Authorized(mtu)) = *phase else {
                unreachable!()
            };
            *phase = CandidatePhase::Payload(mtu);
            return true;
        }
        false
    }

    /// Call only after rechecking durable membership and the caller's handoff
    /// generation and drain prerequisites. The candidate never inherits proof
    /// from the fallback or from a different connection's probe response.
    pub(super) fn finish_probe(
        &mut self,
        binding: Binding,
        request: OutboundRequestId,
        accepted: bool,
        now: Instant,
    ) -> ProbeOutcome {
        let Some(Phase::Candidate(Candidate {
            fallback,
            path,
            deadline,
            phase:
                CandidatePhase::Probe {
                    request: expected,
                    mtu,
                },
        })) = self.phase(binding)
        else {
            return ProbeOutcome::Ignored;
        };
        if request != expected {
            return ProbeOutcome::Ignored;
        }
        let fallback = Binding {
            connection: fallback,
            ..binding
        };
        if !accepted || now >= deadline || !self.has_outbound(fallback, mtu) {
            self.paths.remove(&binding.connection);
            return ProbeOutcome::CloseCandidate(binding);
        }
        let until = now + DRAIN_LIMIT;
        *self.phase_mut(fallback).expect("matching primary") = Phase::Draining {
            successor: binding.connection,
            until,
            mtu,
        };
        *self.phase_mut(binding).expect("matching candidate") = Phase::Primary {
            path,
            authority: Authority::Authorized(mtu),
        };
        ProbeOutcome::Promoted {
            draining: fallback,
            until,
        }
    }

    pub(super) fn outbound(&self, peer: PeerId) -> Option<Selected> {
        self.paths
            .iter()
            .find_map(|(&connection, entry)| match entry.phase {
                Phase::Primary {
                    path,
                    authority: Authority::Authorized(mtu),
                } if entry.peer == peer => Some(Selected {
                    binding: Binding { peer, connection },
                    mtu,
                    path,
                }),
                _ => None,
            })
    }

    pub(super) fn primary(&self, peer: PeerId) -> Option<(Binding, Established)> {
        self.paths
            .iter()
            .find_map(|(&connection, entry)| match entry.phase {
                Phase::Primary { path, .. } if entry.peer == peer => {
                    Some((Binding { peer, connection }, path))
                }
                _ => None,
            })
    }

    /// Refresh an authenticated primary without admitting a pending path.
    pub(super) fn refresh_mtu(&mut self, binding: Binding, mtu: StreamMtu) {
        if let Some(Phase::Primary {
            authority: Authority::Authorized(current),
            ..
        }) = self.phase_mut(binding)
        {
            *current = mtu;
        }
    }

    pub(super) fn inbound_mtu(&self, binding: Binding, now: Instant) -> Option<StreamMtu> {
        match self.phase(binding)? {
            Phase::Candidate(Candidate {
                path: Established::CircuitMember,
                deadline,
                phase: CandidatePhase::Payload(mtu) | CandidatePhase::Probe { mtu, .. },
                ..
            }) if now < deadline => Some(mtu),
            Phase::Primary {
                authority: Authority::Authorized(mtu),
                ..
            } => Some(mtu),
            Phase::Draining {
                successor,
                until,
                mtu,
            } if now < until
                && self.has_outbound(
                    Binding {
                        connection: successor,
                        ..binding
                    },
                    mtu,
                ) =>
            {
                Some(mtu)
            }
            _ => None,
        }
    }

    /// Gate this peer before awaiting a durable authority update or starting a
    /// new capability exchange. Keep its primary transport, but retire all
    /// alternate authority. The returned bindings must be closed by the caller.
    pub(super) fn require_reauthorization(&mut self, peer: PeerId) -> Vec<Binding> {
        self.retain_peer(peer, |phase| {
            if let Phase::Primary { authority, .. } = phase {
                *authority = Authority::Unverified;
                true
            } else {
                false
            }
        })
    }

    /// The durable owner must also prevent this peer's new admissions.
    pub(super) fn revoke(&mut self, peer: PeerId) -> Vec<Binding> {
        self.retain_peer(peer, |_| false)
    }

    /// An exact primary close retires its alternatives, not the other peers.
    /// An old drain close never retires the promoted primary.
    pub(super) fn closed(&mut self, binding: Binding) -> Vec<Binding> {
        let Some(phase) = self.phase(binding) else {
            return Vec::new();
        };
        self.paths.remove(&binding.connection);
        if matches!(phase, Phase::Primary { .. }) {
            self.revoke(binding.peer)
        } else {
            Vec::new()
        }
    }

    fn retain_peer(
        &mut self,
        peer: PeerId,
        mut keep: impl FnMut(&mut Phase) -> bool,
    ) -> Vec<Binding> {
        let mut retired = Vec::new();
        self.paths.retain(|&connection, entry| {
            if entry.peer != peer || keep(&mut entry.phase) {
                true
            } else {
                retired.push(Binding { peer, connection });
                false
            }
        });
        retired
    }

    fn has_outbound(&self, binding: Binding, mtu: StreamMtu) -> bool {
        matches!(self.phase(binding), Some(Phase::Primary { authority: Authority::Authorized(current), .. }) if current == mtu)
    }

    fn phase(&self, binding: Binding) -> Option<Phase> {
        self.paths
            .get(&binding.connection)
            .filter(|entry| entry.peer == binding.peer)
            .map(|entry| entry.phase)
    }

    fn phase_mut(&mut self, binding: Binding) -> Option<&mut Phase> {
        self.paths
            .get_mut(&binding.connection)
            .filter(|entry| entry.peer == binding.peer)
            .map(|entry| &mut entry.phase)
    }

    fn authority_mut(&mut self, binding: Binding) -> Option<&mut Authority> {
        match self.phase_mut(binding)? {
            Phase::Primary { authority, .. }
            | Phase::Candidate(Candidate {
                phase: CandidatePhase::Capabilities(authority),
                ..
            }) => Some(authority),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
