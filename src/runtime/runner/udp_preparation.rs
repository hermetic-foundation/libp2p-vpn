//! Bounded pre-transcript UDP work; completed I/O is adopted, never reselected.

use super::*;
use crate::runtime::packet_plane::{PreparedUdpBinding, PreparedUdpRoute, UdpPreparation};

const CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum Role {
    Initiator,
    Responder,
}

pub(super) struct DeferredResponse {
    pub(super) peer: Libp2pPeerId,
    pub(super) handshake: Vec<u8>,
    pub(super) channel: request_response::ResponseChannel<ControlResponse>,
}

struct Entry {
    dns_snapshot: PacketDnsSnapshot,
    generation: u64,
    started: Instant,
    work: UdpPreparation,
    abort: Option<AbortHandle>,
    ready: Option<PreparedUdpRoute>,
    response: Option<DeferredResponse>,
}

impl Entry {
    fn cancel(&self) {
        self.fail(io::ErrorKind::Interrupted, Instant::now());
    }

    fn fail(&self, kind: io::ErrorKind, now: Instant) {
        self.work.failed(kind, now);
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
}

#[derive(Default)]
pub(super) struct Preparations {
    entries: HashMap<(PeerId, Role), Entry>,
    pub(super) tasks: JoinSet<Completion>,
    generation: u64,
    destinations: HashMap<PeerId, Destination>,
}

struct Destination {
    endpoint: SocketAddr,
    visited: Vec<SocketAddr>,
    deadline: Instant,
}

pub(super) struct Completion {
    pub(super) peer: PeerId,
    pub(super) role: Role,
    generation: u64,
    result: io::Result<PreparedUdpRoute>,
}

pub(super) struct Finished {
    pub(super) peer: PeerId,
    pub(super) role: Role,
    pub(super) response: Option<DeferredResponse>,
    pub(super) result: io::Result<()>,
}

impl Preparations {
    pub(super) fn dns_snapshot(&self, peer: PeerId, role: Role) -> Option<PacketDnsSnapshot> {
        self.entries
            .get(&(peer, role))
            .filter(|entry| {
                entry.work.is_current()
                    && Instant::now().saturating_duration_since(entry.started)
                        < PACKET_PLANE_PENDING_HELLO_TIMEOUT
            })
            .map(|entry| entry.dns_snapshot.clone())
    }

    pub(super) fn retain_dns_snapshot(&mut self, peer: PeerId, role: Role) {
        if let Some(entry) = self.entries.get_mut(&(peer, role)) {
            entry.dns_snapshot = packet_dns_capture();
        }
    }

    pub(super) fn started_at(&self, peer: PeerId, role: Role) -> Option<Instant> {
        self.entries.get(&(peer, role)).map(|entry| entry.started)
    }
    pub(super) fn current_sources(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.entries.values().filter_map(|entry| {
            let ready = entry.ready.as_ref()?;
            (entry.work.is_current()
                && ready.is_current()
                && Instant::now().saturating_duration_since(entry.started)
                    < PACKET_PLANE_PENDING_HELLO_TIMEOUT)
                .then(|| ready.source())
        })
    }

    fn take_response(&mut self, peer: PeerId) -> Option<DeferredResponse> {
        let entry = self.entries.get_mut(&(peer, Role::Responder))?;
        (entry.work.is_current()
            && entry
                .ready
                .as_ref()
                .is_some_and(PreparedUdpRoute::is_current)
            && Instant::now().saturating_duration_since(entry.started)
                < PACKET_PLANE_PENDING_HELLO_TIMEOUT)
            .then(|| entry.response.take())
            .flatten()
    }
    pub(super) fn destination(&self, peer: PeerId) -> Option<SocketAddr> {
        self.destinations
            .get(&peer)
            .filter(|destination| destination.deadline > Instant::now())
            .map(|destination| destination.endpoint)
    }

    pub(super) fn retarget(&mut self, peer: PeerId, from: SocketAddr, to: SocketAddr) -> bool {
        let now = Instant::now();
        self.destinations
            .retain(|_, destination| destination.deadline > now);
        if !self.destinations.contains_key(&peer) && self.destinations.len() >= CAPACITY {
            return false;
        }
        let destination = self
            .destinations
            .entry(peer)
            .or_insert_with(|| Destination {
                endpoint: from,
                visited: vec![from],
                deadline: now + PACKET_PLANE_PENDING_HELLO_TIMEOUT,
            });
        if destination.visited.len() >= 3 || destination.visited.contains(&to) {
            return false;
        }
        destination.visited.push(to);
        destination.endpoint = to;
        true
    }

    pub(super) fn forget(&mut self, peer: PeerId) {
        self.cancel_peer(peer);
        self.destinations.remove(&peer);
    }
    pub(super) fn contains(&self, peer: PeerId, role: Role) -> bool {
        self.entries.contains_key(&(peer, role))
    }

    pub(super) fn contains_current(&self, peer: PeerId, role: Role) -> bool {
        self.entries.get(&(peer, role)).is_some_and(|entry| {
            entry.work.is_current()
                && Instant::now().saturating_duration_since(entry.started)
                    < PACKET_PLANE_PENDING_HELLO_TIMEOUT
        })
    }

    pub(super) fn take_initiator(
        &mut self,
        peer: PeerId,
        destination: SocketAddr,
    ) -> Option<(UdpPreparation, Instant)> {
        let entry = self.entries.remove(&(peer, Role::Initiator))?;
        if entry.work.destination() != destination
            || !entry.work.is_current()
            || Instant::now().saturating_duration_since(entry.started)
                >= PACKET_PLANE_PENDING_HELLO_TIMEOUT
        {
            entry.cancel();
            return None;
        }
        if let Some(abort) = entry.abort {
            abort.abort();
        }
        // Reuse the same retry ticket, including a completed source lookup.
        // The old task's generation cannot complete the new responder entry.
        Some((entry.work, entry.started))
    }

    pub(super) fn inherit_started(&mut self, peer: PeerId, role: Role, started: Instant) {
        if let Some(entry) = self.entries.get_mut(&(peer, role)) {
            entry.started = entry.started.min(started);
        }
    }

    pub(super) fn get_or_start(
        &mut self,
        peer: PeerId,
        role: Role,
        destination: SocketAddr,
        create: impl FnOnce() -> io::Result<UdpPreparation>,
    ) -> io::Result<Option<PreparedUdpRoute>> {
        let key = (peer, role);
        if let Some(entry) = self.entries.get(&key) {
            if !entry.work.is_current() || entry.work.destination() != destination {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "UDP preparation context changed",
                ));
            }
            return Ok(entry.ready.clone());
        }
        if self.entries.len() >= CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP preparation limit",
            ));
        }
        let work = create()?;
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let task_work = work.clone();
        let abort = self.tasks.spawn(async move {
            let result =
                tokio::time::timeout(PACKET_PLANE_PENDING_HELLO_TIMEOUT, task_work.prepare())
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "UDP preparation timed out",
                        ))
                    });
            Completion {
                peer,
                role,
                generation,
                result,
            }
        });
        self.entries.insert(
            key,
            Entry {
                dns_snapshot: packet_dns_capture(),
                generation,
                started: Instant::now(),
                work,
                abort: Some(abort),
                ready: None,
                response: None,
            },
        );
        Ok(None)
    }

    pub(super) fn defer(&mut self, response: DeferredResponse) -> Result<(), DeferredResponse> {
        let Some(entry) = self
            .entries
            .get_mut(&(PeerId::from_libp2p(response.peer), Role::Responder))
        else {
            return Err(response);
        };
        if entry.response.is_some() {
            return Err(response);
        }
        entry.response = Some(response);
        Ok(())
    }

    pub(super) fn finish(&mut self, completion: Completion) -> Option<Finished> {
        let key = (completion.peer, completion.role);
        let entry = self.entries.get_mut(&key)?;
        if entry.generation != completion.generation {
            return None;
        }
        entry.abort = None;
        let response = entry.response.take();
        let result = completion.result.and_then(|ready| {
            if !entry.work.is_current()
                || !ready.is_current()
                || Instant::now().saturating_duration_since(entry.started)
                    >= PACKET_PLANE_PENDING_HELLO_TIMEOUT
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "UDP preparation completed after retirement",
                ));
            }
            entry.ready = Some(ready);
            Ok(())
        });
        if let Err(error) = &result {
            if let Some(entry) = self.entries.remove(&key) {
                entry.fail(error.kind(), Instant::now());
            }
        }
        Some(Finished {
            peer: completion.peer,
            role: completion.role,
            response,
            result,
        })
    }

    pub(super) fn consume(&mut self, peer: PeerId, role: Role) {
        self.entries.remove(&(peer, role));
    }

    pub(super) fn cancel_peer(&mut self, peer: PeerId) {
        for role in [Role::Initiator, Role::Responder] {
            if let Some(entry) = self.entries.remove(&(peer, role)) {
                entry.cancel();
            }
        }
    }

    pub(super) fn expire(&mut self, now: Instant) -> Vec<DeferredResponse> {
        self.destinations
            .retain(|_, destination| destination.deadline > now);
        let expired = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                (!entry.work.is_current()
                    || now.saturating_duration_since(entry.started)
                        >= PACKET_PLANE_PENDING_HELLO_TIMEOUT)
                    .then_some(*key)
            })
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|key| {
                let entry = self.entries.remove(&key)?;
                entry.fail(
                    if entry.work.is_current() {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::Interrupted
                    },
                    now,
                );
                entry.response
            })
            .collect()
    }

    pub(super) fn clear(&mut self) {
        self.destinations.clear();
        for (_, entry) in self.entries.drain() {
            entry.cancel();
        }
        self.tasks.abort_all();
    }
}

impl Drop for Preparations {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(super) fn bind_advertised_source(
    prepared: &PreparedUdpRoute,
    local: &ControlCapabilities,
    config: &Config,
) -> Result<PreparedUdpBinding, PacketPlaneNegotiationError> {
    // Auto hints from another socket/Network are not raw-UDP NAT evidence.
    // Explicit mappings retain their existing configured-assertion semantics.
    let configured = config
        .network
        .packet_plane
        .external_endpoints
        .iter()
        .flat_map(|endpoint| resolve_packet_plane_endpoint_candidate(endpoint))
        .collect::<Vec<_>>();
    let mut candidates = local
        .packet_endpoint_candidates
        .iter()
        .flat_map(|endpoint| resolve_packet_plane_endpoint_candidate(endpoint))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|endpoint| {
        (
            !prepared.matches_source(*endpoint),
            packet_endpoint_priority(*endpoint),
        )
    });
    candidates
        .into_iter()
        .find_map(|endpoint| prepared.bind_endpoint(endpoint, &configured).ok())
        .ok_or(PacketPlaneNegotiationError::MissingLocalEndpoint)
}

pub(super) async fn handle(
    context: &mut PacketPlaneExpiryContext<'_>,
    tracker: &mut PathProbeTracker,
    task: Result<Completion, tokio::task::JoinError>,
) {
    let Ok(completion) = task else {
        return;
    };
    let Some(finished) = context.negotiator.udp_preparations.finish(completion) else {
        return;
    };
    if let Err(error) = &finished.result {
        context.metrics.record_control_failure();
        log_runtime_event(
            LogLevel::Warn,
            "packet_plane_udp_preparation_failed",
            &[
                ("peer", &finished.peer.to_string()),
                ("reason", &format!("{:?}", error.kind())),
            ],
        );
    }
    udp_publication::reconcile(
        context.swarm,
        context.forwarder,
        context.packet_plane,
        context.packet_plane_quic.as_deref(),
        context.negotiator,
        context.local_capabilities,
        context.membership_record_syncs,
        context.metrics,
    );
    if let Some(deferred) = finished.response {
        if finished.result.is_err() {
            send_control_response_nonfatal(
                context.swarm,
                context.metrics,
                deferred.peer,
                deferred.channel,
                ControlResponse::PacketPlaneRejected(
                    ControlRejectionReason::UnsupportedPreferredPath,
                ),
            );
        } else {
            respond_or_defer(context, tracker, deferred).await;
        }
    } else if finished.result.is_ok() && finished.role == Role::Initiator {
        retry_packet_plane_negotiation(context, finished.peer);
    }
}

pub(super) async fn resume(
    context: &mut PacketPlaneExpiryContext<'_>,
    tracker: &mut PathProbeTracker,
    peer: Libp2pPeerId,
) {
    if !context
        .membership_record_syncs
        .packet_capabilities_acknowledged(peer, context.local_capabilities, context.forwarder)
    {
        return;
    }
    if let Some(deferred) = context
        .negotiator
        .dns_waiters
        .get_mut(&PeerId::from_libp2p(peer))
        .and_then(|waiter| waiter.response.take())
    {
        respond_or_defer(context, tracker, deferred).await;
    }
    if let Some(deferred) = context
        .negotiator
        .udp_preparations
        .take_response(PeerId::from_libp2p(peer))
    {
        respond_or_defer(context, tracker, deferred).await;
    }
}

pub(super) async fn resume_dns(
    context: &mut PacketPlaneExpiryContext<'_>,
    tracker: &mut PathProbeTracker,
) {
    let peers = context
        .negotiator
        .dns_waiters
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for peer in peers {
        let response = context
            .negotiator
            .dns_waiters
            .get_mut(&peer)
            .and_then(|waiter| waiter.response.take());
        if let Some(response) = response {
            respond_or_defer(context, tracker, response).await;
        }
    }
    for peer in context.forwarder.configured_overlay_peers() {
        retry_packet_plane_negotiation(context, peer);
    }
}

async fn respond_or_defer(
    context: &mut PacketPlaneExpiryContext<'_>,
    tracker: &mut PathProbeTracker,
    deferred: DeferredResponse,
) {
    let response = if context
        .membership_record_syncs
        .packet_capabilities_acknowledged(
            deferred.peer,
            context.local_capabilities,
            context.forwarder,
        ) {
        packet_plane_accept_result_for_peer(
            PacketPlaneAcceptContext {
                active_connections: context.active_connections,
                forwarder: context.forwarder,
                peer_capabilities: context.peer_capabilities,
                paths: context.paths,
                metrics: context.metrics,
                packet_plane: context.packet_plane,
                packet_plane_quic: context.packet_plane_quic.as_deref_mut(),
                negotiator: context.negotiator,
                identity: context.identity,
                local_capabilities: context.local_capabilities,
                publication: context.membership_record_syncs,
                path_probe_tracker: tracker,
            },
            deferred.peer,
            &deferred.handshake,
        )
        .await
    } else {
        None
    };
    if let Some(response) = response {
        send_control_response_nonfatal(
            context.swarm,
            context.metrics,
            deferred.peer,
            deferred.channel,
            response,
        );
    } else if let Err(deferred) = context.negotiator.defer_response(deferred) {
        send_control_response_nonfatal(
            context.swarm,
            context.metrics,
            deferred.peer,
            deferred.channel,
            ControlResponse::PacketPlaneRejected(ControlRejectionReason::UnsupportedPreferredPath),
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "udp_preparation/tests.rs"]
mod tests;
