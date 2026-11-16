//! Keep an authenticated active session while a replacement proves reception.

use super::*;
use crate::wire::PayloadType;

const MAX_CANDIDATES: usize = 16;
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(20);
const RECEIVE_DRAIN: Duration = Duration::from_secs(3);
const MAX_RETIRING: usize = 16;

#[cfg(test)]
mod tests;

fn cap_to_session_lifetime(deadline: Instant, established: Instant, ttl: Duration) -> Instant {
    established
        .checked_add(ttl)
        .map_or(deadline, |expiry| deadline.min(expiry))
}

#[derive(Debug)]
struct TimedSession {
    connection: QuicPath,
    session: PacketPlaneSession,
    deadline: Instant,
}

#[derive(Debug)]
pub(super) struct Handoffs {
    candidates: HashMap<PeerId, TimedSession>,
    retiring: HashMap<PeerId, TimedSession>,
    session_ttl: Duration,
}

impl Default for Handoffs {
    fn default() -> Self {
        Self {
            candidates: HashMap::new(),
            retiring: HashMap::new(),
            session_ttl: Duration::from_secs(
                crate::config::default_packet_plane_session_ttl_seconds(),
            ),
        }
    }
}

impl Handoffs {
    pub(super) fn has_peer(&self, peer: PeerId) -> bool {
        self.candidates.contains_key(&peer) || self.retiring.contains_key(&peer)
    }

    pub(super) fn remove_peer(&mut self, peer: PeerId) {
        for slot in [&mut self.candidates, &mut self.retiring] {
            if let Some(previous) = slot.remove(&peer) {
                previous
                    .connection
                    .close(0_u32.into(), b"QUIC handoff cancelled");
            }
        }
    }

    pub(super) fn clear(&mut self) {
        for slot in [&mut self.candidates, &mut self.retiring] {
            for (_, previous) in slot.drain() {
                previous
                    .connection
                    .close(0_u32.into(), b"QUIC handoff cancelled");
            }
        }
    }

    fn deadline(&self, peer: Option<PeerId>) -> Option<Instant> {
        self.candidates
            .iter()
            .chain(&self.retiring)
            .filter(|(candidate, _)| peer.is_none_or(|peer| peer == **candidate))
            .map(|(_, slot)| slot.deadline)
            .min()
    }

    fn expire(&mut self, now: Instant) {
        for (slots, reason) in [
            (&mut self.candidates, "validation_expired"),
            (&mut self.retiring, "receive_drain_complete"),
        ] {
            slots.retain(|peer, slot| {
                if slot.deadline > now {
                    return true;
                }
                slot.connection
                    .close(0_u32.into(), b"QUIC handoff deadline");
                eprintln!(
                    "level=info event=packet_plane_quic_handoff_retired peer={peer} reason={reason}"
                );
                false
            });
        }
    }
}

#[derive(Debug)]
pub(crate) struct ScopedQuicFrame {
    pub received: PacketPlaneReceivedFrame,
    pub connection_id: usize,
}

#[derive(Clone, Copy)]
enum Slot {
    Active,
    Candidate,
    Retiring,
}

impl PacketPlaneQuicRuntime {
    pub(crate) fn set_session_ttl(&mut self, ttl: Duration) {
        self.handoffs.session_ttl = ttl;
        for slot in self
            .handoffs
            .retiring
            .values_mut()
            .chain(self.handoffs.candidates.values_mut())
        {
            slot.deadline =
                cap_to_session_lifetime(slot.deadline, slot.session.established_at, ttl);
        }
    }

    /// Derive and check all new session state before touching the active path.
    /// Existing sessions require a fresh authenticated datagram before promotion.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_connection_with_session(
        &mut self,
        peer: PeerId,
        connection: PacketPlaneQuicConnection,
        role: PacketPlaneSessionRole,
        secret: &PacketPlaneEphemeralSecret,
        local: &VerifiedPacketPlaneHandshake,
        remote: &VerifiedPacketPlaneHandshake,
    ) -> Result<PacketPlaneSessionSnapshot, PacketPlaneQuicError> {
        let result = (|| {
            #[cfg(target_os = "linux")]
            if self.route_refresh_needed(peer) && connection.connection.route_lease().is_none() {
                return Err(quic_binding_error(
                    "QUIC route replacement requires owned egress",
                ));
            }
            if !connection.connection.route_is_current() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "stale QUIC egress selection",
                )
                .into());
            }
            if remote.peer != peer || local.peer == remote.peer {
                return Err(quic_binding_error("QUIC session peer mismatch"));
            }
            if connection.connection.max_datagram_size().is_none() {
                return Err(PacketPlaneQuicError::SendDatagram(
                    quinn::SendDatagramError::UnsupportedByPeer,
                ));
            }
            let keys = PacketPlaneSessionKeys::derive(role, secret, local, remote)?;
            if self
                .sessions
                .get(&peer)
                .into_iter()
                .chain(
                    self.handoffs
                        .candidates
                        .get(&peer)
                        .map(|slot| &slot.session),
                )
                .chain(self.handoffs.retiring.get(&peer).map(|slot| &slot.session))
                .any(|previous| previous.keys == keys)
            {
                return Err(quic_binding_error("QUIC replacement reused active keys"));
            }
            Ok(PacketPlaneSession {
                peer,
                endpoint: remote.endpoint,
                mtu: local.mtu.min(remote.mtu),
                role,
                local_session_id: local.session_id,
                remote_session_id: remote.session_id,
                established_at: Instant::now(),
                keys,
                replay_windows: HashMap::new(),
                max_replay_windows: self.max_replay_windows_per_session,
            })
        })();
        let session = match result {
            Ok(session) => session,
            Err(error) => {
                connection
                    .connection
                    .close(0_u32.into(), b"invalid QUIC replacement");
                return Err(error);
            }
        };
        let snapshot = session.snapshot();
        self.handoffs.expire(Instant::now());
        if self.sessions.contains_key(&peer) {
            if !self.handoffs.candidates.contains_key(&peer)
                && self.handoffs.candidates.len() >= MAX_CANDIDATES
            {
                connection
                    .connection
                    .close(0_u32.into(), b"QUIC candidate limit");
                return Err(PacketPlaneQuicError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "QUIC candidate limit",
                )));
            }
            let candidate = TimedSession {
                connection: connection.connection,
                deadline: cap_to_session_lifetime(
                    Instant::now() + VALIDATION_TIMEOUT,
                    session.established_at,
                    self.handoffs.session_ttl,
                ),
                session,
            };
            if let Some(previous) = self.handoffs.candidates.insert(peer, candidate) {
                previous
                    .connection
                    .close(0_u32.into(), b"QUIC candidate superseded");
            }
            eprintln!("level=info event=packet_plane_quic_replacement_staged peer={peer}");
        } else {
            self.connections.insert(peer, connection.connection);
            self.sessions.insert(peer, session);
        }
        Ok(snapshot)
    }

    pub(crate) fn has_pending_replacement(&self, peer: PeerId) -> bool {
        self.handoffs.candidates.contains_key(&peer)
    }

    pub(crate) fn connection_id(&self, peer: PeerId) -> Option<usize> {
        self.connections
            .get(&peer)
            .map(|connection| connection.stable_id())
    }

    pub(crate) fn probe_connection_id(&self, peer: PeerId) -> Option<usize> {
        self.live_candidate(peer)
            .map(|slot| slot.connection.stable_id())
            .or_else(|| self.connection_id(peer))
    }

    pub(crate) fn probe_mtu_for(&self, peer: PeerId) -> Option<u16> {
        self.live_candidate(peer)
            .map(|slot| quic_payload_mtu(&slot.connection, slot.session.mtu))
            .or_else(|| self.session_mtu_for(peer))
    }

    fn live_candidate(&self, peer: PeerId) -> Option<&TimedSession> {
        self.handoffs.candidates.get(&peer).filter(|slot| {
            slot.deadline > Instant::now()
                && slot.connection.close_reason().is_none()
                && slot.connection.route_is_current()
        })
    }

    pub(crate) fn send_path_probe_to_peer(
        &self,
        peer: PeerId,
        frame: &Frame,
    ) -> Result<usize, PacketPlaneQuicError> {
        if frame.header.payload_type != PayloadType::PathProbe {
            return Err(quic_binding_error(
                "QUIC candidate accepts path probes only",
            ));
        }
        if let Some(slot) = self.live_candidate(peer) {
            return send_on(&slot.connection, &slot.session, frame);
        }
        self.send_frame_to_peer(peer, frame)
    }

    pub(crate) fn send_frame_on_connection(
        &self,
        peer: PeerId,
        connection_id: usize,
        frame: &Frame,
    ) -> Result<usize, PacketPlaneQuicError> {
        if frame.header.payload_type != PayloadType::PathProbe {
            return Err(quic_binding_error(
                "QUIC draining path accepts probe replies only",
            ));
        }
        if self.connection_id(peer) == Some(connection_id) {
            return self.send_frame_to_peer(peer, frame);
        }
        if let Some(slot) = self.handoffs.retiring.get(&peer).filter(|slot| {
            slot.deadline > Instant::now() && slot.connection.stable_id() == connection_id
        }) {
            return send_on(&slot.connection, &slot.session, frame);
        }
        Err(PacketPlaneQuicError::NoConnection { peer })
    }

    fn promote_candidate(&mut self, peer: PeerId) {
        let Some(candidate) = self.handoffs.candidates.remove(&peer) else {
            return;
        };
        let old_connection = self.connections.insert(peer, candidate.connection);
        let old_session = self.sessions.insert(peer, candidate.session);
        if let Some(old) = self.handoffs.retiring.remove(&peer) {
            old.connection
                .close(0_u32.into(), b"QUIC receive drain superseded");
        }
        if let (Some(connection), Some(session)) = (old_connection, old_session) {
            if self.handoffs.retiring.len() >= MAX_RETIRING
                && let Some(oldest) = self
                    .handoffs
                    .retiring
                    .iter()
                    .min_by_key(|(_, slot)| slot.deadline)
                    .map(|(peer, _)| *peer)
                && let Some(previous) = self.handoffs.retiring.remove(&oldest)
            {
                previous
                    .connection
                    .close(0_u32.into(), b"QUIC receive drain limit");
            }
            let deadline = cap_to_session_lifetime(
                Instant::now() + RECEIVE_DRAIN,
                session.established_at,
                self.handoffs.session_ttl,
            );
            self.handoffs.retiring.insert(
                peer,
                TimedSession {
                    connection,
                    session,
                    deadline,
                },
            );
        }
        eprintln!("level=info event=packet_plane_quic_replacement_promoted peer={peer}");
    }

    pub(crate) async fn recv_frame_from_session_scoped(
        &mut self,
    ) -> Result<ScopedQuicFrame, PacketPlaneQuicError> {
        self.receive_scoped(None).await
    }

    pub(super) async fn receive_scoped(
        &mut self,
        only_peer: Option<PeerId>,
    ) -> Result<ScopedQuicFrame, PacketPlaneQuicError> {
        loop {
            self.handoffs.expire(Instant::now());
            let deadline = self.handoffs.deadline(only_peer);
            let incoming = {
                let mut reads = Vec::with_capacity(
                    self.connections.len()
                        + self.handoffs.candidates.len()
                        + self.handoffs.retiring.len(),
                );
                let read = |peer, kind, connection: &Connection| {
                    let connection = connection.clone();
                    Box::pin(async move {
                        let data = connection.read_datagram().await;
                        (
                            peer,
                            kind,
                            connection.stable_id(),
                            connection.remote_address(),
                            data,
                        )
                    })
                };
                for peer in self.sessions.keys() {
                    if only_peer.is_some_and(|only| only != *peer) {
                        continue;
                    }
                    if let Some(connection) = self.connections.get(peer) {
                        reads.push(read(*peer, Slot::Active, connection));
                    }
                }
                for (slots, kind) in [
                    (&self.handoffs.candidates, Slot::Candidate),
                    (&self.handoffs.retiring, Slot::Retiring),
                ] {
                    for (peer, slot) in slots {
                        if only_peer.is_none_or(|only| only == *peer) {
                            reads.push(read(*peer, kind, &slot.connection));
                        }
                    }
                }
                if reads.is_empty() {
                    return Err(only_peer.map_or(PacketPlaneQuicError::NoSessions, |peer| {
                        PacketPlaneQuicError::NoConnection { peer }
                    }));
                }
                tokio::select! {
                    ((peer, kind, id, remote, data), _, _) = select_all(reads) => Some((peer, kind, id, remote, data)),
                    () = async { match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => std::future::pending().await,
                    }} => None,
                }
            };
            let Some((peer, kind, connection_id, remote_addr, data)) = incoming else {
                continue;
            };
            if self.reject_obsolete_phase(peer, kind) {
                continue;
            }
            let data = match data {
                Ok(data) => data,
                Err(source) => {
                    self.handle_closed_connection(peer, kind, source)?;
                    continue;
                }
            };
            let Some(frame) = self.open_scoped_datagram(peer, kind, &data)? else {
                continue;
            };
            if self.reject_obsolete_phase(peer, kind) {
                continue;
            }
            if matches!(kind, Slot::Candidate) {
                self.promote_candidate(peer);
            }
            let local_addr = match kind {
                Slot::Retiring => self
                    .handoffs
                    .retiring
                    .get(&peer)
                    .map(|slot| &slot.connection),
                Slot::Active | Slot::Candidate => self.connections.get(&peer),
            }
            .map_or(self.local_addr, |connection| {
                connection.local_socket_addr(self.local_addr)
            });
            return Ok(ScopedQuicFrame {
                received: PacketPlaneReceivedFrame {
                    frame,
                    peer: Some(peer),
                    remote_addr,
                    local_addr,
                },
                connection_id,
            });
        }
    }

    fn reject_obsolete_phase(&mut self, peer: PeerId, kind: Slot) -> bool {
        if matches!(kind, Slot::Candidate)
            && self
                .handoffs
                .candidates
                .get(&peer)
                .is_some_and(|slot| !slot.connection.route_is_current())
        {
            if let Some(stale) = self.handoffs.candidates.remove(&peer) {
                stale
                    .connection
                    .close(0_u32.into(), b"stale QUIC candidate egress");
            }
            eprintln!(
                "level=info event=packet_plane_quic_replacement_failed peer={peer} reason=stale_egress"
            );
            return true;
        }
        // Timers and datagrams can become ready together. Check again after
        // authentication so a phase cannot be promoted beyond its deadline.
        let deadline = match kind {
            Slot::Active => None,
            Slot::Candidate => self
                .handoffs
                .candidates
                .get(&peer)
                .map(|slot| slot.deadline),
            Slot::Retiring => self.handoffs.retiring.get(&peer).map(|slot| slot.deadline),
        };
        let now = Instant::now();
        if deadline.is_some_and(|deadline| deadline <= now) {
            self.handoffs.expire(now);
            return true;
        }
        false
    }

    fn handle_closed_connection(
        &mut self,
        peer: PeerId,
        kind: Slot,
        source: quinn::ConnectionError,
    ) -> Result<(), PacketPlaneQuicError> {
        match kind {
            Slot::Candidate => {
                self.handoffs.candidates.remove(&peer);
                eprintln!(
                    "level=info event=packet_plane_quic_replacement_failed peer={peer} reason=connection_closed"
                );
            }
            Slot::Retiring => {
                self.handoffs.retiring.remove(&peer);
            }
            Slot::Active => {
                self.connections.remove(&peer);
                if let Some(old) = self.handoffs.retiring.remove(&peer).filter(|slot| {
                    slot.deadline > Instant::now() && slot.connection.close_reason().is_none()
                }) {
                    self.connections.insert(peer, old.connection);
                    self.sessions.insert(peer, old.session);
                    eprintln!(
                        "level=info event=packet_plane_quic_replacement_rollback peer={peer}"
                    );
                } else {
                    if !self.handoffs.candidates.contains_key(&peer) {
                        self.sessions.remove(&peer);
                    }
                    return Err(PacketPlaneQuicError::PeerConnection { peer, source });
                }
            }
        }
        Ok(())
    }

    fn open_scoped_datagram(
        &mut self,
        peer: PeerId,
        kind: Slot,
        data: &[u8],
    ) -> Result<Option<Frame>, PacketPlaneQuicError> {
        let session = match kind {
            Slot::Active => self.sessions.get_mut(&peer),
            Slot::Candidate => self
                .handoffs
                .candidates
                .get_mut(&peer)
                .map(|slot| &mut slot.session),
            Slot::Retiring => self
                .handoffs
                .retiring
                .get_mut(&peer)
                .map(|slot| &mut slot.session),
        }
        .ok_or(PacketPlaneQuicError::NoConnection { peer })?;
        let frame = session
            .keys
            .open
            .open_frame(data, usize::from(session.mtu))
            .and_then(|frame| {
                session.accept_datagram(&frame)?;
                Ok(frame)
            });
        match frame {
            Ok(frame) => Ok(Some(frame)),
            Err(_) if matches!(kind, Slot::Candidate) => {
                // An invalid candidate cannot demote the authenticated active path.
                if let Some(slot) = self.handoffs.candidates.remove(&peer) {
                    slot.connection
                        .close(0_u32.into(), b"invalid QUIC candidate frame");
                    eprintln!(
                        "level=info event=packet_plane_quic_replacement_failed peer={peer} reason=invalid_datagram"
                    );
                }
                Ok(None)
            }
            // Return rejected active/draining datagrams to the caller's fairness
            // budget instead of silently looping under sustained invalid input.
            Err(error) => Err(error.into()),
        }
    }
}

fn send_on(
    connection: &Connection,
    session: &PacketPlaneSession,
    frame: &Frame,
) -> Result<usize, PacketPlaneQuicError> {
    let mtu = quic_payload_mtu(connection, session.mtu);
    if frame.payload.len() > usize::from(mtu) {
        return Err(PacketPlaneDatagramError::PayloadTooLarge {
            actual: frame.payload.len(),
            max: usize::from(mtu),
        }
        .into());
    }
    let datagram = session.keys.seal.seal_frame(frame)?;
    let len = datagram.len();
    connection.send_datagram(datagram.into())?;
    Ok(len)
}
