//! Validate a new UDP key/route pair without replacing the working payload path.

use super::*;
use crate::runtime::path_probe::{path_probe_ack_token, path_probe_request_token};
use crate::wire::PayloadType;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_CANDIDATES: usize = 16;
const MAX_RETIRING: usize = 64;
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Active,
    Candidate,
    Retiring(usize),
    LegacyRetiring,
}

#[derive(Debug)]
struct Probe {
    token: u64,
    listener: usize,
    deadline: Instant,
}

#[derive(Debug)]
struct Timed {
    session: PacketPlaneSession,
    routes: Arc<udp_path::Routes>,
    lifetime: Duration,
    deadline: Instant,
    receive_deadline: Instant,
    receive_authorized: AtomicBool,
    #[cfg(target_os = "android")]
    aborted: AtomicBool,
    probe: Mutex<Option<Probe>>,
}

impl Timed {
    fn live(&self, now: Instant) -> bool {
        now < self.cleanup_deadline()
            && now.saturating_duration_since(self.session.established_at) < self.lifetime
    }

    fn validation_live(&self, now: Instant) -> bool {
        #[cfg(target_os = "android")]
        if self.aborted.load(Ordering::Acquire) {
            return false;
        }
        now < self.deadline
            && now.saturating_duration_since(self.session.established_at) < self.lifetime
    }

    fn cleanup_deadline(&self) -> Instant {
        if self.receive_authorized.load(Ordering::Acquire) {
            self.receive_deadline
        } else {
            self.deadline
        }
    }

    fn owner_id(&self) -> usize {
        Arc::as_ptr(&self.routes.token) as usize
    }
}

#[derive(Debug, Default)]
pub(super) struct Handoffs {
    candidates: HashMap<PeerId, Timed>,
    retiring: HashMap<(PeerId, usize), Timed>,
}

impl Handoffs {
    pub(super) fn source_endpoints(&self, now: Instant) -> impl Iterator<Item = SocketAddr> + '_ {
        self.candidates
            .values()
            .filter(move |slot| slot.validation_live(now))
            .flat_map(|slot| slot.routes.current_sources())
    }

    pub(super) fn clear(&mut self) {
        self.candidates.clear();
        self.retiring.clear();
    }
    pub(super) fn remove_peer(&mut self, peer: PeerId) {
        self.candidates.remove(&peer);
        self.retiring.retain(|(candidate, _), _| *candidate != peer);
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.candidates
            .values()
            .chain(self.retiring.values())
            .map(|slot| slot.deadline)
            .min()
    }
    pub(super) fn retiring_count(&self) -> usize {
        self.retiring.len()
    }

    pub(super) fn counts(&self) -> (usize, usize) {
        let now = Instant::now();
        let validating = self
            .candidates
            .values()
            .filter(|slot| slot.validation_live(now))
            .count();
        let receive_only = self.retiring.values().filter(|slot| slot.live(now)).count()
            + self
                .candidates
                .values()
                .filter(|slot| !slot.validation_live(now) && slot.live(now))
                .count();
        (validating, receive_only)
    }
    pub(super) fn cap_lifetime(&mut self, ttl: Duration) {
        for slot in self
            .candidates
            .values_mut()
            .chain(self.retiring.values_mut())
        {
            slot.lifetime = slot.lifetime.min(ttl);
            slot.deadline = cap(slot.deadline, slot.session.established_at, slot.lifetime);
            slot.receive_deadline = cap(
                slot.receive_deadline,
                slot.session.established_at,
                slot.lifetime,
            );
        }
    }

    pub(super) fn can_receive(&self) -> bool {
        self.candidates
            .values()
            .chain(self.retiring.values())
            .any(|slot| slot.live(Instant::now()))
    }

    pub(super) fn can_receive_peer(&self, peer: PeerId) -> bool {
        self.candidates
            .get(&peer)
            .into_iter()
            .chain(
                self.retiring
                    .iter()
                    .filter_map(|((candidate, _), slot)| (*candidate == peer).then_some(slot)),
            )
            .any(|slot| slot.live(Instant::now()))
    }

    fn phases(&self, peer: PeerId) -> impl Iterator<Item = Phase> + '_ {
        [Phase::Active, Phase::Candidate, Phase::LegacyRetiring]
            .into_iter()
            .chain(self.retiring.keys().filter_map(move |(candidate, owner)| {
                (*candidate == peer).then_some(Phase::Retiring(*owner))
            }))
    }

    fn retire(&mut self, peer: PeerId, mut slot: Timed) {
        slot.deadline = slot.receive_deadline;
        slot.probe = Mutex::new(None);
        self.retiring.insert((peer, slot.owner_id()), slot);
    }
}

fn cap(deadline: Instant, established: Instant, lifetime: Duration) -> Instant {
    established
        .checked_add(lifetime)
        .map_or(deadline, |expiry| deadline.min(expiry))
}

impl PacketPlaneRuntime {
    /// Managed startup and renewal both need exact path proof. The public
    /// unmanaged renewal API retains its original direct-install behavior.
    pub(crate) fn install_udp_session(
        &mut self,
        role: PacketPlaneSessionRole,
        secret: &PacketPlaneEphemeralSecret,
        local: &VerifiedPacketPlaneHandshake,
        remote: &VerifiedPacketPlaneHandshake,
    ) -> Result<PacketPlaneSessionSnapshot, String> {
        self.install_udp_session_recovering(role, secret, local, remote, false)
    }

    pub(crate) fn install_udp_session_recovering(
        &mut self,
        role: PacketPlaneSessionRole,
        secret: &PacketPlaneEphemeralSecret,
        local: &VerifiedPacketPlaneHandshake,
        remote: &VerifiedPacketPlaneHandshake,
        _active_failure: bool,
    ) -> Result<PacketPlaneSessionSnapshot, String> {
        self.install_prepared_udp_session(role, secret, local, remote, _active_failure, None)
    }

    pub(crate) fn install_prepared_udp_session(
        &mut self,
        role: PacketPlaneSessionRole,
        secret: &PacketPlaneEphemeralSecret,
        local: &VerifiedPacketPlaneHandshake,
        remote: &VerifiedPacketPlaneHandshake,
        _active_failure: bool,
        prepared: Option<PreparedUdpBinding>,
    ) -> Result<PacketPlaneSessionSnapshot, String> {
        if self.udp_owner.is_none() {
            if prepared.is_some() {
                return Err("UDP prepared owner no longer belongs to this runtime".into());
            }
            return self
                .establish_session_overlapping(role, secret, local, remote)
                .map_err(|error| format!("session: {error:?}"));
        }
        let keys = PacketPlaneSessionKeys::derive(role, secret, local, remote)
            .map_err(|error| format!("session: {error:?}"))?;
        let peer = remote.peer;
        if self
            .sessions
            .get(&peer)
            .into_iter()
            .chain(
                self.udp_handoffs
                    .candidates
                    .get(&peer)
                    .map(|slot| &slot.session),
            )
            .chain(
                self.udp_handoffs
                    .retiring
                    .iter()
                    .filter(|((candidate, _), _)| *candidate == peer)
                    .map(|(_, slot)| slot)
                    .map(|slot| &slot.session),
            )
            .chain(self.retiring_sessions.get(&peer).map(|slot| &slot.session))
            .any(|session| session.keys == keys)
        {
            return Err("UDP replacement reused existing keys".to_owned());
        }
        self.expire_udp_handoffs(Instant::now());
        if !self.udp_handoffs.candidates.contains_key(&peer)
            && self.udp_handoffs.candidates.len() >= MAX_CANDIDATES
        {
            return Err("UDP candidate limit".to_owned());
        }
        // Each candidate reserves room for the previous local TX owner. A
        // successful ACK may already have authorized its peer to use the keys;
        // capacity pressure must reject new negotiation, never evict that RX.
        let previous = self.udp_handoffs.candidates.get(&peer);
        let reserved = self.udp_handoffs.retiring.len()
            + self.udp_handoffs.candidates.len() * 2
            + usize::from(previous.is_none()) * 2
            + usize::from(
                previous.is_some_and(|slot| slot.receive_authorized.load(Ordering::Acquire)),
            );
        if reserved > MAX_RETIRING {
            return Err("UDP receive ownership limit".to_owned());
        }
        let session = PacketPlaneSession {
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
        };
        let snapshot = session.snapshot();
        let deadline = cap(
            Instant::now() + VALIDATION_TIMEOUT,
            session.established_at,
            self.session_ttl,
        );
        let receive_deadline = session
            .established_at
            .checked_add(self.session_ttl)
            .unwrap_or(deadline);
        #[allow(unused_mut)]
        let mut routes = if let Some(prepared) = prepared {
            prepared
                .adopt(self, peer, local.endpoint, remote.endpoint)
                .map_err(|error| format!("UDP prepared owner: {error}"))?
        } else {
            udp_path::Routes::new(self.sockets.len())
        };
        #[cfg(target_os = "android")]
        if routes.recovery.is_none()
            && routes
                .sockets
                .first()
                .is_none_or(|slot| slot.path.get().is_none())
        {
            let recovery = self
                .attach_udp_recovery(
                    peer,
                    remote.endpoint,
                    _active_failure,
                    Arc::clone(&routes.token),
                )
                .map_err(|error| format!("UDP recovery admission: {error}"))?;
            Arc::get_mut(&mut routes)
                .expect("fresh UDP routes")
                .recovery = recovery;
        }
        let previous = self.udp_handoffs.candidates.insert(
            peer,
            Timed {
                session,
                routes,
                lifetime: self.session_ttl,
                deadline,
                receive_deadline,
                receive_authorized: AtomicBool::new(false),
                #[cfg(target_os = "android")]
                aborted: AtomicBool::new(false),
                probe: Mutex::new(None),
            },
        );
        self.insert_endpoint_mapping(snapshot.endpoint, peer);
        if let Some(previous) = previous {
            let endpoint = previous.session.endpoint;
            if previous.receive_authorized.load(Ordering::Acquire) && previous.live(Instant::now())
            {
                self.udp_handoffs.retire(peer, previous);
            }
            self.prune_udp_endpoint(peer, endpoint);
        }
        eprintln!("level=info event=packet_plane_udp_replacement_staged peer={peer}");
        Ok(snapshot)
    }

    pub(crate) fn has_pending_udp_replacement(&self, peer: PeerId) -> bool {
        self.udp_handoffs
            .candidates
            .get(&peer)
            .is_some_and(|slot| slot.validation_live(Instant::now()))
    }

    #[cfg(target_os = "android")]
    pub(super) fn udp_candidate_receive_authorized(&self, peer: PeerId) -> bool {
        self.udp_handoffs
            .candidates
            .get(&peer)
            .is_some_and(|candidate| candidate.receive_authorized.load(Ordering::Acquire))
    }

    pub(crate) fn udp_owner_id(&self, peer: PeerId) -> Option<usize> {
        self.udp_owner.as_ref()?;
        self.udp_routes
            .get(&peer)
            .map(|routes| Arc::as_ptr(&routes.token) as usize)
    }

    pub(crate) fn udp_probe_owner_id(&self, peer: PeerId) -> Option<usize> {
        self.udp_owner.as_ref()?;
        self.udp_handoffs
            .candidates
            .get(&peer)
            .filter(|slot| slot.validation_live(Instant::now()))
            .map(|slot| Arc::as_ptr(&slot.routes.token) as usize)
            .or_else(|| self.udp_owner_id(peer))
    }

    pub(crate) fn udp_probe_mtu_for(&self, peer: PeerId) -> Option<u16> {
        self.udp_handoffs
            .candidates
            .get(&peer)
            .filter(|slot| slot.validation_live(Instant::now()))
            .map(|slot| slot.session.mtu)
            .or_else(|| self.session_mtu_for(peer))
    }

    pub(crate) async fn send_udp_path_probe(
        &self,
        peer: PeerId,
        frame: &Frame,
    ) -> Result<usize, PacketPlaneIoError> {
        if frame.header.payload_type != PayloadType::PathProbe {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP candidate accepts probes only",
            )
            .into());
        }
        let Some(candidate) = self
            .udp_handoffs
            .candidates
            .get(&peer)
            .filter(|slot| slot.validation_live(Instant::now()))
        else {
            return self.send_frame_to_peer(peer, frame).await;
        };
        let token = path_probe_request_token(&frame.payload)
            .filter(|token| *token != 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP candidate probe needs a fresh token",
                )
            })?;
        if frame.payload.len() > usize::from(candidate.session.mtu) {
            return Err(PacketPlaneDatagramError::PayloadTooLarge {
                actual: frame.payload.len(),
                max: usize::from(candidate.session.mtu),
            }
            .into());
        }
        let datagram = candidate.session.keys.seal.seal_frame(frame)?;
        let listener = 0;
        let sent = self
            .send_route_datagram(
                &candidate.routes,
                listener,
                candidate.session.endpoint,
                &datagram,
                true,
                Some(candidate.deadline),
            )
            .await;
        #[cfg(target_os = "android")]
        if let Err(error) = &sent
            && let Some(recovery) = &candidate.routes.recovery
        {
            recovery.failed(error.kind(), Instant::now());
            candidate.aborted.store(true, Ordering::Release);
        }
        let size = sent?;
        *candidate
            .probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Probe {
            token,
            listener,
            deadline: candidate.deadline,
        });
        Ok(size)
    }

    pub(crate) async fn send_udp_probe_reply(
        &self,
        scoped: &ScopedUdpFrame,
        frame: &Frame,
    ) -> Result<usize, PacketPlaneIoError> {
        if frame.header.payload_type != PayloadType::PathProbe {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP scoped sends accept probe replies only",
            )
            .into());
        }
        let peer = scoped.received.peer.ok_or(PacketPlaneIoError::NoSessions)?;
        if self.udp_owner.is_none() {
            return self.send_frame_to_peer(peer, frame).await;
        }
        let session = self
            .udp_scoped_session(peer, scoped.phase, Instant::now())
            .ok_or(PacketPlaneIoError::NoSession { peer })?;
        if frame.payload.len() > usize::from(session.mtu) {
            return Err(PacketPlaneDatagramError::PayloadTooLarge {
                actual: frame.payload.len(),
                max: usize::from(session.mtu),
            }
            .into());
        }
        let routes = self
            .udp_scoped_routes(peer, scoped.phase)
            .filter(|routes| {
                scoped
                    .routes
                    .as_ref()
                    .is_some_and(|expected| Arc::ptr_eq(expected, routes))
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Interrupted, "UDP reply owner was retired")
            })?;
        let datagram = session.keys.seal.seal_frame(frame)?;
        if matches!(scoped.phase, Phase::Retiring(_)) {
            let route = routes
                .sockets
                .get(scoped.listener)
                .and_then(|slot| slot.path.get())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Interrupted,
                        "retired UDP route cannot be reacquired",
                    )
                })?;
            let deadline = self.udp_scoped_deadline(peer, scoped.phase);
            return Ok(
                udp_path::before_deadline(deadline, route.send_before(&datagram, deadline)).await?,
            );
        }
        self.remember_incoming_route(scoped).await?;
        let size = self
            .send_route_datagram(
                routes,
                scoped.listener,
                session.endpoint,
                &datagram,
                scoped.phase == Phase::Candidate,
                self.udp_scoped_deadline(peer, scoped.phase),
            )
            .await?;
        if scoped.phase == Phase::Candidate
            && let Some(request) =
                path_probe_request_token(&scoped.received.frame.payload).filter(|token| *token != 0)
            && path_probe_ack_token(&frame.payload) == Some(request)
            && let Some(candidate) = self.udp_handoffs.candidates.get(&peer)
        {
            // Successful local transmission grants permission to the peer;
            // ACK loss is not evidence that these RX keys are unused.
            candidate.receive_authorized.store(true, Ordering::Release);
        }
        Ok(size)
    }

    pub(super) fn udp_scoped_session(
        &self,
        peer: PeerId,
        phase: Phase,
        now: Instant,
    ) -> Option<&PacketPlaneSession> {
        match phase {
            Phase::Active => self.sessions.get(&peer).filter(|session| {
                self.session_lifetimes
                    .get(&peer)
                    .is_some_and(|ttl| now.saturating_duration_since(session.established_at) < *ttl)
            }),
            Phase::Candidate => self
                .udp_handoffs
                .candidates
                .get(&peer)
                .filter(|slot| slot.live(now))
                .map(|slot| &slot.session),
            Phase::Retiring(owner) => self
                .udp_handoffs
                .retiring
                .get(&(peer, owner))
                .filter(|slot| slot.live(now))
                .map(|slot| &slot.session),
            Phase::LegacyRetiring => self
                .retiring_sessions
                .get(&peer)
                .filter(|slot| {
                    now.saturating_duration_since(slot.session.established_at) < slot.lifetime
                })
                .map(|slot| &slot.session),
        }
    }

    pub(super) fn udp_scoped_deadline(&self, peer: PeerId, phase: Phase) -> Option<Instant> {
        match phase {
            Phase::Candidate => self
                .udp_handoffs
                .candidates
                .get(&peer)
                .map(Timed::cleanup_deadline),
            Phase::Retiring(owner) => self
                .udp_handoffs
                .retiring
                .get(&(peer, owner))
                .map(|slot| slot.deadline),
            Phase::Active => self.sessions.get(&peer).and_then(|session| {
                session
                    .established_at
                    .checked_add(*self.session_lifetimes.get(&peer)?)
            }),
            Phase::LegacyRetiring => self
                .retiring_sessions
                .get(&peer)
                .and_then(|slot| slot.session.established_at.checked_add(slot.lifetime)),
        }
    }

    pub(super) fn udp_scoped_routes(
        &self,
        peer: PeerId,
        phase: Phase,
    ) -> Option<&Arc<udp_path::Routes>> {
        match phase {
            Phase::Active => self.udp_routes.get(&peer),
            Phase::Candidate => self
                .udp_handoffs
                .candidates
                .get(&peer)
                .map(|slot| &slot.routes),
            Phase::Retiring(owner) => self
                .udp_handoffs
                .retiring
                .get(&(peer, owner))
                .map(|slot| &slot.routes),
            Phase::LegacyRetiring => self
                .retiring_sessions
                .get(&peer)
                .and_then(|slot| slot.routes.as_ref()),
        }
    }

    pub(crate) async fn accept_udp_frame(
        &mut self,
        scoped: &ScopedUdpFrame,
    ) -> Result<bool, PacketPlaneIoError> {
        if self.udp_owner.is_none() {
            return Ok(false);
        }
        let peer = scoped
            .received
            .peer
            .ok_or_else(|| io::Error::other("missing UDP peer"))?;
        if !self
            .udp_scoped_routes(peer, scoped.phase)
            .zip(scoped.routes.as_ref())
            .is_some_and(|(current, captured)| Arc::ptr_eq(current, captured))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP session owner was retired",
            )
            .into());
        }
        let candidate_ack = (scoped.phase == Phase::Candidate
            && scoped.received.frame.header.payload_type == PayloadType::PathProbe)
            .then(|| path_probe_ack_token(&scoped.received.frame.payload))
            .flatten();
        if let Some(acknowledged) = candidate_ack
            && !scoped
                .received
                .peer
                .and_then(|peer| self.udp_handoffs.candidates.get(&peer))
                .is_some_and(|candidate| {
                    candidate.validation_live(Instant::now())
                        && candidate
                            .probe
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .as_ref()
                            .is_some_and(|probe| {
                                probe.token == acknowledged
                                    && probe.listener == scoped.listener
                                    && probe.deadline > Instant::now()
                            })
                })
        {
            // A replay on another listener or an unrelated challenge cannot
            // consume the matching candidate's replay slot or acquire a socket.
            return Ok(false);
        }
        self.remember_incoming_route(scoped).await?;
        if self
            .udp_scoped_session(peer, scoped.phase, Instant::now())
            .is_none()
        {
            return Err(PacketPlaneIoError::NoSession { peer });
        }
        if candidate_ack.is_some() {
            let candidate = self
                .udp_handoffs
                .candidates
                .get(&peer)
                .ok_or(PacketPlaneIoError::NoSession { peer })?;
            if !candidate.validation_live(Instant::now()) {
                return Err(
                    io::Error::new(io::ErrorKind::Interrupted, "UDP candidate expired").into(),
                );
            }
            let current = candidate
                .routes
                .sockets
                .get(scoped.listener)
                .and_then(|slot| slot.path.get())
                .is_some_and(|path| path.lease.preferred_dial && path.lease.is_current());
            if !current {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "UDP candidate route changed",
                )
                .into());
            }
        }
        let session = match scoped.phase {
            Phase::Active => self.sessions.get_mut(&peer),
            Phase::Candidate => self
                .udp_handoffs
                .candidates
                .get_mut(&peer)
                .map(|slot| &mut slot.session),
            Phase::Retiring(owner) => self
                .udp_handoffs
                .retiring
                .get_mut(&(peer, owner))
                .map(|slot| &mut slot.session),
            Phase::LegacyRetiring => self
                .retiring_sessions
                .get_mut(&peer)
                .map(|slot| &mut slot.session),
        }
        .ok_or(PacketPlaneIoError::NoSession { peer })?;
        // Route acquisition is outside the cancelable read. Commit replay only
        // after exact tuple/owner validation, so a wrong-interface copy cannot
        // consume a legitimate packet's replay slot.
        let replay = session.accept_datagram(&scoped.received.frame);
        // A fresh outstanding random challenge is a separate one-shot proof.
        // DATA may overtake its ACK by more than the data replay-window width.
        // Never rewind that window or bypass it for application payloads.
        match replay {
            Ok(()) => {}
            Err(
                PacketPlaneDatagramError::ReplayedDatagram { .. }
                | PacketPlaneDatagramError::DatagramOutsideReplayWindow { .. },
            ) if candidate_ack.is_some() => {}
            Err(error) => return Err(error.into()),
        }
        if candidate_ack.is_none() {
            return Ok(false);
        }
        #[cfg(target_os = "android")]
        if let Some((recovery, deadline)) =
            self.udp_handoffs
                .candidates
                .get(&peer)
                .and_then(|candidate| {
                    candidate
                        .routes
                        .recovery
                        .clone()
                        .map(|recovery| (recovery, candidate.deadline))
                })
        {
            recovery
                .confirm_with(deadline, || self.promote_udp_candidate(peer))
                .await?;
            return Ok(true);
        }
        self.promote_udp_candidate(peer);
        Ok(true)
    }

    fn promote_udp_candidate(&mut self, peer: PeerId) {
        let Some(candidate) = self.udp_handoffs.candidates.remove(&peer) else {
            return;
        };
        let mut removed = Vec::new();
        let old_session = self.sessions.insert(peer, candidate.session);
        let old_routes = self.udp_routes.insert(peer, candidate.routes);
        let old_lifetime = self.session_lifetimes.insert(peer, candidate.lifetime);
        self.udp_route_refresh
            .retain(|(current, _), _| *current != peer);
        if let Some(legacy) = self.retiring_sessions.remove(&peer) {
            removed.push((peer, legacy.session.endpoint));
        }
        if let (Some(session), Some(routes), Some(lifetime)) =
            (old_session, old_routes, old_lifetime)
        {
            // Local TX promotion is not proof of remote TX promotion. Retain
            // this silent RX owner within its original key lifetime; there is
            // no timer-driven probe, route reacquisition or active TX here.
            let deadline = session
                .established_at
                .checked_add(lifetime)
                .unwrap_or(Instant::now());
            self.udp_handoffs.retire(
                peer,
                Timed {
                    session,
                    routes,
                    lifetime,
                    deadline,
                    receive_deadline: deadline,
                    receive_authorized: AtomicBool::new(true),
                    #[cfg(target_os = "android")]
                    aborted: AtomicBool::new(false),
                    probe: Mutex::new(None),
                },
            );
        }
        // Prune only after all ownership moves, including shared endpoints.
        for (peer, endpoint) in removed {
            self.prune_udp_endpoint(peer, endpoint);
        }
        if let Some(owner) = &self.udp_owner {
            owner.paths_changed();
        }
        eprintln!("level=info event=packet_plane_udp_replacement_promoted peer={peer}");
    }

    pub(super) fn expire_udp_handoffs(&mut self, now: Instant) {
        let mut removed = Vec::new();
        let expired = self
            .udp_handoffs
            .candidates
            .iter()
            .filter_map(|(peer, slot)| (!slot.validation_live(now)).then_some(*peer))
            .collect::<Vec<_>>();
        for peer in expired {
            let slot = self
                .udp_handoffs
                .candidates
                .remove(&peer)
                .expect("expired candidate exists");
            let endpoint = slot.session.endpoint;
            #[cfg(target_os = "android")]
            if let Some(recovery) = &slot.routes.recovery {
                recovery.failed(io::ErrorKind::TimedOut, now);
            }
            let retained = slot.receive_authorized.load(Ordering::Acquire) && slot.live(now);
            eprintln!(
                "level=info event=packet_plane_udp_validation_expired peer={peer} receive_retained={retained}"
            );
            if retained {
                self.udp_handoffs.retire(peer, slot);
            } else {
                removed.push((peer, endpoint));
            }
        }
        self.udp_handoffs.retiring.retain(|(peer, _), slot| {
            if slot.live(now) {
                return true;
            }
            removed.push((*peer, slot.session.endpoint));
            false
        });
        for (peer, endpoint) in removed {
            self.prune_udp_endpoint(peer, endpoint);
            eprintln!("level=info event=packet_plane_udp_handoff_retired peer={peer}");
        }
    }

    pub(super) fn forget_udp_handoffs(&mut self, peer: PeerId) {
        let endpoints = self
            .udp_handoffs
            .candidates
            .get(&peer)
            .into_iter()
            .chain(
                self.udp_handoffs
                    .retiring
                    .iter()
                    .filter_map(|((candidate, _), slot)| (*candidate == peer).then_some(slot)),
            )
            .map(|slot| slot.session.endpoint)
            .collect::<Vec<_>>();
        self.udp_handoffs.remove_peer(peer);
        for endpoint in endpoints {
            self.prune_udp_endpoint(peer, endpoint);
        }
    }

    pub(super) fn prune_udp_endpoint(&mut self, peer: PeerId, endpoint: SocketAddr) {
        let live = self.udp_handoffs.phases(peer).any(|phase| {
            self.udp_scoped_session(peer, phase, Instant::now())
                .is_some_and(|session| {
                    udp_socket::canonical(session.endpoint) == udp_socket::canonical(endpoint)
                })
        });
        if !live {
            self.remove_endpoint_mapping(peer, endpoint);
        }
    }

    pub(super) fn open_managed_udp_datagram(
        &self,
        peer: PeerId,
        len: usize,
        remote: SocketAddr,
    ) -> Result<(Frame, Phase), PacketPlaneDatagramError> {
        let now = Instant::now();
        for phase in self.udp_handoffs.phases(peer) {
            let session = self.udp_scoped_session(peer, phase, now);
            let Some(session) =
                session.filter(|session| udp_path::same_destination(session.endpoint, remote))
            else {
                continue;
            };
            let Ok(frame) = session
                .keys
                .open
                .open_frame(&self.recv_buffer[..len], usize::from(session.mtu))
            else {
                continue;
            };
            if phase == Phase::Candidate
                && frame.header.payload_type != PayloadType::PathProbe
                && !self
                    .udp_handoffs
                    .candidates
                    .get(&peer)
                    .is_some_and(|slot| slot.receive_authorized.load(Ordering::Acquire))
            {
                return Err(PacketPlaneDatagramError::Decrypt);
            }
            return Ok((frame, phase));
        }
        Err(PacketPlaneDatagramError::Decrypt)
    }
}

#[cfg(test)]
mod tests;
