//! Preferred direct return while the authenticated relay remains active.

use std::time::Duration;

use futures::future::AbortHandle;
use libp2p::{
    Multiaddr, PeerId, request_response as rr,
    swarm::{
        ConnectionId, SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use p2p_vpn::runtime::preferred_handoff::{Command, Outcome, Request, Response};
use p2p_vpn::{
    PathKind,
    runtime::{
        control::{
            self, ControlCapabilities, ControlRequest, ControlResponse,
            checkpoint::CheckpointSyncIndicator,
        },
        packet::PacketResponse,
    },
    wire::Frame,
};
use wasm_bindgen::prelude::*;
use web_time::Instant;

use super::{BehaviourEvent, BrowserVpn, Established, StreamMtu, parse_member_endpoints};
use crate::member_sessions::ProbeOutcome;

mod admission;
pub(super) use admission::CandidateLimits;

const ATTEMPT_LIMIT: Duration = Duration::from_secs(12);
const PACKET_LIMIT: Duration = Duration::from_secs(10);
const PATH_PROBE_V1: &[u8] = b"path-probe-v1";

#[derive(Default)]
pub(super) struct Handoff {
    pub(super) generation: Option<u32>,
    queued: Option<Vec<Multiaddr>>,
    attempt: Option<Attempt>,
    draining: Option<DrainingRelay>,
    released_by: Option<ConnectionId>,
    remote: Option<Request>,
    seen: Vec<[u8; 16]>,
}

struct DrainingRelay {
    fallback: ConnectionId,
    promoted: ConnectionId,
    deadline: Instant,
    closing: bool,
}

struct Attempt {
    generation: u32,
    fallback: ConnectionId,
    candidate: ConnectionId,
    deadline: Instant,
    phase: Phase,
    remote: Option<Request>,
}

enum Phase {
    Dialing,
    CancelledDial,
    Capabilities(PinnedRequest),
    Verify {
        request: PinnedRequest,
        caps: Box<ControlCapabilities>,
        mtu: u16,
    },
    Payload {
        caps: Box<ControlCapabilities>,
        mtu: u16,
    },
    Commit {
        request: PinnedRequest,
        caps: Box<ControlCapabilities>,
        mtu: u16,
        packet: rr::OutboundRequestId,
    },
    Probe {
        request: PinnedRequest,
        caps: Box<ControlCapabilities>,
        mtu: u16,
    },
}

struct PinnedRequest {
    id: rr::OutboundRequestId,
    cancel: AbortHandle,
}

impl From<(rr::OutboundRequestId, AbortHandle)> for PinnedRequest {
    fn from((id, cancel): (rr::OutboundRequestId, AbortHandle)) -> Self {
        Self { id, cancel }
    }
}

#[wasm_bindgen]
impl BrowserVpn {
    /// Stage the newest host-selected LAN endpoints. Ignore older generations;
    /// a newer empty list invalidates pending work. Does not authorize a path.
    pub fn set_preferred_member_endpoints(
        &mut self,
        generation: u32,
        addresses_json: &str,
    ) -> Result<(), JsError> {
        if self
            .handoff
            .generation
            .is_some_and(|current| generation <= current)
        {
            return Ok(());
        }
        let addresses = parse_member_endpoints(addresses_json, self.peer)?;
        self.handoff.generation = Some(generation);
        self.cancel_preferred_attempt();
        self.handoff.remote = None;
        self.handoff.queued = (!addresses.is_empty()).then_some(addresses);
        Ok(())
    }

    /// Whether a promoted direct path is authorized and its old member circuit
    /// has fully closed. Only release a companion relay lease you already own.
    pub fn can_release_discovery_relay(&self) -> bool {
        self.member_connection()
            .is_some_and(|active| self.handoff.released_by == Some(active))
            && self.member_path() == Some(PathKind::DirectWebRtcStream)
            && self.stream_mtu().is_some()
            && self.forwarder.is_configured_transport_peer(self.peer)
    }

    #[cfg(feature = "test-hooks")]
    pub fn test_preferred_path_phase(&self) -> String {
        match self.handoff.attempt.as_ref().map(|attempt| &attempt.phase) {
            Some(Phase::Dialing | Phase::CancelledDial) => "dialing",
            Some(Phase::Capabilities(_)) => "capabilities",
            Some(Phase::Verify { .. }) => "verify",
            Some(Phase::Payload { .. }) => "payload",
            Some(Phase::Commit { .. }) => "commit",
            Some(Phase::Probe { .. }) => "probing",
            None if self.handoff.queued.is_some() => "queued",
            None => "idle",
        }
        .into()
    }

    #[cfg(feature = "test-hooks")]
    pub fn test_established_path_count(&self) -> u32 {
        self.swarm
            .network_info()
            .connection_counters()
            .num_established()
    }

    #[cfg(feature = "test-hooks")]
    pub fn test_queue_path_packet(&mut self, bytes: Vec<u8>) -> Result<(), JsError> {
        let mtu = self
            .stream_mtu()
            .ok_or_else(|| JsError::new("No packet authority"))?;
        let mut queue = p2p_vpn::queue::PeerQueues::new(1, usize::from(mtu));
        self.forwarder
            .enqueue_tun_packet(&mut queue, bytes)
            .map_err(super::debug_error)?;
        let packet = queue
            .dequeue()
            .ok_or_else(|| JsError::new("No queued packet"))?;
        let frame = self
            .forwarder
            .queued_packet_frame_with_mtu(&packet, mtu)
            .map_err(super::debug_error)?;
        let id = self.send_member_packet(frame)?;
        self.pending.insert(id);
        Ok(())
    }
}

impl BrowserVpn {
    pub(super) fn peer_handoff_event(
        &mut self,
        event: rr::Event<Request, Response>,
    ) -> Result<(), JsError> {
        match event {
            rr::Event::Message {
                peer,
                connection_id,
                message:
                    rr::Message::Request {
                        request, channel, ..
                    },
            } => {
                let scope = request.scope.network_name == self.config.network.name
                    && control::membership_tag_matches(
                        request.scope.membership_tag.as_deref(),
                        self.membership_tag().as_deref(),
                        &self.config.network.previous_membership_tags,
                    );
                let allowed = request.command == Command::Offer
                    && peer == self.peer
                    && scope
                    && self.member_connection() == Some(connection_id)
                    && self.relay_ready()
                    && !self.handoff.seen.contains(&request.token)
                    && self.handoff.attempt.is_none()
                    && self.handoff.draining.is_none()
                    && self.handoff.queued.is_none();
                let mut outcome = Outcome::Rejected;
                if allowed {
                    self.refresh_peer_authorization()?;
                    if let Some(address) = self.endpoints.relay_dial_addr() {
                        if self.handoff.seen.len() == 16 {
                            self.handoff.seen.remove(0);
                        }
                        self.handoff.seen.push(request.token);
                        self.handoff.remote = Some(request.clone());
                        self.handoff.queued = Some(vec![address]);
                        outcome = Outcome::Ready;
                    }
                }
                let _ = self.swarm.behaviour_mut().preferred_handoff.send_response(
                    channel,
                    Response {
                        token: request.token,
                        outcome,
                    },
                );
            }
            rr::Event::Message {
                peer,
                connection_id,
                message:
                    rr::Message::Response {
                        request_id,
                        response,
                    },
            } if peer == self.peer && self.is_candidate(connection_id) => {
                let Some(mut attempt) = self.handoff.attempt.take() else {
                    return Ok(());
                };
                let matches = self.attempt_current(&attempt)
                    && attempt
                        .remote
                        .as_ref()
                        .is_some_and(|r| r.token == response.token);
                match &attempt.phase {
                    Phase::Verify { request, caps, mtu } if request.id == request_id => {
                        if matches
                            && response.outcome == Outcome::Verified
                            && self
                                .sessions
                                .allow_candidate_payload(self.member_binding(connection_id))
                        {
                            attempt.phase = Phase::Payload {
                                caps: caps.clone(),
                                mtu: *mtu,
                            };
                            self.handoff.attempt = Some(attempt);
                            return Ok(());
                        }
                    }
                    Phase::Commit { request, .. } if request.id == request_id => {
                        if matches && response.outcome == Outcome::Committed {
                            return self.promote_candidate(attempt, PacketResponse::Accepted);
                        }
                    }
                    _ => {
                        self.handoff.attempt = Some(attempt);
                        return Ok(());
                    }
                }
                self.sessions.closed(self.member_binding(connection_id));
                self.swarm.close_connection(connection_id);
            }
            rr::Event::OutboundFailure { connection_id, .. }
                if self.is_candidate(connection_id) =>
            {
                self.cancel_preferred_attempt();
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn drive_handoff(&mut self) -> Result<(), JsError> {
        let now = Instant::now();
        if let Some(drain) = &mut self.handoff.draining
            && !drain.closing
        {
            let wire = self.swarm.behaviour();
            if now >= drain.deadline
                || (!wire
                    .packet
                    .has_pending_requests_on_connection(&self.peer, drain.fallback)
                    && !wire
                        .control
                        .has_pending_requests_on_connection(&self.peer, drain.fallback))
            {
                drain.closing = true;
                self.swarm.close_connection(drain.fallback);
            }
        }
        if self.handoff.attempt.as_ref().is_some_and(|attempt| {
            now >= attempt.deadline && !matches!(attempt.phase, Phase::CancelledDial)
        }) {
            self.cancel_preferred_attempt();
        }

        if self.handoff.attempt.is_some() || self.handoff.queued.is_none() || !self.relay_ready() {
            return Ok(());
        }
        self.refresh_peer_authorization()?;
        let addresses = self.handoff.queued.take().expect("queued endpoints");
        let fallback = self.member_connection().expect("active relay");
        let opts = DialOpts::peer_id(self.peer)
            .condition(PeerCondition::Always)
            .addresses(addresses)
            .build();
        let candidate = opts.connection_id();
        self.swarm
            .behaviour_mut()
            .limits
            .allow_candidate(self.peer, candidate);
        if self.swarm.dial(opts).is_ok() {
            self.handoff.attempt = Some(Attempt {
                generation: self.handoff.generation.unwrap_or(0),
                fallback,
                candidate,
                deadline: now + ATTEMPT_LIMIT,
                phase: Phase::Dialing,
                remote: self.handoff.remote.take(),
            });
        } else {
            self.swarm
                .behaviour_mut()
                .limits
                .revoke_candidate(candidate);
        }
        Ok(())
    }

    pub(super) fn clear_handoff(&mut self) {
        self.handoff.queued = None;
        self.handoff.remote = None;
        self.handoff.released_by = None;
        self.cancel_preferred_attempt();
        if let Some(drain) = self.handoff.draining.take() {
            self.swarm.close_connection(drain.fallback);
        }
    }

    fn cancel_preferred_attempt(&mut self) {
        let Some(mut attempt) = self.handoff.attempt.take() else {
            return;
        };
        self.swarm
            .behaviour_mut()
            .limits
            .revoke_candidate(attempt.candidate);
        match attempt.phase {
            // Swarm cannot close a pending dial by ID. Keep its identity until
            // a terminal event, so a late establishment cannot become active.
            Phase::Dialing | Phase::CancelledDial => {
                attempt.phase = Phase::CancelledDial;
                self.handoff.attempt = Some(attempt);
            }
            Phase::Capabilities(request)
            | Phase::Probe { request, .. }
            | Phase::Verify { request, .. }
            | Phase::Commit { request, .. } => {
                request.cancel.abort();
                self.sessions.closed(self.member_binding(attempt.candidate));
                self.swarm.close_connection(attempt.candidate);
            }
            Phase::Payload { .. } => {
                self.sessions.closed(self.member_binding(attempt.candidate));
                self.swarm.close_connection(attempt.candidate);
            }
        }
    }

    fn relay_ready(&self) -> bool {
        #[cfg(feature = "relay-client")]
        if self.relay_reservation.is_some() {
            return false;
        }
        self.member_connection().is_some()
            && self.member_path() == Some(PathKind::CircuitRelay)
            && self.stream_mtu().is_some()
            && self.membership_sync.is_none()
            && self
                .checkpoint
                .as_ref()
                .is_none_or(|checkpoint| checkpoint.installed && !checkpoint.blocked)
    }

    fn attempt_current(&self, attempt: &Attempt) -> bool {
        self.handoff.generation.unwrap_or(0) == attempt.generation
            && self.member_connection() == Some(attempt.fallback)
            && self.relay_ready()
            && Instant::now() < attempt.deadline
    }

    fn preferred_capabilities(&self, relayed: bool) -> Result<ControlCapabilities, JsError> {
        let mut caps = self.capabilities()?;
        caps.preferred_path = if relayed {
            PathKind::CircuitRelay
        } else {
            PathKind::DirectWebRtcStream
        }
        .wire_name()
        .into();
        Ok(caps)
    }

    fn validates_candidate(&self, peer: PeerId, caps: &ControlCapabilities, mtu: u16) -> bool {
        if peer != self.peer
            || caps.effective_mtu < mtu
            || control::validate_capabilities(
                caps,
                &self.config.network.name,
                self.membership_tag().as_deref(),
                &self.config.network.previous_membership_tags,
            )
            .is_some()
            || self
                .forwarder
                .authorize_peer_capabilities(peer, caps)
                .is_err()
        {
            return false;
        }
        match (&self.checkpoint, &caps.checkpoint) {
            (None, None) => true,
            (Some(checkpoint), Some(descriptor)) => {
                descriptor.sync == CheckpointSyncIndicator::Participating
                    && descriptor.validate_for(checkpoint.driver.anchor()).is_ok()
                    && checkpoint.driver.state().snapshot().payload.rank().ok()
                        == Some(descriptor.rank())
            }
            _ => false,
        }
    }

    pub(super) fn on_handoff_event(
        &mut self,
        event: &SwarmEvent<BehaviourEvent>,
    ) -> Result<bool, JsError> {
        match event {
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } if *peer_id == self.peer
                && self
                    .handoff
                    .draining
                    .as_ref()
                    .is_some_and(|drain| drain.fallback == *connection_id) =>
            {
                let drain = self.handoff.draining.take().expect("matched relay");
                self.sessions.closed(self.member_binding(*connection_id));
                self.handoff.released_by = Some(drain.promoted);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } if self.is_candidate(*connection_id) => {
                let mut attempt = self.handoff.attempt.take().expect("matched candidate");
                if matches!(attempt.phase, Phase::Dialing)
                    && *peer_id == self.peer
                    && endpoint.is_dialer()
                    && (endpoint.is_relayed() == attempt.remote.is_some())
                    && self.attempt_current(&attempt)
                    && if attempt.remote.is_some() {
                        self.sessions.stage_replacement(
                            self.member_binding(*connection_id),
                            Established::CircuitMember,
                            self.member_binding(attempt.fallback),
                            attempt.deadline,
                        )
                    } else {
                        self.sessions.stage_direct(
                            self.member_binding(*connection_id),
                            Established::DirectMember,
                            self.member_binding(attempt.fallback),
                            attempt.deadline,
                        )
                    }
                {
                    self.set_preferred_outbound(*connection_id, false);
                    if let Ok(caps) = self.preferred_capabilities(attempt.remote.is_some())
                        && let Ok(pending) = self
                            .swarm
                            .behaviour_mut()
                            .control
                            .send_request_on_connection_cancellable(
                                peer_id,
                                *connection_id,
                                ControlRequest::Capabilities(caps),
                                attempt.deadline,
                            )
                        && self
                            .sessions
                            .expect_capabilities(self.member_binding(*connection_id), pending.0)
                    {
                        attempt.phase = Phase::Capabilities(pending.into());
                        self.handoff.attempt = Some(attempt);
                        return Ok(true);
                    }
                }
                self.sessions.closed(self.member_binding(*connection_id));
                self.swarm.close_connection(*connection_id);
                return Ok(true);
            }
            SwarmEvent::OutgoingConnectionError { connection_id, .. }
                if self.is_candidate(*connection_id) =>
            {
                self.handoff.attempt.take();
                return Ok(true);
            }
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if self.is_candidate(*connection_id) =>
            {
                self.cancel_preferred_attempt();
                self.handoff.attempt.take();
                return Ok(true);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Control(rr::Event::Message {
                peer,
                connection_id,
                message:
                    rr::Message::Response {
                        request_id,
                        response,
                    },
            })) if self.is_candidate(*connection_id) => {
                if *peer == self.peer && self.matches_capabilities(*request_id) {
                    self.on_candidate_capabilities(*peer, response);
                }
                return Ok(true);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Packet(rr::Event::Message {
                peer,
                connection_id,
                message:
                    rr::Message::Response {
                        request_id,
                        response,
                    },
            })) if self.is_candidate(*connection_id) => {
                if *peer == self.peer && self.matches_probe(*request_id) {
                    self.pending.remove(request_id);
                    self.on_candidate_probe(*peer, *response)?;
                    return Ok(true);
                }
                return Ok(false);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Control(rr::Event::OutboundFailure {
                connection_id,
                request_id,
                ..
            })) if self.is_candidate(*connection_id) => {
                if self.matches_capabilities(*request_id) {
                    self.cancel_preferred_attempt();
                }
                return Ok(true);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Packet(rr::Event::OutboundFailure {
                connection_id,
                request_id,
                ..
            })) if self.is_candidate(*connection_id) => {
                self.pending.remove(request_id);
                if self.matches_probe(*request_id) {
                    self.cancel_preferred_attempt();
                }
                return Ok(true);
            }
            _ => {}
        }
        Ok(false)
    }

    fn is_candidate(&self, connection: ConnectionId) -> bool {
        self.handoff
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.candidate == connection)
    }

    fn matches_capabilities(&self, id: rr::OutboundRequestId) -> bool {
        matches!(self.handoff.attempt.as_ref().map(|attempt| &attempt.phase),
            Some(Phase::Capabilities(request)) if request.id == id)
    }

    fn matches_probe(&self, id: rr::OutboundRequestId) -> bool {
        matches!(self.handoff.attempt.as_ref().map(|attempt| &attempt.phase),
            Some(Phase::Probe { request, .. }) if request.id == id)
    }

    fn on_candidate_capabilities(&mut self, peer: PeerId, response: &ControlResponse) {
        let mut attempt = self.handoff.attempt.take().expect("matched capabilities");
        let Phase::Capabilities(ref exchange) = attempt.phase else {
            unreachable!("matched capabilities");
        };
        let binding = self.member_binding(attempt.candidate);
        let now = Instant::now();
        if self.attempt_current(&attempt)
            && let Some(mtu) = self.stream_mtu()
            && let ControlResponse::CapabilitiesAccepted(caps) = response
            && self.validates_candidate(peer, caps, mtu)
            && self.sessions.finish_capabilities(
                binding,
                exchange.id,
                StreamMtu::negotiate(mtu, caps.effective_mtu),
                now,
            )
        {
            if let Some(remote) = &attempt.remote {
                let verify = Request {
                    command: Command::Verify,
                    ..remote.clone()
                };
                if let Ok(request) = self
                    .swarm
                    .behaviour_mut()
                    .preferred_handoff
                    .send_request_on_connection_cancellable(
                        &peer,
                        attempt.candidate,
                        verify,
                        attempt.deadline,
                    )
                {
                    attempt.phase = Phase::Verify {
                        request: request.into(),
                        caps: Box::new(caps.clone()),
                        mtu,
                    };
                    self.handoff.attempt = Some(attempt);
                    return;
                }
                self.sessions.closed(binding);
                self.swarm.close_connection(attempt.candidate);
                return;
            }
            // Use the active stream MTU and sequence space so this is the same
            // packet protocol and size that the promoted connection will carry.
            let mut payload = vec![0; usize::from(mtu)];
            let offset = PATH_PROBE_V1.len();
            payload[..offset].copy_from_slice(PATH_PROBE_V1);
            payload[offset..offset + 2].copy_from_slice(&mtu.to_be_bytes());
            if let Ok(frame) = self.forwarder.path_probe_frame_with_mtu(mtu, &payload)
                && let Ok(pending) = self
                    .swarm
                    .behaviour_mut()
                    .packet
                    .send_request_on_connection_cancellable(
                        &peer,
                        attempt.candidate,
                        frame,
                        attempt.deadline,
                    )
                && self.sessions.expect_probe(binding, pending.0, now)
            {
                attempt.phase = Phase::Probe {
                    request: pending.into(),
                    caps: Box::new(caps.clone()),
                    mtu,
                };
                self.handoff.attempt = Some(attempt);
                return;
            }
        }
        self.sessions.closed(binding);
        self.swarm.close_connection(attempt.candidate);
    }

    fn on_candidate_probe(
        &mut self,
        peer: PeerId,
        response: PacketResponse,
    ) -> Result<(), JsError> {
        let mut attempt = self.handoff.attempt.take().expect("matched probe");
        let Phase::Probe {
            ref caps,
            ref request,
            mtu,
        } = attempt.phase
        else {
            unreachable!("matched phase")
        };
        let binding = self.member_binding(attempt.candidate);
        if let Some(remote) = &attempt.remote {
            let commit = Request {
                command: Command::Commit,
                ..remote.clone()
            };
            if response == PacketResponse::Accepted
                && self.attempt_current(&attempt)
                && let Ok(exchange) = self
                    .swarm
                    .behaviour_mut()
                    .preferred_handoff
                    .send_request_on_connection_cancellable(
                        &peer,
                        attempt.candidate,
                        commit,
                        attempt.deadline,
                    )
            {
                attempt.phase = Phase::Commit {
                    request: exchange.into(),
                    caps: caps.clone(),
                    mtu,
                    packet: request.id,
                };
                self.handoff.attempt = Some(attempt);
                return Ok(());
            }
            self.sessions.closed(binding);
            self.swarm.close_connection(attempt.candidate);
            return Ok(());
        }
        self.promote_candidate(attempt, response)
    }

    fn promote_candidate(
        &mut self,
        attempt: Attempt,
        response: PacketResponse,
    ) -> Result<(), JsError> {
        let (caps, mtu, packet) = match &attempt.phase {
            Phase::Probe { caps, mtu, request } => (caps, *mtu, request.id),
            Phase::Commit {
                caps, mtu, packet, ..
            } => (caps, *mtu, *packet),
            _ => unreachable!("candidate payload proof"),
        };
        let peer = self.peer;
        let binding = self.member_binding(attempt.candidate);
        if response == PacketResponse::Accepted && self.attempt_current(&attempt) {
            if let Err(error) = self.refresh_peer_authorization() {
                self.swarm.close_connection(attempt.candidate);
                return Err(error);
            }
            let checkpoint_busy = self
                .swarm
                .behaviour()
                .checkpoint
                .as_ref()
                .is_some_and(|wire| {
                    wire.has_pending_requests_on_connection(&self.peer, attempt.fallback)
                });
            if self.attempt_current(&attempt)
                && self.stream_mtu() == Some(mtu)
                && !checkpoint_busy
                && self.validates_candidate(peer, caps, mtu)
                && let ProbeOutcome::Promoted { draining, until } =
                    self.sessions
                        .finish_probe(binding, packet, true, Instant::now())
            {
                self.set_preferred_outbound(attempt.fallback, false);
                self.set_preferred_outbound(attempt.candidate, true);
                self.counters.connections += 1;
                self.handoff.released_by = None;
                self.handoff.draining = Some(DrainingRelay {
                    fallback: draining.connection,
                    promoted: attempt.candidate,
                    deadline: until,
                    closing: false,
                });
                return Ok(());
            }
        }
        self.sessions.closed(binding);
        self.swarm.close_connection(attempt.candidate);
        Ok(())
    }

    fn set_preferred_outbound(&mut self, id: ConnectionId, enabled: bool) {
        let wire = self.swarm.behaviour_mut();
        wire.control
            .set_connection_outbound_enabled(&self.peer, id, enabled);
        wire.packet
            .set_connection_outbound_enabled(&self.peer, id, enabled);
        if let Some(checkpoint) = wire.checkpoint.as_mut() {
            checkpoint.set_connection_outbound_enabled(&self.peer, id, enabled);
        }
    }

    pub(super) fn answer_candidate_control(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        request: ControlRequest,
        channel: rr::ResponseChannel<ControlResponse>,
    ) {
        if !self
            .handoff
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.candidate == connection && self.attempt_current(attempt))
        {
            return;
        }
        if let ControlRequest::Capabilities(caps) = request
            && let Some(mtu) = self.stream_mtu()
            && self.validates_candidate(peer, &caps, mtu)
            && let Ok(local) = self.preferred_capabilities(
                self.handoff
                    .attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt.remote.is_some()),
            )
        {
            let _ = self
                .swarm
                .behaviour_mut()
                .control
                .send_response(channel, ControlResponse::CapabilitiesAccepted(local));
        }
    }

    pub(super) fn admits_member_packet(&self, connection: ConnectionId) -> bool {
        self.sessions
            .inbound_mtu(self.member_binding(connection), Instant::now())
            .is_some()
    }

    pub(super) fn admits_handoff_wire(
        &mut self,
        connection: ConnectionId,
        event: &BehaviourEvent,
    ) -> bool {
        match event {
            BehaviourEvent::Control(rr::Event::Message {
                message: rr::Message::Request { .. },
                ..
            }) if self.is_candidate(connection) => true,
            BehaviourEvent::Packet(_) if self.admits_member_packet(connection) => true,
            BehaviourEvent::Packet(
                rr::Event::OutboundFailure { request_id, .. }
                | rr::Event::Message {
                    message: rr::Message::Response { request_id, .. },
                    ..
                },
            ) => {
                // Terminal events queued as the old connection closed still
                // release the request slot, but cannot change current authority.
                self.pending.remove(request_id);
                false
            }
            _ => false,
        }
    }

    pub(super) fn send_member_packet(
        &mut self,
        frame: Frame,
    ) -> Result<rr::OutboundRequestId, JsError> {
        if frame.header.payload_type == p2p_vpn::wire::PayloadType::IpPacket
            && let Some(mut attempt) = self.handoff.attempt.take()
        {
            if self.attempt_current(&attempt)
                && matches!(
                    attempt.phase,
                    Phase::Payload { .. } | Phase::Probe { .. } | Phase::Commit { .. }
                )
                && attempt.remote.is_some()
            {
                let sent = self
                    .swarm
                    .behaviour_mut()
                    .packet
                    .send_request_on_connection_cancellable(
                        &self.peer,
                        attempt.candidate,
                        frame,
                        attempt.deadline,
                    )
                    .map_err(|_| JsError::new("Candidate member path closed"));
                let (id, cancel) = match sent {
                    Ok(request) => request,
                    Err(error) => {
                        self.sessions.closed(self.member_binding(attempt.candidate));
                        self.swarm.close_connection(attempt.candidate);
                        return Err(error);
                    }
                };
                if let Phase::Payload { caps, mtu } = attempt.phase {
                    if self.sessions.expect_probe(
                        self.member_binding(attempt.candidate),
                        id,
                        Instant::now(),
                    ) {
                        attempt.phase = Phase::Probe {
                            request: PinnedRequest { id, cancel },
                            caps,
                            mtu,
                        };
                    } else {
                        cancel.abort();
                        self.sessions.closed(self.member_binding(attempt.candidate));
                        self.swarm.close_connection(attempt.candidate);
                        return Err(JsError::new("Candidate packet authority expired"));
                    }
                }
                self.handoff.attempt = Some(attempt);
                return Ok(id);
            }
            self.handoff.attempt = Some(attempt);
        }
        let selected = self
            .sessions
            .outbound(self.peer)
            .ok_or_else(|| JsError::new("No authenticated member path"))?;
        #[cfg(feature = "relay-client")]
        let application_packet = frame.header.payload_type == p2p_vpn::wire::PayloadType::IpPacket;
        let id = self
            .swarm
            .behaviour_mut()
            .packet
            .send_request_on_connection_with_deadline(
                &selected.binding.peer,
                selected.binding.connection,
                frame,
                Instant::now() + PACKET_LIMIT,
            )
            .map_err(|_| JsError::new("Authenticated member path closed"))?;
        #[cfg(feature = "relay-client")]
        if application_packet {
            self.note_application_demand();
        }
        Ok(id)
    }
}
