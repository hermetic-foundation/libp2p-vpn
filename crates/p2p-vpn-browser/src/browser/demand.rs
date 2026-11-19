//! Optional Demand negotiation on the browser's maintained incoming circuit.

#[cfg(target_arch = "wasm32")]
use std::collections::HashSet;
use std::time::Duration;

use futures::future::AbortHandle;
use libp2p::{
    PeerId,
    request_response::{self as rr, Event, Message, OutboundFailure},
    swarm::ConnectionId,
};
#[cfg(target_arch = "wasm32")]
use p2p_vpn::runtime::control::{self, ControlCapabilities, ControlRequest, ControlResponse};
use p2p_vpn::runtime::lifecycle::{
    Epoch, IDLE_EXCHANGE_TIMEOUT, IdleAck, PeerLifecycle, Phase, Readiness, Wake,
    protocol::{
        LifecycleCodec, RejectCode, Reply, Request, Response, Scope, Session, ValidatedRequest,
        ValidatedResponse,
    },
};
use web_time::Instant;
#[cfg(target_arch = "wasm32")]
use {
    rand_core::{OsRng, RngCore},
    wasm_bindgen::prelude::*,
};

#[cfg(target_arch = "wasm32")]
use super::{BrowserVpn, unix_seconds};

pub(super) type Wire = rr::Behaviour<LifecycleCodec>;
#[cfg(target_arch = "wasm32")]
pub(super) use p2p_vpn::runtime::lifecycle::protocol::behaviour;

const FOREGROUND_LEASE: Duration = Duration::from_millis(750);

#[cfg(target_arch = "wasm32")]
#[derive(Default)]
pub(super) struct Demand {
    foreground: Foreground,
    session: Option<Negotiation>,
    control_writes: HashSet<rr::OutboundRequestId>,
    last_authorization_check: Option<u64>,
}

#[derive(Default)]
struct Foreground {
    last_poll: Option<Instant>,
    maintained: bool,
}

impl Foreground {
    fn poll(&mut self, now: Instant, visible: bool) {
        self.maintained = visible && self.recent(now);
        self.last_poll = visible.then_some(now);
    }

    fn recent(&self, now: Instant) -> bool {
        self.last_poll
            .is_some_and(|last| now.saturating_duration_since(last) < FOREGROUND_LEASE)
    }

    fn live(&self, now: Instant, visible: bool) -> bool {
        visible && self.maintained && self.recent(now)
    }
}

struct Outbound {
    id: rr::OutboundRequestId,
    abort: AbortHandle,
    request: Request,
}

struct Negotiation {
    connection: ConnectionId,
    scope: Scope,
    local: Epoch,
    remote: Epoch,
    policy: PeerLifecycle,
    advertised: bool,
    confirmed: bool,
    blocked: bool,
    control: Option<(rr::OutboundRequestId, AbortHandle)>,
    outbound: Option<Outbound>,
    inbound: Option<(rr::InboundRequestId, IdleAck)>,
    wake: Option<Wake>,
    offered: bool,
    requests: [Option<Instant>; 4],
}

impl Drop for Negotiation {
    fn drop(&mut self) {
        self.cancel_control();
        self.cancel_outbound();
    }
}

impl Negotiation {
    fn enabled_on(&self, connection: ConnectionId) -> bool {
        self.connection == connection && self.confirmed && !self.blocked
    }

    fn cancel_control(&mut self) {
        if let Some((_, handle)) = self.control.take() {
            handle.abort();
        }
    }

    fn cancel_outbound(&mut self) {
        if let Some(exchange) = self.outbound.take() {
            exchange.abort.abort();
        }
    }

    fn suspend(&mut self, now: Instant) {
        self.confirmed = false;
        self.cancel_control();
        self.cancel_outbound();
        self.inbound = None;
        self.wake = None;
        self.offered = false;
        self.policy.revoke_quiet_permission(now);
    }

    fn reset_idle(&mut self, now: Instant) {
        self.offered = false;
        self.policy.revoke_quiet_permission(now);
    }

    fn application_demand(&mut self, now: Instant) {
        self.offered = false;
        if matches!(self.policy.phase(), Phase::Dormant | Phase::Quiescing) {
            self.cancel_outbound();
            self.wake = self.policy.wake(now, true).ok();
        } else {
            self.policy.demand(now, true);
        }
    }

    fn context<'a>(&'a self, peer: PeerId, previous: &'a [String]) -> Session<'a> {
        Session {
            peer,
            local_epoch: self.local,
            remote_epoch: self.remote,
            network_name: &self.scope.network_name,
            membership_tag: self.scope.membership_tag.as_deref(),
            previous_membership_tags: previous,
        }
    }

    fn receive(
        &mut self,
        peer: PeerId,
        previous: &[String],
        request: &Request,
        readiness: Readiness,
        now: Instant,
    ) -> (Reply, Option<IdleAck>) {
        let mut ack = None;
        let reply = match self
            .context(peer, previous)
            .validate_request(peer, |_| true, request)
        {
            Ok(ValidatedRequest::Idle(_)) if self.inbound.is_some() => Reply::Rejected {
                reason: RejectCode::Busy,
            },
            Ok(ValidatedRequest::Idle(offer)) => {
                match self.policy.receive_idle(offer, now, readiness) {
                    Ok(accepted) => {
                        ack = Some(accepted);
                        Reply::IdleAccepted {
                            responder_revision: accepted.responder_revision,
                        }
                    }
                    Err(reason) => Reply::Rejected {
                        reason: reason.into(),
                    },
                }
            }
            Ok(ValidatedRequest::Wake(wake)) => match self.policy.receive_wake(wake, now, true) {
                Ok(()) => {
                    self.cancel_outbound();
                    self.wake = None;
                    self.offered = false;
                    Reply::WakeAccepted {}
                }
                Err(reason) => Reply::Rejected {
                    reason: reason.into(),
                },
            },
            Err(_) => Reply::Rejected {
                reason: RejectCode::Unauthorized,
            },
        };
        (reply, ack)
    }

    fn drive(&mut self, wire: &mut Wire, peer: PeerId, readiness: Readiness, now: Instant) {
        self.policy.expire_exchanges(now);
        if self.outbound.is_some() || self.inbound.is_some() {
            return;
        }
        let request = if let Some(wake) = self.wake.take() {
            Request::wake(self.scope.clone(), wake)
        } else if !self.offered
            && let Ok(offer) = self.policy.offer_idle(now, readiness)
        {
            self.offered = true;
            Request::idle(self.scope.clone(), offer)
        } else {
            return;
        };
        if let Ok((id, abort)) = wire.send_request_on_connection_cancellable(
            &peer,
            self.connection,
            request.clone(),
            now + IDLE_EXCHANGE_TIMEOUT,
        ) {
            self.outbound = Some(Outbound { id, abort, request });
        }
    }

    fn event(
        &mut self,
        wire: &mut Wire,
        event: Event<Request, Response>,
        peer: PeerId,
        previous: &[String],
        readiness: Readiness,
        now: Instant,
    ) {
        match event {
            Event::Message {
                message:
                    Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                if self.requests[0].is_some_and(|first| {
                    now.saturating_duration_since(first) < Duration::from_secs(1)
                }) {
                    return;
                }
                self.requests.rotate_left(1);
                self.requests[3] = Some(now);
                let (reply, ack) = self.receive(peer, previous, &request, readiness, now);
                if wire
                    .send_response(channel, Response::for_request(&request, reply))
                    .is_ok()
                    && let Some(ack) = ack
                {
                    self.inbound = Some((request_id, ack));
                }
            }
            Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if self
                    .outbound
                    .as_ref()
                    .is_none_or(|exchange| exchange.id != request_id)
                {
                    return;
                }
                let exchange = self.outbound.take().expect("matched request");
                match self.context(peer, previous).validate_response(
                    peer,
                    |_| true,
                    &exchange.request,
                    &response,
                ) {
                    Ok(ValidatedResponse::IdleAccepted(ack)) => {
                        let _ = self.policy.receive_idle_ack(ack, now, readiness);
                    }
                    Ok(ValidatedResponse::Rejected(RejectCode::Unsupported)) => self.blocked = true,
                    _ => {}
                }
            }
            Event::ResponseSent { request_id, .. } => {
                if self
                    .inbound
                    .as_ref()
                    .is_some_and(|(id, _)| *id == request_id)
                {
                    let (_, ack) = self.inbound.take().expect("matched response");
                    let _ = self.policy.idle_reply_sent(ack, now, readiness);
                }
            }
            Event::InboundFailure { request_id, .. } => {
                if self
                    .inbound
                    .as_ref()
                    .is_some_and(|(id, _)| *id == request_id)
                {
                    self.inbound = None;
                }
            }
            Event::OutboundFailure {
                request_id, error, ..
            } => {
                if self
                    .outbound
                    .as_ref()
                    .is_some_and(|exchange| exchange.id == request_id)
                {
                    self.outbound = None;
                    self.blocked |= matches!(error, OutboundFailure::UnsupportedProtocols);
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn visible() -> bool {
    web_sys::window().is_some_and(|window| {
        // This feature needs a visible document, not just a Web API global
        // (workers and other embedders may not have a maintained document).
        js_sys::Reflect::get(window.as_ref(), &"document".into())
            .ok()
            .filter(|document| document.is_object())
            .and_then(|document| js_sys::Reflect::get(&document, &"visibilityState".into()).ok())
            .is_some_and(|state| state.as_string().as_deref() == Some("visible"))
    })
}

#[cfg(target_arch = "wasm32")]
impl BrowserVpn {
    pub(super) fn note_demand_poll(&mut self) {
        let now = Instant::now();
        self.demand.foreground.poll(now, visible());
    }

    fn demand_eligible(&self, connection: ConnectionId, now: Instant) -> bool {
        self.demand.foreground.live(now, visible())
            && self.member_connection() == Some(connection)
            && self.owns_incoming_relay(connection)
            && self.stream_mtu().is_some()
            && self.membership_sync.is_none()
            && self.forwarder.is_configured_transport_peer(self.peer)
            && self.demand.session.as_ref().is_some_and(|s| {
                s.connection == connection && s.scope.membership_tag == self.membership_tag()
            })
    }

    fn demand_readiness(&self, connection: ConnectionId) -> Readiness {
        let wire = self.swarm.behaviour();
        Readiness {
            incoming_path_available: true,
            outstanding_work: !self.pending.is_empty()
                || wire
                    .control
                    .has_pending_requests_on_connection(&self.peer, connection)
                || wire
                    .service
                    .has_pending_requests_on_connection(&self.peer, connection)
                || wire
                    .packet
                    .has_pending_requests_on_connection(&self.peer, connection)
                || wire.checkpoint.as_ref().is_some_and(|wire| {
                    wire.has_pending_requests_on_connection(&self.peer, connection)
                })
                || self
                    .swarm
                    .network_info()
                    .connection_counters()
                    .num_pending()
                    > 0,
        }
    }

    pub(super) fn note_demand_capabilities(
        &mut self,
        connection: ConnectionId,
        caps: &ControlCapabilities,
    ) {
        if self.member_connection() != Some(connection) || !self.owns_incoming_relay(connection) {
            return;
        }
        let scope = Scope {
            network_name: self.config.network.name.clone(),
            membership_tag: self.membership_tag(),
        };
        let Some(remote) = caps.demand_lifecycle_epoch().filter(|_| {
            control::validate_capabilities(
                caps,
                &scope.network_name,
                scope.membership_tag.as_deref(),
                &self.config.network.previous_membership_tags,
            )
            .is_none()
        }) else {
            self.demand.session = None;
            return;
        };
        if self
            .demand
            .session
            .as_ref()
            .is_some_and(|s| s.connection == connection && s.scope == scope && s.remote == remote)
        {
            return;
        }
        let mut bytes = [0; 16];
        self.demand.session = None;
        if OsRng.try_fill_bytes(&mut bytes).is_err() {
            return;
        }
        if let Some(local) = Epoch::new(bytes) {
            self.demand.session = Some(Negotiation {
                connection,
                scope,
                local,
                remote,
                policy: PeerLifecycle::new(local, remote, true, Instant::now()),
                advertised: false,
                confirmed: false,
                blocked: false,
                control: None,
                outbound: None,
                inbound: None,
                wake: None,
                offered: false,
                requests: [None; 4],
            });
        }
    }

    pub(super) fn demand_advertisement(
        &self,
        connection: ConnectionId,
        caps: ControlCapabilities,
    ) -> ControlCapabilities {
        if let Some(s) = &self.demand.session
            && s.connection == connection
            && s.advertised
            && !s.blocked
            && self.demand_eligible(connection, Instant::now())
        {
            return caps.with_demand_lifecycle_epoch(s.local);
        }
        caps
    }

    pub(super) fn demand_control_event(
        &mut self,
        event: &rr::Event<ControlRequest, ControlResponse>,
    ) -> bool {
        let (peer, connection) = super::wire_source(event);
        let (id, response) = match event {
            Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => (*request_id, Some(response)),
            Event::OutboundFailure { request_id, .. } => (*request_id, None),
            _ => return false,
        };
        if !self.demand.control_writes.remove(&id) {
            return false;
        }
        let eligible = peer == self.peer && self.demand_eligible(connection, Instant::now());
        let Some(s) = self
            .demand
            .session
            .as_mut()
            .filter(|s| s.control.as_ref().is_some_and(|(sent, _)| *sent == id))
        else {
            return true;
        };
        s.control = None;
        s.confirmed = eligible
            && s.advertised
            && matches!(response, Some(ControlResponse::CapabilitiesAccepted(caps))
            if caps.demand_lifecycle_epoch() == Some(s.remote)
                && control::validate_capabilities(caps, &s.scope.network_name, s.scope.membership_tag.as_deref(),
                    &self.config.network.previous_membership_tags).is_none());
        s.blocked |= s.advertised && !s.confirmed;
        true
    }

    pub(super) fn drive_demand(&mut self) -> Result<(), JsError> {
        let Some(connection) = self.demand.session.as_ref().map(|s| s.connection) else {
            return Ok(());
        };
        if self.member_connection() != Some(connection) {
            self.demand.session = None;
            return Ok(());
        }
        let now = Instant::now();
        let wall_now = unix_seconds();
        if self.demand_eligible(connection, now)
            && self.demand.last_authorization_check != Some(wall_now)
        {
            self.refresh_peer_authorization()?;
            self.demand.last_authorization_check = Some(wall_now);
        }
        let eligible = self.demand_eligible(connection, now);
        let Some(s) = self.demand.session.as_mut() else {
            return Ok(());
        };
        let desired = eligible && !s.blocked;
        if s.advertised != desired {
            if !desired {
                s.suspend(now);
            }
            if self.demand.control_writes.len() >= 4 {
                return Ok(());
            }
            s.cancel_control();
            if desired {
                s.reset_idle(now);
            }
            let local = s.local;
            s.advertised = desired;
            let caps = self.capabilities()?;
            let caps = if desired {
                caps.with_demand_lifecycle_epoch(local)
            } else {
                caps
            };
            let pending = self
                .swarm
                .behaviour_mut()
                .control
                .send_request_on_connection_cancellable(
                    &self.peer,
                    connection,
                    ControlRequest::Capabilities(caps),
                    now + IDLE_EXCHANGE_TIMEOUT,
                )
                .ok();
            if let Some((id, _)) = &pending {
                self.demand.control_writes.insert(*id);
            }
            if let Some(s) = &mut self.demand.session {
                s.control = pending;
            }
            return Ok(());
        }
        let readiness = self.demand_readiness(connection);
        if let Some(s) = self
            .demand
            .session
            .as_mut()
            .filter(|s| desired && s.confirmed)
            && let Some(wire) = self.swarm.behaviour_mut().demand.as_mut()
        {
            s.drive(wire, self.peer, readiness, now);
        }
        Ok(())
    }

    pub(super) fn demand_event(&mut self, event: Event<Request, Response>) {
        let (peer, connection) = super::wire_source(&event);
        let now = Instant::now();
        if peer != self.peer || !self.demand_eligible(connection, now) {
            return;
        }
        let readiness = self.demand_readiness(connection);
        if let Some(s) = self
            .demand
            .session
            .as_mut()
            .filter(|s| s.enabled_on(connection))
            && let Some(wire) = self.swarm.behaviour_mut().demand.as_mut()
        {
            s.event(
                wire,
                event,
                peer,
                &self.config.network.previous_membership_tags,
                readiness,
                now,
            );
        }
    }

    pub(super) fn note_application_demand(&mut self) {
        let now = Instant::now();
        if let Some(connection) = self
            .member_connection()
            .filter(|id| self.demand_eligible(*id, now))
            && let Some(s) = self
                .demand
                .session
                .as_mut()
                .filter(|s| s.enabled_on(connection))
        {
            s.application_demand(now);
        }
    }

    pub(super) fn clear_demand(&mut self) {
        self.demand.session = None;
    }
}

#[cfg(test)]
#[path = "demand_tests.rs"]
mod tests;
