use libp2p::{Multiaddr, core::transport::ListenerId, request_response as rr};
use p2p_vpn::runtime::control::checkpoint::CheckpointSync;
use p2p_vpn::{
    pairing::{
        PairingOffer, PairingOfferOptions, PairingRequest, PairingResponse,
        export_code_pairing_offer_at,
    },
    pairing_code::{
        PairingCode, PairingCodeSession, answer_pairing_code_hello_v2_at,
        verify_pairing_request_code_authentication,
    },
    runtime::pairing_code::{
        PairingCodeRejectionReason as Rejection, PairingCodeV2Request as Request,
        PairingCodeV2Response as Response,
    },
};

use super::{
    code_invitation::WireEvent,
    issuer::{BrowserCheckpointInvitation, invitation_config},
    *,
};
use crate::code_inviter::locator_stream;

const WINDOW: Duration = Duration::from_secs(120);
const HANDSHAKE: Duration = Duration::from_secs(5);

pub(super) struct Invitation {
    code: Option<PairingCode>,
    base: BrowserCheckpointInvitation,
    deadline: Instant,
    expires: u64,
    circuit: Option<Circuit>,
    published: Option<Multiaddr>,
    distributed: Option<bool>,
    accepted: Option<Box<PairingResponse>>,
    sending: Option<rr::InboundRequestId>,
    recovery_peer: Option<libp2p::PeerId>,
    #[cfg(feature = "test-hooks")]
    drop_accepted: bool,
}

struct Circuit {
    binding: Binding,
    deadline: Instant,
    hello_seen: bool,
    attempt: Option<(PairingCodeSession, PairingOffer)>,
    review: Option<(Box<PairingRequest>, String)>,
}

fn rejected(reason: Rejection) -> Response {
    Response::Rejected { reason }
}

fn cancelled() -> JsError {
    JsError::new("Checkpoint code invitation is no longer live")
}

#[wasm_bindgen]
impl BrowserVpn {
    pub fn start_checkpoint_code(&mut self) -> Result<String, JsError> {
        if self.checkpoint_code_active() {
            return Err(cancelled());
        }
        let base = self.checkpoint_invitation()?;
        let code = PairingCode::generate();
        let text = code.to_string();
        let deadline = Instant::now() + WINDOW;
        self.additional_inbound.pairing(Some(deadline));
        self.checkpoint_code = Some(Invitation {
            code: Some(code),
            base,
            deadline,
            expires: unix_seconds() + WINDOW.as_secs(),
            circuit: None,
            published: None,
            distributed: None,
            accepted: None,
            sending: None,
            recovery_peer: None,
            #[cfg(feature = "test-hooks")]
            drop_accepted: false,
        });
        Ok(text)
    }

    /// Request publication only on an alias confirmed by this exact reservation.
    #[cfg(feature = "test-hooks")]
    pub fn publish_checkpoint_code(&mut self, alias: &str) -> Result<(), JsError> {
        let alias: Multiaddr = alias.parse().map_err(debug_error)?;
        let invite = self.checkpoint_code.as_ref().ok_or_else(cancelled)?;
        let (reservation, outer) = self.confirmed_reservation().ok_or_else(cancelled)?;
        let local = *self.swarm.local_peer_id();
        if invite.published.is_some()
            || self.checkpoint_code_is_scoped()
            || !self.live_code_reservation(invite.base.reservation)
            || !self.reservation_confirms_address(&alias)
            || p2p_vpn::peer_address_record::browser_advertisement::circuit_relay(&alias, local)
                != Some(reservation.relay)
        {
            return Err(cancelled());
        }
        let relay = reservation.relay;
        let locator = invite.code.as_ref().ok_or_else(cancelled)?.global_locator();
        if !self
            .swarm
            .behaviour_mut()
            .code_invitation
            .as_mut()
            .expect("checkpoint code wire")
            .publisher
            .start(relay, outer, local, alias.clone(), &locator)
        {
            return Err(cancelled());
        }
        self.checkpoint_code
            .as_mut()
            .expect("live invitation")
            .published = Some(alias);
        Ok(())
    }

    pub fn checkpoint_code_publication(&self) -> Option<bool> {
        let invite = self.checkpoint_code.as_ref()?;
        invite.published.as_ref()?;
        if self.checkpoint_code_is_scoped() {
            return invite.distributed;
        }
        self.swarm
            .behaviour()
            .code_invitation
            .as_ref()?
            .publisher
            .result()
    }

    pub fn checkpoint_code_is_scoped(&self) -> bool {
        self.endpoints
            .relay
            .as_ref()
            .and_then(RelayRoute::scoped_checkpoint)
            .is_some()
    }

    /// Ingress scope is independent of the Browser's libp2p connection event.
    pub async fn check_checkpoint_ingress(&mut self) -> Result<(), JsError> {
        if let Some((lease, ingress)) = self
            .endpoints
            .relay
            .as_ref()
            .and_then(RelayRoute::scoped_checkpoint)
            && !locator_stream::check_ingress(lease, ingress).await
        {
            self.release_relay();
            return Err(JsError::new("Scoped checkpoint relay lease ended"));
        }
        Ok(())
    }

    pub async fn publish_checkpoint_code_distributed(&mut self) -> Result<(), JsError> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use futures::future::{Either, select};
        use rand_core::{OsRng, RngCore as _};

        let route = self.endpoints.relay.as_ref().ok_or_else(cancelled)?;
        let (lease, ingress) = route.scoped_checkpoint().ok_or_else(|| {
            JsError::new("Checkpoint publication requires a scoped incoming relay lease")
        })?;
        let (lease, ingress) = (lease.to_owned(), ingress.clone());
        let alias = route
            .public_reservation_addr(*self.swarm.local_peer_id())
            .ok_or_else(cancelled)?;
        let invite = self.checkpoint_code.as_ref().ok_or_else(cancelled)?;
        if !self.live_code_reservation(invite.base.reservation)
            || !self.reservation_confirms_address(&alias)
            || invite.published.is_some()
            || invite.accepted.is_some()
        {
            return Err(JsError::new(
                "Checkpoint publication already attempted or reservation unavailable",
            ));
        }
        let expected = invite.base.reservation;
        let locator = invite.code.as_ref().ok_or_else(cancelled)?.global_locator();
        let key = p2p_vpn::pairing_code::pairing_code_v2_provider_key(&locator);
        let keys = self
            .config
            .identity()
            .map_err(debug_error)?
            .keypair()
            .map_err(debug_error)?;
        let mut child = [0; 24];
        OsRng.fill_bytes(&mut child);
        let child = URL_SAFE_NO_PAD.encode(child);
        self.checkpoint_code
            .as_mut()
            .expect("live invitation")
            .published = Some(alias.clone());
        let result = {
            let publish =
                locator_stream::publish_child(&lease, &child, &ingress, &keys, &key, &alias);
            futures::pin_mut!(publish);
            loop {
                self.expire_checkpoint_code();
                if !self
                    .checkpoint_code
                    .as_ref()
                    .is_some_and(|invite| invite.base.reservation == expected)
                    || !self.reservation_confirms_address(&alias)
                {
                    break Err(cancelled());
                }
                let foreground = self.poll_foreground();
                futures::pin_mut!(foreground);
                match select(publish.as_mut(), foreground).await {
                    Either::Left((result, _)) => break result,
                    Either::Right((Err(error), _)) => break Err(error),
                    Either::Right((Ok(()), _)) => {}
                }
            }
        };
        locator_stream::retire_child(&lease, &child).await;
        self.check_checkpoint_ingress().await?;
        self.expire_checkpoint_code();
        let invite = self.checkpoint_code.as_mut().ok_or_else(cancelled)?;
        invite.distributed = Some(result.is_ok());
        result
    }

    pub fn checkpoint_code_public_alias(&self) -> Option<String> {
        self.confirmed_reservation()?
            .0
            .publication_addresses
            .first()
            .map(ToString::to_string)
    }

    pub fn checkpoint_code_pending(&self) -> bool {
        self.checkpoint_code
            .as_ref()
            .is_some_and(|invite| invite.recovery_peer.is_none())
    }

    #[cfg(feature = "test-hooks")]
    pub fn test_drop_next_checkpoint_accepted(&mut self) -> Result<(), JsError> {
        let invite = self.checkpoint_code.as_mut().ok_or_else(cancelled)?;
        if invite.accepted.is_none() || invite.sending.is_some() {
            return Err(cancelled());
        }
        invite.drop_accepted = true;
        Ok(())
    }

    pub fn checkpoint_code_delivered(&self) -> bool {
        self.checkpoint_joiner.is_some() && self.shared_relay()
    }

    pub fn checkpoint_code_review(&self) -> Option<String> {
        let invite = self.checkpoint_code.as_ref()?;
        let circuit = invite.circuit.as_ref()?;
        let (request, ticket) = circuit.review.as_ref()?;
        if invite.accepted.is_some() || !self.valid_code_circuit(invite, circuit.binding) {
            return None;
        }
        Some(
            serde_json::json!({
                "peer": request.payload.joiner_peer,
                "hostname": request.payload.requested_hostname,
                "ticket": ticket,
            })
            .to_string(),
        )
    }

    pub fn cancel_checkpoint_code(&mut self) {
        self.additional_inbound.pairing(None);
        if let Some(invite) = self.checkpoint_code.take() {
            if let Some(circuit) = invite.circuit {
                self.swarm.close_connection(circuit.binding.connection);
            }
            if let Some(wire) = self.swarm.behaviour_mut().code_invitation.as_mut() {
                wire.publisher.cancel();
            }
        }
    }

    pub async fn approve_checkpoint_code(&mut self, ticket: &str) -> Result<(), JsError> {
        self.check_checkpoint_ingress().await?;
        let invite = self.checkpoint_code.as_ref().ok_or_else(cancelled)?;
        let circuit = invite.circuit.as_ref().ok_or_else(cancelled)?;
        let (request, ticket) = circuit
            .review
            .as_ref()
            .filter(|(_, current)| current == ticket)
            .ok_or_else(cancelled)?;
        let (session, offer) = circuit.attempt.as_ref().ok_or_else(cancelled)?;
        if invite.accepted.is_some() || !self.valid_code_circuit(invite, circuit.binding) {
            return Err(cancelled());
        }
        let base = BrowserCheckpointInvitation {
            offer: offer.clone(),
            boundary: invite.base.boundary,
            reservation: invite.base.reservation,
            address: invite.base.address.clone(),
        };
        let (request, session, peer) = (request.clone(), session.clone(), circuit.binding.peer);
        let recovery = (ticket.clone(), invite.expires);
        match self
            .issue_checkpoint(base, &request, Some((&session, peer)), Some(recovery))
            .await
        {
            Ok(response) => {
                self.additional_inbound.pairing(None);
                self.checkpoint_code
                    .as_mut()
                    .expect("serialized approval")
                    .accepted = Some(Box::new(response));
                Ok(())
            }
            Err(error) => {
                self.cancel_checkpoint_code();
                Err(error)
            }
        }
    }
}

impl BrowserVpn {
    pub(super) fn arm_code_recovery(&mut self) {
        if self.checkpoint_code.is_some() || self.shared_relay() {
            return;
        }
        let Some(checkpoint) = &self.checkpoint else {
            return;
        };
        let Some(recovery) = &checkpoint.code_recovery else {
            return;
        };
        let now = unix_seconds();
        let expires = recovery.expires();
        let Some(peer) = recovery.peer() else { return };
        if expires <= now {
            return;
        }
        let Ok(base) = self.checkpoint_invitation() else {
            return;
        };
        if !recovery.current(base.boundary, &base.address.to_string(), now)
            || !self.forwarder.is_configured_transport_peer(peer)
        {
            return;
        }
        let Ok(transfer) = CheckpointSync::new(
            *self.swarm.local_peer_id(),
            checkpoint.driver.anchor().clone(),
            Default::default(),
        ) else {
            return;
        };
        self.install_checkpoint_joiner(peer, base.boundary, transfer);
        let deadline = Instant::now() + Duration::from_secs((expires - now).min(WINDOW.as_secs()));
        self.additional_inbound
            .pairing_for(Some(deadline), Some(peer));
        self.checkpoint_code = Some(Invitation {
            code: None,
            base,
            deadline,
            expires,
            circuit: None,
            published: None,
            distributed: None,
            accepted: None,
            sending: None,
            recovery_peer: Some(peer),
            #[cfg(feature = "test-hooks")]
            drop_accepted: false,
        });
    }

    pub(super) fn checkpoint_code_active(&self) -> bool {
        self.checkpoint_code.is_some()
    }

    fn live_code_reservation(&self, expected: (ListenerId, ConnectionId)) -> bool {
        self.confirmed_reservation()
            .is_some_and(|(r, outer)| (r.listener, outer) == expected)
    }

    fn owns_code_circuit(&self, invite: &Invitation, binding: Binding) -> bool {
        self.confirmed_reservation().is_some_and(|(r, outer)| {
            (r.listener, outer) == invite.base.reservation
                && self.swarm.behaviour().relay.as_ref().is_some_and(|relay| {
                    relay.circuit_connection_owner(binding.peer, binding.connection)
                        == Some((r.relay, outer))
                })
        })
    }

    fn valid_code_circuit(&self, invite: &Invitation, binding: Binding) -> bool {
        Instant::now() < invite.deadline
            && (invite.accepted.is_none() || self.retains_checkpoint_joiner(binding.peer))
            && invite
                .published
                .as_ref()
                .is_none_or(|alias| self.reservation_confirms_address(alias))
            && self.owns_code_circuit(invite, binding)
            && invite.circuit.as_ref().is_some_and(|c| {
                c.binding == binding && (c.review.is_some() || Instant::now() < c.deadline)
            })
    }

    pub(super) fn expire_checkpoint_code(&mut self) {
        let Some(invite) = self.checkpoint_code.as_ref() else {
            return;
        };
        let authority_changed = if invite.accepted.is_none() {
            !self.checkpoint.as_ref().is_some_and(|checkpoint| {
                !checkpoint.blocked
                    && checkpoint.driver.state().snapshot().payload.boundary().ok()
                        == Some(invite.base.boundary)
            })
        } else {
            invite
                .circuit
                .as_ref()
                .is_none_or(|c| !self.retains_checkpoint_joiner(c.binding.peer))
        };
        if authority_changed
            || Instant::now() >= invite.deadline
            || !self.live_code_reservation(invite.base.reservation)
            || invite
                .published
                .as_ref()
                .is_some_and(|alias| !self.reservation_confirms_address(alias))
        {
            self.cancel_checkpoint_code();
        } else if let Some(circuit) = invite.circuit.as_ref()
            && circuit.review.is_none()
            && Instant::now() >= circuit.deadline
        {
            self.swarm.close_connection(circuit.binding.connection);
        }
    }

    pub(super) fn checkpoint_code_event(&mut self, event: &SwarmEvent<BehaviourEvent>) -> bool {
        self.expire_checkpoint_code();
        self.arm_code_recovery();
        let Some(mut invite) = self.checkpoint_code.take() else {
            return false;
        };
        let mut finish = None;
        let handled = match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } if endpoint.is_listener()
                && *peer_id != self.peer
                && !self.endpoints.is_relay_hop(*peer_id) =>
            {
                let binding = Binding {
                    peer: *peer_id,
                    connection: *connection_id,
                };
                if invite.circuit.is_none()
                    && invite.accepted.is_none()
                    && invite.recovery_peer.is_none_or(|peer| peer == binding.peer)
                    && self.owns_code_circuit(&invite, binding)
                {
                    invite.circuit = Some(Circuit {
                        binding,
                        deadline: Instant::now() + HANDSHAKE,
                        hello_seen: false,
                        attempt: None,
                        review: None,
                    });
                } else {
                    self.swarm.close_connection(*connection_id);
                }
                true
            }
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if invite
                    .circuit
                    .as_ref()
                    .is_some_and(|c| c.binding.connection == *connection_id) =>
            {
                invite.circuit = None;
                invite.sending = None;
                true
            }
            SwarmEvent::Behaviour(BehaviourEvent::CodeInvitation(WireEvent::Pake(
                rr::Event::ResponseSent {
                    peer,
                    request_id,
                    connection_id,
                },
            ))) if invite.sending == Some(*request_id)
                && self.valid_code_circuit(
                    &invite,
                    Binding {
                        peer: *peer,
                        connection: *connection_id,
                    },
                ) =>
            {
                finish = Some(*peer);
                true
            }
            SwarmEvent::Behaviour(BehaviourEvent::CodeInvitation(WireEvent::Pake(
                rr::Event::InboundFailure { request_id, .. },
            ))) if invite.sending == Some(*request_id) => {
                invite.sending = None;
                true
            }
            _ => false,
        };
        self.checkpoint_code = Some(invite);
        if let Some(peer) = finish {
            self.cancel_checkpoint_code();
            self.set_additional_relay_peer(Some(peer));
        }
        handled
    }

    pub(super) fn checkpoint_code_request(
        &mut self,
        binding: Binding,
        id: rr::InboundRequestId,
        request: Request,
        channel: rr::ResponseChannel<Response>,
    ) {
        let Some(mut invite) = self.checkpoint_code.take() else {
            if self.owns_shared_relay_binding(binding)
                && binding.peer != self.peer
                && let Request::Poll { ticket } = request
            {
                let response = self.recover_checkpoint_response(binding.peer, &ticket);
                if let Some(wire) = self.swarm.behaviour_mut().code_invitation.as_mut() {
                    let _ = wire.pake.send_response(channel, response);
                }
            }
            return;
        };
        if self.valid_code_circuit(&invite, binding) {
            let response = if invite.recovery_peer.is_some() {
                match request {
                    Request::Poll { ticket } => {
                        self.recover_checkpoint_response(binding.peer, &ticket)
                    }
                    _ => rejected(Rejection::Unavailable),
                }
            } else {
                invite.respond(&self.config, request)
            };
            let accepted = matches!(response, Response::Accepted { .. });
            #[cfg(feature = "test-hooks")]
            if accepted && std::mem::take(&mut invite.drop_accepted) {
                self.checkpoint_code = Some(invite);
                return;
            }
            if self
                .swarm
                .behaviour_mut()
                .code_invitation
                .as_mut()
                .expect("checkpoint code wire")
                .pake
                .send_response(channel, response)
                .is_ok()
                && accepted
            {
                invite.sending = Some(id);
            }
        }
        self.checkpoint_code = Some(invite);
    }

    fn recover_checkpoint_response(&self, peer: libp2p::PeerId, ticket: &str) -> Response {
        let response = (|| {
            let checkpoint = self.checkpoint.as_ref()?;
            if !self.retains_checkpoint_joiner(peer) || self.checkpoint_joiner_served() {
                return None;
            }
            let address = self.relay_reservation_address()?;
            let boundary = checkpoint
                .driver
                .state()
                .snapshot()
                .payload
                .boundary()
                .ok()?;
            checkpoint.code_recovery.as_ref()?.recover(
                peer,
                ticket,
                boundary,
                &address,
                unix_seconds(),
                &checkpoint.secret,
            )
        })();
        response.map_or_else(
            || rejected(Rejection::Unavailable),
            |response| Response::Accepted {
                response: Box::new(response),
            },
        )
    }
}

impl Invitation {
    fn respond(&mut self, config: &Config, request: Request) -> Response {
        let now = unix_seconds();
        let Some(remaining) = self
            .expires
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
        else {
            return rejected(Rejection::Expired);
        };
        let circuit = self.circuit.as_mut().expect("admitted circuit");
        match request {
            Request::Hello { hello } if !circuit.hello_seen => {
                circuit.hello_seen = true;
                let Some(code) = self.code.as_ref() else {
                    return rejected(Rejection::Unavailable);
                };
                let config = invitation_config(config, &self.base.address);
                let options = PairingOfferOptions {
                    expires_in_seconds: remaining,
                    rendezvous_token: None,
                };
                let Ok((challenge, session)) = answer_pairing_code_hello_v2_at(
                    &config,
                    code,
                    &hello,
                    circuit.binding.peer,
                    options,
                    now,
                ) else {
                    return rejected(Rejection::Unavailable);
                };
                let Ok(offer) = export_code_pairing_offer_at(
                    &config,
                    PairingOfferOptions {
                        expires_in_seconds: remaining,
                        rendezvous_token: Some(session.rendezvous_token().to_owned()),
                    },
                    now,
                ) else {
                    return rejected(Rejection::Unavailable);
                };
                circuit.attempt = Some((session, offer));
                return Response::Challenge {
                    challenge: Box::new(challenge),
                };
            }
            Request::Submit { request } => {
                if let Some((reviewed, _)) = &circuit.review {
                    if &request != reviewed {
                        return rejected(Rejection::Unavailable);
                    }
                } else {
                    let Some((session, offer)) = &circuit.attempt else {
                        return rejected(Rejection::Unavailable);
                    };
                    if request.payload.joiner_peer != circuit.binding.peer.to_string()
                        || request.payload.requested_vpn_ip.is_some()
                        || !request.payload.requested_routes.is_empty()
                        || verify_pairing_request_code_authentication(&request, session).is_err()
                        || request.verify_for_offer_at(offer, now).is_err()
                    {
                        return rejected(Rejection::Unavailable);
                    }
                    circuit.review = Some((request, PairingCode::generate().to_string()));
                }
            }
            Request::Poll { ticket }
                if circuit
                    .review
                    .as_ref()
                    .is_some_and(|(_, current)| current == &ticket) => {}
            _ => return rejected(Rejection::Unavailable),
        }
        if let Some(response) = &self.accepted {
            if self.sending.is_some() {
                return rejected(Rejection::Busy);
            }
            Response::Accepted {
                response: response.clone(),
            }
        } else {
            Response::Pending {
                ticket: circuit.review.as_ref().expect("reviewed request").1.clone(),
                expires_at_unix_seconds: self.expires,
            }
        }
    }
}
