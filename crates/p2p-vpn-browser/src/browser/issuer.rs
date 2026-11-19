use libp2p::{
    Multiaddr, PeerId, core::transport::ListenerId, request_response as rr, swarm::ConnectionId,
};
use p2p_vpn::{
    config::Config,
    membership::checkpoint::{CheckpointBoundary, MembershipSyncState},
    pairing::{
        MAX_PAIRING_MESSAGE_LEN, PairingOffer, PairingOfferOptions, PairingRequest,
        export_pairing_offer_at,
    },
    runtime::control::{
        checkpoint::{
            CheckpointPageResponse, CheckpointRejection, CheckpointSync, CheckpointSyncIndicator,
        },
        checkpoint_mutation::CheckpointMutationRequest,
    },
};

use super::*;
use crate::checkpoint_inviter::{FileApproval, PreparedAdmission};

#[wasm_bindgen]
pub struct BrowserCheckpointInvitation {
    pub(super) offer: PairingOffer,
    pub(super) boundary: CheckpointBoundary,
    pub(super) reservation: (ListenerId, ConnectionId),
    pub(super) address: Multiaddr,
}

#[wasm_bindgen]
impl BrowserCheckpointInvitation {
    pub fn offer_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.offer).map_err(debug_error)
    }
}

pub(super) struct CheckpointJoiner {
    peer: PeerId,
    boundary: CheckpointBoundary,
    transfer: CheckpointSync,
    pending_final: Option<rr::InboundRequestId>,
    served: bool,
}

impl CheckpointJoiner {
    pub(super) fn disconnected(&mut self, now: Instant) {
        self.transfer.cancel_peer(self.peer, now);
        self.pending_final = None;
        self.served = false;
    }
}

#[wasm_bindgen]
impl BrowserVpn {
    /// Prepare a file offer for the confirmed reservation and current authority.
    pub fn checkpoint_invitation(&self) -> Result<BrowserCheckpointInvitation, JsError> {
        let checkpoint = self.checkpoint.as_ref().ok_or_else(unavailable)?;
        if !checkpoint.installed
            || checkpoint.blocked
            || self.stream_mtu().is_none()
            || self.shared_relay()
        {
            return Err(unavailable());
        }
        let incumbent = self.selected_member_binding()?;
        if !self.owns_incoming_relay(incumbent.connection) {
            return Err(unavailable());
        }
        let (reservation, outer) = self.confirmed_reservation().ok_or_else(unavailable)?;
        let boundary = checkpoint
            .driver
            .state()
            .snapshot()
            .payload
            .boundary()
            .map_err(debug_error)?;
        let address = reservation.address.clone();
        let offer = export_pairing_offer_at(
            &invitation_config(&self.config, &address),
            PairingOfferOptions::default(),
            unix_seconds(),
        )
        .map_err(debug_error)?;
        Ok(BrowserCheckpointInvitation {
            offer,
            boundary,
            reservation: (reservation.listener, outer),
            address,
        })
    }

    /// Approve the operator-selected signed request. The response contains sensitive
    /// enrollment credentials and must be delivered separately to the joiner.
    pub async fn approve_checkpoint_invitation(
        &mut self,
        invitation: BrowserCheckpointInvitation,
        request_json: &str,
    ) -> Result<String, JsError> {
        if request_json.len() > MAX_PAIRING_MESSAGE_LEN || self.checkpoint_code_active() {
            return Err(unavailable());
        }
        let request: PairingRequest = serde_json::from_str(request_json)
            .map_err(|_| JsError::new("Invalid checkpoint pairing request"))?;
        let response = self.issue_checkpoint(invitation, &request, None).await?;
        serde_json::to_string(&response).map_err(debug_error)
    }
}

impl BrowserVpn {
    pub(super) async fn issue_checkpoint(
        &mut self,
        invitation: BrowserCheckpointInvitation,
        request: &PairingRequest,
        code: Option<(&p2p_vpn::pairing_code::PairingCodeSession, PeerId)>,
    ) -> Result<p2p_vpn::pairing::PairingResponse, JsError> {
        if self.shared_relay() || self.stream_mtu().is_none() {
            return Err(unavailable());
        }
        let (reservation, outer) = self.confirmed_reservation().ok_or_else(unavailable)?;
        if (reservation.listener, outer) != invitation.reservation
            || reservation.address != invitation.address
        {
            return Err(unavailable());
        }
        let incumbent = self.selected_member_binding()?;
        if !self.owns_incoming_relay(incumbent.connection) {
            return Err(unavailable());
        }
        let peer: PeerId = request.payload.joiner_peer.parse().map_err(debug_error)?;
        if peer == self.peer || self.endpoints.is_relay_hop(peer) {
            return Err(unavailable());
        }
        let checkpoint = self.checkpoint.as_mut().ok_or_else(unavailable)?;
        if !checkpoint.installed || checkpoint.blocked || checkpoint.enrollment_floor.is_some() {
            return Err(unavailable());
        }
        let store = checkpoint.store.as_ref().ok_or_else(unavailable)?;
        let transfer = CheckpointSync::new(
            *self.swarm.local_peer_id(),
            checkpoint.driver.anchor().clone(),
            Default::default(),
        )
        .map_err(debug_error)?;
        let config = invitation_config(&self.config, &invitation.address);
        let admission = PreparedAdmission::prepare_bound(
            &config,
            checkpoint.driver.issuing_state().ok_or_else(unavailable)?,
            &mut self.forwarder,
            &checkpoint.secret,
            FileApproval {
                expected: invitation.boundary,
                offer: &invitation.offer,
                request,
                wall_now: unix_seconds(),
            },
            code,
        )
        .map_err(|_| JsError::new("Checkpoint approval does not match current authority"))?;
        for binding in self.sessions.require_reauthorization(self.peer) {
            self.swarm.close_connection(binding.connection);
        }
        let issued = admission
            .commit_with_store(&mut checkpoint.blocked, store)
            .await
            .map_err(|_| JsError::new("Checkpoint admission storage or projection failed"))?;
        let boundary = checkpoint
            .driver
            .state()
            .snapshot()
            .payload
            .boundary()
            .map_err(debug_error)?;
        let mutation = CheckpointMutationRequest::new(issued.mutation).map_err(debug_error)?;
        checkpoint.blocked = false;
        self.checkpoint_joiner = Some(CheckpointJoiner {
            peer,
            boundary,
            transfer,
            pending_final: None,
            served: false,
        });
        if code.is_none() {
            self.set_additional_relay_peer(Some(peer));
        }
        // Only one incumbent exists in this issuer profile. Do not redial or
        // redirect the signed handoff to a different connection.
        let _ = self
            .swarm
            .behaviour_mut()
            .checkpoint_mutation
            .as_mut()
            .expect("checkpoint behaviour")
            .send_request_on_connection_with_deadline(
                &incumbent.peer,
                incumbent.connection,
                mutation,
                Instant::now() + checkpoint_mutation::MUTATION_REQUEST_TIMEOUT,
            );
        if code.is_some() {
            // The commit is irreversible. Do not discard the grant because
            // incumbent renegotiation could not be queued.
            let _ = self.send_capabilities_on(incumbent);
        } else {
            self.send_capabilities_on(incumbent)?;
        }
        Ok(issued.response)
    }
}

impl BrowserVpn {
    pub(super) fn retains_checkpoint_joiner(&self, peer: PeerId) -> bool {
        let Some(joiner) = self
            .checkpoint_joiner
            .as_ref()
            .filter(|joiner| joiner.peer == peer)
        else {
            return false;
        };
        self.checkpoint.as_ref().is_some_and(|checkpoint| {
            let state = checkpoint.driver.state();
            !checkpoint.blocked
                && state.sync_state() == MembershipSyncState::Participating
                && state.snapshot().payload.boundary().ok() == Some(joiner.boundary)
                && self.forwarder.is_configured_transport_peer(peer)
        })
    }

    pub(super) fn admit_checkpoint_joiner(
        &self,
        peer: PeerId,
        caps: &ControlCapabilities,
        mtu: StreamMtu,
    ) -> Result<Option<StreamMtu>, ControlRejectionReason> {
        if !self.retains_checkpoint_joiner(peer) {
            return Err(ControlRejectionReason::UnauthorizedPeer);
        }
        let checkpoint = self.checkpoint.as_ref().expect("checkpoint issuer");
        if let Some(reason) = control::validate_capabilities(
            caps,
            &self.config.network.name,
            Some(checkpoint.driver.membership_tag()),
            &[],
        ) {
            return Err(reason);
        }
        let descriptor = caps
            .checkpoint
            .as_ref()
            .ok_or(ControlRejectionReason::InvalidMembershipRecord)?;
        descriptor
            .validate_for(checkpoint.driver.anchor())
            .map_err(|_| ControlRejectionReason::InvalidMembershipRecord)?;
        let joiner = self.checkpoint_joiner.as_ref().expect("committed joiner");
        if !joiner.served
            || descriptor.sync != CheckpointSyncIndicator::Participating
            || descriptor.boundary != joiner.boundary
        {
            return Ok(None);
        }
        self.forwarder.authorize_peer_capabilities(peer, caps)?;
        Ok(Some(mtu))
    }

    pub(super) fn checkpoint_joiner_event(
        &mut self,
        event: crate::checkpoint::CheckpointEvent,
    ) -> Result<(), JsError> {
        // The event loop has already checked exact reservation and primary
        // connection ownership. Reset all transfer state on circuit retirement.
        let joiner = self.checkpoint_joiner.as_mut().expect("committed joiner");
        let now = Instant::now();
        match event {
            rr::Event::Message {
                peer,
                message:
                    rr::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                let checkpoint = self.checkpoint.as_ref().expect("checkpoint issuer");
                let response = joiner
                    .transfer
                    .respond_at(
                        peer,
                        &request,
                        checkpoint.driver.state(),
                        &self.config.identity().map_err(debug_error)?,
                        &checkpoint.secret,
                        now,
                        unix_seconds(),
                    )
                    .unwrap_or_else(|error| {
                        let reason = match error {
                            checkpoint_wire::CheckpointSyncError::Unauthorized => {
                                CheckpointRejection::Unauthorized
                            }
                            checkpoint_wire::CheckpointSyncError::ResourceLimit => {
                                CheckpointRejection::Busy
                            }
                            checkpoint_wire::CheckpointSyncError::Expired => {
                                CheckpointRejection::Expired
                            }
                            _ => CheckpointRejection::InvalidTransfer,
                        };
                        CheckpointPageResponse::rejected(&request, reason)
                    });
                let final_page = matches!(&response, CheckpointPageResponse::Page(page)
                    if page.cursor as usize + page.bytes.len() == page.total_bytes as usize);
                if final_page {
                    joiner.pending_final = Some(request_id);
                }
                if self
                    .swarm
                    .behaviour_mut()
                    .checkpoint
                    .as_mut()
                    .expect("checkpoint behaviour")
                    .send_response(channel, response)
                    .is_err()
                {
                    joiner.transfer.cancel(peer, &request.challenge, now);
                    if joiner.pending_final == Some(request_id) {
                        joiner.pending_final = None;
                    }
                }
            }
            rr::Event::ResponseSent { request_id, .. }
                if joiner.pending_final == Some(request_id) =>
            {
                joiner.pending_final = None;
                joiner.served = true;
            }
            rr::Event::InboundFailure { request_id, .. }
                if joiner.pending_final == Some(request_id) =>
            {
                joiner.pending_final = None;
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn invitation_config(config: &Config, address: &Multiaddr) -> Config {
    let mut config = config.clone();
    config.network.listen_addresses.clear();
    config.network.external_addresses = vec![address.to_string()];
    config.network.relay.reservations.clear();
    config
}

fn unavailable() -> JsError {
    JsError::new(
        "Checkpoint issuance requires live authority and a confirmed unshared relay reservation",
    )
}
