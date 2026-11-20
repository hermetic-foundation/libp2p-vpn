//! Durable checkpoint admission for an existing, live issuer.
//! The owner must keep its origin lock, serialize swarm work, and refresh
//! control capabilities and mutation delivery before ungating forwarding.

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "checkpoint_inviter/tests.rs"]
mod tests;

use p2p_vpn::{
    config::Config,
    membership::{
        MembershipRole,
        checkpoint::{
            CheckpointBoundary, CheckpointError, CheckpointMember, CooperativeMembershipState,
            MembershipChange, MembershipSyncState, RetainedCheckpointState,
            SignedMembershipMutation, SnapshotPublisher,
        },
    },
    pairing::{
        DEFAULT_PAIRING_EXPIRES_IN_SECONDS, PairingAcceptanceMode, PairingCheckpointGrant,
        PairingError, PairingOffer, PairingRequest, PairingResponse, PairingResponseOptions,
        build_checkpoint_pairing_response_at,
    },
    pairing_code::{PairingCodeSession, verify_pairing_request_code_authentication},
    runtime::forward::{ForwardError, Forwarder, ForwarderUpdate},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodeRecovery {
    boundary: CheckpointBoundary,
    ticket: String,
    expires: u64,
    response: PairingResponse,
}

impl CodeRecovery {
    pub(crate) fn new(
        boundary: CheckpointBoundary,
        ticket: String,
        expires: u64,
        mut response: PairingResponse,
    ) -> Self {
        response
            .payload
            .checkpoint
            .as_mut()
            .expect("checkpoint grant")
            .capability_secret
            .clear();
        Self {
            boundary,
            ticket,
            expires,
            response,
        }
    }

    pub(crate) fn peer(&self) -> Option<libp2p::PeerId> {
        self.response.payload.joiner_peer.parse().ok()
    }

    pub(crate) fn expires(&self) -> u64 {
        self.expires
    }

    pub(crate) fn current(&self, boundary: CheckpointBoundary, address: &str, now: u64) -> bool {
        self.matches_checkpoint(boundary, now)
            && self.response.payload.inviter_addresses == [address]
    }

    pub(crate) fn matches_checkpoint(&self, boundary: CheckpointBoundary, now: u64) -> bool {
        now < self.expires && self.boundary == boundary
    }

    pub(crate) fn recover(
        &self,
        peer: libp2p::PeerId,
        ticket: &str,
        boundary: CheckpointBoundary,
        address: &str,
        now: u64,
        secret: &[u8],
    ) -> Option<PairingResponse> {
        use base64::Engine as _;
        if self.peer() != Some(peer)
            || self.ticket != ticket
            || !self.current(boundary, address, now)
        {
            return None;
        }
        let mut response = self.response.clone();
        response.payload.checkpoint.as_mut()?.capability_secret =
            base64::engine::general_purpose::STANDARD.encode(secret);
        Some(response)
    }
}

pub(crate) struct FileApproval<'a> {
    /// The checkpoint boundary shown when the operator reviewed this request.
    pub(crate) expected: CheckpointBoundary,
    pub(crate) offer: &'a PairingOffer,
    pub(crate) request: &'a PairingRequest,
    pub(crate) wall_now: u64,
}

#[derive(Debug)]
pub(crate) enum AdmissionError {
    NotParticipating,
    StaleApproval,
    InvalidFileRequest,
    InvalidCodeRequest,
    UnsupportedGrant,
    AlreadyInRoster,
    LocatorChanged,
    Authority(CheckpointError),
    Pairing(PairingError),
    Projection(ForwardError),
}

#[derive(Debug)]
pub(crate) enum CommitError<StorageError> {
    AlreadyGated,
    Storage(StorageError),
    Projection(ForwardError),
}

/// The response contains the network capability. Do not log it or persist it
/// in site storage. The signed mutation can be handed to existing peers.
pub(crate) struct IssuedEnrollment {
    pub(crate) response: PairingResponse,
    pub(crate) mutation: SignedMembershipMutation,
}

/// Holds the exact authority and its projection until commit or drop. No
/// accessor exposes a prepared grant, response, or mutation before commit.
#[must_use]
pub(crate) struct PreparedAdmission<'a> {
    installed: &'a mut CooperativeMembershipState,
    forwarder: &'a mut Forwarder,
    candidate: CooperativeMembershipState,
    update: ForwarderUpdate,
    response: PairingResponse,
    mutation: SignedMembershipMutation,
}

impl<'a> PreparedAdmission<'a> {
    fn code_recovery(&self, ticket: String, expires: u64) -> CodeRecovery {
        let boundary = self
            .candidate
            .snapshot()
            .payload
            .boundary()
            .expect("validated candidate");
        CodeRecovery::new(boundary, ticket, expires, self.response.clone())
    }

    pub(crate) fn prepare(
        config: &Config,
        installed: &'a mut CooperativeMembershipState,
        forwarder: &'a mut Forwarder,
        capability_secret: &[u8],
        approval: FileApproval<'_>,
    ) -> Result<Self, AdmissionError> {
        Self::prepare_bound(
            config,
            installed,
            forwarder,
            capability_secret,
            approval,
            None,
        )
    }

    pub(crate) fn prepare_bound(
        config: &Config,
        installed: &'a mut CooperativeMembershipState,
        forwarder: &'a mut Forwarder,
        capability_secret: &[u8],
        approval: FileApproval<'_>,
        code: Option<(&PairingCodeSession, libp2p::PeerId)>,
    ) -> Result<Self, AdmissionError> {
        let FileApproval {
            expected,
            offer,
            request,
            wall_now,
        } = approval;
        let current = &installed.snapshot().payload;
        if installed.sync_state() != MembershipSyncState::Participating
            || forwarder.checkpoint_sync_state() != Some(MembershipSyncState::Participating)
            || forwarder.config().network.name != config.network.name
            || config.network.membership_key.is_some()
            || !config.network.previous_membership_tags.is_empty()
            || !config.network.member_records.is_empty()
        {
            return Err(AdmissionError::NotParticipating);
        }
        if current.boundary().map_err(AdmissionError::Authority)? != expected {
            return Err(AdmissionError::StaleApproval);
        }
        if request.payload.offer_signature.is_empty()
            || request.payload.offer_signature != offer.signature
            || request
                .offer
                .as_ref()
                .is_some_and(|embedded| embedded != offer)
        {
            return Err(AdmissionError::InvalidFileRequest);
        }
        match code {
            Some((session, peer))
                if offer.payload.acceptance_mode == PairingAcceptanceMode::CodeApproval
                    && session.protocol_version() == 2
                    && request.payload.joiner_peer.as_str() == peer.to_string()
                    && verify_pairing_request_code_authentication(request, session).is_ok() => {}
            Some(_) => return Err(AdmissionError::InvalidCodeRequest),
            None if offer.payload.acceptance_mode == PairingAcceptanceMode::FileBearer
                && request.code_authentication.is_none() => {}
            None => return Err(AdmissionError::InvalidFileRequest),
        }
        request
            .verify_for_offer_at(offer, wall_now)
            .map_err(AdmissionError::Pairing)?;
        let joiner = &request.payload.joiner_peer;
        if current.member(joiner).is_some() {
            return Err(AdmissionError::AlreadyInRoster);
        }
        if request.payload.requested_vpn_ip.is_some()
            || !request.payload.requested_routes.is_empty()
        {
            return Err(AdmissionError::UnsupportedGrant);
        }
        let identity = config
            .identity()
            .map_err(|error| AdmissionError::Pairing(error.into()))?;
        let member = CheckpointMember {
            subject: SnapshotPublisher {
                peer_id: joiner.clone(),
                public_key: request.payload.joiner_public_key.clone(),
            },
            // The shared signer replaces this with the exact-base incarnation.
            incarnation: [1; 32],
            roles: vec![MembershipRole::OverlayMember],
            route_grants: Vec::new(),
            expires_at_unix_seconds: None,
        };
        let mutation = installed
            .sign_mutation_at(&identity, MembershipChange::UpsertMember(member), wall_now)
            .map_err(AdmissionError::Authority)?;
        let mut candidate = installed.clone();
        candidate
            .apply_mutation_at(&mutation, wall_now)
            .map_err(AdmissionError::Authority)?;
        let update = forwarder
            .prepare_checkpoint_update(&candidate, &current.anchor, wall_now)
            .map_err(AdmissionError::Projection)?;
        let grant =
            PairingCheckpointGrant::from_state_at(&candidate, capability_secret, joiner, wall_now)
                .map_err(|error| AdmissionError::Pairing(error.into()))?;
        let response = build_checkpoint_pairing_response_at(
            config,
            offer,
            PairingResponseOptions {
                joiner_peer: joiner.clone(),
                assigned_vpn_ip: None,
                membership_key: None,
                member_records: Vec::new(),
                expires_in_seconds: DEFAULT_PAIRING_EXPIRES_IN_SECONDS,
            },
            grant,
            wall_now,
        )
        .map_err(AdmissionError::Pairing)?;
        if offer.payload.inviter_addresses.is_empty()
            || response.payload.inviter_addresses != offer.payload.inviter_addresses
        {
            return Err(AdmissionError::LocatorChanged);
        }
        Ok(Self {
            installed,
            forwarder,
            candidate,
            update,
            response,
            mutation,
        })
    }

    /// Only the owner of the already-held identity lock may supply this store
    /// operation. It must verify and replace the exact base before returning
    /// success. After a write attempt, the caller must reconcile before ungating
    /// packets, even if the write reports an error or this future is dropped.
    async fn commit<E>(
        self,
        forwarding_blocked: &mut bool,
        persist: impl AsyncFnOnce(RetainedCheckpointState, RetainedCheckpointState) -> Result<(), E>,
    ) -> Result<IssuedEnrollment, CommitError<E>> {
        if *forwarding_blocked {
            return Err(CommitError::AlreadyGated);
        }
        let Self {
            installed,
            forwarder,
            candidate,
            update,
            response,
            mutation,
        } = self;
        *forwarding_blocked = true;
        persist(installed.retained(), candidate.retained())
            .await
            .map_err(CommitError::Storage)?;
        forwarder
            .commit_checkpoint_update(update)
            .map_err(CommitError::Projection)?;
        *installed = candidate;
        Ok(IssuedEnrollment { response, mutation })
    }

    /// Borrow the live driver's existing store; never open a parallel lock or
    /// use a restored (resync-required) state as issuing authority.
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn commit_with_store(
        self,
        forwarding_blocked: &mut bool,
        store: &crate::membership_store::CheckpointStore,
        recovery: Option<(String, u64)>,
    ) -> Result<IssuedEnrollment, CommitError<wasm_bindgen::JsError>> {
        use crate::membership_store::StoredCheckpoint;

        let recovery = recovery.map(|(ticket, expires)| self.code_recovery(ticket, expires));
        self.commit(forwarding_blocked, async |base, retained| {
            let previous = store.load().await?;
            if !previous
                .is_some_and(|saved| saved.enrollment_floor.is_none() && saved.retained == base)
            {
                return Err(wasm_bindgen::JsError::new(
                    "Saved checkpoint does not match the approved base",
                ));
            }
            store
                .save(StoredCheckpoint {
                    retained,
                    enrollment_floor: None,
                    code_recovery: recovery,
                })
                .await
        })
        .await
    }
}
