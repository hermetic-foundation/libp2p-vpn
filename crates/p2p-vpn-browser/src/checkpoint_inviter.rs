//! Detached file-bearer checkpoint admission for an existing, live issuer.
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
    runtime::forward::{ForwardError, Forwarder, ForwarderUpdate},
};

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
    pub(crate) fn prepare(
        config: &Config,
        installed: &'a mut CooperativeMembershipState,
        forwarder: &'a mut Forwarder,
        capability_secret: &[u8],
        approval: FileApproval<'_>,
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
        if offer.payload.acceptance_mode != PairingAcceptanceMode::FileBearer
            || request.code_authentication.is_some()
            || request.payload.offer_signature.is_empty()
            || request.payload.offer_signature != offer.signature
            || request
                .offer
                .as_ref()
                .is_some_and(|embedded| embedded != offer)
        {
            return Err(AdmissionError::InvalidFileRequest);
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
    ) -> Result<IssuedEnrollment, CommitError<wasm_bindgen::JsError>> {
        use crate::membership_store::StoredCheckpoint;

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
                })
                .await
        })
        .await
    }
}
