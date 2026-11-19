//! File-bearer enrollment uses only signed artifacts and the caller's local identity.

use p2p_vpn::{
    identity::NodeIdentity,
    pairing::{
        MAX_PAIRING_MESSAGE_LEN, PairingAcceptanceMode, PairingError, PairingOffer,
        PairingRequestOptions, PairingResponse, build_named_pairing_request_at,
    },
};

// Allow formatted files and base64url URIs before the native compact frame limit.
const MAX_ARTIFACT_INPUT_LEN: usize = 2 * MAX_PAIRING_MESSAGE_LEN;

#[derive(Debug)]
pub(super) enum OfflineError {
    TooLarge,
    Offer,
    RequiresFileBearer,
    Request,
    Response,
    Verification(PairingError),
}

pub(super) struct OfflineSession {
    pub(super) offer: PairingOffer,
    pub(super) identity: NodeIdentity,
    pub(super) request_json: String,
}

impl OfflineSession {
    pub(super) fn begin_at(
        input: &str,
        identity: NodeIdentity,
        hostname: Option<&str>,
        now: u64,
    ) -> Result<Self, OfflineError> {
        if input.len() > MAX_ARTIFACT_INPUT_LEN {
            return Err(OfflineError::TooLarge);
        }
        let input = input.trim();
        let offer: PairingOffer = if input.starts_with("p2pvpn:") {
            PairingOffer::from_uri(input).map_err(|_| OfflineError::Offer)?
        } else {
            serde_json::from_str(input).map_err(|_| OfflineError::Offer)?
        };
        if offer.payload.acceptance_mode != PairingAcceptanceMode::FileBearer {
            return Err(OfflineError::RequiresFileBearer);
        }
        let request = build_named_pairing_request_at(
            &offer,
            PairingRequestOptions {
                identity: identity.clone(),
                requested_vpn_ip: None,
                requested_routes: Vec::new(),
            },
            hostname
                .map(str::trim)
                .filter(|hostname| !hostname.is_empty()),
            now,
        )
        .map_err(OfflineError::Verification)?;
        let request_json = serde_json::to_string(&request).map_err(|_| OfflineError::Request)?;
        Ok(Self {
            offer,
            identity,
            request_json,
        })
    }

    pub(super) fn verify_response_at(
        &self,
        response_json: &str,
        now: u64,
    ) -> Result<PairingResponse, OfflineError> {
        if response_json.len() > MAX_ARTIFACT_INPUT_LEN {
            return Err(OfflineError::TooLarge);
        }
        let response: PairingResponse =
            serde_json::from_str(response_json).map_err(|_| OfflineError::Response)?;
        response
            .verify_for_offer_at(&self.offer, &self.identity, now)
            .map_err(OfflineError::Verification)?;
        Ok(response)
    }
}
