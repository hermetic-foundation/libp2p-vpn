//! WebAssembly binding for explicitly addressed browser enrollment.

use std::time::Duration;

use libp2p::{request_response::OutboundFailure, swarm::DialError};
use p2p_vpn::{
    config::Config,
    dns::canonical_dns_label,
    identity::NodeIdentity,
    pairing::{
        PairingConfigOptions, PairingError, PairingOffer, PairingResponse,
        import_pairing_response_config_at,
    },
    pairing_code::PairingCodeError,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::pairing_joiner::{JoinError, JoinOptions, join_v2};

/// One browser-owned identity and at most one active pairing operation.
#[wasm_bindgen]
pub struct BrowserPairing {
    pub(crate) identity: NodeIdentity,
}

#[wasm_bindgen]
impl BrowserPairing {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BrowserPairing, JsError> {
        let identity = NodeIdentity::generate_ed25519()
            .map_err(|_| JsError::new("Identity generation failed"))?;
        Ok(Self { identity })
    }

    pub fn peer_id(&self) -> String {
        self.identity.peer_id.clone()
    }

    /// Returns sensitive JSON after approval. Legacy config contains the private
    /// identity. Checkpoint credentials require separate activation. Keep both local.
    pub async fn join_v2(
        &mut self,
        code: String,
        expected_peer: String,
        dial_address: String,
        timeout_ms: u32,
        requested_hostname: Option<String>,
        on_pending: Option<js_sys::Function>,
    ) -> Result<String, JsError> {
        let code = code
            .parse()
            .map_err(|_| JsError::new("Invalid pairing code"))?;
        let peer = expected_peer
            .parse()
            .map_err(|_| JsError::new("Invalid expected peer ID"))?;
        let address = dial_address
            .parse()
            .map_err(|_| JsError::new("Invalid WebRTC Direct address"))?;
        let requested_hostname = requested_hostname
            .as_deref()
            .map(str::trim)
            .filter(|hostname| !hostname.is_empty())
            .map(canonical_dns_label)
            .transpose()
            .map_err(|_| JsError::new("Invalid requested hostname"))?;
        let enrollment = join_v2(
            &self.identity,
            &code,
            peer,
            address,
            JoinOptions {
                timeout: Duration::from_millis(u64::from(timeout_ms)),
                requested_hostname,
                requested_vpn_ip: None,
                requested_routes: Vec::new(),
            },
            || {
                if let Some(notify) = on_pending {
                    let _ = notify.call0(&JsValue::UNDEFINED);
                }
            },
        )
        .await
        .map_err(join_error)?;
        let offer = &enrollment.offer;
        let response = &enrollment.response;
        let transcript_sha256 = &enrollment.transcript_sha256;
        let dial_address = &dial_address;
        let serialized = if response.payload.checkpoint.is_some() {
            serde_json::to_string(&Artifacts::Checkpoint {
                offer,
                response,
                dial_address,
                transcript_sha256,
            })
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| JsError::new("Invalid browser clock"))?
                .as_secs();
            let config = import_pairing_response_config_at(
                offer,
                response,
                PairingConfigOptions {
                    identity: self.identity.clone(),
                    interface_name: "p2p-browser".to_owned(),
                    mtu: 1280,
                    local_routes: Vec::new(),
                    peer_name: None,
                },
                now,
            )
            .map_err(|_| JsError::new("Could not import approved pairing configuration"))?;
            serde_json::to_string(&Artifacts::Legacy {
                config: &config,
                dial_address,
                transcript_sha256,
            })
        };
        serialized.map_err(|_| JsError::new("Could not encode approved pairing artifacts"))
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Artifacts<'a> {
    Legacy {
        config: &'a Config,
        dial_address: &'a str,
        transcript_sha256: &'a str,
    },
    Checkpoint {
        offer: &'a PairingOffer,
        response: &'a PairingResponse,
        dial_address: &'a str,
        transcript_sha256: &'a str,
    },
}

fn join_error(error: JoinError) -> JsError {
    let message = match error {
        JoinError::InvalidAddress => "WebRTC Direct address must pin the expected peer",
        JoinError::InvalidIdentity => "Invalid browser identity",
        JoinError::InvalidTimeout => "Pairing timeout must be positive and at most one hour",
        JoinError::InvalidClock => "Invalid browser clock",
        JoinError::Dial(DialError::WrongPeerId { .. }) | JoinError::WrongPeer => {
            "Pairing connection or response came from an unexpected peer"
        }
        JoinError::Dial(_) => "WebRTC Direct dial failed",
        JoinError::Disconnected => "Pairing connection closed",
        JoinError::Expired
        | JoinError::Code(PairingCodeError::Expired { .. })
        | JoinError::Pairing(PairingError::Expired { .. }) => "Pairing expired",
        JoinError::Rejected(reason) => {
            return JsError::new(&format!("Pairing rejected: {reason:?}"));
        }
        JoinError::Transport(OutboundFailure::Timeout) => "Pairing request timed out",
        JoinError::Transport(_) => "Pairing transport failed",
        JoinError::UnexpectedResponse => "Unexpected pairing response",
        JoinError::InvalidTicket => "Invalid approval ticket",
        JoinError::Code(_) => "Pairing code authentication failed",
        JoinError::Pairing(_) => "Pairing message validation failed",
    };
    JsError::new(message)
}
