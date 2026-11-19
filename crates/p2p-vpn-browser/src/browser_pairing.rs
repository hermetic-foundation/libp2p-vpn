//! WebAssembly binding for explicitly addressed browser enrollment.

use std::time::Duration;

use libp2p::{request_response::OutboundFailure, swarm::DialError};
use p2p_vpn::{
    config::Config,
    dns::canonical_dns_label,
    identity::NodeIdentity,
    pairing::{
        PairingConfigOptions, PairingError, PairingOffer, PairingResponse,
        checkpoint_grant::VerifiedCheckpointEnrollment, import_pairing_response_config_at,
    },
    pairing_code::{PairingCode, PairingCodeError},
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::pairing_joiner::{CandidateMiss, JoinError, JoinOptions, join_v1, join_v2};

/// One browser-owned identity and at most one active pairing operation.
#[wasm_bindgen]
pub struct BrowserPairing {
    pub(crate) identity: NodeIdentity,
    checkpoint_activation: Option<BrowserCheckpointActivation>,
}

#[wasm_bindgen]
impl BrowserPairing {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BrowserPairing, JsError> {
        let identity = NodeIdentity::generate_ed25519()
            .map_err(|_| JsError::new("Identity generation failed"))?;
        Ok(Self {
            identity,
            checkpoint_activation: None,
        })
    }

    pub fn peer_id(&self) -> String {
        self.identity.peer_id.clone()
    }

    /// Take the approved checkpoint activation once. The handle exposes no secrets to JS.
    pub fn take_checkpoint_activation(&mut self) -> Option<BrowserCheckpointActivation> {
        self.checkpoint_activation.take()
    }

    /// Returns sensitive JSON after approval. Legacy config contains the private
    /// identity. Checkpoint credentials require separate activation. Keep both local.
    /// Only a `PairingCandidateMiss` error permits automatic same-version fallback.
    pub async fn join_v2(
        &mut self,
        code: String,
        expected_peer: String,
        dial_address: String,
        timeout_ms: u32,
        requested_hostname: Option<String>,
        on_pending: Option<js_sys::Function>,
    ) -> Result<String, JsValue> {
        self.join(
            None,
            code,
            expected_peer,
            dial_address,
            timeout_ms,
            requested_hostname,
            on_pending,
        )
        .await
    }

    /// Network-scoped v1, selected explicitly rather than as a retry of v2.
    pub async fn join_v1(
        &mut self,
        code: String,
        network_name: String,
        expected_peer: String,
        dial_address: String,
        timeout_ms: u32,
        requested_hostname: Option<String>,
        on_pending: Option<js_sys::Function>,
    ) -> Result<String, JsValue> {
        self.join(
            Some(network_name),
            code,
            expected_peer,
            dial_address,
            timeout_ms,
            requested_hostname,
            on_pending,
        )
        .await
    }
}

impl BrowserPairing {
    async fn join(
        &mut self,
        network_name: Option<String>,
        code: String,
        expected_peer: String,
        dial_address: String,
        timeout_ms: u32,
        requested_hostname: Option<String>,
        on_pending: Option<js_sys::Function>,
    ) -> Result<String, JsValue> {
        self.checkpoint_activation = None;
        let code = code
            .parse()
            .map_err(|_| JsError::new("Invalid pairing code"))?;
        let peer = expected_peer
            .parse()
            .map_err(|_| JsError::new("Invalid expected peer ID"))?;
        if dial_address.len() > 1024 {
            return Err(JsError::new("Pairing address exceeds its byte limit").into());
        }
        let address = dial_address
            .parse()
            .map_err(|_| JsError::new("Invalid pairing address"))?;
        let requested_hostname = requested_hostname
            .as_deref()
            .map(str::trim)
            .filter(|hostname| !hostname.is_empty())
            .map(canonical_dns_label)
            .transpose()
            .map_err(|_| JsError::new("Invalid requested hostname"))?;
        let options = JoinOptions {
            timeout: Duration::from_millis(u64::from(timeout_ms)),
            requested_hostname,
            requested_vpn_ip: None,
            requested_routes: Vec::new(),
        };
        let notify = || {
            if let Some(notify) = on_pending {
                let _ = notify.call0(&JsValue::UNDEFINED);
            }
        };
        let enrollment = match network_name.as_deref() {
            Some(network) => {
                join_v1(
                    &self.identity,
                    &code,
                    network,
                    peer,
                    address,
                    options,
                    notify,
                )
                .await
            }
            None => join_v2(&self.identity, &code, peer, address, options, notify).await,
        }
        .map_err(join_error)?;
        let offer = &enrollment.offer;
        let response = &enrollment.response;
        let transcript_sha256 = &enrollment.transcript_sha256;
        let dial_address = &dial_address;
        let now = unix_seconds()?;
        let serialized = if response.payload.checkpoint.is_some() {
            let activation = BrowserCheckpointActivation::from_approved_response(
                offer,
                response,
                &self.identity,
                dial_address,
                now,
            )?;
            let artifact = serde_json::to_string(&Artifacts::Checkpoint {
                offer,
                response,
                dial_address,
                transcript_sha256,
            });
            if artifact.is_ok() {
                self.checkpoint_activation = Some(activation);
            }
            artifact
        } else {
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
        serialized.map_err(|_| JsError::new("Could not encode approved pairing artifacts").into())
    }
}

/// Derive only the public rendezvous locator. No identity, transport, or lookup is used.
#[wasm_bindgen]
pub fn pairing_code_v2_global_locator(code: &str) -> Result<String, JsError> {
    code.parse::<PairingCode>()
        .map(|code| code.global_locator())
        .map_err(|_| JsError::new("Invalid pairing code"))
}

/// Derive the public locator for an explicitly selected scoped v1 exchange.
#[wasm_bindgen]
pub fn pairing_code_v1_scoped_locator(code: &str, network_name: &str) -> Result<String, JsError> {
    code.parse::<PairingCode>()
        .and_then(|code| code.locator(network_name))
        .map_err(|_| JsError::new("Invalid v1 pairing code or network name"))
}

#[wasm_bindgen]
pub struct BrowserCheckpointActivation {
    peer_id: String,
    last_valid_unix_second: u64,
    inputs: CheckpointActivationInputs,
}

#[wasm_bindgen]
impl BrowserCheckpointActivation {
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Open the gated VPN over the circuit which carried the approved pairing.
    /// Call `connect` to fetch and commit the remote checkpoint.
    #[cfg(feature = "relay-client")]
    pub async fn open_relay(self) -> Result<crate::BrowserVpn, JsError> {
        let inputs = self.into_inputs()?;
        crate::BrowserVpn::open_checkpoint_with_relay(
            &inputs.config_json,
            "",
            &inputs.dial_address,
            &inputs.bootstrap_json,
            inputs.capability_secret,
        )
        .await
    }
}

/// Rust-only handoff to the browser checkpoint runtime. Do not serialize or log it.
pub struct CheckpointActivationInputs {
    pub config_json: String,
    pub dial_address: String,
    pub bootstrap_json: String,
    pub capability_secret: Vec<u8>,
}

impl BrowserCheckpointActivation {
    pub fn into_inputs(self) -> Result<CheckpointActivationInputs, JsError> {
        if unix_seconds()? > self.last_valid_unix_second {
            return Err(JsError::new("Checkpoint enrollment expired"));
        }
        Ok(self.inputs)
    }

    fn from_approved_response(
        offer: &PairingOffer,
        response: &PairingResponse,
        identity: &NodeIdentity,
        dial_address: &str,
        now: u64,
    ) -> Result<Self, JsError> {
        let invalid = || JsError::new("Could not prepare approved checkpoint enrollment");
        let enrollment = VerifiedCheckpointEnrollment::verify_at(offer, response, identity, now)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let grant = enrollment.grant();
        let seed = enrollment.into_pending_seed().map_err(|_| invalid())?;
        let capability_secret = grant.secret_bytes().map_err(|_| invalid())?;
        let config_json = serde_json::json!({
            "network": {
                "name": response.payload.network_name,
                "local_peer": identity.peer_id,
                "private_key": identity.private_key,
                "vpn_ip": response.payload.assigned_vpn_ip,
                "listen_addresses": [],
            },
        })
        .to_string();
        let bootstrap_json = serde_json::json!({
            "anchor": grant.anchor,
            "retained": seed.retained,
            "enrollment_floor": seed.enrollment_floor,
        })
        .to_string();
        let last_valid_unix_second = [
            grant.inviter.expires_at_unix_seconds,
            grant.joiner.expires_at_unix_seconds,
        ]
        .into_iter()
        .flatten()
        .map(|expiry| expiry.saturating_sub(1))
        .fold(
            offer
                .payload
                .expires_at_unix_seconds
                .min(response.payload.expires_at_unix_seconds),
            u64::min,
        );
        Ok(Self {
            peer_id: identity.peer_id.clone(),
            last_valid_unix_second,
            inputs: CheckpointActivationInputs {
                config_json,
                dial_address: dial_address.to_owned(),
                bootstrap_json,
                capability_secret,
            },
        })
    }
}

fn unix_seconds() -> Result<u64, JsError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JsError::new("Invalid browser clock"))?
        .as_secs())
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

fn join_error(error: JoinError) -> JsValue {
    let message = match error {
        JoinError::CandidateMiss(miss) => {
            let (reason, message) = match miss {
                CandidateMiss::Transport => ("transport", "Pairing candidate could not be reached"),
                CandidateMiss::Unavailable => ("unavailable", "Pairing rejected: Unavailable"),
            };
            let error = js_sys::Error::new(message);
            error.set_name("PairingCandidateMiss");
            let _ = js_sys::Reflect::set(
                error.as_ref(),
                &JsValue::from_str("reason"),
                &JsValue::from_str(reason),
            );
            return error.into();
        }
        JoinError::InvalidAddress => "Pairing address must pin the expected peer",
        JoinError::InvalidIdentity => "Invalid browser identity",
        JoinError::InvalidTimeout => "Pairing timeout must be positive and at most one hour",
        JoinError::InvalidClock => "Invalid browser clock",
        JoinError::Dial(DialError::WrongPeerId { .. }) | JoinError::WrongPeer => {
            "Pairing connection or response came from an unexpected peer"
        }
        JoinError::Dial(_) => "Pairing transport dial failed",
        JoinError::Disconnected => "Pairing connection closed",
        JoinError::Expired
        | JoinError::Code(PairingCodeError::Expired { .. })
        | JoinError::Pairing(PairingError::Expired { .. }) => "Pairing expired",
        JoinError::Rejected(reason) => {
            return JsError::new(&format!("Pairing rejected: {reason:?}")).into();
        }
        JoinError::Transport(OutboundFailure::Timeout) => "Pairing request timed out",
        JoinError::Transport(_) => "Pairing transport failed",
        JoinError::UnexpectedResponse => "Unexpected pairing response",
        JoinError::InvalidTicket => "Invalid approval ticket",
        JoinError::Code(_) => "Pairing code authentication failed",
        JoinError::Pairing(_) => "Pairing message validation failed",
    };
    JsError::new(message).into()
}
