//! Test-only bindings for the standalone browser joiner.

#[cfg(target_arch = "wasm32")]
#[path = "../src/pairing_joiner.rs"]
mod pairing_joiner;

#[cfg(target_arch = "wasm32")]
mod fixture {
    use std::time::Duration;

    use p2p_vpn::identity::NodeIdentity;
    use wasm_bindgen::prelude::*;

    use super::pairing_joiner::{JoinError, JoinOptions, join_v2};

    #[wasm_bindgen]
    pub struct PairingJoinerFixture {
        identity: NodeIdentity,
    }

    #[wasm_bindgen]
    impl PairingJoinerFixture {
        #[wasm_bindgen(constructor)]
        pub fn new() -> Result<PairingJoinerFixture, JsError> {
            console_error_panic_hook::set_once();
            let identity = NodeIdentity::generate_ed25519()
                .map_err(|_| JsError::new("identity generation failed"))?;
            Ok(Self { identity })
        }

        pub fn peer_id(&self) -> String {
            self.identity.peer_id.clone()
        }

        pub async fn join(
            &self,
            code: String,
            expected_peer: String,
            address: String,
            timeout_ms: u32,
            hostname: String,
            on_pending: js_sys::Function,
        ) -> Result<String, JsError> {
            let enrollment = join_v2(
                &self.identity,
                &code
                    .parse()
                    .map_err(|_| JsError::new("invalid pairing code"))?,
                expected_peer
                    .parse()
                    .map_err(|_| JsError::new("invalid peer ID"))?,
                address
                    .parse()
                    .map_err(|_| JsError::new("invalid multiaddress"))?,
                JoinOptions {
                    timeout: Duration::from_millis(u64::from(timeout_ms)),
                    requested_hostname: Some(hostname),
                    requested_vpn_ip: None,
                    requested_routes: Vec::new(),
                },
                || {
                    let _ = on_pending.call0(&JsValue::UNDEFINED);
                },
            )
            .await
            .map_err(|error| {
                JsError::new(&match error {
                    JoinError::Dial(error) => format!("Dial({error:?})"),
                    JoinError::Transport(error) => format!("Transport({error})"),
                    JoinError::Code(error) => format!("Code({error:?})"),
                    JoinError::Pairing(error) => format!("Pairing({error:?})"),
                    JoinError::Rejected(reason) => format!("Rejected({reason:?})"),
                    other => format!("{other:?}"),
                })
            })?;
            let payload = enrollment.response.payload;
            let member = payload.member_records.iter().any(|record| {
                record.payload.member_peer == self.identity.peer_id && !record.payload.revoked
            }) || payload
                .checkpoint
                .as_ref()
                .is_some_and(|grant| grant.joiner.subject.peer_id == self.identity.peer_id);
            Ok(serde_json::json!({
                "network": enrollment.offer.payload.network_name,
                "inviter": payload.inviter_peer,
                "joiner": payload.joiner_peer,
                "member": member,
                "transcript_sha256": enrollment.transcript_sha256,
            })
            .to_string())
        }
    }
}

fn main() {}
