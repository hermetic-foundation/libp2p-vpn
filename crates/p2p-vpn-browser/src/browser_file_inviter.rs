//! Detached legacy enrollment; no network or companion calls.

use p2p_vpn::{config::Config, pairing::MAX_PAIRING_MESSAGE_LEN};
use wasm_bindgen::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::membership_store::MembershipStore;

#[path = "file_inviter_core.rs"]
mod file_inviter_core;
use file_inviter_core::{ApprovalError, FileInviter};

/// A single local, exclusive legacy inviter session. Close BrowserVpn for the
/// same identity before opening this session.
#[wasm_bindgen]
pub struct BrowserFileInviter {
    session: Option<(FileInviter, MembershipStore)>,
}

#[wasm_bindgen]
impl BrowserFileInviter {
    pub async fn open(config_json: &str) -> Result<BrowserFileInviter, JsError> {
        // The founder config stays local; only signed membership records are saved.
        if config_json.len() > 32 * MAX_PAIRING_MESSAGE_LEN {
            return Err(JsError::new("Legacy config exceeds its size limit"));
        }
        let config: Config = serde_json::from_str(config_json)
            .map_err(|_| JsError::new("Invalid legacy inviter config"))?;
        let peer = config
            .local_peer()
            .map_err(|_| JsError::new("Invalid inviter identity"))?;
        let store = MembershipStore::open(&config.network.name, &peer).await?;
        let inviter = FileInviter::open(config, &store.load()?, now()?).map_err(JsError::new)?;
        Ok(Self {
            session: Some((inviter, store)),
        })
    }

    /// Return a signed p2pvpn: URI. Replaces any pending offer or request.
    pub fn create_offer(&mut self, expires_in_seconds: Option<u32>) -> Result<String, JsError> {
        self.active()?
            .0
            .create_offer(expires_in_seconds, now()?)
            .map_err(JsError::new)
    }

    /// Verify and retain one exact signed request; return non-secret review JSON.
    pub fn review_request(&mut self, request_json: &str) -> Result<String, JsError> {
        self.active()?
            .0
            .review_request(request_json, now()?)
            .map_err(JsError::new)
    }

    /// Explicit approval. The returned native response can contain a membership
    /// key; deliver it privately to the reviewed requester.
    pub fn approve(&mut self, reviewed_peer_id: &str) -> Result<String, JsError> {
        let (inviter, store) = self.active()?;
        inviter
            .approve(reviewed_peer_id, now()?, |ledger| store.save(ledger))
            .map_err(|error| match error {
                ApprovalError::Storage(error) => error,
                ApprovalError::Rejected(message) => JsError::new(message),
            })
    }

    pub fn cancel_offer(&mut self) -> Result<(), JsError> {
        self.active()?.0.cancel_offer();
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), JsError> {
        if let Some((_, store)) = self.session.take() {
            store.close().await?;
        }
        Ok(())
    }
}

impl BrowserFileInviter {
    fn active(&mut self) -> Result<&mut (FileInviter, MembershipStore), JsError> {
        self.session
            .as_mut()
            .ok_or_else(|| JsError::new("Inviter is closed"))
    }
}

fn now() -> Result<u64, JsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|age| age.as_secs())
        .map_err(|_| JsError::new("Invalid browser clock"))
}
