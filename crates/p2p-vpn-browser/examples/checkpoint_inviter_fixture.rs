//! Test-only issuer with an explicitly formed synthetic genesis. Never dials
//! or listens; the production joiner must remain gated without a snapshot.

#[cfg(all(target_arch = "wasm32", feature = "test-hooks"))]
#[path = "../src/checkpoint_bundle.rs"]
mod checkpoint_bundle;
#[cfg(all(target_arch = "wasm32", feature = "test-hooks"))]
#[path = "../src/checkpoint_inviter.rs"]
mod checkpoint_inviter;
#[cfg(all(target_arch = "wasm32", feature = "test-hooks"))]
#[path = "../src/membership_store.rs"]
mod membership_store;
#[cfg(all(target_arch = "wasm32", feature = "test-hooks"))]
mod browser {
    use p2p_vpn::{
        config::Config,
        identity::NodeIdentity,
        membership::checkpoint::{
            CheckpointBoundary, CheckpointMember, CooperativeMembershipState, NetworkAnchor,
            NetworkCapability, SnapshotPolicy,
        },
        pairing::{PairingOffer, PairingOfferOptions, PairingRequest, export_pairing_offer_at},
        runtime::forward::Forwarder,
    };
    use wasm_bindgen::prelude::*;
    use web_time::{SystemTime, UNIX_EPOCH};

    use crate::{
        checkpoint_bundle::{self, Credentials},
        checkpoint_inviter::{FileApproval, PreparedAdmission},
        membership_store::{CheckpointBootstrap, CheckpointStore, StoredCheckpoint},
    };

    const NETWORK: &str = "checkpoint-issuer-fixture";
    const SECRET: [u8; 32] = [171; 32];

    #[wasm_bindgen]
    pub struct CheckpointIssuerFixture {
        config: Config,
        issuer: String,
        state: CooperativeMembershipState,
        forwarder: Forwarder,
        store: Option<CheckpointStore>,
        reviewed_base: CheckpointBoundary,
        offer: PairingOffer,
        gated: bool,
    }

    #[wasm_bindgen]
    impl CheckpointIssuerFixture {
        pub async fn form() -> Result<CheckpointIssuerFixture, JsError> {
            let issuer = NodeIdentity::generate_ed25519().map_err(fixture_error)?;
            let relay = NodeIdentity::generate_ed25519().map_err(fixture_error)?;
            // An undialed locator exercising the production relay-only import path.
            let address = format!(
                "/ip4/127.0.0.1/udp/9/webrtc-direct/certhash/uEiD7VDkYVNXbTnQGCAuZUs4xWZFItU3fiq9fbgLLsT2RFg/p2p/{}/p2p-circuit/p2p/{}",
                relay.peer_id, issuer.peer_id
            );
            let config = serde_json::from_value(serde_json::json!({
                "network": {
                    "name": NETWORK,
                    "private_key": issuer.private_key,
                    "listen_addresses": [],
                    "external_addresses": [address],
                },
            }))
            .map_err(fixture_error)?;
            let wall_now = now()?;
            let anchor = NetworkAnchor::new([119; 32]).map_err(fixture_error)?;
            let state = CooperativeMembershipState::bootstrap_at(
                NetworkCapability::from_secret(anchor.clone(), Some(&SECRET))
                    .map_err(fixture_error)?,
                issuer.peer_id.clone(),
                vec![CheckpointMember::new(&issuer).map_err(fixture_error)?],
                SnapshotPolicy::default(),
                wall_now,
            )
            .map_err(fixture_error)?;
            let forwarder = Forwarder::from_checkpoint_config(&config, &state, &anchor, wall_now)
                .map_err(fixture_error)?;
            let store = CheckpointStore::open(NETWORK, &issuer.peer_id, &SECRET).await?;
            store.save(StoredCheckpoint {
                retained: state.retained(),
                enrollment_floor: None,
            }).await?;
            let offer = export_pairing_offer_at(&config, PairingOfferOptions::default(), wall_now)
                .map_err(fixture_error)?;
            let reviewed_base = state.snapshot().payload.boundary().map_err(fixture_error)?;
            Ok(Self {
                config,
                issuer: issuer.peer_id,
                state,
                forwarder,
                store: Some(store),
                reviewed_base,
                offer,
                gated: false,
            })
        }

        pub fn offer_json(&self) -> Result<String, JsError> {
            serde_json::to_string(&self.offer).map_err(fixture_error)
        }

        pub async fn approve(&mut self, request_json: &str) -> Result<String, JsError> {
            if request_json.len() > p2p_vpn::pairing::MAX_PAIRING_MESSAGE_LEN {
                return Err(JsError::new("Fixture request exceeds the pairing limit"));
            }
            let request: PairingRequest = serde_json::from_str(request_json).map_err(fixture_error)?;
            let store = self.store.as_ref().ok_or_else(|| JsError::new("Issuer is closed"))?;
            let issued = PreparedAdmission::prepare(
                &self.config,
                &mut self.state,
                &mut self.forwarder,
                &SECRET,
                FileApproval {
                    expected: self.reviewed_base,
                    offer: &self.offer,
                    request: &request,
                    wall_now: now()?,
                },
            ).map_err(fixture_error)?
                .commit_with_store(&mut self.gated, store).await.map_err(fixture_error)?;
            let saved = store.load().await?.ok_or_else(|| JsError::new("No committed authority"))?;
            let snapshot = &saved.retained.snapshot.payload;
            let grant = issued.response.payload.checkpoint.as_ref().ok_or_else(failed)?;
            let joiner = request.payload.joiner_peer.parse().map_err(fixture_error)?;
            if saved.retained != self.state.retained()
                || saved.enrollment_floor.is_some()
                || snapshot.rank().map_err(fixture_error)? != grant.minimum
                || snapshot.member(&request.payload.joiner_peer) != Some(&grant.joiner)
                || issued.mutation.payload.base != self.reviewed_base
                || !self.forwarder.is_configured_transport_peer(joiner)
                || !self.gated
            {
                return Err(failed());
            }
            serde_json::to_string(&issued.response).map_err(fixture_error)
        }

        /// Test the existing encryption primitive on the committed issuer
        /// state. This is not a production export of a live BrowserVpn.
        pub async fn encrypted_backup(&self, passphrase: &str) -> Result<String, JsError> {
            let store = self.store.as_ref().ok_or_else(|| JsError::new("Issuer is closed"))?;
            let saved = store.load().await?.ok_or_else(failed)?;
            let retained = saved.retained;
            let floor = retained.snapshot.payload.rank().map_err(fixture_error)?;
            let backup = checkpoint_bundle::seal(&Credentials {
                config: self.config.clone(),
                bootstrap: CheckpointBootstrap {
                    anchor: retained.snapshot.payload.anchor.clone(),
                    retained: retained.clone(),
                    enrollment_floor: Some(floor),
                },
                capability_secret: SECRET.to_vec(),
                direct_addresses: Vec::new(),
                relay_address: self.offer.payload.inviter_addresses.first().cloned(),
            }, passphrase).await?;
            let decoded = checkpoint_bundle::unseal(&backup, passphrase).await?;
            if decoded.bootstrap.retained != retained
                || decoded.bootstrap.enrollment_floor != Some(floor)
                || decoded.capability_secret != SECRET
                || decoded.config.local_peer().map_err(fixture_error)? != self.issuer
            {
                return Err(failed());
            }
            Ok(backup)
        }

        pub async fn close(&mut self) -> Result<(), JsError> {
            if let Some(store) = self.store.take() {
                store.close().await?;
            }
            Ok(())
        }
    }

    #[wasm_bindgen]
    pub async fn can_lock_issuer(peer: &str) -> Result<bool, JsError> {
        match CheckpointStore::open(NETWORK, peer, &SECRET).await {
            Ok(store) => {
                store.close().await?;
                Ok(true)
            }
            Err(error) => {
                let value: JsValue = error.into();
                if js_sys::Reflect::get(&value, &"message".into())
                    .map_err(fixture_error)?.as_string().as_deref()
                    == Some("This browser identity is in use by another tab")
                {
                    Ok(false)
                } else {
                    Err(failed())
                }
            }
        }
    }

    fn now() -> Result<u64, JsError> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(fixture_error)?.as_secs())
    }

    fn fixture_error<E>(_: E) -> JsError {
        failed()
    }

    fn failed() -> JsError {
        JsError::new("Checkpoint issuer fixture invariant failed")
    }
}

fn main() {}
