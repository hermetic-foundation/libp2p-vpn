//! Per-origin membership storage. The lock spans the active peer's lifetime.
use futures::{FutureExt as _, channel::oneshot};
use gloo_timers::future::TimeoutFuture;
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use p2p_vpn::membership::{
    MAX_MEMBERSHIP_RECORD_ENCODED_LEN, MAX_MEMBERSHIP_RECORDS, SignedMembershipRecord,
    checkpoint::{
        MAX_CAPABILITY_BYTES, MAX_SNAPSHOT_OFFER_BYTES, NetworkAnchor, RetainedCheckpointState,
        SnapshotRank,
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast as _, prelude::*};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::Storage;

const MAX_ENCODED: usize = MAX_MEMBERSHIP_RECORDS * (MAX_MEMBERSHIP_RECORD_ENCODED_LEN + 1) + 2;
const MAX_CHECKPOINT_ENCODED: usize = MAX_SNAPSHOT_OFFER_BYTES + 4096;
const CHECKPOINT_STORE_DOMAIN: &[u8] = b"p2p-vpn browser checkpoint store v1\n";

#[wasm_bindgen]
extern "C" {
    type BrowserLockManager;

    #[wasm_bindgen(method, catch, js_name = request)]
    fn request_lock(
        this: &BrowserLockManager,
        name: &str,
        options: &Object,
        callback: &Function,
    ) -> Result<Promise, JsValue>;

    type BrowserSubtleCrypto;

    #[wasm_bindgen(method, catch, js_name = importKey)]
    fn import_key(
        this: &BrowserSubtleCrypto,
        format: &str,
        key: &Uint8Array,
        algorithm: &Object,
        extractable: bool,
        usages: &Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = sign)]
    fn sign(
        this: &BrowserSubtleCrypto,
        algorithm: &str,
        key: &JsValue,
        data: &Uint8Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = verify)]
    fn verify(
        this: &BrowserSubtleCrypto,
        algorithm: &str,
        key: &JsValue,
        signature: &Uint8Array,
        data: &Uint8Array,
    ) -> Result<Promise, JsValue>;
}

pub(crate) struct MembershipStore {
    storage: Storage,
    key: String,
    checkpoint_key: String,
    // Dropping the sender resolves the Promise that holds the Web Lock.
    hold: oneshot::Sender<()>,
    completion: Promise,
}

impl MembershipStore {
    pub(crate) async fn open(network: &str, local_peer: &str) -> Result<Self, JsError> {
        let store = Self::lock(network, local_peer).await?;
        if store.read(&store.checkpoint_key)?.is_some() {
            store.close().await?;
            return Err(JsError::new(
                "This browser identity requires explicit checkpoint bootstrap",
            ));
        }
        Ok(store)
    }

    async fn lock(network: &str, local_peer: &str) -> Result<Self, JsError> {
        let unavailable = || JsError::new("Browser membership storage or locking is unavailable");
        let window = web_sys::window().ok_or_else(unavailable)?;
        let storage = window
            .local_storage()
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let locks = Reflect::get(window.navigator().as_ref(), &JsValue::from_str("locks"))
            .map_err(|_| unavailable())?;
        if locks.is_undefined() || locks.is_null() {
            return Err(unavailable());
        }
        let locks: BrowserLockManager = locks.unchecked_into();
        // A just-freed peer releases its Web Lock through a Promise. Let that
        // release run before testing availability, without queueing behind a live peer.
        TimeoutFuture::new(0).await;
        let scope = serde_json::to_string(&[network, local_peer])?;
        // Keep the old lock name so legacy and checkpoint cannot open concurrently.
        let key = format!("p2p-vpn:legacy-membership:1:{scope}");
        let checkpoint_key = format!("p2p-vpn:checkpoint-membership:1:{scope}");
        let options = Object::new();
        Reflect::set(&options, &JsValue::from_str("ifAvailable"), &JsValue::TRUE)
            .map_err(|_| unavailable())?;
        let (claim, claimed) = oneshot::channel();
        let (hold, release) = oneshot::channel::<()>();
        let callback = Closure::once(move |lock: JsValue| {
            if lock.is_null() || lock.is_undefined() || claim.send(()).is_err() {
                return Promise::resolve(&JsValue::UNDEFINED);
            }
            future_to_promise(async move {
                let _ = release.await;
                Ok(JsValue::UNDEFINED)
            })
        });
        let completion = locks
            .request_lock(&key, &options, callback.as_ref().unchecked_ref())
            .map_err(|_| unavailable())?;
        let request = JsFuture::from(completion.clone()).fuse();
        let claimed = claimed.fuse();
        futures::pin_mut!(request, claimed);
        futures::select_biased! {
            result = claimed => {
                result.map_err(|_| JsError::new("This browser identity is in use by another tab"))?;
            },
            result = request => {
                result.map_err(|_| unavailable())?;
                return Err(JsError::new("This browser identity is in use by another tab"));
            },
        }
        Ok(Self {
            storage,
            key,
            checkpoint_key,
            hold,
            completion,
        })
    }

    pub(crate) async fn close(self) -> Result<(), JsError> {
        drop(self.hold);
        JsFuture::from(self.completion)
            .await
            .map_err(|_| JsError::new("Could not release the membership store lock"))?;
        Ok(())
    }

    fn read(&self, key: &str) -> Result<Option<String>, JsError> {
        self.storage
            .get_item(key)
            .map_err(|_| JsError::new("Could not read saved membership"))
    }

    pub(crate) fn load(&self) -> Result<Vec<SignedMembershipRecord>, JsError> {
        let Some(encoded) = self
            .storage
            .get_item(&self.key)
            .map_err(|_| JsError::new("Could not read the saved membership ledger"))?
        else {
            return Ok(Vec::new());
        };
        if encoded.len() > MAX_ENCODED {
            return Err(JsError::new(
                "Saved membership ledger exceeds its size limit",
            ));
        }
        let records: Vec<SignedMembershipRecord> = serde_json::from_str(&encoded)
            .map_err(|_| JsError::new("Saved membership ledger is unreadable"))?;
        if records.len() > MAX_MEMBERSHIP_RECORDS {
            return Err(JsError::new(
                "Saved membership ledger exceeds its record limit",
            ));
        }
        Ok(records)
    }

    pub(crate) fn save(&self, records: &[SignedMembershipRecord]) -> Result<(), JsError> {
        let encoded = serde_json::to_string(records)?;
        if records.len() > MAX_MEMBERSHIP_RECORDS || encoded.len() > MAX_ENCODED {
            return Err(JsError::new("Membership ledger exceeds its storage limit"));
        }
        self.storage
            .set_item(&self.key, &encoded)
            .map_err(|_| JsError::new("Could not save the signed membership ledger"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointBootstrap {
    pub(crate) anchor: NetworkAnchor,
    pub(crate) retained: RetainedCheckpointState,
    pub(crate) enrollment_floor: Option<SnapshotRank>,
}

impl CheckpointBootstrap {
    pub(crate) fn parse(json: &str) -> Result<Self, JsError> {
        if json.len() > MAX_CHECKPOINT_ENCODED {
            return Err(JsError::new("Checkpoint bootstrap exceeds its size limit"));
        }
        serde_json::from_str(json).map_err(|_| JsError::new("Invalid checkpoint bootstrap"))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredCheckpoint {
    pub(crate) retained: RetainedCheckpointState,
    pub(crate) enrollment_floor: Option<SnapshotRank>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEnvelope {
    payload: StoredCheckpoint,
    mac: [u8; 32],
}

pub(crate) struct CheckpointStore {
    lock: MembershipStore,
    crypto: BrowserSubtleCrypto,
    key: JsValue,
}

impl CheckpointStore {
    pub(crate) async fn close(self) -> Result<(), JsError> {
        self.lock.close().await
    }

    pub(crate) async fn open(
        network: &str,
        local_peer: &str,
        secret: &[u8],
    ) -> Result<Self, JsError> {
        if !(32..=MAX_CAPABILITY_BYTES).contains(&secret.len()) {
            return Err(JsError::new("Invalid checkpoint capability length"));
        }
        let lock = MembershipStore::lock(network, local_peer).await?;
        if !lock.load()?.is_empty() {
            return Err(JsError::new(
                "Saved legacy membership requires explicit migration",
            ));
        }
        let unavailable = || JsError::new("Browser checkpoint storage requires Web Crypto");
        let window = web_sys::window().ok_or_else(unavailable)?;
        let crypto = Reflect::get(window.as_ref(), &JsValue::from_str("crypto"))
            .map_err(|_| unavailable())?;
        let subtle =
            Reflect::get(&crypto, &JsValue::from_str("subtle")).map_err(|_| unavailable())?;
        if subtle.is_null() || subtle.is_undefined() {
            return Err(unavailable());
        }
        let crypto: BrowserSubtleCrypto = subtle.unchecked_into();
        let algorithm = Object::new();
        for (name, value) in [("name", "HMAC"), ("hash", "SHA-256")] {
            Reflect::set(&algorithm, &name.into(), &value.into()).map_err(|_| unavailable())?;
        }
        let usages = Array::of2(&"sign".into(), &"verify".into());
        let key = JsFuture::from(
            crypto
                .import_key("raw", &Uint8Array::from(secret), &algorithm, false, &usages)
                .map_err(|_| unavailable())?,
        )
        .await
        .map_err(|_| unavailable())?;
        Ok(Self { lock, crypto, key })
    }

    pub(crate) async fn load(&self) -> Result<Option<StoredCheckpoint>, JsError> {
        let Some(json) = self.lock.read(&self.lock.checkpoint_key)? else {
            return Ok(None);
        };
        let invalid = || JsError::new("Saved checkpoint state failed authentication");
        if json.len() > MAX_CHECKPOINT_ENCODED {
            return Err(invalid());
        }
        let CheckpointEnvelope { payload, mac } =
            serde_json::from_str(&json).map_err(|_| invalid())?;
        let message = self.message(&payload)?;
        let verified = JsFuture::from(
            self.crypto
                .verify(
                    "HMAC",
                    &self.key,
                    &Uint8Array::from(mac.as_slice()),
                    &message,
                )
                .map_err(|_| invalid())?,
        )
        .await
        .map_err(|_| invalid())?;
        if verified.as_bool() != Some(true) {
            return Err(invalid());
        }
        Ok(Some(payload))
    }

    pub(crate) async fn save(&self, payload: StoredCheckpoint) -> Result<(), JsError> {
        let failed = || JsError::new("Could not save authenticated checkpoint state");
        let message = self.message(&payload)?;
        let signature = JsFuture::from(
            self.crypto
                .sign("HMAC", &self.key, &message)
                .map_err(|_| failed())?,
        )
        .await
        .map_err(|_| failed())?;
        let mac = Uint8Array::new(&signature)
            .to_vec()
            .try_into()
            .map_err(|_| failed())?;
        let json = serde_json::to_string(&CheckpointEnvelope { payload, mac })?;
        if json.len() > MAX_CHECKPOINT_ENCODED {
            return Err(JsError::new("Checkpoint state exceeds its storage limit"));
        }
        // One atomic Web Storage replacement: the checkpoint and pending floor
        // cannot be torn or updated independently. Never store the raw secret.
        self.lock
            .storage
            .set_item(&self.lock.checkpoint_key, &json)
            .map_err(|_| failed())
    }

    fn message(&self, payload: &StoredCheckpoint) -> Result<Uint8Array, JsError> {
        let mut bytes = CHECKPOINT_STORE_DOMAIN.to_vec();
        bytes.extend_from_slice(self.lock.checkpoint_key.as_bytes());
        bytes.push(b'\n');
        serde_json::to_writer(&mut bytes, payload)?;
        Ok(Uint8Array::from(bytes.as_slice()))
    }
}
