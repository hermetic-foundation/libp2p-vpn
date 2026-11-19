//! Per-origin storage for signed records only. The lock spans the active peer's lifetime.
use futures::{FutureExt as _, channel::oneshot};
use js_sys::{Function, Object, Promise, Reflect};
use p2p_vpn::membership::{
    MAX_MEMBERSHIP_RECORD_ENCODED_LEN, MAX_MEMBERSHIP_RECORDS, SignedMembershipRecord,
};
use wasm_bindgen::{JsCast as _, prelude::*};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::Storage;

const MAX_ENCODED: usize = MAX_MEMBERSHIP_RECORDS * (MAX_MEMBERSHIP_RECORD_ENCODED_LEN + 1) + 2;

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
}

pub(crate) struct MembershipStore {
    storage: Storage,
    key: String,
    // Dropping the sender resolves the Promise that holds the Web Lock.
    _hold: oneshot::Sender<()>,
}

impl MembershipStore {
    pub(crate) async fn open(network: &str, local_peer: &str) -> Result<Self, JsError> {
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
        let key = format!(
            "p2p-vpn:legacy-membership:1:{}",
            serde_json::to_string(&[network, local_peer])?
        );
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
        let request = JsFuture::from(
            locks
                .request_lock(&key, &options, callback.as_ref().unchecked_ref())
                .map_err(|_| unavailable())?,
        )
        .fuse();
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
            _hold: hold,
        })
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
