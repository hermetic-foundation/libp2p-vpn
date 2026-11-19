//! Password-protected checkpoint credentials for explicit local backup and import.
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use p2p_vpn::{config::Config, membership::checkpoint::MAX_SNAPSHOT_OFFER_BYTES};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast as _, prelude::*};
use wasm_bindgen_futures::JsFuture;

use crate::membership_store::CheckpointBootstrap;

const VERSION: u8 = 1;
const PBKDF2_ITERATIONS: u32 = 600_000;
const DOMAIN: &[u8] = b"p2p-vpn browser checkpoint credential bundle v1";
const MAX_PLAINTEXT: usize = MAX_SNAPSHOT_OFFER_BYTES + 256 * 1024;
const GCM_TAG_LEN: usize = 16;
const MAX_JSON: usize = 4 * (MAX_PLAINTEXT + GCM_TAG_LEN) + 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    pub(crate) config: Config,
    pub(crate) bootstrap: CheckpointBootstrap,
    pub(crate) capability_secret: Vec<u8>,
    pub(crate) direct_addresses: Vec<String>,
    pub(crate) relay_address: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
extern "C" {
    type SubtleCrypto;

    #[wasm_bindgen(method, catch, js_name = importKey)]
    fn import_key(
        this: &SubtleCrypto,
        format: &str,
        bytes: &Uint8Array,
        algorithm: &str,
        extractable: bool,
        usages: &Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = deriveKey)]
    fn derive_key(
        this: &SubtleCrypto,
        algorithm: &Object,
        key: &JsValue,
        derived: &Object,
        extractable: bool,
        usages: &Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn encrypt(
        this: &SubtleCrypto,
        algorithm: &Object,
        key: &JsValue,
        bytes: &Uint8Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn decrypt(
        this: &SubtleCrypto,
        algorithm: &Object,
        key: &JsValue,
        bytes: &Uint8Array,
    ) -> Result<Promise, JsValue>;
}

pub(crate) async fn seal(credentials: &Credentials, passphrase: &str) -> Result<String, JsError> {
    let plaintext = serde_json::to_vec(credentials).map_err(|_| invalid())?;
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(JsError::new(
            "Checkpoint credentials exceed the bundle size limit",
        ));
    }
    let mut salt = [0; 16];
    let mut nonce = [0; 12];
    OsRng
        .try_fill_bytes(&mut salt)
        .and_then(|_| OsRng.try_fill_bytes(&mut nonce))
        .map_err(|_| JsError::new("Could not generate checkpoint bundle randomness"))?;
    let crypto = crypto()?;
    let key = derive(&crypto, passphrase, &salt, "encrypt").await?;
    let input = Uint8Array::from(plaintext.as_slice());
    let ciphertext = bytes(await_promise(crypto.encrypt(&cipher(&nonce)?, &key, &input)).await?);
    serde_json::to_string(&Envelope {
        version: VERSION,
        salt,
        nonce,
        ciphertext,
    })
    .map_err(|_| invalid())
}

pub(crate) async fn unseal(json: &str, passphrase: &str) -> Result<Credentials, JsError> {
    if json.len() > MAX_JSON {
        return Err(JsError::new(
            "Checkpoint credential bundle exceeds its size limit",
        ));
    }
    let envelope: Envelope = serde_json::from_str(json).map_err(|_| invalid())?;
    if envelope.version != VERSION
        || !(GCM_TAG_LEN..=MAX_PLAINTEXT + GCM_TAG_LEN).contains(&envelope.ciphertext.len())
    {
        return Err(invalid());
    }
    let crypto = crypto()?;
    let key = derive(&crypto, passphrase, &envelope.salt, "decrypt").await?;
    let input = Uint8Array::from(envelope.ciphertext.as_slice());
    let plaintext =
        bytes(await_promise(crypto.decrypt(&cipher(&envelope.nonce)?, &key, &input)).await?);
    serde_json::from_slice(&plaintext).map_err(|_| invalid())
}

fn invalid() -> JsError {
    JsError::new("Checkpoint credential bundle or passphrase is invalid")
}

fn crypto() -> Result<SubtleCrypto, JsError> {
    let unavailable = || JsError::new("Checkpoint credential bundles require Web Crypto");
    let window = web_sys::window().ok_or_else(unavailable)?;
    let crypto = Reflect::get(window.as_ref(), &"crypto".into()).map_err(|_| unavailable())?;
    let subtle = Reflect::get(&crypto, &"subtle".into()).map_err(|_| unavailable())?;
    if subtle.is_null() || subtle.is_undefined() {
        return Err(unavailable());
    }
    Ok(subtle.unchecked_into())
}

fn dictionary(fields: &[(&str, JsValue)]) -> Result<Object, JsError> {
    let result = Object::new();
    for (name, value) in fields {
        Reflect::set(&result, &(*name).into(), value).map_err(|_| invalid())?;
    }
    Ok(result)
}

async fn await_promise(value: Result<Promise, JsValue>) -> Result<JsValue, JsError> {
    JsFuture::from(value.map_err(|_| invalid())?)
        .await
        .map_err(|_| invalid())
}

fn bytes(value: JsValue) -> Vec<u8> {
    Uint8Array::new(&value).to_vec()
}

async fn derive(
    crypto: &SubtleCrypto,
    passphrase: &str,
    salt: &[u8; 16],
    usage: &str,
) -> Result<JsValue, JsError> {
    if passphrase.len() > 1024 || passphrase.chars().count() < 12 {
        return Err(JsError::new(
            "Use a checkpoint bundle passphrase of at least 12 characters",
        ));
    }
    let input = Uint8Array::from(passphrase.as_bytes());
    let password = await_promise(crypto.import_key(
        "raw",
        &input,
        "PBKDF2",
        false,
        &Array::of1(&"deriveKey".into()),
    ))
    .await?;
    let algorithm = dictionary(&[
        ("name", "PBKDF2".into()),
        ("salt", Uint8Array::from(salt.as_slice()).into()),
        ("iterations", PBKDF2_ITERATIONS.into()),
        ("hash", "SHA-256".into()),
    ])?;
    let derived = dictionary(&[("name", "AES-GCM".into()), ("length", 256.into())])?;
    await_promise(crypto.derive_key(
        &algorithm,
        &password,
        &derived,
        false,
        &Array::of1(&usage.into()),
    ))
    .await
}

fn cipher(nonce: &[u8; 12]) -> Result<Object, JsError> {
    dictionary(&[
        ("name", "AES-GCM".into()),
        ("iv", Uint8Array::from(nonce.as_slice()).into()),
        ("additionalData", Uint8Array::from(DOMAIN).into()),
    ])
}
