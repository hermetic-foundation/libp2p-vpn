//! The browser host uses the same p2p-vpn codecs and authorization core as native peers.
#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
mod browser_file_inviter;
#[cfg(target_arch = "wasm32")]
mod browser_pairing;
#[cfg(any(target_arch = "wasm32", test))]
mod checkpoint;
#[cfg(target_arch = "wasm32")]
mod checkpoint_bundle;
#[cfg(all(target_arch = "wasm32", feature = "relay-client"))]
mod code_inviter;
#[cfg(target_arch = "wasm32")]
mod membership_store;
pub mod net;
#[cfg(target_arch = "wasm32")]
mod pairing_joiner;
#[cfg(all(target_arch = "wasm32", feature = "relay-client"))]
mod relay;
#[cfg(target_arch = "wasm32")]
pub use browser::BrowserVpn;
#[cfg(target_arch = "wasm32")]
pub use browser_file_inviter::BrowserFileInviter;
#[cfg(target_arch = "wasm32")]
pub use browser_pairing::{
    BrowserCheckpointActivation, BrowserOfflineEnrollment, BrowserPairing,
    CheckpointActivationInputs, pairing_code_v1_scoped_locator, pairing_code_v2_global_locator,
};
#[cfg(all(target_arch = "wasm32", feature = "relay-client"))]
pub use code_inviter::BrowserCodeInviter;
