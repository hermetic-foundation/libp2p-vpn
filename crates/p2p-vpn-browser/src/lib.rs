//! The browser host uses the same p2p-vpn codecs and authorization core as native peers.
#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
mod browser_pairing;
#[cfg(target_arch = "wasm32")]
mod membership_store;
pub mod net;
#[cfg(all(target_arch = "wasm32", feature = "relay-client"))]
mod relay;
#[cfg(target_arch = "wasm32")]
mod pairing_joiner;
#[cfg(target_arch = "wasm32")]
pub use browser::BrowserVpn;
#[cfg(target_arch = "wasm32")]
pub use browser_pairing::BrowserPairing;
