//! The browser host uses the same p2p-vpn codecs and authorization core as native peers.
#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
mod membership_store;
pub mod net;
#[cfg(target_arch = "wasm32")]
pub use browser::BrowserVpn;
