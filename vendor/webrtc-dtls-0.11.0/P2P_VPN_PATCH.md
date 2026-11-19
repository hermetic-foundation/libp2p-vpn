# Supported-group negotiation backport

Base: crates.io `webrtc-dtls` 0.11.0.

The server selects the first *supported* offered group (P-256, P-384, X25519),
skipping unknown/GREASE entries. If no group is supported it fails closed with
the existing insufficient-security alert. Cipher suites, certificate validation,
signature checks and the supported group set are unchanged.

This follows the supported-curve selection fix in upstream WebRTC 0.13.0,
with an explicit failure when the intersection is empty:
https://github.com/webrtc-rs/webrtc/blob/v0.13.0/dtls/src/flight/flight0.rs
https://github.com/webrtc-rs/webrtc/issues/417

The browser crate's DTLS regression test calls the same selector used in the
server handshake. The end-to-end qualification requires a real current browser.
