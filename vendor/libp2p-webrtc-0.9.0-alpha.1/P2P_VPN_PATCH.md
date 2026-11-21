# Local WebRTC Direct r2 compatibility patch

Base: crates.io `libp2p-webrtc` 0.9.0-alpha.1, retained for the repository's
libp2p 0.56 / libp2p-core 0.43 dependency graph. Original license is in LICENSE.

The listener now reads both fragments from STUN USERNAME. Before allocating
an inbound peer connection it validates the ICE character set and lengths,
recognizes only `libp2p+webrtc+v1/` and `libp2p+webrtc+v2/`, and rejects malformed
or unknown versions. v2 reconstructs the client's separate fragment/password
and uses the encoded server fragment as the listener's local ICE credentials.
The v1 path retains equal-credential behavior. Noise identity authentication,
certificate-bound prologues, and data channel framing are unchanged.

Native outbound dials still default to v1. The companion's WebRTC entrance
probe opts into v2 so a legacy-only relay is not mistaken for one Chromium
can use.

The UDP receive loop also consumes recoverable reset/timeout errors and polls
again to rearm its receive waker. Without this, a Windows WSAECONNRESET after a
browser disconnect can leave the shared listener asleep for subsequent peers.

Reference: https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md
revision r2 (2026-06-20). `tests/webrtc_ice.rs` exercises the actual parser source.
