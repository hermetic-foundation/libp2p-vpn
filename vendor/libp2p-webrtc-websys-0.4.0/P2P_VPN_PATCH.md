# Local WebRTC Direct r2 browser dialer

Base: crates.io `libp2p-webrtc-websys` 0.4.0, compatible with libp2p 0.56.
Original license is in LICENSE.

The browser sets its generated local offer without credential munging, reads
the actual ICE password back from localDescription, validates it, and encodes
it in the synthetic remote answer's `libp2p+webrtc+v2/` fragment/password.
Certificate hash verification and the Noise identity handshake are unchanged.
Dialing therefore requires a native listener supporting WebRTC Direct r2.

Dropping the browser peer-connection wrapper explicitly closes the underlying
RTCPeerConnection, including when an outbound handshake is cancelled.
The final shared data-channel owner detaches DOM event handlers before releasing
their WASM closures, and peer teardown detaches `ondatachannel` before closing.
Connection state events wake the muxer so terminal RTC failure reaches the
swarm even when it is not reading a data channel.

Reference: https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md
