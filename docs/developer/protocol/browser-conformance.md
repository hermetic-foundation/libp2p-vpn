# Browser Conformance Audit

Scope: the foreground, static IPv4 stream peer on `browser-wasm`, compared
with the [protocol draft](README.md). This is browser/native interoperability
within one reference codebase, not independent implementation evidence.

## Live Evidence

| Check | Result |
| --- | --- |
| WebRTC Direct r2 | Passed in Chromium 156.0.8078.73. Initial dial and reconnect preserved the original browser ICE credentials. |
| Static peer and scope | The app rejected an unauthorized peer, a wrong network name, and a mismatched membership tag before overlay HTTP. A native sender also received the browser's typed `CapabilitiesRejected(WrongNetwork)` reply. |
| Control and packet exchange | The app received fresh HTTP responses across disconnect and reconnect on a Linux daemon with a real TUN. |
| Negotiated IPv4 MTU | Segmented HTTP worked at browser MTUs of 1500 and 1200 against native MTU 1400. The browser accepted a probe at the negotiated limit and returned `PacketTooLarge` one byte over it. |
| Packet authorization | A native test peer and the browser both sent typed `UnauthorizedSource` rejections. The browser also sent `UnauthorizedDestination` for a packet not addressed to it. |
| Reliable-stream replay | The same IP frame was accepted twice. A nonempty keepalive returned `UnexpectedPayload`; a repeated valid keepalive returned `Replay`. |
| Optional service status | The browser echoed the request nonce and reported the negotiated stream path MTU. A wrong-scope request returned `MembershipMismatch`. |
| Portable byte vectors | Three tests passed. These are reference-codec and derivation tests, not browser transport tests. |

The runs used Chromium 156.0.8078.73 in isolated Linux user and network
namespaces with one test underlay. The production app used no test hooks.
The separate r2 and inbound wire fixtures used a test-hooks package.

Reuse the [normal daemon and inbound wire test commands](../browser-wasm-validation.md).
Run the vector check with `cargo test --locked --test protocol_spec`.

## Shared Implementation

The native and browser adapters use the same capability validation, frame
admission, routing authority, packet rejection reasons, and wire codecs.
The browser uses its own in-process IPv4 device, driven during operations,
instead of native TUN I/O.

## Other Profiles

| Profile or feature | Current browser status |
| --- | --- |
| Discoverable mesh | Not implemented. Dials one pinned endpoint; no LAN discovery, public DHT, relay fallback, or automatic preferred-path return. |
| Managed membership | Partial. Uses configured peers and can merge inline legacy records; no pairing, paged membership convergence, or cooperative checkpoints. |
| Datagram and service extensions | No owned UDP or QUIC packet plane. The browser can answer authorized service-status requests while its swarm is running. |
| Demand lifecycle | Not implemented. The foreground app does not participate in the negotiated idle/wake lifecycle. |
| Host behavior | No strict physical-interface binding, system TUN, or system DNS integration. The one-underlay tests do not test default-network preference. |

Public discovery must remain off until a browser-capable transport can meet
the [local egress rules](discovery.md). Static member dials do not imply that
automatic public dials are safe on the same adapter.
