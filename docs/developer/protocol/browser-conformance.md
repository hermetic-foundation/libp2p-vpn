# Browser Conformance Audit

Scope: the foreground WebRTC stream peer on `browser-wasm`, compared
with the [protocol draft](README.md). This is browser/native interoperability
within one reference codebase, not independent implementation evidence.

## Live Evidence

| Check | Result |
| --- | --- |
| WebRTC Direct r2 | Passed in Chromium 156.0.8078.73. Initial dial and reconnect preserved the original browser ICE credentials. |
| Static peer and scope | The app rejected an unauthorized peer, a wrong network name, and a mismatched membership tag before overlay HTTP. A native sender also received the browser's typed `CapabilitiesRejected(WrongNetwork)` reply. |
| Control and packet exchange | The app received fresh HTTP responses across disconnect and reconnect on a Linux daemon with a real TUN. |
| IPv6 and overlay names | The production app fetched over IPv6 through a Linux TUN and resolved an authorized overlay hostname for an IPv4 fetch. |
| Alternate member endpoints | The browser connected with an unavailable alternate endpoint and rejected endpoint lists containing a different peer ID. |
| Linux LAN discovery | Chromium and the native daemon used opposite ends of an isolated veth. The browser authenticated the member after mDNS lookup through the companion, with no remote address in its config. |
| Explicit relay fallback | Chromium passed relay-only, direct failure with relay fallback, and alternate direct preference. A direct capability rejection did not trigger a circuit. |
| Signed legacy membership | A native peer sent an eleven-record snapshot in two pages. The browser validated and merged it, then served the resulting snapshot back. |
| Durable legacy revocation | A new browser peer opened the original config after revocation and refused to dial. A second live instance was denied the ledger lock. |
| Code pairing v2 | Production WASM waited for native approval and connected using the approved legacy config. It also activated a checkpoint grant only after authenticated snapshot sync. The app's code-only flow passed against a controlled lookup response. |
| Negotiated IPv4 MTU | Segmented HTTP worked at browser MTUs of 1500 and 1200 against native MTU 1400. The browser accepted a probe at the negotiated limit and returned `PacketTooLarge` one byte over it. |
| Packet authorization | A native test peer and the browser both sent typed `UnauthorizedSource` rejections. The browser also sent `UnauthorizedDestination` for a packet not addressed to it. |
| Reliable-stream replay | The same IP frame was accepted twice. A nonempty keepalive returned `UnexpectedPayload`; a repeated valid keepalive returned `Replay`. |
| Optional service status | The browser echoed the request nonce and reported the negotiated stream path MTU. A wrong-scope request returned `MembershipMismatch`. |
| Portable byte vectors | Three tests passed. These are reference-codec and derivation tests, not browser transport tests. |

The runs used Chromium 156.0.8078.73 in isolated Linux user and network
namespaces with one test underlay. The production app used no test hooks.
The separate r2 and inbound wire fixtures used a test-hooks package.

Use the [isolated Linux test harness](../browser-wasm-validation.md#repeatable-linux-tests).
Run the vector check with `cargo test --locked --test protocol_spec`.

## Shared Implementation

The native and browser adapters use the same capability validation, frame
admission, routing authority, packet rejection reasons, and wire codecs.
The browser uses its own in-process IP device, driven during operations,
instead of native TUN I/O.

## Other Profiles

| Profile or feature | Current browser status |
| --- | --- |
| Discoverable mesh | Linux companion provides LAN lookup and default-network-only public DHT. The browser can connect to one selected member per session. Automatic public relay reservation, relay discovery and preferred-path return still need integrated qualification. |
| Managed membership | Signed legacy snapshots, durable revocation, v2 enrollment and checkpoint activation work against the reference peer. Real LAN and public enrollment lookup still need integrated qualification. |
| Datagram and service extensions | No owned UDP or QUIC packet plane. The browser can answer authorized service-status requests while its swarm is running. |
| Demand lifecycle | Not implemented. The foreground app does not participate in the negotiated idle/wake lifecycle. |
| Host behavior | Only the companion can verify physical-interface binding for the sockets it owns. Browser WebRTC is browser-managed. DNS is in-app only; no system TUN or DNS. |

The standalone page does not perform public infrastructure traffic. In
companion mode, native discovery enforces the [local egress rules](discovery.md)
before returning hints. The browser authenticates the member independently.
