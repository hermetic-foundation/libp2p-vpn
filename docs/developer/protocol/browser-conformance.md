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
| LAN code-only enrollment | The companion returned a LAN hint from an empty request. Chromium completed PAKE and native approval without making a public locator request. |
| Explicit relay fallback | Chromium passed relay-only, direct failure with relay fallback, and alternate direct preference. A direct capability rejection did not trigger a circuit. |
| Native-initiated circuit | A native peer dialed the browser's confirmed reservation and exchanged authenticated control and IP traffic. The browser did not dial the member first. |
| Browser-to-browser circuit | Two Chromium peers exchanged VPN capabilities and IP packet acknowledgments in both directions over a real relay. This did not require generic WebRTC signaling. |
| Shared incoming circuit reservation (SDK) | Chromium handled two authorized legacy members with distinct MTUs. A local close left the other circuit usable. Prompt detection of remote graceful close was not verified. |
| Scoped companion gateway | On a separate veth path, Chromium tried a dead direct hint, then authenticated over the Linux companion's circuit lease. Lease release freed the loopback port. |
| Cross-family relay | IPv4-only Chromium reached an IPv6-only native member over one dual-stack relay. The companion discovered the relay and sent no fixture traffic over its alternate interface. |
| Relay publication | Chromium published a signed, confirmed reservation with an explicit permit. A separate companion found it on a cooperating DHT and its native member connected. |
| Path recovery | Following loss of its WebRTC connection, Chromium cleared transport authority and authenticated the same peer at a replacement endpoint. Both sides exchanged capabilities again. |
| Preferred return | An authenticated direct connection passed an exact-path probe before taking over from the circuit. A failed or superseded candidate preserved the circuit. |
| Signed legacy membership | A native peer sent an eleven-record snapshot in two pages. The browser validated and merged it, then served the resulting snapshot back. |
| Durable legacy revocation | A new browser peer opened the original config after revocation and refused to dial. A second live instance was denied the ledger lock. |
| Code pairing v2 | Production WASM waited for native approval and connected using the approved legacy config. It also activated a checkpoint grant only after authenticated snapshot sync. The app's code-only flow passed against a controlled lookup response. |
| Pairing compatibility | Explicit scoped v1 worked with the native daemon. Legacy and checkpoint v2 approval and activation both worked over a real circuit. |
| Signed file invitations | A detached legacy founder or rooted delegate reviewed a request in Chromium. The browser released a native-compatible signed response only after explicit approval and a successful ledger save. |
| Explicit code invitations | Chromium enrolled a pre-pinned joiner in a new or existing rooted legacy network. After approval both browser peers used the original relay reservation and exchanged IP traffic. |
| Companion pairing relay | Chromium enrolled over a real companion lease, handed it off after approval, fetched HTTP over the new gateway, and closed the gateway on disconnect. |
| Native v2 bootstrap relay | An isolated Linux joiner followed the DHT's exact reserved-provider hint over its default link. Stale and secondary-link paths were rejected. |
| Checkpoint credentials | The app reopened the same encrypted identity in Chromium after closing the prior session. The native peer authenticated it again without another approval. |
| Checkpoint revocation | On a LAN path, native removal reached Chromium. The browser stored the exclusion before acknowledging it and rejected the original credential file after reload. |
| Checkpoint roster changes | Chromium durably installed and acknowledged a native member upsert and another member's removal before its own revocation. |
| Demand lifecycle | On an incoming, maintained relay the foreground browser negotiated Demand and exchanged real Idle and Wake messages with a native fixture. Hidden and outgoing cases stayed in legacy mode. |
| Negotiated IPv4 MTU | Segmented HTTP worked at browser MTUs of 1500 and 1200 against native MTU 1400. The browser accepted a probe at the negotiated limit and returned `PacketTooLarge` one byte over it. |
| Packet authorization | A native test peer and the browser both sent typed `UnauthorizedSource` rejections. The browser also sent `UnauthorizedDestination` for a packet not addressed to it. |
| Reliable-stream replay | The same IP frame was accepted twice. A nonempty keepalive returned `UnexpectedPayload`; a repeated valid keepalive returned `Replay`. |
| Optional service status | The browser echoed the request nonce and reported the negotiated stream path MTU. A wrong-scope request returned `MembershipMismatch`. |
| Portable byte vectors | Three tests passed. These are reference-codec and derivation tests, not browser transport tests. |

The runs used Chromium 156.0.8078.73 in isolated Linux user and network
namespaces. The production app used no test hooks.
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
| Discoverable mesh | LAN, default-network DHT, eligible companion relay fallback, and preferred return work for a selected member. The SDK can admit a second authorized legacy member on an incoming relay reservation; the app does not expose it yet. |
| Managed membership | Signed legacy snapshots, checkpoint mutations, durable revocation, and enrollment as a joiner work with the native peer. Detached legacy issuers can create file and code invitations. Code requires a pinned joiner and an explicit relay. |
| Datagram and service extensions | No owned UDP or QUIC packet plane. The browser can answer authorized service-status requests while its swarm is running. |
| Demand lifecycle | Negotiated only on a maintained incoming circuit while the foreground browser is polled. No background wake or standalone direct-path guarantee. |
| Host behavior | Only the companion can verify physical-interface binding for the sockets it owns. Browser WebRTC is browser-managed. DNS is in-app only; no system TUN or DNS. |

The standalone page does not perform public infrastructure traffic. In
companion mode, native discovery enforces the [local egress rules](discovery.md)
before returning hints. The browser authenticates the member independently.

## Remaining Acceptance Checks

| Work | Exit condition |
| --- | --- |
| Concurrent member sessions in the app | The served app exposes the two-member incoming relay profile and shows the surviving member after the other connection closes. |
| Checkpoint-issued invitation | The browser commits the admission before releasing approval. A live joiner reaches the signed enrollment floor and exchanges authorized IP traffic. |
| Public code locator | A native joiner uses only the code to discover the browser, approves over the authenticated relay path, and sends VPN traffic. Automatic public infrastructure traffic stays on the selected default network. |
