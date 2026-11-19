# Browser Conformance Audit

Scope: the browser and native runtime at `b9762435159d`, compared with the
[protocol draft](README.md). This is an interoperability check against the
same reference implementation, not an independent implementation result.

## Live Evidence

| Check | Result |
| --- | --- |
| WebRTC Direct r2 | Passed in Chromium 156.0.8078.73. Initial dial and reconnect preserved the original browser ICE credentials. |
| Static peer and scope | Passed. The app rejected an unauthorized peer, a wrong network name, and a mismatched membership tag before overlay HTTP. |
| Control and packet exchange | Passed on a normal Linux daemon and real TUN. The app received two fresh HTTP responses across disconnect/reconnect. |
| Browser as packet sender | The native fixture rejected a spoofed source as `UnauthorizedSource`; the native drop counter incremented. This does not verify the browser's inbound replies. |
| Portable byte vectors | Three tests passed. These are reference-codec and derivation tests, not browser transport tests. |

The runs used isolated Linux user/network namespaces with a single test
underlay. The production app used no test hooks. The separate r2 fixture
enabled them to send the spoofed-source frame.

Reuse the [normal daemon and fixture commands](../browser-wasm-validation.md).
Run the vector check with `cargo test --locked --test protocol_spec`.

## Static Stream Differences

These are source-audit findings. The successful HTTP exchange did not exercise
these failure paths in the browser receiver.

| Requirement | Browser behavior |
| --- | --- |
| [Typed packet rejection](stream.md#packet-response) | The browser sends `MalformedPacket` for every receive-side failure, even when the shared forwarder distinguishes unauthorized source, destination, or replay. |
| [Reliable-stream sequence semantics](stream.md#packet-stream) | The browser calls `accept_inbound_packet`, which applies the overlay replay window to IP frames. The native stream receiver calls `accept_inbound_stream_packet`, which does not. |
| [Typed control rejection](stream.md#control-stream) | A failed inbound capability check returns a JS error before `send_response`, instead of sending `CapabilitiesRejected` with the reason. The local UI rejection still works. |
| Effective path MTU | The browser requires 1280 in its config and rejects a remote MTU below 1280. It does not support the native range of MTUs. |

The browser shares the control and packet codecs, the forwarding core, and
bounded queues. The differences above arise in how its event loop invokes
those components. Static stream happy-path interoperability is verified;
full static-stream conformance is not.

## Other Profiles

| Profile or feature | Current browser status |
| --- | --- |
| Discoverable mesh | Not implemented. Dials one pinned endpoint; no LAN discovery, public DHT, relay fallback, or automatic preferred-path return. |
| Managed membership | Partial. Uses configured peers and can merge inline legacy records; no pairing, paged membership convergence, or cooperative checkpoints. |
| Datagram and service extensions | Not implemented. No owned UDP/QUIC datagram negotiation or service status handler. |
| Demand lifecycle | Not implemented. The foreground app does not participate in the negotiated idle/wake lifecycle. |
| Host behavior | No strict physical-interface binding, system TUN, or system DNS integration. The one-underlay tests do not test default-network preference. |

Reuse native stream admission and response policy in the portable core before
adding more browser protocol adapters. Verify both directions of the typed
rejection and sequence tests before claiming static-stream conformance.
