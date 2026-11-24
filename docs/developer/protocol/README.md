# p2p-vpn Protocol Specification

**Working draft.** This specifies the deployed v1 overlay and its extensions.
It is language-independent and does not require the reference Rust code.
The [coverage table](#coverage) identifies sections not yet sufficient on their own.

## Implementer Map

| Section | Defines |
| --- | --- |
| [Stream Wire](stream.md) | Authenticated connection setup, control exchange, packet framing, and rejection codes. |
| [Discovery And Paths](discovery.md) | LAN discovery, public DHT keys and records, circuit relay, recovery, and default-network policy. |
| [Identity And Membership](membership.md) | Peer IDs, addresses, signed records, route authority, revocation, sync, and DNS. |
| [Cooperative Checkpoints](checkpoints.md) | Canonical rosters, key derivation, authenticated transfers, mutations, and grants. |
| [Enrollment](enrollment.md) | Offline pairing, pair-by-code, versions, discovery, approval, and activation. |
| [Datagrams](datagrams.md) | Owned UDP and QUIC packet-plane negotiation, framing, keys, and replay boundaries. |
| [Demand Lifecycle](../demand-lifecycle-wire.md) | Optional authenticated idle and wake coordination. |
| [Path Policy](../shared-path-policy.md) | Local default-route enforcement and authenticated handoff across adapters. |
| [Preferred-Interface Handoff](preferred-handoff.md) | Optional peer-initiated replacement, exact physical ownership, and payload-gated retirement. |
| [Browser Conformance Audit](browser-conformance.md) | Tested interoperability and browser deviations from the draft. |

The underlay uses existing [libp2p specifications](https://github.com/libp2p/specs),
including peer identity, secure transports, stream multiplexing, Identify,
mDNS, Kademlia, Circuit Relay v2, and DCUtR. WebRTC Direct uses the
[libp2p r2 handshake](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md).

## Conformance

| Profile | Required |
| --- | --- |
| Static stream peer | A shared authenticated libp2p transport, core control and packet streams, static membership, route enforcement, bounded I/O. |
| Discoverable mesh peer | Static stream peer requirements plus eligible LAN discovery, public rendezvous, relay fallback and direct recovery, with the local egress rules. |
| Managed membership peer | The applicable authority model, enrollment, durable revocation, and authenticated membership sync. List support for legacy and checkpoints separately. |
| Datagram peer | A stream peer plus the negotiated UDP and/or bound QUIC profile. Keep compatible stream fallback. |
| Full client | Discoverable mesh and managed membership, plus explicit support declarations for transport, datagram, lifecycle, DNS, and host capabilities. |

Declare supported profiles and extensions. Supporting one secure transport does
not imply that all other peers can dial it. Supporting WebRTC Direct does not
imply generic browser-to-browser signaling or a native QUIC socket.

An implementation MUST NOT advertise a capability it cannot perform. Absence
of an optional capability selects compatible behavior, not an authorization
bypass. A full-client claim requires the corresponding interoperability tests.

## What To Share

| Layer | Reuse |
| --- | --- |
| Protocol and policy core | Codecs, identity, authority, route validation, discovery records, scheduling, pairing, queueing, handoff decisions. |
| Host adapters | Sockets, route and link notifications, TUN or in-app IP I/O, clock, storage, user approval, DNS integration. |

The adapter reports what it can enforce. A browser tab does not claim strict
default-interface policy or host-wide routing simply because it speaks the
overlay protocol. These limits do not justify separate formats or trust rules.

## Invariants

- Authenticate a transport peer before associating it with an overlay identity.
- Never treat a network name, DHT result, relay reservation, or route advertisement as authority.
- Recheck current authority before sending, accepting, or promoting a path.
- Do not permit denied or expired traffic by retrying it through another transport.
- Bound untrusted decoding, pending work, cached data, and retransmission.
- Keep wire version changes separate from platform implementation or package versions.

## Coverage

| Area | Evidence and outstanding specification work |
| --- | --- |
| Static stream profile | Byte layouts and examples are specified. Validate with an independent implementation exchanging live traffic. |
| LAN and public discovery | Keys, provenance, signed address envelope, and recovery are described. Add signed vectors and independent default-network and relay tests. |
| Enrollment | Framing, messages, signing fields and key derivations are specified. Independent SPAKE2 and signed admission transcript fixtures remain open. |
| Dynamic membership | Legacy and checkpoint transcripts and convergence described; independently produced signed roster, mutation and sync vectors remain open. |
| Owned datagrams | Frame and handshake formats described; complete binding and path-validation vectors remain open. |
| DNS and lifecycle | Existing protocol sections referenced. Add cross-implementation coverage before claiming parity. |

The [byte vectors](vectors.json) are implementation-neutral inputs and
expected outputs. The reference checks them with
`cargo test --locked --test protocol_spec`. This is a codec/derivation
gate, not yet an independent client interoperability result.

The fixture code and checkpoint secret are fixed test inputs. Never use them
to enroll peers or protect a real network.

Keep the current wire identifiers until an incompatible change is deliberately
versioned. Do not start a browser-specific redesign to fill a specification gap.
