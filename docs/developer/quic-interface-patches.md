# QUIC Interface Selection Patches

## Purpose

Accepted QUIC connections share a listener socket. Source-address selection alone
does not constrain their physical egress. Rebinding or closing that socket would
also affect unrelated peers.

The local patches add per-connection transmit-interface ownership without
changing the shared socket's receive filtering or the QUIC wire protocol.

## Provenance

| Package | Base | Local location |
| --- | --- | --- |
| Quinn | crates.io `quinn` 0.11.11 | `vendor/quinn-0.11.11` |
| UDP backend | crates.io `quinn-udp` 0.5.15 | `vendor/quinn-udp-0.5.15` |

- Original MIT/Apache licenses and upstream source metadata are retained.
- Workspace Cargo patches select these copies; dependency versions are unchanged.
- Linux and both Android Nix source sets include the complete patched packages.
- No new unsafe blocks or application unsafe code are introduced.

## Additive API

| API | Contract |
| --- | --- |
| `AsyncUdpSocket::supports_interface_selection` | Defaults to false; Tokio opts in on Linux and Android |
| `AsyncUdpSocket::try_send_on_interface` | `None` preserves ordinary sends; unsupported selections fail rather than being discarded |
| `Incoming::accept_on_interface` | Installs an immutable interface before creating the connection driver |
| `Endpoint::connect_with_on_interface` | Installs a concrete source and immutable interface before spawning an outgoing connection |
| `Endpoint::send_on_interface` | Sends one hole-punch datagram of at most 64 bytes through the existing socket; no new connection, timer, or socket |
| `Connection::egress_interface` | Reports the connection's selected transmit interface, if present |
| `UdpSocketState::send_on_interface` | Encodes the selected index in IPv4/IPv6 packet-info ancillary data |

- Existing constructors, accepts, and outgoing connects retain `None` selection.
- Unmodified async runtimes retain their previous behavior and reject selection.
- Other operating systems retain their previous send implementations.
- Libp2p's unmodified Quinn callers do not acquire physical-network policy automatically.

### Outgoing Selection

- Source and interface overrides belong to one connection, not its shared endpoint.
- Concrete socket binds must match the selected source; wildcard sockets remain wildcard-bound.
- Source/interface overrides survive handshake retries, buffered sends, and close packets without changing sibling connections.
- Link-local scope IDs must agree with the interface. IPv4 sockets cannot send native IPv6.
- Invalid inputs fail before connection creation; unsupported backends return `Unsupported` and stopped endpoints return `NotConnected`.
- Hole-punch sends return `WouldBlock` without waiting. The caller must bound retries and revalidate its route lease.

## Fail-Closed Rules

1. Require a concrete source IP and a nonzero interface index within signed range.
2. Normalize IPv4-mapped sources and validate the source/destination address family.
3. Keep the interface on retransmission, buffered sends, and ancillary-data retries.
4. Propagate interface-loss, unreachable-route, unavailable-source, and permission errors.
5. Route immediate acceptance-error responses through the selected interface.
6. Ignore unsupported or invalid incoming selections without an unselected refusal.

Existing MTU/GSO handling remains in place. An interface failure must never
trigger an unscoped send retry. The interface is immutable for that connection;
changing physical networks requires an authenticated replacement path.

## Application Integration

| Concern | Implementation |
| --- | --- |
| Reply route | Linux kernel lookup using the incoming destination IP, listener port, peer endpoint, mark, and UID |
| Lifetime | Route lease retained through staging, active use, receive drain, and rollback |
| Cancellation | Managed incoming attempts ignore cancellation before route selection, including before first future poll |
| Shared listener | Retiring one accepted connection does not close the listener or another peer's connection |
| Explicit overrides | Explicit source addresses and fixed listen ports retain existing dialing behavior |

An accepted source can be an assigned local alias reached through another
interface. Preserve it when its reply interface already matches OS policy;
do not force a reverse dial solely because a new socket would choose another IP.

## Verification And Limits

- Application tests cover native IPv4, native IPv6, dual-stack IPv4, shared listeners, cancellation, unsupported backends, and invalid source families.
- Real-TUN route tests cover accepted-path ownership, blocked preferred validation, fallback service, autonomous return, and wrong-interface transmit guards.
- Android cross-compilation checks backend portability; it is not device traffic evidence.
- Three outgoing-selector tests passed: invalid selections send nothing, shared-port hole punching preserves `WouldBlock`, and source/interface overrides survive retries and close while siblings remain usable.
- No formal kernel or Quinn proof exists. The executable checks do not certify every physical-network requirement.

The standalone outgoing-selector run used the existing offline target cache.
Its temporary test manifest adapted upstream test helpers to cached `rcgen` 0.13
and `tracing`; production source and the new test bodies were unchanged.

See [Physical Network Policy](physical-network-policy.md) for current evidence,
open transport/device scope, and the full acceptance matrix.
