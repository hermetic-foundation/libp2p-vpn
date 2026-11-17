# UDP Receive Scope

## Status

This is an additive socket primitive, not activation or certification of
Android physical-network handoff. Existing `RecvMeta` literals and legacy
`recv`/`poll_recv` callers remain supported.

## Low-Level Contract

| API | Output |
| --- | --- |
| `quinn_udp::UdpSocketState::recv_scoped` | Incoming kernel interface parallel to each filled metadata slot |
| Existing `recv` | Existing receive metadata; no caller migration required |
| Missing or truncated packet-info | `None`, never the requested egress interface |
| GRO | One ingress interface applies to all segments in its receive buffer |

- Empty scoped outputs are rejected before receiving.
- Scoped receive fills at most the shortest output slice.
- IPv4 and IPv6 packet-info are parsed independently.
- Android's signed IPv6 interface index must convert to a nonzero unsigned index.

## Evidence

| Check | Result |
| --- | --- |
| Low-level host library suite | Five passed; includes three receive-scope tests |
| Ancillary parser | Missing, zero, negative IPv4 and truncated metadata rejected; GRO and ECN retained |
| Real loopback receive | IPv4/IPv6 interface attribution and legacy receive passed |
| Android arm64 default compilation | Passed after the signed IPv6-index conversion repair |

The host suite used a small offline manifest pointing directly to the checked-in
library and build script, with cached dependency versions. No syscall fault
injection, Android deployment or modem-energy measurement was performed.

## Limits

- An interface index is not an Android Network handle or incarnation.
- A socket routing mark is not proof of kernel ingress ownership.
- Android inventory correlation, overlapping sockets and stacked CLAT paths need additional validation.
- Windows and other platform implementations were source-reviewed, not executed in this Linux check.

## Quinn Fan-In

| API or bound | Contract |
| --- | --- |
| `AsyncUdpSocket::poll_recv_scoped` | Additive method; legacy implementors clear scope outputs and delegate to `poll_recv` |
| `UdpRecvScope::network` | Immutable receiving companion identity, not an ingress Network assertion |
| `UdpRecvScope::interface_index` | Kernel incoming interface; never copied from the requested egress route |
| Receive ownership | Keep scope beside its buffer across GRO segments and canceled reads |
| Network companions | At most 32 live plus pending preparations per endpoint |
| Duplicate preparation | Return `WouldBlock`; do not wait for a binding callback under the cache lock |
| Backend cancellation | Keep the reservation until the actual blocking bind returns, errors or unwinds |

Socket derivation and binding callbacks run outside the shared receive-cache
lock. Existing socket reuse still checks immutable identity, routing mode and
IPv6 scope. Successful insertion wakes an already-pending receiver.

### Host Evidence

- Thirty-four runtime tests passed using exact copies of the checked-in runtime sources.
- Gated binding models cover pending/live capacity, cancellation and unwind cleanup.
- Real loopback tests cover IPv4/IPv6 IIF, overlapping companions and original/strict receive fan-in.
- Legacy implementor and `RecvMeta` literal compatibility tests passed.

The offline harness adapts older cached upstream test dependencies; it does not
replace the runtime source or emulate Android netd. Host and Android compilation
are separate from device proof.

The complete Quinn host suite passes 69 tests, with three ignored. Standalone
Clippy gates pass with one explicit pre-existing upstream exception:
`clippy::useless_borrows_in_formatting` in unchanged `recv_stream.rs`.

### Android Admission

Receiving-FD identity alone is insufficient. Callers must correlate actual IIF,
local tuple and immutable lease with current unambiguous Network inventory.
Record-revision updates must not be confused with Network reincarnation.

Overlapping sockets can deliver a valid packet to an unintended companion.
Such a mismatch is ambiguous delivery, not evidence of wrong physical ingress.
Stacked CLAT and real device delivery remain open integration gates.

### Lease Admission Helper

`RouteLease::validate_receive_scope` checks immutable Android source ownership.
The helper is independently tested; packet-plane activation remains separate.

| Input or transition | Admission rule |
| --- | --- |
| Receiving companion identity | Does not admit or reject a packet by itself |
| Kernel IIF | Required; must match the lease's interface and one unique live Network |
| Source and incarnation | Preserve the lease's original Network/source; reject withdrawal, replacement and reused handles |
| Preference or record update | May retain published-source RX; does not renew stale TX ownership |
| Omitted stacked source | Require still-current source proof; stale or unknown CLAT attribution fails closed |

Host models cover conflicting FD provenance, missing/foreign/ambiguous IIF,
IPv4/IPv6 source withdrawal, interface replacement and Network reincarnation.
No device/netd, guessed CLAT mapping or full handoff result is claimed.

The independently extracted component passes six focused host tests, with one
existing namespace case ignored, plus Android arm64 release compilation and
format checks. These results do not certify the remaining local activation.

This helper does not replace peer/tuple authentication, replay checks or the
original receive-key expiry. Those remain caller obligations.
