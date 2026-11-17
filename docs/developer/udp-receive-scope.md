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
