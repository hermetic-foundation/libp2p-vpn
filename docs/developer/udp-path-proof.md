# UDP Path Proof

## Scope

This is the route-managed packet-plane contract. Runtime/controller activation
is tracked separately in [Android Transport Policy](android-transport-policy.md).
Wire formats, identity, membership and user configuration are unchanged.

## Admission

| State | Allowed behavior |
| --- | --- |
| Signed Hello/Accept installed | Candidate keys and an immutable route owner; no active payload session |
| Probe successfully sent | Still a candidate; a successful local write is not path proof |
| Exact authenticated ACK received | Promote only after owner, token, listener, tuple, deadline and current-route checks |
| ACK sent to the peer | Permit its authenticated DATA on these RX keys; do not authorize unproven local TX |
| Wrong, stale or retired-attempt ACK | No promotion; preserve the legitimate candidate's replay protection |
| Candidate expires | Discard ungranted keys; retain necessary granted RX keys within their original lifetime |
| Unmanaged public API | Preserve direct installation and existing renewal behavior |

First-session startup and replacement use the same proof rules. Each direction
must prove its own outgoing path; one peer's promotion is not proof of the other.
Existing stream or datagram fallbacks remain selected until validation succeeds.

## Bounds

| Resource | Limit |
| --- | --- |
| Concurrent candidates | 16 |
| Validation window | 20 seconds, capped by key lifetime |
| Retained ownership budget | 64 slots, including candidate reservations |
| Required old RX keys | Original key lifetime; no extension on retry |

Runner integration must include pending first-session candidates in the existing
probe pass. No additional polling loop is required. Pending-Hello and maintenance
gates must prevent duplicate requests and new work for deliberately paused peers.

## Verification

- IPv4/IPv6 loopback tests cover exact, wrong and late ACKs, tuple rejection and directional authorization.
- Replacement fixtures establish their base path through real ACK promotion.
- Runner-level signed negotiation, fallback, scheduled probes and data delivery remain a separate integration gate.
- These checks do not prove Android Network/netd routing or battery savings.

## Remaining Work

Alternate-Network recovery still needs request-owned retries, a freshly valid
signed advertised endpoint for each attempt, and final ACK-driven completion.
A kernel-local address is not necessarily the advertised external NAT endpoint.
Do not weaken endpoint admission or reuse the previous Network's signed tuple.
