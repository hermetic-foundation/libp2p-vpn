# Linux TCP Handoff

## Scope

The main runner replaces affected managed TCP paths to authorized overlay peers.
It uses OS route audits and existing peer discovery without additional configuration.

| Included | Not completed by this component |
| --- | --- |
| Direct TCP overlay connections | Public DHT/AutoNAT infrastructure migration |
| Numeric and DNS/TCP candidate addresses | Proactive profile-free pairing migration |
| Exact authenticated validation | libp2p QUIC and owned UDP/QUIC integration |
| Bounded fallback drain and retirement | Relay reservation/circuit handoff and relay-server migration |
| Route loss, return, and rollback | Android physical-device verification and energy comparison |

The [physical-network acceptance matrix](physical-network-policy.md#acceptance-matrix)
remains authoritative. A passing TCP fixture does not complete those broader rows.

## State Machine

| State | Behavior |
| --- | --- |
| Waiting | An exact live owner requires replacement in the current audited generation |
| Dialing | Try a direct TCP address with a fresh port through the managed OS-routed transport |
| Validating | Quarantine ordinary sends; request capabilities on the exact candidate connection |
| Draining | Publish the validated candidate; stop ordinary new fallback requests and drain existing work |
| Exhausted | Stop this generation's bounded attempts; retain working service |

- Candidate addresses are LAN-first, bounded, deduplicated, and exclude relay circuits and listener ephemeral ports.
- The existing DNS transport resolves supported DNS/TCP addresses.
- Both Noise identity and matching capability scope are required; a sibling connection's reply is not evidence.
- Pairing and checkpoint reconciliation cannot publish an unvalidated outbound candidate.
- Pending native request slots remain owned until their terminal event, including after cancellation.
- [Connection-scoped requests](connection-scoped-requests.md) provide selection, cancellation, and drain accounting without changing wire protocols.

## Transition Safety

| Condition | Required action |
| --- | --- |
| Route changes during validation | Cancel the stale attempt; preserve its working fallback |
| Candidate closes or rejects capabilities | Retry with backoff; do not promote or retire the fallback |
| Fallback closes during an owned attempt | Continue candidate validation if its generation remains current |
| Unrelated change after promotion | Continue drain only when a fresh audit confirms the same path remains preferred |
| Observer unavailable after promotion | Preserve validated service and pause fallback retirement until a fresh audit |
| Preferred path changes during drain | Restore a surviving healthy tracked fallback, if available |
| Previous fallbacks already retired | Preserve the promoted path as the next fallback; never close the sole working path |
| Required relay owner | Preserve its transport until relay-specific handoff is implemented |

TCP duplicate arbitration grants each candidate its own bounded grace at both
updated endpoints. It uses bound ownership before first muxer adoption;
another connection cannot extend or inherit that candidate's grace.

### Observer Recovery

- An audit epoch includes observer identity and generation; equal numbers from different observers are not interchangeable.
- Replacement observers can audit existing TCP owners without rewriting their original socket leases or resetting their connections.
- Pending validation must match its exact owner and current epoch. A result from a retired observer cannot promote a replacement.
- Observer loss does not invalidate completed authentication. Preserve the validated path while its new route audit is pending.
- Resume drain only after a fresh audit confirms preference; use normal rollback when that audit identifies a changed preferred path.

## Bounds

| Resource | Bound |
| --- | --- |
| Tracked rounds / duplicate-grace connections | 64 each |
| Active replacement rounds | 4 |
| Native validation requests, including cancelled work | 8 |
| Attempts per round/generation | 3 |
| Candidate addresses | 16 |
| Connect window | 20 seconds |
| Exact request window | 10 seconds |
| Retry delays | 10 then 20 seconds |
| Drain window | 20 seconds |
| Duplicate grace | 40 seconds per connection; repeated observations do not extend it |
| Scheduling | Existing 10-second maintenance tick, plus candidate establishment |

- Route auditing is event-driven and sends no network probes.
- Only an affected owner starts a round; stable peers are not periodically redialed.
- Draining checks exact request ownership plus pinned packet work; its deadline bounds cleanup under continued inbound activity.
- Existing connection, handshake, and stream limits remain in force.

## Remaining Work

- Exhausted rounds currently wait for route-generation or owner changes. Discovery/demand rearming and prolonged blackhole recovery need further integration and tests.
- Mixed-version peers retain existing service, but full migration can require duplicate-grace support at both endpoints.
- Relay owners are preserved conservatively; completing their handoff is required before claiming full fallback retirement.
- IPv6 migration, repeated flapping, Android integration, and controlled device energy evidence remain open.

## Diagnostics

| Event | Meaning |
| --- | --- |
| `control_tcp_replacement_dialing` | A generation-scoped replacement attempt started |
| `control_tcp_replacement_validating` | Exact candidate capability request queued |
| `control_tcp_replacement_promoted` | Exact authenticated reply accepted under current policy |
| `control_tcp_fallback_retired` | Closure requested, or exact affected fallback closed by its peer/transport after promotion |
| `control_tcp_replacement_abandoned` | An unpromoted attempt was cancelled or superseded |
| `control_tcp_replacement_rolled_back` | Invalidated promotion removed; a surviving tracked fallback remains |
| `control_tcp_promotion_superseded` | Sole working validated path preserved for the next round |

Combine these events with `control_tcp_route_owned` and `connection_closed`.
A closure request alone is not proof that the underlying socket is gone.

## Verification

| Check | Result |
| --- | --- |
| Standard workspace suites | 2,168 passed; 61 opt-in/platform cases skipped |
| Handoff controller cases | 15 passed, including an opt-in isolated observer-replacement namespace |
| Linux route/ownership cases | 49 passed, including opt-in isolated namespaces |
| Live TCP observer recovery | IPv4/IPv6 Noise/Yamux connection IDs and authenticated pings preserved through two observer replacements |
| Exact request API | 9 standalone library tests passed |
| Minimal-config real-TUN scenarios | 10 passed in 335 seconds with two workers |
| Pairing and relay | Peerless code pairing and forced-relay overlay ping passed |
| Android native | Default and diagnostic/trial arm64 release cross-checks passed |
| Static/source checks | Clippy correctness/suspicious/performance, formatting, whitespace, and Nix source ownership passed |

- The first return test exposed closure of the sole working path during an earlier drain; the controller now preserves it as the next fallback.
- Observer replacement reproduced a permanently stale audit on live owners. Epoch-scoped audits now reject retired results and recover without connection churn.
- A controller regression preserves both the promoted path and its fallback when the observer becomes unavailable during drain, including past the cleanup deadline.
- Simultaneous mDNS startup required a deterministic fixture direction instead of assuming startup order determines the initiator.
- Remote duplicate cleanup required exact closure accounting, and grace now belongs to each connection rather than an earlier peer-wide window.
- No assertions were relaxed: source ownership, promotion, socket disappearance, and continued TCP payload remain required.
- Full Nix package/VM builds, a linked APK, physical-device checks, and energy measurements are not claimed by these results.

### Real-TUN Method

The real-TUN tests use two isolated veth paths and an unchanged advertised peer
destination. They block new SYNs while keeping established fallback traffic usable.

1. Restrict reverse initial SYNs inside the fixture; require TCP-only payload counters and the intended initial initiator role.
2. Remove the preferred route; prove fallback traffic while replacement SYNs are blocked.
3. Unblock without another route event; require exact promotion and the alternate source address.
4. Require fallback retirement, actual connection closure, socket disappearance, and continuing payload traffic.
5. Restore the preferred route during the preceding drain window and repeat the same assertions.

- Both initial dialer and acceptor roles are covered; replacement attempts originate at the changed node.
- These fixtures cover IPv4. Physical IPv6 migration and repeated-flapping certification remain open.
- No real device, APK deployment, or measured battery reduction is implied by these tests.
