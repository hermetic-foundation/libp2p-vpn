# Android Transport Policy

## Status

Work in progress. The route backend and Android inventory/JNI bridge are
published foundations, not an enabled Android handoff implementation.
Managed transports and controllers remain local pending complete integration.

Host tests and cross-compilation are not physical-device routing proof.

## Implemented Pieces

| Component | Behavior | Evidence |
| --- | --- | --- |
| Inventory | Published bounded Java/Rust Network records, independent default preference, source addresses and routes | Rust and JVM models; not device callback proof |
| Callback lifetime | Incarnation fencing, coalesced publication and service-teardown withdrawal | JVM tests; no device callback proof |
| Socket binder | Borrowed-descriptor binding contract, route preparation and JNI/NDK adapter | Android arm64 cross-check; not link/device proof |
| Native transports | Working-tree managed TCP and native QUIC use Network leases and exact authenticated ownership | Wiring compiles; full Android transport tests remain |
| QUIC companions | Immutable Network identity, bounded weak pooling, shared receive path and drain ownership | Vendor loopback/TLS tests with host callbacks |
| Controllers | Published shared ownership registry; Android controller activation remains local | Linux regressions and Android compilation; not complete Android behavior |
| Owned QUIC | Working-tree startup, incoming acceptance and outgoing sockets use platform leases; leases/tokens survive handoff phases | Android cross-check; physical-device handoff remains unverified |
| Owned UDP | Working-tree session route slots, exact audits, selected shared-port sends and actual destination metadata | Host tests; startup, replacement validation and bounded route drain remain incomplete |
| Stacked sources | Published Network-bound UDP connect selects a source without transmitting; no base-family assumption | Host CLAT models and zero-transmission check; not device CLAT proof |
| Diagnostics | Ownership events include Network handle, incarnation and record revision | Implemented; device correlation remains |

The [NDK socket-binding API](https://developer.android.com/ndk/reference/group/networking#android_setsocknetwork)
is available from API 23. UID exclusion from this app's VPN remains unchanged.
No JSON/Nix user configuration, identity, membership or wire format is changed.

## State Contract

| Value | Meaning |
| --- | --- |
| Inventory revision | Current policy observation; fences stale handshake/audit completion |
| Network incarnation | Distinguishes a newly available Network from a retired use of its handle |
| Record revision | Advances for meaningful source, route, interface or eligibility metadata changes |
| Availability | A surviving Network/source can carry fallback traffic after preference changes |
| Unknown stacked source | Metadata changed without proving source loss; retain existing bound fallback I/O, but require fresh proof for socket admission |
| Preference | OS-selected default, with destination-specific LAN routing preserved |
| Fallback candidate | Eligible validated Network after the preferred Network's kernel source lookup fails; not authenticated promotion |
| Stacked-source proof | Network-bound kernel lookup, fenced by incarnation and record revision; no guessed CLAT address or base-interface routing override |

- Ignore unrelated capability churn without revoking unchanged routing data.
- Do not guess a Network from a source IP shared by multiple records.
- New socket binding fails closed on stale state, missing routes or binding failure.
- Existing ownership is not removed merely because a newer preference revision exists.
- Unknown CLAT proof does not authorize new socket binding or candidate promotion. Network withdrawal, reincarnation and interface loss still invalidate the old owner.
- Route audits are event-driven; they send no peer probes or periodic interface scans.
- Source lookups run off the async executor. Cancellation retains lookup capacity until blocking work finishes.
- Incoming unlisted sources require unique Network attribution; overlapping stacked sources fail closed.
- Interface index is diagnostic metadata for Network-bound Internet traffic, not a forced CLAT device.

## Resource Bounds

| Resource | Limit |
| --- | --- |
| Inventory JSON | 128 KiB |
| Available Networks | 16 |
| Source addresses per Network | 64 |
| Routes per Network | 128 |
| Socket preparations per owner | 4 |
| Async route lookup wait | 3 seconds; blocking work retains its permit after timeout |
| Connecting sockets per owner | 16 |
| Native QUIC Network companions per endpoint | 32 weak entries |
| Pending audit delivery | One coalesced snapshot and one bounded output channel |

## Remaining Acceptance

| Gate | Required next work | Criteria |
| --- | --- | --- |
| IPv6-only cellular | Finish review and regressions for kernel-selected stacked sources and platform routing, then verify real CLAT RX/TX | P2, P7, P9 |
| Native incoming paths | Verify accepted TCP binding, ambiguous addresses and native QUIC ownership against Android's kernel/netd | P2, P4, P10 |
| Complete handoff | Owned QUIC wiring exists locally; integrate raw UDP ownership and replace the preference-triggered global reset only after fallback preservation works | P4-P8 |
| Stacked-source availability | Host models preserve bound fallback on unknown CLAT metadata and reject stale admission; device source-change and loss evidence remains | P4, P5, P7 |
| Unusable preferred path | Bound alternate-Network attempts when a preferred route exists but authentication/connectivity fails | P4, P5, P8 |
| DNS and discovery | Network-scoped DNS, selected-LAN mDNS query/reply isolation, pairing scope and advertised-address reconciliation | P2, P3, P9 |
| Device evidence | Incoming/outgoing access, address replacement, network loss/return, flapping and quiet retired paths | P7-P10 |
| Energy | Separate controlled modem/front-end comparison; no numerical saving inferred from routing tests | P11 |

## Verification Record

| Check | Result |
| --- | --- |
| Latest Android backend model tests | 23 passed, including CLAT unknown/withdrawn distinction, stale binding rejection, fresh-source audits, family return and cancellation bounds |
| Java main/debug compilation and JVM suite | 172 passed with cached SDK/JDK, including 20 inventory regressions and callback retirement/idempotency |
| Vendor unit harnesses | 63 Quinn and six native-library tests passed; three upstream stress tests ignored |
| Physical-network suite with opt-in Linux namespaces | 76 passed; includes 20 Android models, not 76 Android/device checks |
| Owned QUIC route/handoff tests | 22 passed, including rollback-policy coverage; not Android kernel proof |
| Working-tree packet-plane suite | 90 passed; one ignored. Includes 17 UDP socket/ownership/audit tests and final tuple/GRO/scope regressions |
| Shared overlay controller with opt-in namespaces | 37 passed |
| Shared infrastructure controller with opt-in namespaces | 20 passed |
| Workspace regression baseline | 2,390 passed across 20 suites; 84 ignored, before the final UDP tuple/GRO/scope review fixes |
| Working-tree Android arm64 release cross-check | Diagnostics/demand-lifecycle-trial variant passed after final review |
| Isolated backend foundation | Linux all-target compilation and Android arm64 default release cross-check passed |
| Isolated inventory/JNI bridge | Android arm64 default release cross-check passed without the unpublished transport/controller activation |
| Formatting, Clippy correctness/suspicious/performance, Nix source parity | Passed; advisory warnings remain |

The final backend regressions were checked after the workspace baseline.
No physical-device, APK link/package, full Nix package/VM, CLAT or complete
Android handoff result is established by these checks.

The published backend slice is also checked in isolation from the unpublished
managed-transport, controller and packet-plane wiring. The inventory/JNI bridge
is independently published without activating those unfinished transports.

JVM retirement coverage does not invoke Android framework registration failures
or unregister exceptions. Those lifecycle branches still need device coverage.

Builds reused one target cache, approximately 6.6 GiB, with two build jobs and
incremental/debug artifacts disabled. No energy comparison was performed.

## Publication Boundary

- Publish verified additive vendor primitives and the inactive route-backend foundation independently.
- Publish inventory/JNI plumbing independently; do not couple it to unfinished transport activation.
- Keep managed transport, controller and packet-plane activation local until complete handoff gates are satisfied.
- Do not disable global recovery merely to make a handoff-only test pass.
- No APK deployment or battery comparison has been performed for this implementation stage.

## Raw UDP Integration

These pieces remain local until the full handoff is integrated.

| Boundary | Implemented behavior | Remaining proof |
| --- | --- | --- |
| Socket | Reuse tested shared-port companion I/O; retain original and companion receive paths | Android netd and device RX/TX |
| Receive | Preserve GRO boundaries and the actual destination address; lookup follows authenticated event selection | Host large-aggregate regression passed; device evidence remains |
| Ownership | Exact per-session token, per-listener immutable route, cached source/remote tuple checks | Address changes and withdrawal on a device |
| Preparation | No lookup per cached packet; failures/cancellation use bounded local cooldown | Sustained churn/resource evidence |
| Audit | Epoch, token, listener and destination must all match; healthy siblings cannot clear unrelated flags | Production observer/negotiator integration |
| Cleanup | Forget/expiry drops matching route ownership without disturbing siblings | Candidate promotion, rollback and bounded fallback drain |

- GRO backing storage is bounded by the runtime's advertised segment capacity, up to 64 datagrams per listener.
- Each delivered datagram remains bounded to 65,535 bytes; aggregate storage can reach approximately 4 MiB.
- Raw UDP startup policy and automatic replacement are not enabled yet.
- The global network-reset path remains unchanged; this is not make-before-break evidence.
