# Android Transport Policy

## Status

Work in progress. The Network-owned route backend is a published foundation,
not an enabled Android handoff implementation. Managed transports, controllers
and Java/JNI integration remain working-tree work pending complete integration.

Host tests and cross-compilation are not physical-device routing proof.

## Implemented Pieces

| Component | Behavior | Evidence |
| --- | --- | --- |
| Inventory | Published bounded Network records, independent default preference, source addresses and routes | Rust models; working-tree Java inventory has JVM tests |
| Callback lifetime | Working-tree incarnation fencing, coalesced publication and service-teardown withdrawal | JVM tests; no device callback proof |
| Socket binder | Published borrowed-descriptor binding contract and route preparation; NDK adapter remains local | Android arm64 cross-check; not link/device proof |
| Native transports | Working-tree managed TCP and native QUIC use Network leases and exact authenticated ownership | Wiring compiles; full Android transport tests remain |
| QUIC companions | Immutable Network identity, bounded weak pooling, shared receive path and drain ownership | Vendor loopback/TLS tests with host callbacks |
| Controllers | Published shared ownership registry; Android controller activation remains local | Linux regressions and Android compilation; not complete Android behavior |
| Owned QUIC | Working-tree startup, incoming acceptance and outgoing sockets use platform leases; leases/tokens survive handoff phases | Android cross-check; physical-device handoff remains unverified |
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
| Preference | OS-selected default, with destination-specific LAN routing preserved |
| Fallback candidate | Eligible validated Network after the preferred Network's kernel source lookup fails; not authenticated promotion |
| Stacked-source proof | Network-bound kernel lookup, fenced by incarnation and record revision; no guessed CLAT address or base-interface routing override |

- Ignore unrelated capability churn without revoking unchanged routing data.
- Do not guess a Network from a source IP shared by multiple records.
- New socket binding fails closed on stale state, missing routes or binding failure.
- Existing ownership is not removed merely because a newer preference revision exists.
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
| Unusable preferred path | Bound alternate-Network attempts when a preferred route exists but authentication/connectivity fails | P4, P5, P8 |
| DNS and discovery | Network-scoped DNS, selected-LAN mDNS query/reply isolation, pairing scope and advertised-address reconciliation | P2, P3, P9 |
| Device evidence | Incoming/outgoing access, address replacement, network loss/return, flapping and quiet retired paths | P7-P10 |
| Energy | Separate controlled modem/front-end comparison; no numerical saving inferred from routing tests | P11 |

## Verification Record

| Check | Result |
| --- | --- |
| Latest Android backend model tests | 20 passed, including CLAT source proof, ambiguous/inconclusive incoming attribution, family return, cancellation and timeout bounds |
| Java main/debug compilation and JVM suite | Passed with cached SDK/JDK; 166 tests, including 15 inventory regressions |
| Vendor unit harnesses | 63 Quinn and six native-library tests passed; three upstream stress tests ignored |
| Physical-network suite with opt-in Linux namespaces | 76 passed; includes 20 Android models, not 76 Android/device checks |
| Owned QUIC route/handoff tests | 22 passed, including rollback-policy coverage; not Android kernel proof |
| Shared overlay controller with opt-in namespaces | 37 passed |
| Shared infrastructure controller with opt-in namespaces | 20 passed |
| Workspace regression baseline | 2,373 passed across 20 suites; 84 ignored, before final scope/rollback review fixes and the last backend regressions |
| Working-tree Android arm64 release cross-check | Diagnostics/demand-lifecycle-trial variant passed after final review |
| Isolated backend foundation | Linux all-target compilation and Android arm64 default release cross-check passed |
| Formatting, Clippy correctness/suspicious/performance, Nix source parity | Passed; advisory warnings remain |

The final backend regressions were checked after the workspace baseline.
No physical-device, APK link/package, full Nix package/VM, CLAT or complete
Android handoff result is established by these checks.

The published backend slice is also checked in isolation from the unpublished
managed-transport, controller, packet-plane and Java/JNI wiring.

Builds reused one target cache, approximately 6.6 GiB, with two build jobs and
incremental/debug artifacts disabled. No energy comparison was performed.

## Publication Boundary

- Publish verified additive vendor primitives and the inactive route-backend foundation independently.
- Keep managed transport, controller and app wiring local until compatibility and complete handoff gates are satisfied.
- Do not disable global recovery merely to make a handoff-only test pass.
- No APK deployment or battery comparison has been performed for this implementation stage.
