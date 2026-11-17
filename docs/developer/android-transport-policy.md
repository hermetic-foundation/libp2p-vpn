# Android Transport Policy

## Status

Current milestones and exit conditions are in the
[fixed acceptance ledger](physical-network-acceptance.md). Historical stage
results below do not certify newer working-tree changes.

Backend, inventory/JNI and inactive packet-plane primitives are separate published
components. Managed transports, raw-UDP physical startup/auditing and Android
handoff activation remain local and unpublished.

Stage30 repairs asymmetric key promotion with independent RX/TX authorization and
bounded original-TTL RX retention. The workspace passes 2,427 tests, with 86 ignored;
three explicit namespace cases and both Android cross-checks also pass.

Host tests and cross-compilation are not physical-device routing proof.

## Implemented Pieces

| Component | Behavior | Evidence |
| --- | --- | --- |
| Inventory | Published bounded Java/Rust Network records, independent default preference, source addresses and routes | Rust and JVM models; not device callback proof |
| Callback lifetime | Incarnation fencing, coalesced publication and service-teardown withdrawal | JVM tests; no device callback proof |
| Socket binder | Borrowed-descriptor binding contract, route preparation and JNI/NDK adapter | Android arm64 cross-check; not link/device proof |
| Native transports | Working-tree managed TCP and native QUIC use Network leases and exact authenticated ownership | Final Stage30 Android default/trial cross-checks passed, including counters and expiry logging; device proof remains |
| QUIC companions | Immutable Network identity, bounded weak pooling, shared receive path and drain ownership | Vendor loopback/TLS tests with host callbacks |
| Controllers | Published shared ownership registry; Android controller activation remains local | Baseline Linux regressions and Android compilation; not Stage29/device verification |
| Owned QUIC | Published platform-aware primitives; Android startup activation remains local | Host regressions and Android compilation; device handoff remains unverified |
| Owned UDP | Published inactive ownership/directional primitives; Runner startup and auditing remain local | Focused suite: 110 passed, one ignored; local integration passes full workspace and three namespace cases |
| Physical-network notification | Local `PhysicalNetworkChanged` request and Android JNI routing reconcile without the legacy global reset; stable-epoch coalescing avoids repeated LAN-grace restart | Two real loopback integration tests passed, preserving eight hints before an explicit legacy reset; epoch/model unit checks green |
| Stacked sources | Published Network-bound UDP connect selects a source without transmitting; no base-family assumption | Host CLAT models and zero-transmission check; not device CLAT proof |
| Diagnostics | Ownership events include Network handle/incarnation/record revision; local status/state counters separate pending UDP validation from receive-only retention | Current workspace and namespace passes include counters; device correlation remains |

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
- Physical preference notifications request reconciliation, not a destructive reset. The explicit legacy `NetworkChanged` recovery path remains separate.
- Repeated notifications in one stable physical epoch do not restart LAN-first grace indefinitely.
- RX and TX authorization are directional. New-key TX proof alone does not prove that the peer has stopped sending with old keys.
- Necessary old RX-key retention is distinct from permission to keep transmitting on the old underlay.

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
| Raw-UDP retained ownership/admission budget | 64 total slots, reserving two per candidate; capacity rejects new negotiation rather than evicting retained RX owners |

## Remaining Acceptance

| Gate | Required next work | Criteria |
| --- | --- | --- |
| IPv6-only cellular | Finish review and regressions for kernel-selected stacked sources and platform routing, then verify real CLAT RX/TX | P2, P7, P9 |
| Native incoming paths | Verify accepted TCP binding, ambiguous addresses and native QUIC ownership against Android's kernel/netd | P2, P4, P10 |
| Complete handoff | Complete final workspace and updated namespace reruns after the focused directional repair pass, before publication | P4-P8 |
| Directional key retention | Focused and integration tests pass; complete device/churn checks without premature key eviction or redundant old TX maintenance | P4-P6, P8 |
| Bounded resource retirement | Stop redundant old TX/maintenance; keep necessary RX state within hard bounds and release it at original protocol expiry; early retirement is optional | M2, M3 |
| Stacked-source availability | Host models preserve bound fallback on unknown CLAT metadata and reject stale admission; device source-change and loss evidence remains | P4, P5, P7 |
| Unusable preferred path | Bound alternate-Network attempts when a preferred route exists but authentication/connectivity fails | P4, P5, P8 |
| DNS and discovery | Network-scoped DNS, selected-LAN mDNS query/reply isolation, pairing scope and advertised-address reconciliation | P2, P3, P9 |
| Device evidence | Incoming/outgoing access, address replacement, network loss/return, flapping and quiet retired paths | P7-P10 |

## Verification Record

### Stage28 and Earlier Baselines

These counts predate Stage29 activation and its directional repair. They are
baseline evidence, not a green result for the current Stage29/30 working tree.

| Check | Result |
| --- | --- |
| Android backend model tests | 23 passed, including CLAT unknown/withdrawn distinction, stale binding rejection, fresh-source audits, family return and cancellation bounds |
| Java main/debug compilation and JVM suite | 172 passed with cached SDK/JDK, including 20 inventory regressions and callback retirement/idempotency |
| Vendor unit harnesses | 63 Quinn and six native-library tests passed; three upstream stress tests ignored |
| Physical-network suite with opt-in Linux namespaces | 76 passed; includes 20 Android models, not 76 Android/device checks |
| Owned QUIC route/handoff tests | 22 passed, including rollback-policy coverage; not Android kernel proof |
| Stage28 packet-plane baseline | 104 passed; one ignored; predates the directional repair |
| Shared overlay controller with opt-in namespaces | 37 passed |
| Shared infrastructure controller with opt-in namespaces | 20 passed |
| Stage28 working-tree workspace regression | 2,412 passed across 20 suites; zero failed, 84 ignored; includes the then-current UDP handoff/replay/deadline fixes |
| Stage28 Android arm64 release cross-check | Diagnostics/demand-lifecycle-trial variant passed after that stage's review |
| Isolated backend foundation | Linux all-target compilation and Android arm64 default release cross-check passed |
| Isolated inventory/JNI bridge | Android arm64 default release cross-check passed without the unpublished transport/controller activation |
| Formatting, Clippy correctness/suspicious/performance, Nix source parity | Passed; advisory warnings remain |

### Current Results and Baselines

Full-workspace and namespace counts below include the unpublished Runner activation.
They are local-integration evidence, not isolated-main certification.
The packet-plane component has its own focused checks and publication boundary.

| Check | Result and limits |
| --- | --- |
| Physical notification and legacy reset integration | Two real loopback integration tests passed; physical reconciliation preserves eight hints, followed by an explicit legacy reset |
| Stable physical epoch and recovery models | Unit checks green; repeated same-epoch notifications do not repeatedly restart LAN grace |
| Raw-UDP namespace initiator | Passed in 103.71 seconds with two real interfaces and fixed IPv4 endpoints |
| Raw-UDP namespace responder | Passed in 98.50 seconds with the same fixed-endpoint constraints |
| Asymmetric key promotion before repair | Deterministic red regression: A uses new TX keys while B rejects candidate DATA; A's old RX drain can end before B proves its reverse direction |
| Stage30 directional repair | Focused packet-plane suite: 110 passed, zero failed, one ignored; original asymmetric failure now green |
| Isolated packet-plane component | 110 passed, one ignored; host all-target compilation, Android arm64 default/trial cross-checks, formatting and Nix source parity passed without runtime activation |
| Stage30 host library check | Passed; compilation is not a repaired-regression result |
| Stage30 Android default/trial cross-checks | Final checks passed, including status/state counters and validation-expiry logging |
| Stage30 Clippy | Denied correctness/suspicious/performance checks passed; 739 library-test advisories remain |
| Stage30 source parity | Passed, including the new Rust source files |
| Workspace attempt | Stopped at root units: 1,970 passed, one failed, 32 ignored; randomized legacy-ledger fixture hit a builtin-IPv4 collision, isolated rerun passed |
| Fixture correction | Six identities now have unique builtin IPv4 addresses; production conflict rejection unchanged. Isolated fixture passed and was published independently |
| Stage30 full workspace | 2,427 passed across 20 suites, zero failed, 86 ignored; includes 1,971 root-library and eight real connection-recovery tests |
| Stage30 updated namespace run | Three passed in 208.17 seconds: minimal UDP config and fixed-endpoint failback for both original peer roles |
| Stage29 Android cross-check | Not performed; earlier Android cross-checks are baseline only |
| Namespace scope | Fixed IPv4 endpoints, two real interfaces; strict active IDs/data through blocked validation, 20-second expiry and no-event retry |
| Namespace limits | Moving-host outbound UDP quietness only; legitimate peer destination-specific RX may remain on the old link. No RX/FD retirement, default-source or Android proof |

These passes do not establish device/CLAT, APK, full Nix package/VM, complete
Android handoff or energy results.

The published backend slice is also checked in isolation from the unpublished
managed-transport, controller and packet-plane wiring. The inventory/JNI bridge
is independently published without activating those unfinished transports.

JVM retirement coverage does not invoke Android framework registration failures
or unregister exceptions. Those lifecycle branches still need device coverage.

The baseline builds reused one target cache, approximately 6.6 GiB, with two build
jobs and incremental/debug artifacts disabled. No energy comparison was performed.

## Publication Boundary

- Publish verified additive vendor primitives and the inactive route-backend foundation independently.
- Publish inventory/JNI plumbing independently; do not couple it to unfinished transport activation.
- Publish [packet-plane primitives](packet-plane-physical-ownership.md) without enabling physical-policy startup or Android managed controllers.
- Keep managed transport, controller and packet-plane activation local until complete handoff gates are satisfied.
- Startup/handoff wiring remains unpublished despite green host integration; device and remaining implementation gates still apply.
- Preserve explicit legacy global recovery while routing physical preference updates through non-destructive reconciliation.
- No APK deployment or battery comparison has been performed for this implementation stage.

## Raw UDP Integration

The primitives are published separately from the local Runner activation below.
Activation remains unpublished while Android implementation/device gates are open.

| Boundary | Implemented behavior | Remaining proof |
| --- | --- | --- |
| Socket | Reuse tested shared-port companion I/O; retain original and companion receive paths | Android netd and device RX/TX |
| Receive | Preserve GRO boundaries and the actual destination address; lookup follows authenticated event selection | Host large-aggregate regression passed; device evidence remains |
| Ownership | Exact per-session token, per-listener immutable route, cached source/remote tuple checks | Address changes and withdrawal on a device |
| Preparation | No lookup per cached packet; failures/cancellation use bounded local cooldown | Sustained churn/resource evidence |
| Startup and audit | Local Runner activates physical ownership and route reconciliation on Linux/Android; epoch, token, listener and destination must match | Android cross-checks, full workspace and three Linux namespace cases pass; no device proof |
| Validation | Independent candidate RX authorization after successful matching scoped ACK send, and local TX promotion after its own matching ACK proof | Focused repair and updated namespaces pass; Android kernel/netd remains unverified |
| Notification | Android JNI uses local non-destructive physical reconciliation; stable-epoch handling coalesces repeated recovery signals | Loopback integration and epoch/model checks passed; device callbacks remain unverified |
| Retention and cleanup | Preserve possibly-used RX keys and immutable slots through original TTL; 64-slot budget reserves two per candidate and rejects admission when full | Focused, lifecycle and counter integration pass; early/exact old-socket retirement remains open for P6 |

- GRO backing storage is bounded by the runtime's advertised segment capacity, up to 64 datagrams per listener.
- Each delivered datagram remains bounded to 65,535 bytes; aggregate storage can reach approximately 4 MiB.
- Raw-UDP physical startup and automatic route replacement are enabled in the local Stage29 Runner only, not published.
- Physical notifications no longer request the global reset in that local integration. Explicit legacy reset remains available and tested separately.
- Stopping redundant old outbound traffic does not establish that old receive keys are safe to discard.

### Lifecycle Diagnostics

| Status/state counter | Meaning |
| --- | --- |
| `packet_plane_udp_validation_pending` | Candidates still awaiting TX validation; the updated namespace lifecycle gate waits for zero |
| `packet_plane_udp_receive_only_sessions` | Retained receive-only UDP ownership, not scheduled old-path maintenance; must remain bounded by the 64-slot admission budget |
| `packet_plane_retiring_sessions` | Existing retirement count remains visible; it is not redefined or required to be zero merely because TX validation completed |
| `packet_plane_udp_validation_expired receive_retained=bool` | Validation ended, including when authorized RX archives; fixture timeout proof even after a locally successful but firewall-dropped ACK |
| `packet_plane_udp_handoff_retired` | Actual key retirement, not validation-timeout proof |
| Updated fixture gate | Passed: pending validation zero, one healthy UDP path per peer, retained RX at most 64, not zero |
| Continuity checks | Exact blocked-stage session IDs and six-second moving-host old-outbound quietness |
| Admission invariant | Retained ownership plus two reservations per pending candidate must fit 64; RX count alone does not prove reservation handling |

### Managed UDP Candidate Contract

The published primitives are covered by the focused 110-test pass. Local activation
also passes workspace/namespace checks; complete Android behavior and P6 remain open.

| Phase | Payload path | Promotion or retirement |
| --- | --- | --- |
| Candidate validating | Existing active TX keys and cached route remain installed; candidate DATA has no unconditional admission | Fresh-token ACK on the exact candidate listener and current preferred route |
| Candidate RX authorized | New-key DATA becomes eligible only after successfully sending the exact scoped ACK on that candidate owner | RX authorization does not itself prove or promote local new-key TX |
| Candidate timeout or supersession | Existing active TX continues; an RX-authorized candidate is archived as silent RX ownership | Twenty-second validation expiry or supersession does not evict authorized RX state; unauthorized candidates cannot authorize DATA |
| TX promoted | New application sends use the validated key/route pair | Do not infer that the peer has proved its reverse TX direction or stopped using old keys |
| Old RX retained | Preserve all possibly-used keys, original age, DATA replay state and immutable slots independently of old outbound traffic retirement | Retain through original TTL under hard-bounded admission; no eviction merely to admit a new candidate |
| Archived owner silent | No scheduled old-path payload, probes or keepalives; exact scoped replies use cached slots only | No route/socket reacquisition; original expiry releases ownership, while early/exact socket retirement remains an open P6 gate |

- Candidate DATA must fail closed before exact scoped ACK success; merely preparing, starting or failing an ACK send cannot authorize it.
- Exact route validation precedes replay acceptance. Wrong-interface copies cannot consume the valid packet's replay slot.
- Scoped receive does not await route acquisition; selected-event handling performs validation and replay acceptance.
- Probe replies use the received session owner, not whichever session is now active.
- Promotion ACK freshness is one-time, separate from DATA replay. Validate exact route, listener, token, deadline and current lease first.
- DATA replay protection is unchanged.
- Candidate/reply sends check expiry before every transmission attempt, including writable resumes.
- Link-local scope-zero lookup identifies authentication candidates only; route validation still requires the received scope and local tuple.
- When retention capacity is exhausted, defer or reject new admission rather than evict still-needed old RX keys to make room.
- Retention never extends the original key lifetime or authorizes redundant old-underlay TX. No monotonic handshake/key ordering is assumed and no new wire field is added.
- The blind three-second old-RX eviction is removed. Retaining immutable receive ownership through original TTL is not proof of early/exact old-socket retirement.

| Bound | Value or pending requirement |
| --- | --- |
| Candidate validation | 20 seconds, capped by original key lifetime |
| Retiring-map ownership/admission budget | 64 total slots, with two reserved per candidate; full capacity rejects new negotiation, never evicts possibly-used RX keys |
| Authorized RX retention | Original key TTL, including authorization-preserving archival on candidate timeout or supersession; no blind three-second eviction |
| Archived TX | Cached exact replies only; no socket/route reacquisition or scheduled probes |
| Verification | Focused, workspace/counter and namespace runs pass; P6 early/exact socket retirement remains open |

Stage28's nine encrypted loopback handoff cases and two deadline cases are baseline
evidence. Current results and pending gates are recorded above, not device/netd
routing or energy proof.
