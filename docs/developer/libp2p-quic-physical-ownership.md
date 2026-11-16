# Native QUIC Physical Ownership

## Status

The Linux native circuit-migration milestone is implemented and verified in
isolated namespaces. This is native libp2p TLS/streams, not the separate owned
packet-plane QUIC implementation. Android runtime integration remains incomplete;
additive socket primitives are verified separately, not as Android-device evidence.

## Contract

| Stage | Requirement |
| --- | --- |
| Endpoint | Preserve wildcard/fixed listeners, port reuse, native TLS, and QUIC multiplexing |
| Outgoing | Resolve the destination using the actual local port, routing mark, address family, and source constraints before transmitting |
| Shared socket | Install source/interface selection on the individual connection; never rebind the listener for one peer |
| Incoming | Select the reply route before accepting; cancellation, including unpolled futures, ignores rather than refuses |
| Authentication | Capture the real TLS peer and current route lease; reject stale preparation |
| Admission | Bind the exact swarm CID through the existing admitted-muxer hook; rejected peers cannot create adopted owners |
| Hole punching | Preserve native bounded random probes, but apply the same source/interface policy before sending |
| Return | Reuse current route audits and exact Identify/capability validation before promotion and fallback drain |
| Retirement | Close the old CID, stop its transport maintenance, and preserve unrelated connections sharing its listener |

## Boundaries

- Optional transport hooks preserve upstream behavior when no policy is installed.
- TLS certificate validation, peer identities, protocol bytes, and JSON/Nix schemas remain unchanged.
- Source/interface selectors come from kernel routing, not a fixed Wi-Fi/Ethernet ranking.
- Destination-specific routes and explicitly bound source addresses remain authoritative.
- No policy lookup is performed per application packet; accepted selections live with the connection.
- Do not treat owned packet-plane QUIC tests as evidence for native control ownership.

## Optional Outgoing Retry Hook

| Boundary | Contract |
| --- | --- |
| Existing policies | Default `dial` calls `prepare` and the native operation once; `dial_timeout` preserves the configured deadline |
| Custom policy | May select successive immutable owners within a bounded outgoing dial; the transport supplies a fresh native handshake per operation |
| Native operation | Rechecks source/interface ownership, retains TLS authentication, and carries the selected owner into admission |
| Cancellation | Dropping the dial drops the selected owner and prevents subsequent policy attempts |
| Incoming paths | Accepted connections and hole-punch listeners retain their existing preparation and configured timeout |
| Errors | `ConnectionError::as_ref` exposes typed Quinn failures; callers need not parse diagnostic strings |

Four integration tests cover default-policy compatibility, failed preparation,
real source-selective UDP loss followed by TLS/payload recovery, and cancellation.
The proxy drops packets from one loopback source; it does not inject syscall errors.

This is Linux loopback evidence for an additive transport hook, not Android
Network/netd or full-handoff proof. The raw-transport fixture uses a synthetic
admission ID and does not claim that a Swarm assigned it.

```sh
nix develop -c cargo test --offline --locked --test native_quic_retry
```

## Required Evidence

1. Default native interoperability and TLS identity checks still pass.
2. Outbound handshakes and retransmits use the selected source/interface on shared endpoints.
3. Incoming cancellation emits no unselected refusal; sibling listener connections remain usable.
4. Exact authenticated swarm ownership exists for initiating and accepting connections and disappears on teardown.
5. Hole-punch role overrides retain their ports and enforce selection.
6. IPv4/IPv6 namespace cases verify preference changes, address replacement, return, and stale-result fencing.
7. Native QUIC-only DHT/AutoNAT/relay cases prove replacement and actual redundant-owner retirement.
8. Linux and both Android Nix source sets carry identical patches; Android release cross-checks pass.

## Source

The local `libp2p-quic` 0.13.1 copy retains the published source and manifest.
Its crates.io archive SHA-256 is
`9dcc597d70bf7f6f30cbe07081802c836184e48416e89e9ce73a0ba2c56a319e`.
Cargo cache markers and its unrelated standalone lock file are excluded.

## Component Evidence

| Check | Result |
| --- | --- |
| Quinn outgoing selectors | 3 passed: invalid selections, shared-port probes, retry/close isolation |
| Native library unit suite | 5 passed; default lifecycle and canceled hole-punch registry cleanup |
| Managed native QUIC | 7 passed; exact TLS/CID owners, source families, cancellation, stale-selection rejection, preparation bounds |
| Overlay controller | 33 passed; two isolated namespace checks run separately |
| Infrastructure controller | 9 passed; four isolated namespace checks run separately |
| Native QUIC source return | IPv4 and IPv6 passed with real TLS, on-wire source checks, DHT RPCs, and old UDP-port release |
| Existing TCP infrastructure return | DHT and configured/automatic relay-reservation cases passed |
| Nix source parity | Passed for Linux and both Android native source sets |

## Runtime Integration Verification

| Check | Result |
| --- | --- |
| Offline locked workspace, all targets | 2,342 passed across 20 suites; 74 ignored; zero failures |
| Linux physical routes, including opt-in namespaces | 49 passed |
| Overlay handoff, including opt-in namespaces | 35 passed |
| Infrastructure handoff, including opt-in namespaces | 13 passed |
| DHT-discovered real-TUN ping | Passed |
| Relay-backed real-TUN ping | Passed |
| Workspace Clippy correctness/suspicious/performance | Passed; advisory warnings remain |
| Android arm64 release cross-check | Default and diagnostics/demand-lifecycle-trial variants passed |
| Root/native formatting and whitespace | Passed |

The first core run overlapped a rebuild of its own executable. Two subprocess
tests could not re-execute that replaced file. A non-overlapping core rerun and
the final workspace run passed without weakening their assertions.

The source-policy regression now distinguishes an explicit-source dial from a
wildcard dial instead of changing only the old dial-role flag on an accepted
lease. It retains the IPv4/IPv6 source-policy checks and zero-packet assertions.

Verification reused one existing target cache, approximately 6.4 GiB, with two
build jobs and no incremental/debug artifacts. No new APK, live deployment,
full Nix package/VM build, or energy comparison was performed for this stage.
The six prolonged packet-plane/TCP/circuit TUN route-return cases were not rerun.

The namespace source-return fixtures run in isolated user/network namespaces.
They change a kernel route's preferred source A-to-B-to-A; they do not prove
two-interface WAN migration, Android execution, or modem-energy improvement.

IPv6 address assignment creates an implicit metric-0 local destination route.
The fixture removes that exact route before installing its selected-source
route; otherwise the kernel correctly ignores the test's lower-priority route.

## Recovery Selection

- One bounded round per peer covers mixed TCP and native QUIC owners.
- Preserve LAN locality, interleaving transport choices within that locality so one transport cannot consume every attempt.
- Record the selected candidate's actual protocol; only that candidate's exact authenticated owner can validate it.
- Cross-transport fallback is allowed, but a TCP proof is never reported as native QUIC evidence.
- Require the union of the stale owners' identified services before public-service promotion.
- Preserve native work, circuit dependencies, destination-specific paths, and fallback service through validation and bounded draining.

## Native Service Fixtures

### Circuit Ownership Diagnostics

`control_relay_circuit_owned` is emitted once at circuit establishment, only
when the real inner-CID binding has an exact live, adopted physical owner.

| Field | Meaning |
| --- | --- |
| `peer`, `connection_id` | Authenticated overlay peer and local inner circuit CID |
| `relay`, `outer` | Relay peer and exact local physical CID carrying the circuit |
| `physical_transport`, `source`, `interface` | Native TCP/QUIC transport and its owned local socket route |
| `generation` | Lease generation, not a fresh preferred-route validation proof |

Missing, mismatched, unadopted, or revoked owners suppress the event. A sibling
connection cannot substitute. TCP/QUIC loopback tests verify both circuit roles,
pinned outer selection, and closure without resurrecting stale bindings.

Connection IDs are process-local. Receiver-side evidence must correlate the
authenticated peer and observed socket tuple, not compare CIDs across hosts.

### Service Cases

| Case | Required evidence |
| --- | --- |
| Configured and automatic reservations, IPv4/IPv6 | Initial A, replacement B, return A; native QUIC owner and source confirmed on both endpoints |
| Reservation promotion | Incoming readiness preserved; exactly one replacement listener, pinned to the confirmed replacement connection |
| Incoming access | Fresh third peer authenticates a relayed circuit and pings on its exact CID before and after each move |
| Incoming physical binding | Destination's real circuit binding identifies the expected relay and exact QUIC reservation connection |
| Reservation retirement | Old listener and local/remote owner disappear; old local UDP tuple becomes bindable |
| AutoNAT, IPv4/IPv6 | Five distinct successful probe IDs: initial, before/after retirement on B, and before/after retirement on A |
| AutoNAT dispatch | Native pending-request APIs identify the exact outgoing and incoming connection owners; siblings cannot substitute |
| AutoNAT dial-back | Real QUIC dial-back connections and correlated successful responses, not cached public status |

### Results

| Check | Result |
| --- | --- |
| Final infrastructure suite, including isolated namespaces | 19 passed, zero failures; includes all eight QUIC namespace cases |
| Final core library suite | 1,897 passed; 32 ignored; zero failures |
| Clippy correctness/suspicious/performance | Passed; test-size/style advisories remain |
| Formatting and whitespace | Passed |

Production source, defaults, and user configuration are unchanged in this test
addition. It reuses the existing target cache, approximately 6.4 GiB. Android
cross-checks, the full workspace run, and TUN cases above belong to the preceding
runtime-integration stage; they were not rerun for this test-only addition.

### Proof Limits

- Automatic mode seeds acquisition bookkeeping, then verifies migration. It does not prove automatic relay acquisition.
- Incoming probe circuits close before route transitions. Fresh access is proven; migration of an existing long-lived circuit is not.
- Pre-retirement AutoNAT probes hold the controller at its promotion boundary while both native Swarms continue polling.
- Initial and post-retirement AutoNAT probes drive the controller normally. Native dial-back siblings close before the next probe so they cannot hide a failed owner selection.
- Fixture-only probe timers and relay rate-limit settings permit bounded isolated runs; production settings are unchanged.
- These are kernel source-route changes on one interface, not two-interface WAN or physical-device evidence.

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --offline --locked --lib \
  physical_infrastructure_handoff -- --include-ignored --test-threads=1
```

## Unverified Integration

- The Linux strict IPv6 and long-lived circuit milestone is verified below; it does not close the full platform acceptance matrix.
- AutoNAT and reservation source-route fixtures do not establish two-interface migration or complete concurrent-drain behavior.
- Native circuit two-interface movement covers IPv4/IPv6 and both initial roles. Address replacement, simultaneous endpoint moves, and broader transport/role coverage remain open.
- Android integration, available-device traffic evidence, and the separate controlled energy comparison remain open.
- The complete physical-network acceptance matrix is not satisfied by these component checks.

## Strict IPv6 Isolation

Packet capture reproduced old-source traffic leaving the wrong interface despite
`IPV6_PKTINFO`. A retained lower-priority route did not fix that kernel behavior.
Source correctness alone is therefore not physical-interface evidence.

| Property | Implementation |
| --- | --- |
| Isolation | Immutable `SO_BINDTOIFINDEX` socket per selected IPv6 source/interface and endpoint port |
| Shared receive path | Fair fan-in from the original socket and live companions; insertion wakes a pending receiver |
| Resource bound | At most 32 live route entries per endpoint; weak pooling, no polling timer |
| Socket reuse | Same-UID `SO_REUSEPORT`; do not enable `SO_REUSEADDR` or change the base's device binding |
| Lifetime | Connection and writable poller retain selected I/O through drain, then release it even with closed handles retained |
| Failure | Unsupported or conflicting selections fail closed; terminal I/O errors notify callers and retire endpoint ownership once |
| Hole punching | Retain only the prepared I/O guard through incoming upgrade; free the preparation permit before acquiring another |
| Compatibility | Unselected and IPv4 sockets do not acquire companions or change reuse options; wire protocol and user configuration unchanged |

Preparation occurs before creating selected protocol connections. A prepared
probe rejects endpoint rebind or close. Selected rebind must prepare compatible
I/O or terminate; it cannot silently discard source/interface selection.

## Native Circuit Migration

| Fixture check | Required evidence |
| --- | --- |
| Matrix | IPv4/IPv6, initially outgoing/incoming circuits, primary to alternate and back |
| Transport isolation | Native QUIC relay only; owned datagrams and direct packet-stream counters remain zero |
| Blocked preferred path | Distinct bounded retries while the original circuit still carries complete payload samples |
| Automatic recovery | Remove only the preferred-path firewall block, without another route event |
| Promotion | Exact inner/outer binding, authenticated replacement, actual source/interface, and a fresh relay-side tuple observation |
| Continuity | Payload checks continue through admission, validation, promotion, and retirement waits |
| Cleanup | Old inner/outer close; dedicated UDP port is released, shared listener is preserved |
| Quiet fallback | After bounded protocol drain, old bidirectional tuple counters stay unchanged for at least 16 seconds during payload |

The namespace fixture retains both links and source addresses. Its wrong-interface
drop remains enabled; removing it would hide the original IPv6 defect.

The fixture alone uses a 600-second/4-MiB circuit budget and a 480-second total
watchdog. Per-phase deadlines remain bounded. Production relay limits are unchanged.

### Delivery Evidence

| Check | Result |
| --- | --- |
| Final offline locked workspace, all targets | 2,354 passed across 20 suites; 84 ignored; zero failures |
| Native QUIC active-circuit migration | Four cases passed: IPv4/IPv6, initially incoming/outgoing, primary to alternate and back |
| Existing TCP active-circuit migration | Both roles passed on the final production source |
| Quinn unit harness | 34 passed; three upstream stress tests ignored; includes eight strict-pool regressions |
| Native libp2p QUIC unit harness | Five passed |
| Single-slot native hole punching | IPv4 and IPv6 passed; incoming TLS acquires ownership after preparation permit release |
| Overlay handoff with opt-in namespaces | 37 passed |
| Infrastructure handoff with opt-in namespaces | 20 passed |
| Android arm64 release compatibility | Default and diagnostics/demand-lifecycle-trial cross-checks passed; not Android policy implementation |
| Clippy correctness/suspicious/performance | Passed; advisory warnings remain |
| Nix source parity | Passed for Linux and both Android source sets |
| Root/changed-vendor formatting and whitespace | Passed; unrelated upstream import-formatting differences were left unchanged |

The first four-case delivery run passed three cases. The fourth failed before
traffic: the initiator's startup wait was shorter than parent reservation setup.
Its bounded setup-only wait was corrected; the targeted rerun passed in 332 seconds.

An initial workspace run also exposed an existing raw-TCP relay test race between
transport address announcement and behaviour reservation confirmation. The test
now waits for both within its existing deadline, retaining exact-owner assertions.

Migration deadlines and payload/owner/interface assertions were not weakened.
Exact receiver-side tuples, zero wrong-interface packets and at least 16 seconds
of retired bidirectional-tuple silence are required during continued payload.

Verification reused one target cache, approximately 6.5 GiB after removing
superseded executable copies. Standalone vendor harnesses used cached test-only
dependency adapters; production sources and assertions were not substituted.

No full Nix package/VM build, APK deployment, physical-device test or energy
comparison was performed. Older-kernel support, cross-UID port-collision rejection
and sustained receive/churn stress are not established by these runs.

These cases do not prove WAN performance, simultaneous endpoint movement,
Android integration, or battery savings. P2-P11 remain subject to their complete
acceptance requirements, with Android implementation taking priority next.

## Platform Network Binding Primitive

This additive vendor API carries real platform socket ownership, not just
source/interface metadata. Existing owners default to no platform binding.
It does not itself install an Android backend or complete Android handoff.

| Boundary | Contract |
| --- | --- |
| Identity | Binding identity distinguishes Network incarnation and record revision |
| Preparation | Bind a fresh socket before local bind, QUIC Initial, or hole-punch transmission |
| Pool | At most 32 weak Network entries per endpoint, separate from Linux strict IPv6 routes |
| Sharing | Reuse the endpoint port, not its mutable routing mark; preserve same-UID port isolation |
| Receive | Fair original/companion receive fan-in, including existing Linux strict companions |
| Lifetime | Retain binding and selected I/O through handshake, use, rebind and protocol drain |
| Failure | Reject unsupported bindings; never downgrade to interface-only or unselected I/O |
| Diagnostics | Preserve the first terminal error when implicit cleanup follows a transport failure |
| Compatibility | Existing endpoint methods delegate without binding; old `Selection` literals and owners remain valid |

### Primitive Verification

| Check | Result |
| --- | --- |
| Quinn unit harness | 47 passed; three upstream stress tests ignored |
| Added coverage | 13 Quinn tests for identity, bounds, real loopback receive/TLS, rebind, cancellation and drain |
| Native library unit harness | Six passed, including existing owners and `Selection` literals without binding |

Network tests use host binding callbacks, not Android netd. They verify the
acquisition/lifetime contract, not Android Network routing or cellular behavior.
The original rebind test exposed cleanup overwriting the transport error with
`LocallyClosed`; the production fix and exact-error/retirement assertions passed.

### Platform-Owned Routing

Android Networks can use virtual CLAT interfaces that differ from the base
interface in public LinkProperties. A Network-bound socket must retain that
platform decision instead of forcing the base index through packet info.

| Binding API | Default | Platform behavior |
| --- | --- | --- |
| `uses_platform_routing()` | `false` | Concrete-source socket sends without source/interface packet-info overrides |
| `ipv6_scope_id()` | `None` | Explicit link-local source scope survives wildcard endpoint acquisition |
| Immutable key | Identity, source and interface | Also snapshots routing mode and explicit scope |
| Conflict handling | Fail closed | Reject callback mutation, conflicting scopes, cache retargeting and incompatible rebind |

- Linux/default forced-interface behavior is unchanged.
- Interface metadata is still validated; it is not used as an invented platform scope.
- Unscoped platform link-local acquisition fails before the binding callback.
- Socket ownership, receive fan-in, resource bounds and drain semantics remain unchanged.

| Verification | Result |
| --- | --- |
| Final Quinn harness | 63 passed; three upstream stress tests ignored |
| Added platform coverage | 16 tests covering both families, dual-stack receive/TLS, probe/rebind, immutable mode/scope and retirement |
| Scope-specific proof | Exact link-local bind plans and conflict rejection; host loopback checks immutable ownership |

The deliberately nonexistent metadata index in loopback tests establishes that
platform sends do not force that index. These tests do not bind a real Android
Network or prove CLAT, device link-local routing, mobile energy or full handoff.
