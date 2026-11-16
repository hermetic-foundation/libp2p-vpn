# Physical Network Policy

## Status

Implementation in progress. This document defines the acceptance contract, not a claim that the current runtime satisfies it.

## Default Contract

| Traffic | Selection |
| --- | --- |
| Public discovery, relays, and Internet peer paths | Current OS-preferred physical route for the destination and address family |
| Direct LAN peer traffic | OS destination-specific route; do not force a LAN destination through an Internet gateway |
| mDNS queries and replies | Selected eligible physical LAN only; never cellular or p2p-vpn overlay interfaces |
| Fallback maintenance | Only while needed for recovery or incoming reachability; no redundant indefinite maintenance |

- No additional JSON or Nix configuration is required.
- Network preference comes from the OS, not a fixed Ethernet/Wi-Fi/cellular ranking.
- An interface being up does not prove that it has a usable authenticated peer path.
- IPv4 and IPv6 can have different usable routes. A change in one family must not invalidate unrelated healthy paths blindly.
- Preserve explicit listen-address configuration; wildcard listeners do not authorize unsolicited transmission on every interface.

## Selection Inputs

| Platform | Required inputs |
| --- | --- |
| Android | OS default/underlying physical network identity, link addresses, capabilities, availability, and loss events |
| Linux | Link, address, and routing changes; destination-specific route decisions including policy routing and route metrics |
| Shared runtime | Physical-network generation, eligible source addresses, per-peer path ownership, and validation results |

- Exclude our own overlay from underlay selection and discovery.
- Do not classify cellular solely by address ranges: carrier addresses and overlay addresses can overlap.
- Treat a newly available network as inventory, not automatic permission to transmit on it.
- Keep stale callback and connection results from restoring an obsolete selection.

## Path Transitions

| State | Action | Exit condition |
| --- | --- | --- |
| Preferred usable | Send through preferred path; retain only necessary incoming infrastructure | Failure or OS preference change |
| Recovering | Attempt eligible fallback with bounded retries and LAN-first recovery | Authenticated fallback succeeds or no route remains |
| Fallback active | Maintain service; react to preferred-route return | Preferred candidate becomes eligible |
| Preferred validating | Continue fallback service while validating preferred candidate | Authenticated success, failure, timeout, or newer generation |
| Preferred promoted | Stop new fallback application sends and drain bounded in-flight work | Redundant fallback connections and maintenance retired |

- Validation must prove authenticated peer reachability on the candidate physical network.
- Do not promote solely from an interface-up event, cached address, or successful routing-table lookup.
- OS preference changes supersede an originally preferred interface; do not pin that original interface forever.
- Rate-limit flapping and failed validation. Prefer events and bounded retry schedules over periodic probes on all available networks.
- Necessary destination-specific LAN paths and incoming relay anchors are not redundant fallbacks.
- Preserve membership, identity, TUN addresses, DNS, pairing, and protocol compatibility across transitions.

## Native Reconciliation

1. Capture a consistent selection generation and eligible addresses.
2. Reconcile overlay and pairing mDNS tasks, send sockets, multicast reception, and advertised addresses.
3. Associate UDP, QUIC, TCP, public discovery, AutoNAT, and relay work with their selected underlay.
4. Reject stale completions and stop scheduling new work on retired underlays.
5. Validate and promote replacement paths before retiring working fallback service where possible.
6. Expire redundant fallback probes, keepalives, sessions, and connections after bounded cleanup.

Abrupt loss can require invalidation before a replacement exists. Preferred-route return must not use that disruptive loss path as a substitute for validated failback.

## Diagnostics

- Report the selected physical network, eligible discovery interfaces, generation, and last transition reason.
- Count validation attempts, preferred promotions, stale results, and retired fallback resources.
- Expose pending cleanup and its bounded deadline.
- Use bounded snapshots and transition logs; do not add high-frequency diagnostic polling.
- Exclude keys and raw packet contents from evidence.

## Acceptance Matrix

All rows remain open until linked evidence demonstrates the complete behavior described.

| ID | Requirement | Evidence required | State |
| --- | --- | --- | --- |
| P1 | OS preference, not fixed transport priority | Android callback/tracker tests and Linux route-selection tests | Open |
| P2 | Destination-specific and IPv4/IPv6 routing preserved | Multi-route namespace/VM tests | Open |
| P3 | Discovery excludes cellular and overlay | Query/reply tests and interface-level device evidence, including pairing mDNS | Open |
| P4 | Automatic fallback | Induced route loss with successful authenticated recovery and incoming access | Open |
| P5 | Automatic validated return | Preferred path restored while fallback carries traffic; no manual intervention | Open |
| P6 | Full redundant fallback retirement | No new fallback payload/probes/keepalives after cleanup; bounded resource counters | Open |
| P7 | Address replacement and stale events | Tests for same-interface address changes, out-of-order callbacks, and obsolete validation completions | Open |
| P8 | Stable behavior under flapping | Bounded attempts, memory, and timers across repeated transitions | Open |
| P9 | Existing workflows preserved | Minimal config, Nix module, pairing, DNS, membership, LAN-first, and transport regression checks | Open |
| P10 | Android integration | Authorized device deployment, traffic checks, incoming/outgoing access, failover and return | Open |
| P11 | Energy effect evaluated separately | Same-build reversible control, accepted screen-off windows, modem/front-end counters, and explicit uncertainty | Open |

## Energy Investigation

- Previous Wi-Fi-default observations found cellular-source mDNS sends and local multicast receive duplication.
- A VPN-off/on control found substantially different modem/front-end power; it did not isolate the responsible subsystem.
- Syscall fault injection was rejected by Android app seccomp and terminated the app. Do not reuse it or weaken security protections.
- Use a debug-only, automatically expiring, exact-target control for selective testing within one build.
- Verify that the control changes only intended traffic and preserves connectivity before collecting energy windows.
- Use equal settling/measurement durations, reversed or counterbalanced order, and explicit rejection criteria.
- Report hardware rail energy separately from Android app attribution and whole-device discharge.
- No numerical battery target, including 10x, is a prerequisite for completing this network-policy implementation. Report a missed target honestly and re-evaluate afterward.

## Delivery

| Stage | Deliverable |
| --- | --- |
| 1 | Policy, Android OS-directed selection, and platform-independent transition tests |
| 2 | Physical-network snapshots and event-driven Linux/Android native integration |
| 3 | Interface-scoped discovery and transport source/path ownership |
| 4 | Validated promotion, bounded fallback retirement, and reproducible multi-interface tests |
| 5 | Physical-device verification, controlled energy comparison, and final requirement audit |

### Selection Progress

- Android tracker now separates physical inventory from OS default selection.
- Service registers and unregisters a default callback in addition to physical inventory callbacks.
- Tracker tests cover OS preference overrides, fallback/return, repeated events, and stale loss handling.
- Android address-generation and native mDNS admission are implemented; physical-device verification remains open.
- Linux runners and profile-free pairing now supply route-selected IPv4 LAN discovery admission automatically.
- QUIC replacement validation is implemented; OS-directed path selection and promotion remain open.
- Dual-stack multicast scope, transport ownership, and complete fallback retirement remain open.
- No device deployment or battery improvement is implied by this Java selection change.

### Discovery Library Progress

| Component | State |
| --- | --- |
| Exact source-address allowlist | Implemented in locally patched libp2p-mdns |
| Task retirement and behaviour cleanup | Explicit cancellation; asynchronous cleanup must still be accounted for |
| Readmission without another interface-up event | Implemented and checked on an assigned IPv4 address |
| Restricted mDNS address advertisements | Non-selected source addresses omitted |
| Linux/Android multicast receive scope | Global multicast reception disabled for each receiver |
| Nix source ownership | Linux and both Android native source filesets include the patch |
| OS selection wired into native allowlist | Android and Linux runtime/pairing integration implemented; Linux currently uses the IPv4 multicast route |
| Cross-interface packet evidence | Linux namespace query/reply checks implemented; physical-device verification still open |

Android now supplies selected physical source addresses through a native watch
channel. Linux runtime integrations start a route-selected discovery owner when
no explicit selection channel is supplied. Raw swarm builders remain low-level
APIs. Device packet evidence is required before claiming deployed behavior.

### Android Snapshot Connection

| Property | Contract |
| --- | --- |
| Input | OS-selected network kind, interface name, handle, link addresses, and generation |
| Shape | Private JNI JSON; maximum 8192 bytes and 64 distinct source addresses |
| Ownership | Immutable Java snapshot; native latest-value watch channel shared by active instances |
| Initial state | No admitted sources until selected LAN metadata is available |
| Ordering | Native publisher rejects duplicate or older generations |
| Source admission | Wi-Fi, Ethernet, or Bluetooth LAN addresses; never cellular/other/none |
| Address changes | Callback-driven generation update; same-network route changes also trigger existing recovery |
| Service recreation | Process-wide Java counter prevents generation reset while native publisher survives |
| Publisher loss | Discovery admission closes; no repeated closed-channel wake loop |
| Hot-path cost | Reconcile on generation or behaviour-presence change; no per-packet address-set rebuild |
| Observability | Generation, admitted-source count, and publisher state logged without raw addresses |

The native policy is applied before the runtime polls discovery. It is applied
again when pairing installs a new mDNS behaviour, even if the physical generation
has not changed. The integration does not restart the runtime to change discovery.

Profile-free code joining has its own bootstrap swarm and receives the same
subscription. The existing three-argument Rust join API remains available;
platform integrations can use the additive selection-aware entry point.

The existing `nativeNetworkChanged` recovery transaction is still separate and
disruptive. It must not be mistaken for the goal's validated failback mechanism.

### Library-Stage Verification

| Check | Result |
| --- | --- |
| Standalone mDNS unit tests | 13 passed; assigned-interface test is separate |
| Assigned-interface socket resume | Passed explicitly on the current Linux LAN address |
| Workspace library tests | 1763 core and 72 Android Rust tests passed; 9 platform tests ignored |
| Android arm64 mDNS cross-check | Passed with cached Nix Android compiler and standard library |
| mDNS Clippy correctness/suspicious/performance | Passed |
| Rust formatting and whitespace | Passed |
| Nix source inclusion | Linux and Android source evaluations include the patched crate |
| Nix `rust-test-sources` check | Passed, including Linux and both Android vendor-source comparisons |
| Nix formatting | Android expression passes; existing flake formatting debt confirmed on parent revision |
| Device and two-interface packet checks | Not yet performed for this patch |

An initial workspace test run failed a DNS bind with `Address already in use`.
The individual DNS test and final complete library rerun passed without changing
the test or DNS implementation. This remains a test-flakiness observation.

Standalone tests also exposed implicit upstream feature dependencies: identity
generation for tests and Tokio runtime support. These are now explicitly
declared; the production workspace already enabled Tokio runtime support.

All Rust checks reuse one existing target cache with two build jobs, incremental
compilation disabled, and host debug information disabled. No third build tree
or phone deployment was created for this stage.

### Snapshot Verification

| Check | Result |
| --- | --- |
| Snapshot publication and admission tests | 7 passed within the core suite |
| Core and Android Rust library suites | 1770 core and 72 Android tests passed; 9 platform tests ignored |
| Android Java tests | 151 passed across 33 classes, including 6 snapshot tests |
| Java main/debug compilation | Passed against cached Nix Android API 37 SDK |
| Android arm64 workspace cross-check | Passed, including JNI publication and profile-free bootstrap |
| Clippy correctness/suspicious/performance | Passed for workspace libraries; existing advisory warnings remain |
| Rust formatting and whitespace | Passed |
| Nix source ownership check | Passed for Linux and both Android native source sets |
| Linked APK, lint, device packet capture, and energy comparison | Not performed for this stage |

The full test compile caught a private helper missing the new optional selection
receiver argument. That call was corrected; the complete library suite then
passed. No test assertions were weakened.

The publisher validates before replacing state. A generation that is no newer
than the current value is a no-op. The watch channel retains only the latest
snapshot, including when no VPN runtime currently subscribes.

### Linux Route Observation

| Property | Contract |
| --- | --- |
| Events | Kernel link, IPv4/IPv6 address, route, and policy-rule notifications |
| Route decision | `RTM_GETROUTE` for the actual destination and effective process UID; not a main-table dump |
| Current lookup scope | Unmarked, unbound, locally originated sockets; no source, transport-port, or device constraints |
| No synthetic default | Do not interpret a public probe address's route as the general OS preference |
| Overlay exclusion | Reject routes selecting a caller-supplied owned interface index; do not silently bypass routing policy |
| Coalescing | Latest-value revision; 50 ms quiet window capped at 250 ms during continuous events |
| Lookups | At most four concurrent requests; two-second deadline; no Internet packets |
| Stale results | Check generation after lookup and again before using a retained decision |
| Cleanup | Driver aborted on drop; explicit shutdown awaits exit |
| Failure | Closed monitor or generation exhaustion invalidates observations |
| Abandoned lookup | Cancellation or timeout retires the observer to release pending library requests |

The observation component does not choose a host-wide default, bind transports,
authenticate a peer path, or promote a preferred path. The Linux discovery
integration below consumes it; transport acceptance requirements remain open.

- Mark-, source-, port-, and device-sensitive sockets need matching lookup context before authorization.
- IPv6 link-local destinations need an interface scope; the current unbound lookup rejects them.
- Explicit nexthop-object notifications are not yet supported by the cached route parser.
- Discovery owns monitor recreation/backoff and LAN-link admission; transport ownership still needs integration.
- Do not cancel in-flight lookups on every unrelated event; finish them, reject stale results, and recreate retired observers with backoff.
- Retained route observations belong to one observer lifetime. Discard them when recreating the observer; generations are not comparable across observers.
- A kernel route lookup proves a routing decision, not packet delivery or authenticated peer reachability.

The isolated kernel fixture uses two dummy underlays with different per-family
defaults. It changes only routes, rules, addresses, and links inside a fresh
user/network namespace. It sends no Internet or VPN traffic.

```sh
nix develop -c cargo test --locked --lib \
  runtime::physical_network::linux::tests::kernel_routes_follow_metrics_rules_loss_and_return \
  -- --ignored --exact --nocapture
```

### Linux Observation Verification

| Check | Result |
| --- | --- |
| Core and Android Rust library suites | 1780 core and 72 Android tests passed; 10 platform tests ignored |
| Final Linux component rerun | All 11 tests passed, including the normally ignored kernel namespace fixture |
| Isolated kernel route fixture | Passed explicitly, including both families' policy-rule changes |
| Ownership and cleanup | Overlay routes rejected; explicit shutdown and drop tested |
| Pending request cleanup | Cancelled/timed-out observations retire; completed kernel-error responses remain usable |
| Nix source ownership | Passed for Linux and both Android native source sets |
| Clippy correctness/suspicious/performance | Passed; no new-module warnings, existing repository advisories remain |
| Formatting and whitespace | Passed |
| Live runtime, Android deployment, packet ownership, and energy | Not verified by this component stage |

The kernel fixture caught missing table-identity reporting in the initial
request. Adding `RTM_F_LOOKUP_TABLE` preserved the actual policy decision and
made its selected table observable; the assertion was retained.

The fixture also exposed an incorrect assumption that restoring an IPv4
address restores the default route. It now checks fallback while that route
is absent and preference return only after the simulated OS restores it.

No existing test assertion was weakened. This stage reuses the existing build
cache with two jobs and disabled incremental/debug data. It does not change
the personal NixOS configuration or any live VPN service.

The final focused run followed mechanical Clippy style cleanup. The complete
workspace library suite passed before that cleanup. Full package builds and
Android device checks are still required by the later integration stages.

### Linux Discovery Integration

| Property | Behavior |
| --- | --- |
| Entry points | Normal Linux runtime runners and profile-free code joining |
| Defaults | Automatic unless an embedding supplies its own physical selection channel |
| Selection | Kernel route to `224.0.0.251`, including destination-specific route exceptions |
| LAN-only fallback | If the unbound lookup has no eligible LAN, validate an interface-bound multicast route; no gateway or installed route required |
| Unranked LAN ties | Stable kernel interface-index order, at most 16 eligible candidates; never transmit on every candidate |
| Scope | IPv4 mDNS queries/replies; retain usable IPv4/IPv6 address advertisements on the selected LAN |
| Source ownership | Selected link only; reject the owned TUN name, non-Ethernet and point-to-point links, unsupported tunnel kinds, and modem metadata |
| Device metadata | WWAN sysfs parents and known modem drivers supplement kernel link type; never infer from names or IP ranges |
| Link labels | Ethernet-like LAN admission includes Wi-Fi and supported local Ethernet link types |
| Addresses | At most 64 usable sources; omit tentative, failed-DAD, deprecated, expired, loopback, unspecified, and multicast addresses |
| Work bounds | Route choice and address dump have deadlines; at most 1024 links and 4096 address records scanned |
| Events | Refresh after coalesced kernel changes; no periodic lookup while healthy or without a route |
| Failure | Disable discovery on stale/unavailable observation; recreate broken monitors with 1–30 second backoff |
| Generations | Publication counter survives observer replacement; duplicate selections do not churn discovery |
| Lifetime | Runtime shutdown awaits owner and Netlink cleanup; cancellation/drop aborts owned work |
| Diagnostics | Bounded transition logs report generation, interface, LAN kind, and source count; no raw addresses |

The two-interface fixture injects real multicast queries and parses DNS
responses. It checks source ownership, advertisement filtering, suppression of
cross-interface replies, fallback, return, and retirement of old mDNS tasks.

```sh
nix develop -c cargo test --locked --lib \
  runtime::physical_network::linux -- --include-ignored
```

- No JSON/Nix configuration fields or persisted identities change.
- IPv6-only multicast discovery remains open; the vendored library still defaults to IPv4 and needs explicit IPv6 scope work.
- This does not migrate unicast UDP/QUIC/TCP sessions, DHT, AutoNAT, or relay connections.
- Source-, mark-, and port-sensitive route context remains a certification gap; the current kernel lookup supplies destination, UID, and optional multicast interface.
- Retiring discovery tasks is not evidence of authenticated data-path failback or complete fallback retirement.

### Linux Integration Verification

| Check | Result |
| --- | --- |
| Workspace library suites | 1786 core and 72 Android Rust tests passed; 11 platform tests ignored |
| Focused Linux suite | 18 passed, including both explicit kernel namespace fixtures |
| Packet-level scope | Queries, replies, advertised addresses, fallback, return, and old-source retirement checked on isolated links |
| Minimal real-TUN configurations | QUIC, UDP-only compatibility, and stream-only compatibility passed |
| Peerless code pairing | Real-TUN LAN pairing and resulting connectivity passed |
| Static checks | Workspace library/binary Clippy correctness, suspicious, and performance checks passed |
| Android arm64 | Workspace library cross-check passed, including JNI callers |
| Nix source ownership | Passed for Linux and both Android source sets |
| Formatting and whitespace | Passed |
| Deployment and energy | No phone APK or live service deployed; no battery-improvement claim |

The real-TUN fixture exposed a LAN-only startup gap: an unbound multicast
lookup can fail without a default route. The implementation now validates
interface-bound LAN routes instead of requiring a manually installed gateway.

The fixture also assumed node A must initiate. It now requires authentication
on both nodes and at least one automatic mDNS dial. Bidirectional packet and
backend assertions remain, with new checks that both runtimes apply admission.

The final namespace rerun followed a test-only correction: veth peer creation
order is kernel-defined. Expected fallback ordering now reads actual interface
indices rather than assuming the named endpoint has the smaller index.

All checks reuse the existing target cache with two build jobs. This stage adds
no configuration fields, modifies no personal NixOS configuration, and does
not certify the remaining transport migration or physical-device requirements.

### QUIC Handover Progress

| Component | Implementation |
| --- | --- |
| Connection/control ordering | Hold the new connection until its matching verified Accept is available; never reuse the old connection as completion evidence |
| Candidate validation | Fresh packet keys; authenticated, replay-checked datagram on the candidate's exact QUIC connection |
| Working-path preservation | Stage replacement without moving application data, keepalives, active keys, or path health |
| Probe ownership | Match peer, token, and connection; candidate failure or timeout cannot demote the active path |
| Receive drain | Retain original keys, age, and replay state for at most three seconds; reply to incoming probes on the connection that requested them |
| Cleanup | Candidate deadline 20 seconds; at most one candidate and drain per peer, with global limits of 16 for each |
| Rollback | Restore a still-live draining connection if the promoted connection fails before its drain deadline |
| Session expiry | Validation and drain deadlines are capped by the original configured key lifetime |
| Compatibility | Existing wire format, capability gating, identity, configuration, and legacy UDP/stream behavior retained |

Real loopback QUIC sockets exercise staging with bidirectional data, promotion,
failed/expired/superseded candidates, old replay rejection, rollback, and cleanup.
The runner fixture exercises both handshake arrival orders and old-connection
ACK rejection through the normal negotiation and probe handlers.

- This is a transport prerequisite, not completion of P4-P8.
- The OS route-generation controller and source-bound replacement endpoints are not yet connected to this lifecycle.
- UDP migration, libp2p stream/discovery/relay reconciliation, and complete redundant-underlay retirement remain open.
- No phone deployment, physical-network transition certification, or energy improvement is implied.

### QUIC Handover Verification

| Check | Result |
| --- | --- |
| Workspace libraries and binaries | 2042 passed; 13 opt-in/platform tests ignored |
| Pairing CLI and authorization integration | 6 passed |
| Namespace fixture/helper checks | 61 passed; 34 opt-in scenarios initially ignored |
| Explicit real-TUN scenarios | 6 passed: minimal QUIC, UDP-only, stream-only, startup block/recovery, address change/return, and live block/recovery |
| Peerless code pairing | Real-TUN LAN pairing and resulting overlay connectivity passed separately |
| Handover coverage | Both control/connection arrival orders, continued old-path data, authentic old-path ACK rejection, and session-install failure covered |
| Negative and lifetime coverage | Candidate failure, expiry, supersession, replay, rollback, cancellation, and extreme configured lifetimes covered |
| Android arm64 workspace | Normal and battery-diagnostic/demand-lifecycle-trial cross-checks passed |
| Static analysis | Workspace library/binary Clippy correctness, suspicious, and performance checks passed; existing advisory warnings remain |
| Nix source ownership | Linux and both Android source sets passed |
| Formatting and whitespace | Passed |

The six explicit namespace scenarios completed in 199 seconds. They cover
existing single-LAN/address-movement workflows, not the remaining multi-interface
OS preference, full redundant-underlay retirement, or physical-device gates.

No full NixOS VM build, new Android APK, live service deployment, or energy
measurement was performed for this handover stage. Checks reuse the existing
target cache, two build jobs, and disabled incremental/debug information.

### Initial Selection Verification

| Check | Result |
| --- | --- |
| Main and debug Java compilation | Passed against cached Nix Android API 37 SDK and generated resource jar |
| All Java unit suites | 145 tests passed across 32 test classes, including 15 tracker tests |
| Diff whitespace check | Passed |
| Full Gradle/lint/package build | Not yet run for this stage |
| Native/OS callback/device behavior | Not yet verified; remains an acceptance gate |

The bounded Java check reuses cached Nix JDK 17, the SDK, JUnit, JSON, and the
Gradle-generated mockable Android jar. It does not rebuild native libraries.

The first manual full-suite invocation omitted the generated resource jar and
failed one test with `NoClassDefFoundError`. The corrected classpath passed all
145 tests; no test assertions were weakened.

### Platform Reference

Android default callbacks describe the calling application's default, which can
be physical or virtual. Our own VPN excludes the app UID, and virtual candidates
are rejected. See [ConnectivityManager default callbacks](https://developer.android.com/reference/android/net/ConnectivityManager#registerDefaultNetworkCallback(android.net.ConnectivityManager.NetworkCallback,%20android.os.Handler)).

- Keep builds bounded in job count and retained storage.
- Use atomic Conventional Commits through Jujutsu; verify and push each completed change to `main`.
- Do not count a foundation module or green narrow test as completion of native integration.
