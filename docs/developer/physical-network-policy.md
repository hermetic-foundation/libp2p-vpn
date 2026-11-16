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
- Owned packet-plane QUIC has route selection and authenticated replacement validation; native libp2p QUIC control-owner integration remains open.
- Dual-stack multicast scope, transport ownership, and complete fallback retirement remain open.
- No device deployment or battery improvement is implied by this Java selection change.
- Linux public-service TCP has [exact-role migration](infrastructure-connection-controls.md#linux-infrastructure-handoff), [reservation handoff](infrastructure-connection-controls.md#relay-reservation-handoff), and [active circuit handoff](infrastructure-connection-controls.md#circuit-handoff-design).
- Broader transport-owner integration, physical-device evidence, and the separate energy comparison remain open.

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
| Unbound lookup | Destination and UID; suitable for discovery's multicast selection |
| Socket-context lookup | Source/destination addresses, UDP/TCP protocol, actual ports, socket mark, UID, and optional bound interface |
| No synthetic default | Do not interpret a public probe address's route as the general OS preference |
| Overlay exclusion | Reject routes selecting a caller-supplied owned interface index; do not silently bypass routing policy |
| Coalescing | Latest-value revision; 50 ms quiet window capped at 250 ms during continuous events |
| Lookups | At most four concurrent requests; two-second deadline; no Internet packets |
| Stale results | Check generation after lookup and again before using a retained decision |
| Cleanup | Driver aborted on drop; explicit shutdown awaits exit |
| Failure | Closed monitor or generation exhaustion invalidates observations |
| Abandoned lookup | Cancellation or timeout retires the observer to release pending library requests |

The observation component alone does not choose a host-wide default, bind transports,
authenticate a peer path, or promote a preferred path. The Linux discovery
integration below consumes it; transport acceptance requirements remain open.

- Socket-sensitive authorization must use the actual socket context, not the unbound discovery lookup.
- IPv6 link-local destinations require a consistent interface scope; the socket-context lookup validates it, while the unbound API rejects it.
- Explicit nexthop-object notifications are not yet supported by the cached route parser.
- Discovery owns LAN-link admission; the outgoing QUIC socket owner separately recreates retired route observers on demand.
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
- Socket-context lookup now supports source, mark, protocol, ports, and interface; discovery still uses the separate multicast lookup.
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
- Linux outgoing QUIC now retains source-bound route leases across this lifecycle; event-driven reconciliation of existing paths remains open.
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

### Linux QUIC Source Ownership

| Property | Implementation |
| --- | --- |
| Automatic integration | Linux runtime enables route ownership for wildcard, ephemeral owned-QUIC listeners; no new JSON/Nix options |
| Explicit listeners | A specific address or fixed port retains the existing dial socket and source-port semantics |
| Selection | Query the actual peer destination, source address, reserved port, UDP protocol, socket mark, and effective UID |
| Socket preparation | Reserve the source port without sending packets, bind a new socket to the selected source and interface, then release the reservation |
| Binding policy | Bind by interface index; older-kernel fallback uses its kernel-reported name, never an unbound socket |
| Final check | Recheck bound-socket routing and unbound-interface preference before handing the socket to Quinn |
| Ownership lifetime | Retain the route lease with the connection through candidate staging, promotion, drain, and rollback |
| Stale fencing | Check observer identity/generation after TLS, before key installation, and before candidate authentication can promote |
| Failure | Reject the candidate, preserving a working active connection; normal negotiation owns retries and transport fallback |
| Metadata | Received client-side frames report the actual source-bound socket address rather than the original wildcard listener |
| Work bounds | Four preparations, a two-second preparation-queue deadline, and sixteen connecting attempts per runtime |
| Observer recovery | Recreate unavailable observers on demand; a lease from the old observer cannot become current after generation numbering restarts |

The source owner does not treat the mDNS interface as an Internet default.
Each destination/family gets its own kernel decision, so LAN-specific routing
can remain on LAN even when the Internet default uses another network.

- This stage changes outgoing Linux QUIC dials, not accepted listener connections or Android socket binding.
- At this source-ownership stage, existing paths were not yet reconciled from route events; the following stage adds source-bound Linux client reconciliation.
- UDP, TCP/libp2p, DHT, AutoNAT, relay ownership, IPv6 multicast, and full redundant-underlay retirement remain open.
- New source-bound client sockets use a reserved ephemeral port. Physical NAT/hole-punch interoperability still needs certification.
- No physical-device, production-deployment, or battery-improvement claim follows from these socket checks.

### Linux Source Verification

| Check | Result |
| --- | --- |
| Workspace libraries and binaries | 2049 passed; 15 opt-in/platform tests ignored |
| Pairing CLI and authorization | 6 passed |
| Namespace fixture/helper tests | 61 passed; 34 opt-in scenarios initially ignored |
| Focused Linux checks | 24 passed, including three real kernel namespace fixtures |
| Routed QUIC checks | 2 passed, including isolated stale-install/promotion rejection with active data preserved |
| Unprivileged binding | Loopback source/interface binding and packet delivery passed without added capabilities |
| Socket-context policy | Kernel protocol/port/mark selection, IPv4/IPv6 sources, IPv4 address replacement/loss/return, and owned-interface rejection passed |
| Resource boundaries | Preparation waits without opening sockets; connecting-attempt limits release capacity; abandoned observers are recreated |
| Explicit listener compatibility | Fixed ports and specifically bound addresses keep their existing dial socket |
| Real-TUN transport scenarios | 6 passed in 295 seconds: minimal QUIC, UDP-only, stream-only, startup block, address change/return, and live block/recovery |
| Peerless code pairing | Additional real-TUN pairing/connectivity check passed in 13 seconds |
| Android arm64 | Normal and diagnostic/demand-lifecycle-trial workspace cross-checks passed |
| Static/source checks | Clippy correctness/suspicious/performance, Nix source ownership, formatting, and whitespace passed |

The startup firewall fixture previously assumed the dial socket used the
listener port. It now blocks non-data/non-mDNS UDP output in the isolated
namespace, covering both QUIC directions while preserving TCP control.

The fixture also requires zero QUIC payload during blocking, positive packet-drop
counters, UDP payload delivery, and autonomous QUIC payload delivery after
restoration. It does not disable route ownership to make the test pass.

- All checks reuse the existing target cache, now 9.7 GB, with two build jobs and no incremental/debug information.
- Existing project-wide advisory warnings remain; the new source-owner/path modules add none in the checked production targets.
- No new APK, live service, personal NixOS configuration, physical WAN trial, full NixOS VM build, or energy measurement was deployed/run.
- P4-P8 and P10-P11 remain open: source-bound dials are not automatic reconciliation and retirement of every existing transport.

### Linux QUIC Route Events

| Component | Behavior |
| --- | --- |
| Integration | Linux runner owns an abort-on-drop reconciler sharing the dial-route observer |
| Trigger | Coalesced kernel changes; no additional periodic path polling |
| Snapshot | Established source-owned paths only; not a per-packet peer scan |
| Work | One latest snapshot, one bounded event channel, at most four concurrent checks |
| Decision | Re-evaluate destination/family with UDP ports, mark, UID and destination scope; compare selected source/interface |
| Compatible routes | Gateway/table-only changes do not recreate a socket that can follow the new route on its existing source/interface |
| Stale results | Fence observer generation, active connection lifetime token/ID, and live peer endpoint before requesting replacement |
| Replacement | Normal signed Hello/Accept, certificate pinning and authenticated candidate reception; active fallback remains installed |
| Initiation | Either end can initiate its own route replacement; simultaneous proposals retain the lower-ID transcript |
| Retry | Existing per-peer QUIC retry interval and demand/authorization gates; observer failures and contended local lookups use bounded backoff |
| Preferred validation | Use owned outbound egress; reverse acceptance cannot masquerade as preferred-path success |
| Retirement | Existing receive-only drain closes replaced QUIC connections; protocol/socket closure must also be checked |

- Kernel rechecks do not emit data, discovery queries, keepalives, or probes.
- Lifetime tokens prevent identifier-reuse races without retaining retired connection or socket handles.
- A route lookup is not proof of peer reachability; only authenticated candidate reception can promote.
- No JSON/Nix setting, new wire field, private key, membership record, or TUN address changes.
- Explicit source/fixed-port listeners retain their previous override semantics.

#### Remaining Scope

- QUIC remote-address migration without a kernel event still needs destination-policy reconciliation.
- IPv6 source selection is checked independently; complete IPv6 multicast and physical migration certification remain open.
- UDP/libp2p TCP/QUIC, DHT, AutoNAT, and relay policy integration remain open, including adoption of shared Linux overlay exclusion.
- Active-session expiry still needs independent candidate-lifetime handling; seamless handover across key expiry is not certified.
- Android deployment, available-device traffic checks, and the separate energy comparison remain open.
- No holistic acceptance row is closed by the Linux source-bound client work alone.

#### Route-Event Verification

| Check | Result |
| --- | --- |
| Workspace libraries/binaries, pairing CLI, authorization, and namespace helpers | 2122 passed; opt-in/platform tests run separately where applicable |
| Focused Linux checks | 28 passed, including real IPv4/IPv6 route preference, IPv4 source replacement, event fencing, and observer recovery |
| QUIC handover checks | 14 passed, including real source-bound connections, lifetime-token fencing, reverse-path rejection, and stale candidate rejection |
| Minimal-config real-TUN scenarios | 7 passed in 386 seconds: QUIC, UDP-only, stream-only, startup/live blocking, address movement, and route preference/return |
| Peerless code pairing | Passed with resulting overlay connectivity in 13 seconds |
| Android arm64 libraries | Default and diagnostic/demand-lifecycle-trial release cross-checks passed |
| Static/source checks | Clippy correctness/suspicious/performance, Nix source ownership, formatting, and whitespace passed |
| Build storage | Existing 9.7 GB target reused; two build jobs, no incremental/debug artifacts or new cache |

The route-preference fixture keeps both links and source addresses available.
Its peer endpoint stays unchanged while the preferred source/interface changes.
Each service check requires all five packets and subsequent QUIC payload growth.

- The preferred-path firewall block must cause a failed attempt without promoting a reverse fallback or disrupting the active path.
- Removing only that block must trigger autonomous retry and authenticated promotion, without another route event or manual reconnect.
- Restoring the original route must promote its source again and close the retired client socket within a bounded deadline.
- IPv4/IPv6 kernel rechecks require zero transmitted packets and no periodic wake while settled.
- Identifier-reuse and stale-generation decisions cannot refresh another connection lifetime.

The initial fixture exposed a second advertised peer endpoint, violating its
unchanged-endpoint premise. Link-local transit gateways now leave one advertised
peer endpoint reachable through both links; the endpoint assertion stays intact.

The packet-counter fixture now reads namespace-local netlink statistics, not
host-mounted sysfs. A contention assertion also exposed overbroad error mapping;
busy lookups now retain their type and retry locally without requesting a dial.

- Existing project-wide advisory warnings remain; the new production route modules add none in the checked targets.
- No full NixOS VM/package build, new APK, physical-device deployment, personal flake update, or energy measurement was performed.
- ADB listed no attached device at this stage; Linux work continued rather than marking the goal blocked.
- No formal-verification setup exists; these checks are executable evidence, not a formal kernel/protocol proof.

Reproduce the kernel policy and stable-endpoint route-return checks separately:

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --lib runtime::physical_network::linux -- --include-ignored

CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --test tun_namespace \
  tun_namespace_minimal_quic_follows_route_preference_and_returns \
  -- --ignored --exact --nocapture
```

### Linux Accepted QUIC Ownership

| Component | Behavior |
| --- | --- |
| Reply selection | Kernel UDP route lookup using the received destination IP, shared listener port, peer endpoint, mark, and UID |
| Physical ownership | Immutable per-connection interface, encoded in each transmit's packet-info metadata |
| Shared listener | No device-wide bind/rebind; other peers and incoming reception remain available |
| Pending paths | Accepted route leases remain owned through binding dispatch, candidate staging, promotion, drain, and rollback |
| Change triggers | Coalesced kernel events plus path-install/promotion notifications; no new periodic peer polling |
| Assigned aliases | Retain the incoming source when it is still assigned and its reply interface already matches OS preference |
| Source policy | Recheck the concrete reply source before preserving an alias; source-specific rules can select another interface |
| Preferred validation | Requires locally dialed preferred egress; reverse acceptance cannot complete that validation |
| Cancellation | Ignore managed incoming attempts on preparation failure or cancellation, including an unpolled queued handshake |
| Compatibility | Existing wire protocol, minimal config, and explicit listener overrides are unchanged |

The [Quinn interface patch contract](quic-interface-patches.md) records upstream
versions, additive APIs, fail-closed send behavior, and source-package ownership.
The library extension alone does not apply policy to unmodified libp2p callers.

- Native IPv4, IPv6, and IPv4 on dual-stack listeners have dedicated ownership checks.
- Invalid families, unsupported backends, invalid indices, and cancellation must not emit an unselected refusal.
- A second accepted peer must remain usable after the first connection retires.
- The acceptor route fixture keeps the old shared listener open and requires zero packets through its wrong-interface guard.
- Both route fixtures require fallback service while preferred TLS is blocked, autonomous retry, and authenticated return.

#### Accepted-Path Verification

| Check | Result |
| --- | --- |
| Standard workspace set | 2,128 passed; opt-in/platform cases accounted separately |
| QUIC ownership and error paths | 6 passed: explicit overrides, IPv4/IPv6/dual-stack ownership, shared listener, cancellation before/during polling, unsupported backend, and invalid families |
| Focused Linux checks | 30 passed, including IPv4/IPv6 source-rule redirection, policy return, alias removal, and zero-packet route checks |
| QUIC handover checks | 14 passed, including source ownership and stale-generation cases |
| Minimal-config real-TUN scenarios | 8 passed in 472 seconds; final acceptor rerun after lint cleanup passed in 91 seconds |
| Peerless code pairing | Passed with resulting overlay connectivity in 13 seconds |
| Android arm64 libraries | Default and diagnostic/demand-lifecycle-trial release cross-checks passed |
| Static/source checks | Clippy correctness/suspicious/performance, formatting, whitespace, and Nix source ownership passed |
| Build storage | Existing target reused at 3.9 GiB, two build jobs, no incremental/debug artifacts or new cache |

- Standard counts are 1,817 core, 161 CLI, 72 Android-native, 11 fixture, 5 pairing-CLI, 1 authorization, and 61 namespace-helper tests.
- Standard runs leave 53 opt-in/platform cases skipped; the focused and real-TUN runs above exercise selected cases explicitly, not all 53.
- Review found and fixed unselected refusal paths, mapped-address handling, Android's signed IPv6 index field, and accepted-source policy reconciliation.
- No new warning remains in the changed production modules; existing project-wide advisory warnings remain.
- No full NixOS VM/package rebuild, APK, physical-device deployment, personal flake update, or energy measurement was performed.
- A local-only dependency preflight planned 859 fetch/unpack/vendor derivations; that separate dependency tree was not built.
- No Android device was attached when checked; Linux verification continued without marking the goal blocked.
- There is no formal-verification setup; these are executable regression checks, not a formal kernel or protocol proof.

The remaining transport, IPv6 migration, Android-device, and energy requirements
above stay open. Shared Linux overlay ownership is implemented separately below;
no holistic P1-P11 row is closed by these component stages alone.

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --lib runtime::physical_network::linux -- --include-ignored

CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --test tun_namespace \
  tun_namespace_minimal_quic_acceptor_follows_route_preference_and_returns \
  -- --ignored --exact --nocapture
```

### Linux Cross-Instance Overlay Ownership

Native startup now marks its TUN before overlay routes are installed. The route
monitor rejects marked TUN egress, and QUIC preparation excludes source addresses
owned by other instances. Kernel metadata follows renames without a registry file.

- Exact marker and TUN-kind checks avoid excluding every VPN or guessing from interface names and address ranges.
- An overlay-selected multicast route still permits eligible interface-bound LAN discovery.
- Unmarked third-party VPN routes and sources remain eligible underlays.
- The configured-name exclusion remains for local legacy setups; older instances need a binary restart to register their marker.
- Unmodified UDP/libp2p transports still need policy adoption; this metadata does not bind their sockets automatically.

See [Linux Overlay Ownership](linux-overlay-ownership.md) for the lifecycle
contract, bounds, reproducible checks, and current verification results.

### Linux Control Transport Ownership

Linux TCP control transport ownership is tracked in
[Linux Control Transport Ownership](linux-control-transport.md). Established
control-plane failback and the holistic acceptance rows remain open.

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
