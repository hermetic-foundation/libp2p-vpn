# Native QUIC Physical Ownership

## Status

Implementation in progress. This is the native libp2p TLS/stream transport,
not the separate owned packet-plane QUIC implementation. No device or energy
result is implied by this design.

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

- Native QUIC-backed long-lived active-circuit migration still needs dedicated physical fixtures.
- AutoNAT and reservation source-route fixtures do not establish two-interface migration or complete concurrent-drain behavior.
- Two-interface movement, address replacement, simultaneous endpoint moves, and full role coverage remain open.
- Android integration, available-device traffic evidence, and the separate controlled energy comparison remain open.
- The complete physical-network acceptance matrix is not satisfied by these component checks.
