# Infrastructure Connection Controls

## Status

Linux now has a separate infrastructure TCP handoff controller using these native APIs.
It validates exact authenticated replacements before draining public-service fallbacks.
The [physical-network acceptance matrix](physical-network-policy.md#acceptance-matrix) remains open.

## API Contract

Both local Kademlia and AutoNAT v1 patches expose these methods:

| Method | Purpose |
| --- | --- |
| `set_connection_outbound_enabled(peer, connection, enabled)` | Control future outbound request selection on a known matching connection |
| `has_pending_requests_on_connection(peer, connection)` | Inspect exact transport work without polling, allocating, or performing I/O |

- Unknown connections and mismatched peer/connection pairs return `false` without creating work.
- Disabling a connection does not cancel or move its queued or in-flight work.
- Inbound requests, pinned replies, and protocol maintenance still work on disabled connections.
- There are no new protocol bytes, configuration fields, identities, or user-managed routes.

## Selection Semantics

| Component | Enabled selection | All connections disabled |
| --- | --- | --- |
| Kademlia | Lowest-ID enabled live connection; dispatch names its exact ID | Hold RPCs in the existing pending-RPC queue; no replacement dial for a still-connected peer |
| AutoNAT | Existing request-response selection among enabled connections | Preserve request-response's existing dial-and-queue behavior |

- Connections start enabled; Kademlia replaces unspecified `Any` dispatch with explicit connection ownership.
- Re-enabling a Kademlia connection schedules eligible unassigned RPCs; existing owned requests stay pinned.
- AutoNAT preserves the request-response contract: re-enabling does not move requests already waiting in its dial queue.
- A controller must enable a validated replacement before excluding the last usable fallback.

## Kademlia Ownership

| Work location | Accounting |
| --- | --- |
| Behaviour action queue | Exact `One(connection)` notifications remain owned before dispatch |
| Swarm dispatcher | Count dispatched actions until their handler accepts them |
| Handler | Track pending messages, negotiation, active streams, and rejection work |
| Handler-to-behaviour delivery | Keep emitted notifications busy until the behaviour receives them |
| Mode changes | Include scheduled mode updates and pinned commands |
| New handler preloading | Register ownership before delivering pending RPCs directly to the handler |

- Publish codec and dispatcher handovers atomically; there is no observable idle gap between those queues.
- Keep one fixed-size observation beside each existing connection record; do not create a separate unbounded owner registry.
- Handler drop marks the observation dead; behaviour polling removes dropped records, including rejected adoption.
- Cleanup scans run only after a handler-drop signal; unchanged idle observations take no mutex lock.
- Drain accounting fails closed on counter exhaustion until the connection record is discarded.
- Unassigned peer-level RPCs and completed query metadata are not exact-connection transport work.

### Service Support

- Protocol confirmation is stored beside the exact live connection record.
- An unsupported replacement cannot mark a still-supporting sibling disconnected in the routing table.
- Closing the last supporting connection marks the routing entry disconnected, even if an unsupported transport sibling remains.
- Unknown, mismatched, and dropped handlers cannot change a peer's protocol-support state.
- This tracks native protocol reports; it does not replace exact physical-route and identity validation.

## AutoNAT Ownership

- Forward selection and exact request accounting to the existing patched request-response behaviour.
- Request ownership includes active codecs, request/reply channels, and queued request-response notifications.
- An inbound probe awaiting its dial-back remains busy through its response-channel owner.
- Exact request accounting excludes unassigned dial queues and outer semantic probe notifications.
- Global `has_pending_work` remains available; exact request idleness is not proof that every AutoNAT operation has finished.
- Client probe pause and incoming server operation retain their existing independent semantics.

## Verification

| Fixture | Coverage |
| --- | --- |
| `tests/kad_connection_resources.rs` | Exact dispatch, defaults, exclusion/re-enable, unassigned RPCs, preloading, terminal delivery, sibling isolation, counter exhaustion |
| Kademlia socket case | Two real Noise/TCP/Yamux connections; enabled sibling handles the RPC; disabled server connections still reply and drain |
| Kademlia service-support socket case | Same authenticated identity with compatible and incompatible services; unsupported sibling preserves confirmed service; last-supporting close updates the routing status |
| `tests/autonat_work.rs` | Exact owner selection, disabled-owner completion, dial-back response-channel ownership, invalid pairs, quiet timers, client pause |

The private observation tests compile the unchanged production owner source.
Metadata-only handler tests are not physical-route migration evidence.
Socket cases separately exercise the linked production dependencies.

### Native API Baseline

| Check | Result |
| --- | --- |
| Offline locked workspace, all targets | 2,278 passed; 68 ignored; no failures |
| Exact Kademlia and AutoNAT ownership cases | 17 passed |
| Service-support socket regression repetition | Five additional runs passed |
| Linux physical routes, managed TCP, and handoff cases | 77 passed |
| Isolated DHT-discovered and relay TUN ping cases | Both passed |
| Workspace Clippy correctness, suspicious, and performance groups | Passed; existing advisory warnings remain |
| Root and changed native-source formatting | Passed |
| Nix Rust test-source ownership check | Passed |
| Android default release cross-check | Passed |
| Android diagnostics and demand-lifecycle-trial release cross-check | Passed |

This table records verification before infrastructure-controller integration.
It is not evidence of physical-device failback. Controller checks are listed below.

### Relay Fixture Limitation

- One follow-up relay run rejected authentication after a physical-route generation change and never produced `ready-b`.
- The fixture waits for relay readiness before starting the runner, so its normal recovery loop was not active in this failure.
- An unchanged rerun passed. This does not demonstrate that the startup race is fixed.
- Retain this case when improving startup/recovery coverage; do not weaken stale-route authentication checks to make it pass.

## Remaining Integration

1. Complete native libp2p QUIC service/role coverage beyond the [Linux ownership and DHT source-return fixtures](libp2p-quic-physical-ownership.md). Owned packet-plane QUIC is separate.
2. Extend coverage to IPv6 circuit migration, simultaneous endpoint moves, and remaining role/transport owners.
3. Complete Android/device validation and the separate controlled energy comparison.

Do not treat wider overlay eligibility, successful routing-table lookup, or
asynchronous close requests as proof of infrastructure migration.

## Circuit Handoff Design

Linux TCP-backed circuit handoff is implemented and verified by the checks below.
The full physical-network acceptance matrix remains open; this is not a claim
of complete transport coverage, Android execution, or energy improvement.

| Proof | Required evidence |
| --- | --- |
| Physical relay transport | Exact authenticated relay identity, current kernel route epoch, adopted source lease and required relay service |
| Overlay circuit | Authenticated remote overlay identity and exact local physical owner captured before Noise consumes the raw circuit |
| Connection ID | Register the circuit binding through the existing post-admission muxer hook, never by FIFO or address correlation |
| Replacement pin | Bind a real pending circuit request to the validated physical owner before native behaviour dispatch |
| Overlay validation | Capabilities accepted on that exact replacement circuit for the expected network and membership context |
| Promotion | Publish the validated circuit as the packet path, then exclude new sends on stale circuit owners |
| Retirement | Drain old circuit work, observe circuit teardown, and then permit otherwise idle physical owners to close |

### Cancellation And Compatibility

- A pending dial owns its pin/cancellation lifetime; never-submitted IDs must not accumulate permanent tombstones.
- Dropped or mismatched pinned owners fail closed, without switching physical connections or redialing the relay implicitly.
- Preserve the existing unpinned transport behavior and Noise/Yamux wire protocols.
- Reuse the existing bounded TCP validation, retry, epoch, and drain lifecycle rather than adding a second recovery loop.
- A circuit's successful validation is not proof that its physical owner serves public DHT/AutoNAT roles.
- A tracked fallback with a fresh exact-owner audit showing a valid route leaves retirement tracking and regains usable sends.
- Unknown audits and already-retiring owners still require resolution or observed closure; recovered routes are logged as released, not retired.

### Receiver Ownership

- The sender's pin controls only its local physical relay connection.
- The relay server independently chooses the receiver's reservation; verify the receiver's binding separately.
- Keep necessary old incoming paths until their replacements are validated. Reservation confirmation alone cannot prove live circuit migration.

### Required Regression Evidence

1. Concurrent identical-address dials keep their exact pins across preference changes.
2. Authenticated incoming/outgoing bindings exist at establishment and disappear on teardown.
3. Cancellation, rejected admission, closed owners, and failed replacement preserve the working path without leaking resources.
4. Relay-only TUN payload survives two-interface preference changes and return, on both the outgoing and incoming sides.
5. Old physical sockets actually disappear after old circuits drain; a close-request log is insufficient.

### Circuit Handoff Checks

| Check | Result |
| --- | --- |
| Offline locked workspace, all targets | 2,324 passed across 20 suites; 72 opt-in tests ignored by default; no failures |
| Native circuit identity, alternatives, cancellation, and authenticated mapping | 12 passed against the production dependency graph |
| Standalone native relay unit source | 16 passed, including admitted-I/O locking/waker and reservation-drain checks |
| Existing native relay ownership, dependencies, and reservation drain | 15 passed unchanged |
| Explicit Linux physical-network cases | 49 passed, including normally ignored namespace cases |
| Explicit control handoff cases | 27 passed, including recovered-drain capacity release and observer/audit cases |
| Explicit public-service and reservation source-route return | Two passed |
| Real-TUN physical route preference and return | Six passed: QUIC, TCP, and relay, each initiating and accepting; 649.77 seconds total |
| DHT-discovered and forced-relay TUN ping | Both passed |
| Android default and diagnostics/trial release cross-checks | Both passed; no device deployment |
| Workspace Clippy correctness, suspicious, and performance groups | Passed; advisory warnings remain |
| Root/native formatting, whitespace, and Nix Rust-source parity | Passed |

- Relay TUN cases keep both interfaces usable, change preference away and back, and check payload plus old established-socket removal.
- Recovered-drain tests preserve a currently valid exact binding without calling it retired; unknown, stale, or retiring owners remain fenced.
- A temporary standalone manifest compiles unchanged vendored relay unit source with cached dependencies; production-lock integration is checked separately.
- The full workspace includes real bilateral dormancy, first-packet wake, and QUIC-to-relay recovery regressions.

No phone was attached. APK/device tests, energy measurements, and full Nix
package/VM builds were not run. An offline package dry run scheduled 1,433
derivations, including bootstrap tooling; that build was not started locally.
All Rust work reused one shared target cache, approximately 5.1 GiB.

### Relay Dependency Boundary

| Dependency | Required protection before retirement |
| --- | --- |
| Configured reservation or relay-server mode | Preserve until its own migration is proven |
| Automatic reservation setup | Include pending reservations, setup dials, and listener owners, not only native confirmation |
| Confirmed reservation | Preserve its exact owning connection |
| Active or negotiating circuits | Track the backing outer connection; an inner circuit ID is not its owner |
| Pairing relay, pairing probe, or live membership probe | Respect its separate ownership and deadline |

The [native dependency query](relay-connection-dependencies.md) includes pending
work and circuit leases. Confirmation queries alone still exclude pending work.
TCP reservation transfer uses the lifecycle below. Active circuits protect
their backing connection until exact circuit replacement and teardown complete.

### Authenticated Endpoint Reuse

Automatic relay admission can reuse the exact authenticated outbound destination
already reached, without trusting unrelated private advertisements. See the
[ownership and privacy rules](demand-lifecycle-incoming-anchor.md#authenticated-endpoint-reuse).

## Relay Reservation Handoff

| Stage | Action |
| --- | --- |
| Admission | Use an exact authenticated current-route candidate from infrastructure or overlay TCP validation |
| Binding | Create a separate listener pinned to that physical connection; changes in peer-wide preference cannot redirect it |
| Confirmation | Require exact listener ownership, native reservation confirmation, current route epoch, and required Identify services |
| Promotion | Replace configured/automatic listener ownership atomically while incoming readiness remains available |
| Old reservation | Stop its renewals and reservation-only keepalive; preserve STOP acceptance and live circuit/codecs |
| Retirement | Exclude new native sends, wait for exact work to drain, then close and observe physical owner removal |
| Failed replacement | Keep the old reservation; quiesce uncertain assigned setup against a confirmed working anchor before closing it |
| Late success | Never promote a stale route; retain it only if it is the remaining authenticated incoming anchor |

### Ownership And Bounds

- Reservation operations outlive their parent route rounds until native ownership settles.
- A timeout alone cannot cancel a reservation that may already have committed remotely.
- Keep at most eight concurrent moves and 64 retry budgets.
- Allow three attempts per route epoch; apply cooldown and require a genuinely new address after exhaustion.
- Retired records track existing physical owners and are released after their close is observed.
- Ignore retired listener events when updating replacement readiness or advertisements.
- The existing driver tick advances work; no independent timer or per-interface probe loop is added.

### Evidence Scope

- The namespace test changes a real TCP source route A → B → A for configured and automatic reservations.
- It checks continuous incoming readiness, exact replacement binding, and old physical-owner removal.
- Native socket tests separately cover a live old circuit, shared advertised addresses, and failed replacement cleanup.
- This is not proof of active circuit migration, full physical-interface failback, Android execution, or battery savings.

### Reservation Handoff Checks

| Check | Result |
| --- | --- |
| Offline locked workspace, all targets | 2,304 passed across 19 suites; 70 ignored; no failures |
| Native binding/drain socket and dispatch regressions | Seven passed |
| Existing native relay ownership/dependency cases | Eight passed unchanged |
| Explicit namespace public-service and reservation source-route return | Two passed; configured and automatic ownership exercised |
| Explicit Linux physical-network namespace cases | Nine passed |
| Explicit overlay handoff observer/audit cases | Two passed |
| Forced-relay and DHT-discovered TUN ping | Both passed |
| Minimal TCP TUN preferred return, acceptor return, and retry exhaustion/rearm | Three passed |
| Android default and diagnostic/trial release cross-checks | Both passed |
| Workspace Clippy correctness, suspicious, and performance groups | Passed; advisory warnings remain |
| Root/native formatting and Nix Rust-source check | Passed |

These checks use the final implementation, including cancellation protection
and current-anchor selection during aborted-move cleanup. No phone was attached
at validation time. No APK, production service, or energy run was changed.

Excluded vendored unit tests and full Nix package/VM builds were not run.
Root integration tests exercise the linked production relay implementation.

## Linux Infrastructure Handoff

| Property | Implementation |
| --- | --- |
| Trigger | Current route inspection requests replacement of an adopted public-service TCP owner |
| Role evidence | Identify reports stored in the existing exact connection record; wrong identities cannot populate it |
| Validation | Expected Noise identity, exact Identify reply/service set, current route observer and generation, adopted outbound source lease |
| Service coverage | Replacement must cover the services on all stale connections it will replace |
| Promotion | Enable supported native Kademlia/AutoNAT sends, prefer future relay work, then exclude stale owners |
| Drain | Inspect exact native work; close unprotected fallbacks after drain or the 20-second deadline |
| Completion | Observe native owner/socket removal, not merely a successful close request |
| Observer loss | Preserve validated service; pause retirement until current audits are available |
| Lost fallback | Preserve an already owned recovery attempt even if the peer-level role record disappears |
| Identity/role changes | Restore usable sends and hand ownership back to the appropriate lifecycle |

### Bounds

- At most 64 rounds and four concurrent replacement dials.
- Wait for one second of stable route generation before starting a round.
- Three attempts per round; shared exponential backoff and at most 16 cached candidate addresses.
- Exhaustion waits for a fresh generation or genuinely new address; elapsed time alone does not rearm work.
- Reuse only a freshly authenticated, current-generation outbound candidate with the required services.
- No new protocol bytes, user configuration, timer task, or per-interface network probe loop.

### Regression Scope

- Stateful dispatch checks cover unsupported/failed candidates and stale sibling generations.
- An isolated namespace replaces an actual kernel source route A→B→A, validates Noise/Identify, exchanges DHT RPCs, and observes old TCP owners disappear.
- That source-route test is not proof of multi-device WAN behavior or full physical-interface failback.
- Overlay TCP handoff now excludes and drains native DHT/AutoNAT work sharing its connections as well.
- Reservation handoff can release an otherwise idle old owner. Live circuit dependencies still protect it until their own handoff completes.

### Controller Checks

| Check | Result |
| --- | --- |
| Final offline locked workspace, all targets | 2,294 passed; 69 ignored; no failures |
| Targeted Linux routes, transport, handoff, retention, and Identify dispatch | 93 passed, including explicitly selected namespace cases |
| Native relay dependency cases | Six passed, including real TCP circuit handoff/drop |
| DHT-discovered and forced-relay TUN ping | Both passed |
| Overlay TCP preferred-route return, dialer and acceptor | Both passed |
| Android default and diagnostic/trial release cross-checks | Both passed; no device deployment |
| Workspace Clippy correctness, suspicious, and performance groups | Passed; advisory warnings remain |
| Root/native formatting and Nix Rust source ownership | Passed |

All source checks above used the version including the authorized-overlay
Identify guard. No full Nix package/VM build or physical-device/energy run was
performed for this controller change. The acceptance matrix remains open.
