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

1. Migrate configured and automatic relay reservations while preserving incoming reachability.
2. Replace active fallback circuits before releasing their outer connections when still needed.
3. Extend integration evidence across physical interfaces, IPv4/IPv6, and the remaining transport owners.
4. Complete Android/device validation and the separate controlled energy comparison.

Do not treat wider overlay eligibility, successful routing-table lookup, or
asynchronous close requests as proof of infrastructure migration.

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
Reservation and circuit transfer remains integration work; those owners stay protected.

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
- Relay dependencies protect required old owners; their existence is not proof that relay migration has completed.

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
