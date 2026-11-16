# Infrastructure Connection Controls

## Status

These native APIs are prerequisites for physical-network migration.
They do not yet enable an infrastructure handoff controller.
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
| `tests/autonat_work.rs` | Exact owner selection, disabled-owner completion, dial-back response-channel ownership, invalid pairs, quiet timers, client pause |

The private observation tests compile the unchanged production owner source.
Metadata-only handler tests are not physical-route migration evidence.
Socket cases separately exercise the linked production dependencies.

### Recorded Checks

| Check | Result |
| --- | --- |
| Offline locked workspace, all targets | 2,277 passed; 68 ignored; no failures |
| Exact Kademlia and AutoNAT ownership cases | 16 passed |
| Linux physical routes, managed TCP, and handoff cases | 77 passed |
| Isolated DHT-discovered and relay TUN ping cases | Both passed |
| Workspace Clippy correctness, suspicious, and performance groups | Passed; existing advisory warnings remain |
| Root and changed native-source formatting | Passed |
| Nix Rust test-source ownership check | Passed |
| Android default release cross-check | Passed |
| Android diagnostics and demand-lifecycle-trial release cross-check | Passed |

These checks validate native controls and existing paths, not an enabled
infrastructure migration controller or physical-device failback.

## Remaining Integration

1. Add a separate infrastructure migration owner using current role and dependency records.
2. Validate the exact candidate's identity, service support, current route epoch, and ownership.
3. Keep candidate Identify failures and Kademlia unsupported-protocol notifications from invalidating a healthy sibling or its peer role.
4. Enable the replacement, exclude the fallback, drain exact work, and verify actual socket removal.
5. Preserve configured relays, pending reservations, active circuits, and incoming reachability until their own migration is proven.

Do not treat wider overlay eligibility, successful routing-table lookup, or
asynchronous close requests as proof of infrastructure migration.
