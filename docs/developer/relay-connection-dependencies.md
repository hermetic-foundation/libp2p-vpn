# Relay Connection Dependencies

## Contract

`relay::client::Behaviour::has_connection_dependencies(peer, connection)`
reports whether native relay work still needs an exact physical connection.

| Included owner | Lifetime |
| --- | --- |
| Assigned reservation/circuit command | Pending physical dial, behaviour dispatch, and handler acceptance |
| Exact circuit pin | Selection of an established outer owner through native command dispatch or cancellation |
| Substream negotiation | Queued request and swarm-owned open info |
| Reservation | Request codec, accepted reservation, and renewal |
| Incoming circuit | Negotiation, stop codec, rejection, and listener handoff |
| Outgoing circuit | Hop codec and dialer handoff |
| Relayed connection | Until the returned connection object is dropped |

- Ownership moves with RAII leases; stream handoff does not create an idle gap.
- Unknown, mismatched, closed, and inner-circuit IDs do not identify a live physical owner.
- The getter reads existing observations without I/O, allocation, timers, or retention changes.
- Counter exhaustion fails closed until the owning record is removed.

## Boundaries

- Unassigned transport requests have no physical owner yet.
- Inbound work cannot be observed before the swarm exposes it to the handler.
- Before protocol selection, inbound negotiation conservatively protects the physical owner.
- Closing a relayed stream is not the same as dropping its connection object.
- The dependency getter neither transfers reservations nor migrates existing circuits.

## Exact Circuit Ownership

| API | Contract |
| --- | --- |
| `pin_circuit_dial(peer, inner, relay_peer, outer) -> Option<CircuitDialPin>` | Constrain an existing pending inner dial to a known established direct outer connection of that relay |
| `circuit_connection_owner(peer, inner) -> Option<(PeerId, ConnectionId)>` | Return the actual local relay peer and physical outer CID of a live authenticated inner connection |
| `Connection::circuit_binding()` | Capture the raw connection's ownership sidecar before authentication |
| `CircuitBinding::wrap_muxer(authenticated_peer, muxer)` | Associate that sidecar with the exact inner CID at swarm admission |

Build dial options and save their inner CID, submit the dial successfully, then
pin immediately before the next swarm poll. Retain the returned guard during
setup. Synchronous behaviour admission records the actual pending attempt before
deferred DNS or transport futures run; an unknown or wrong-peer CID cannot
allocate an intent. A pin must precede native assignment. An invalid target for
a matching pending peer/CID cancels that attempt instead of permitting default
selection. Pin once per attempt: repeating a pin is not idempotent, and the API
is not a way to redirect an already assigned connection.

When multiple relays were explicitly offered, a valid pin selects the matching
relay branch and cancels the others. The constraint also rejects unmatched late
behaviour-extended or deferred relay branches without a default selection or
physical redial. Wholly unpinned alternative dialing retains its existing
selection and physical-dial behavior.

The getter checks the authenticated overlay peer and inner CID, not a physical
relay CID presented as an inner connection. It returns `None` for unknown,
mismatched, closed, or absent physical owners. Inbound and outbound circuits use
the same admission hook; the mapping is available at `ConnectionEstablished`.
Installing the tagged authenticated relay transport is required for that map.

### Local And Remote Owners

The outgoing pin selects only the sender's local outer connection. The relay
server independently chooses a reservation for the receiving peer and supports
multiple reservation CIDs for that peer. The receiver's incoming mapping records
the actual local outer on which STOP arrived. A successful sender pin does not
prove the receiver moved off its old outer connection.

Controllers must combine the exact local map with physical route ownership and
current route-epoch validation before promoting or retiring a binding. Neither
peer-wide relay preference nor an advertised address is an ownership proof.

## Cancellation And Admission

| State | Drop/cancellation behavior |
| --- | --- |
| Pending, not dispatched | Guard drop cancels the request and releases the pin's outer dependency lease |
| Native negotiation or codec in flight | Cancellation prevents admission, but negotiation and codec leases remain until their actual completion or drop |
| Authenticated and admitted | Guard drop cannot cancel the established circuit; the raw connection retains its dependency lease |
| Real swarm attempt finishes | Establishment or dial failure removes its admission records; losing one alternative does not cancel its siblings |
| Raw owner/muxer drops or swarm observes closure | The live inner ownership mapping is removed; stream-object lifetime still determines dependency release |

Metadata follows real pending attempts and existing native owners, not arbitrary
caller IDs. Standalone raw dial futures also reclaim their registrations. There
are no permanent never-submitted cancellation tombstones or timer tasks.

Registry scans retain upgraded strong references until after unlocking. Owner
getter temporaries and removed admission records also drop outside the registry
critical section. Pin selection and cancellation flags are applied atomically
under the registry lock, but wakeups occur after unlocking. Pending status and
association locks are released before cleanup reacquires the registry, avoiding
reentrant drop and reversed-lock-order deadlocks.

Admission and cancellation serialize on pending status, with one authoritative
admitted atomic. Once admitted, raw circuit I/O checks that atomic and skips
intent-mutex locking and waker registration. This is a hot-path invariant, not
an energy measurement.

## Exact Listener Binding

| Method | Contract |
| --- | --- |
| `pin_reservation_listener(peer, listener, connection)` | Bind an existing live listener request to an established direct connection before native dispatch |
| `reservation_listener_connection(peer, listener)` | Read the actual assigned physical owner, including a pending physical dial |

- A pin survives changes in peer-wide connection preference; a vanished owner never falls back silently.
- Unknown listeners, wrong peers, and invalid connections cannot allocate bindings.
- An assigned listener cannot be redirected; repeating its exact binding is allowed.
- Closing a queued listener prevents its request from performing I/O or replacing another listener.

## Reservation Draining

| Method | Contract |
| --- | --- |
| `begin_reservation_drain(peer, old, replacement)` | Quiesce a pending or accepted reservation against a distinct confirmed replacement for the same peer |
| `is_reservation_draining(peer, connection)` | Include requested policy awaiting handler delivery; unknown owners return false |

- Stop reservation-only keepalive and future renewals, not live circuits or codec work.
- Keep the old listener available for incoming STOP requests until its physical owner closes.
- Track the drain command itself as a dependency until the handler applies it.
- Late renewal completion cannot restart maintenance on a draining connection.
- A normal new reservation request can reactivate that connection.
- Closing the old owner must not expire an address still advertised by its replacement.

The relay server has no reservation-cancellation message. Removing a local
listener alone does not withdraw its server-side reservation. Controllers must
preserve acceptance until the corresponding physical connection can close.

## Regressions And Physical Evidence

| Regression source | Intended invariant |
| --- | --- |
| `tests/relay_connection_dependencies.rs` | Exact physical selection, command/negotiation/codec leases, failure cleanup, and live raw TCP circuit lifetime |
| `tests/relay_reservation_drain.rs` | Exact listener binding, cancelled requests, invalid drain pairs, live circuits, idle release, and failed replacements |
| `tests/relay_circuit_ownership.rs` | Deferred admission, concurrent same-peer ownership, pin/preference races, alternative rejection/default compatibility, synchronous cancellation cleanup, and authenticated teardown |
| Native circuit unit test | Admitted raw I/O does not lock pending status or replace its waker |

The runtime combines this native query with configured reservations, pairing,
relay-server policy, and its own setup/listener records before retiring a socket.

These entries describe regression coverage, not final verification results.
Reservation draining does not move an existing circuit. Circuit migration
requires a new authenticated inner connection, exact local outer verification,
overlay validation/promotion, and controlled retirement of proven stale local
bindings. Real-TUN physical migration evidence must separately show traffic and
actual closure; native loopback regressions or close-request logs alone do not
establish that outcome. No broad completion or battery claim is made here.
