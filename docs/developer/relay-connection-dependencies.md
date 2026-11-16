# Relay Connection Dependencies

## Contract

`relay::client::Behaviour::has_connection_dependencies(peer, connection)`
reports whether native relay work still needs an exact physical connection.

| Included owner | Lifetime |
| --- | --- |
| Assigned reservation/circuit command | Pending physical dial, behaviour dispatch, and handler acceptance |
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

## Coverage

`tests/relay_connection_dependencies.rs` exercises six cases:

1. Exact selection before dispatch and preference changes.
2. Multiple commands sharing one owner without premature release.
3. Pending physical dials, failure cleanup, and handler handoff.
4. Inner circuit IDs excluded from physical ownership.
5. Negotiation, failed requests, inbound open info, and closed owners.
6. Real TCP reservation and circuit streams retained through handoff and released on drop.

The runtime combines this native query with configured reservations, pairing,
relay-server policy, and its own setup/listener records before retiring a socket.

`tests/relay_reservation_drain.rs` adds exact-binding, cancelled-request,
invalid-pair, live-circuit, idle-release, and failed-replacement socket cases.
These contracts do not migrate active circuits to another outer connection.
