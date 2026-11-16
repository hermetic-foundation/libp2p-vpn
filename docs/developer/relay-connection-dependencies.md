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
- This API neither transfers reservations nor migrates existing circuits.

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
