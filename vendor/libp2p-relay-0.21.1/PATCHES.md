# Local Patch

Base: crates.io `libp2p-relay` 0.21.1. Archive SHA-256:
`d8b9b0392ed623243ad298326b9f806d51191829ac7585cc825c54c6c67b04d9`.
Wire protocols, existing event variants, and user configuration remain unchanged.

## Reservation And Dependency APIs

| Surface | Local contract |
| --- | --- |
| Confirmed reservation IDs | Read native owners, excluding drain-requested reservations |
| Direct connection preference | Select a known authenticated direct owner for future unpinned work; do not transfer existing ownership |
| `has_connection_dependencies(peer, connection)` | Query RAII command, negotiation, codec, reservation, and raw circuit leases for an exact physical owner |
| `pin_reservation_listener(peer, listener, connection)` | Bind an actual live listener before assignment; cancellation before dispatch performs no I/O |
| `reservation_listener_connection(peer, listener)` | Read the exact assigned owner, including a pending physical dial |
| `begin_reservation_drain(peer, old, replacement)` | Drain a pending or confirmed source against a distinct confirmed non-draining same-peer replacement |
| `is_reservation_draining(peer, connection)` | Include policy awaiting handler acceptance without creating unknown-owner records |

Draining drops reservation-only keepalive and future renewals, not the listener,
incoming STOP acceptance, circuits, or in-flight codec leases. The drain command
itself owns a lease until handler acceptance. Late reserve completion cannot
restart maintenance. A normal reservation request can reactivate the owner.
An old physical close preserves any address retained by another confirmed,
non-draining owner.

## Exact Circuit Bridge

| API | Contract |
| --- | --- |
| `pin_circuit_dial(peer, inner, relay_peer, outer) -> Option<CircuitDialPin>` | Pin a real pending inner dial to an established matching direct outer owner |
| `circuit_connection_owner(peer, inner) -> Option<(PeerId, ConnectionId)>` | Return the live authenticated inner connection's exact local relay/outer association |
| `Connection::circuit_binding()` and `CircuitBinding::wrap_muxer(peer, muxer)` | Carry native ownership through authentication into the admitted muxer's exact swarm CID |

Submit `Swarm::dial` successfully, then pin immediately before the next swarm
poll, retaining the guard through setup. Synchronous
`handle_pending_outbound_connection` admission records the real CID and offered
relays before lazy transport futures run. Unknown and wrong-peer IDs allocate
nothing. Invalid targets for a matching pending peer/CID cancel rather than
falling back; already assigned requests cannot be redirected.

A valid selection among offered relays cancels the other branches. CID-wide
constraints reject unmatched late deferred or behaviour-extended relay branches
without default selection or physical redial. Entirely unpinned alternative
dialing keeps legacy behavior. Admission records end with the actual swarm
attempt; losing one address future does not cancel its siblings. No permanent
never-submitted-ID tombstones are retained.

The pin selects the sender's local outer only. The relay server independently
selects the receiving peer's reservation and supports multiple reservation CIDs
for a peer. Both inbound and outbound authenticated streams tag the actual local
outer; a sender pin is not proof of receiver-side migration.

## Adapter And Lifetime Requirements

The accompanying core/swarm patches add
`Transport::dial_with_connection_id(addr, opts, usize)`, adapter forwarding, and
a typed `ConnectionId` conversion. Boxed futures restore scoped dial identity
on each poll, including deferred inner calls made by upstream DNS. This does
not require vendoring the top-level libp2p crate. The runtime installs its
ownership-tagged relay transport with `with_other_transport`, using the existing
Noise/Yamux upgrade logic and unchanged wire/security negotiation.

Guard drop cancels pending setup, never an admitted circuit. Active negotiation
and codec leases survive cancellation until actual completion; admitted raw
connections retain their lease until drop. Owner/muxer teardown removes the
authenticated map. Registry scans retain upgraded references past unlock, and
cancellation wakeups happen outside registry/status locks so last-reference
cleanup cannot reenter a held registry mutex.

One authoritative admitted atomic is synchronized with pending cancellation.
Established raw I/O therefore skips intent locking and waker registration. There
is no added maintenance timer or replacement transport engine.

## Regressions And Evidence

| Source | Intended coverage |
| --- | --- |
| Repository `tests/relay_ownership.rs` | Native reservation ownership and preference |
| Repository `tests/relay_connection_dependencies.rs` | Exact physical dependencies and stream handoff |
| Repository `tests/relay_reservation_drain.rs` | Listener binding, drain behavior, and replacement failure |
| Repository `tests/relay_circuit_ownership.rs` | ID-aware deferred adapters, branch constraints, cancellation/drop, authenticated mapping, and teardown |
| Native circuit unit test | Admitted I/O fast path without status locking or waker replacement |

This is a patch/invariant inventory, not final test results. Native loopback
regressions do not establish physical route migration: that needs separate
real-TUN evidence of exact replacement binding, overlay promotion, traffic, and
observed old-connection closure. A close request is not observed retirement.
No broad migration-completion or battery/energy claim is made.
