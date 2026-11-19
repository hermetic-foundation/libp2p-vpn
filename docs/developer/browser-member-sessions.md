# Browser member sessions

Browser mesh needs one identity, one swarm, and one durable authority per
network. It does not need one `BrowserVpn` per remote member. Multiple
`BrowserVpn` instances would open duplicate storage locks and would not
agree on the current authority after a membership change.

## Connection authority

`MemberSessions` is a bounded, in-memory table keyed by `ConnectionId`.
Each entry also checks the authenticated `PeerId`. Admission to the table
does not grant packet access. The browser admits a member connection only
after a pinned member dial or an authenticated circuit through the exact
confirmed reservation. It classifies infrastructure by connection
ownership, not by peer ID: one peer identity can provide both a relay hop
and an independent member connection.

Open packet access only after a capability reply matches the peer,
connection, and outbound request ID. Validate the reply against the current
durable projection before recording the negotiated MTU. Checkpoint exchanges
that have not installed authority remain control-only. The table never
installs a checkpoint or infers membership from capabilities.

Each peer has one primary and at most one alternate. A direct candidate
must prove its own capabilities and complete a packet probe on its exact
connection before replacing the relay. The candidate must support the
current MTU. The old relay can receive packets for the bounded drain interval
but cannot send new requests. Closing that relay cannot close the promoted
path. Reauthorization gates the peer and retires its alternates. Revocation
removes all of the peer's paths; durable authority must also reject new
admissions for that peer.

The WASM runtime defaults to one member and preserves the single-peer API.
The opt-in profile below admits two members on one incoming reservation.
Outbound dialing, HTTP flows, and checkpoint sync remain single-member.

## Share one incoming reservation

For legacy membership, call `reserve_relay()`, then call
`allow_incoming_relay_member(peerId)` for one additional peer with an active
signed overlay membership record. Keep calling `receive_relay_packet(timeoutMs)`
serially to drive both circuits and receive their authorized IP packets.
`accept_relay()` still waits for the original selected peer.

The additional peer must authenticate through the same confirmed reservation
and complete its own capability exchange. Each circuit has its own MTU
and packet source checks. The additional peer can use the committed
membership but cannot initiate membership sync or install records. Closing
one inner circuit leaves the other in place. `release_relay()` closes both.
Checkpoint membership and code invitation keep their existing ownership.

## Next Integration Stages

1. Move network-wide membership and checkpoint commits through the one store
   and `Forwarder`. Before a durable update, gate every affected peer and
   cancel its stale capability and handoff work. After commit, close
   excluded peers and request fresh capabilities from affected survivors.
   If the update changes the checkpoint descriptor or packet grant boundary
   for all peers, gate all of them. Keep the checkpoint bootstrap and sync
   driver pinned to its current source initially. Separate sync source
   selection from shared authority before making sync itself multi-source.
2. Add bounded per-peer endpoint, dial, discovery generation, and handoff
   state under the same swarm. Drive all events from one dispatcher instead
   of waiting in a dial loop that discards other members' events. Route
   outbound frames via `Forwarder` to the selected connection for the
   packet's actual destination. Apply each connection's MTU. Keep foreground
   HTTP flows bound to their routed member rather than delivering unrelated
   packets to the current request's device.

## Keep an owned reservation across admissions

Outbound relay dials still pin one Noise identity. The transport admits an
additional inbound Noise identity only while the live membership projection
permits it. The dispatcher requires the inner `ConnectionId` to belong to
the exact confirmed reservation's relay and outer connection. Publication
and the relay's claimed source ID grant no authority.

After a durable roster commit, update inbound admission from the same
`Forwarder` used for packet validation. A newly authorized peer can then
negotiate on the existing reservation without replacing the old member.
Each inner connection still needs its own capability exchange. Remove
revoked peers by exact connection ID. Preserve other members and the
reservation unless the local identity or the reservation itself loses
authority.

The Chromium fixture in `tests/incoming-relay.mjs` drives two independent
native identities against one browser reservation. It checks packets from both,
per-peer MTU, forged source rejection, and traffic on the original surviving
circuit after the browser observes the other circuit close. The fixture can
close the exact browser-side circuit because graceful closure may not promptly
propagate through the relay. Multi-member relay-to-direct handoff and checkpoint
reauthorization are outside this profile. The member session unit tests cover
the underlying authority transitions.
