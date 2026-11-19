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

## Integration order

The WASM runtime uses the member session table with a limit of one. The
single-peer API and its wire behavior remain in place; this limit is not
yet browser mesh support.

1. The table owns the existing selected member, MTU, and handoff authority.
   Route control replies, failures, packet requests,
   and closure by exact binding. Send control requests with the same pinned
   request API the packet path uses. Keep attempt generations and cancellation
   in the handoff driver. Use the promotion result's drain deadline to close
   the exact fallback connection and release its relay lease. Preserve
   foreground demand.
2. Move network-wide membership and checkpoint commits through the one store
   and `Forwarder`. Before a durable update, gate every affected peer and
   cancel its stale capability and handoff work. After commit, close
   excluded peers and request fresh capabilities from affected survivors.
   If the update changes the checkpoint descriptor or packet grant boundary
   for all peers, gate all of them. Keep the checkpoint bootstrap and sync
   driver pinned to its current source initially. Separate sync source
   selection from shared authority before making sync itself multi-source.
3. Add bounded per-peer endpoint, dial, discovery generation, and handoff
   state under the same swarm. Drive all events from one dispatcher instead
   of waiting in a dial loop that discards other members' events. Route
   outbound frames via `Forwarder` to the selected connection for the
   packet's actual destination. Apply each connection's MTU. Keep foreground
   HTTP flows bound to their routed member rather than delivering unrelated
   packets to the current request's device.

## Keep an owned reservation across admissions

The existing relay transport pins the Noise identity to one destination
even for inbound circuits. The listener also has one member slot. Change
both together when enabling multiple incoming members. Keep outbound
identity pins per dial. For inbound circuits, admit only identities in the
current durable projection and require the inner `ConnectionId` to belong
to the exact confirmed reservation's relay and outer connection. A
publication or a relay-supplied source ID cannot add an admitted identity.

After a durable roster commit, update inbound admission from the same
`Forwarder` used for packet validation. A newly authorized peer can then
negotiate on the existing reservation without replacing the old member.
Each inner connection still needs its own capability exchange. Remove
revoked peers by exact connection ID. Preserve other members and the
reservation unless the local identity or the reservation itself loses
authority.

The browser integration test must establish two authenticated members with
one identity and storage lock. It must cover traffic to both, a relay-to-direct
handoff for one, and continued traffic to the other during reauthorization,
revocation, and connection loss. The module tests exercise the connection
authority transitions without a browser or a second swarm.
