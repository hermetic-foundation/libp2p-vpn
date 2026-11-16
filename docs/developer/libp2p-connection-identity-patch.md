# Local libp2p Connection Identity

## Patch Contract

| Property | Contract |
| --- | --- |
| Libraries | Pinned `libp2p-core` 0.43.2 and `libp2p-swarm` 0.47.1 |
| Origin | Local crates.io registry copies, excluding Cargo cache markers |
| Production dependencies | Original versions, requirements, and license notices retained |
| Test dependency | Explicit identity `rand` feature for test peer generation |
| Admitted identity | Default no-op `StreamMuxer::on_swarm_connection(Pin<&mut Self>, usize)` |
| Pending dial identity | Additive `Transport::dial_with_connection_id(addr, opts, usize)`; swarm uses `usize::from(ConnectionId)` |
| Muxer forwarding | Safe projections through `Wrap<T>`, `StreamMuxerBox`, and both futures `Either` variants |
| Dial forwarding | Boxing, choice, mapping, upgrade, timeout, optional, and address-filter adapters preserve the dial identity |
| Identity | Exact process-local swarm ID; no endpoint/order inference or display-string conversion |
| Compatibility | Additive APIs; no wire, existing event/behaviour contract, key, or user-configuration changes |

The pool calls the hook after extracting an admitted connection and before
spawning its established driver. The typed `From<ConnectionId> for usize`
conversion exposes the existing process-local value without parsing `Display`.
Neither an endpoint nor the order of concurrent completions identifies a connection.

## Admission Order

1. Transport authenticates the remote peer.
2. Pool rejects wrong or local peer identities.
3. Network behaviour admits or denies the connection.
4. Pool associates the admitted muxer with its exact swarm ID.
5. Established driver starts polling the muxer.

- Denied, aborted, or dropped setup does not reach the hook.
- Existing close paths and errors remain unchanged.
- The hook itself introduces no fallible operation or network traffic.
- The managed TCP adapter rejects conflicting associations and requires ownership before adoption.

## ID-Aware Dial Adapters

`Transport::dial_with_connection_id` defaults to ordinary `dial` under a scoped
identity context. Existing transports need not implement a new wire protocol or
change `DialOpts`. `transport::dial_connection_id()` reads that context, not a
global association inferred from addresses.

Boxed ID-aware dial futures restore the context for each poll and restore its
previous value on exit. This covers upstream DNS wrappers that defer their inner
`dial` call until polling, including literal-IP addresses. The scoped value is
not an asynchronous task-local: a custom adapter that detaches dialing into an
independent task must explicitly forward the ID instead of assuming inheritance.

## Authenticated Relay Tagging

The runtime captures `relay::client::Connection::circuit_binding()` before
authentication consumes the raw stream. It applies Noise and Yamux, then calls
`CircuitBinding::wrap_muxer(authenticated_peer, muxer)`. The tagged transport is
installed with `with_other_transport`, alongside its matching relay behaviour.
The additive core `upgrade::apply` helper reuses the existing upgrade logic;
Noise identity checks, Yamux, and `V1Lazy` negotiation remain unchanged.

The admitted muxer hook records the exact local inner CID, authenticated remote
peer, relay peer, and local physical outer CID. The relay ownership getter is
available at `SwarmEvent::ConnectionEstablished`. Denied authentication or
behaviour admission cannot create an authenticated mapping; closing or dropping
the owner removes it.

## Exact Circuit Dial Order

| Step | Required action |
| --- | --- |
| Prepare | Build `DialOpts` for the overlay peer and relay circuit address; save `options.connection_id()` |
| Submit | Call `Swarm::dial(options)` successfully, or the runtime's epoch-tracked equivalent |
| Pin | Before polling the swarm again, call `relay.pin_circuit_dial(peer, inner, relay_peer, outer)` |
| Retain | Hold the returned `CircuitDialPin` through setup; dropping it cancels pending setup, not an admitted circuit |
| Verify | At establishment, query `circuit_connection_owner(peer, inner)` rather than inferring the owner from preference |

Relay behaviour synchronously admits the actual pending CID and offered relay
branches in `handle_pending_outbound_connection`, before the transport pool
starts its futures. Post-dial pinning therefore does not depend on DNS polling
or executor timing. Queued relay work cannot behaviour-dispatch until the next
swarm poll. Pinning before submission is not the supported ordering.

A pin constrains the local sender's physical relay connection. The server
independently selects the receiver's reservation, potentially from multiple
reservations for that receiver peer. Both endpoints tag their actual local
outer CID; neither endpoint's CID or preference proves the other's owner.

Cancellation, registry lock lifetimes, and default alternative-dial compatibility
are detailed in [Relay Connection Dependencies](relay-connection-dependencies.md).

## Source Ownership

| Package path | Included in |
| --- | --- |
| `vendor/libp2p-core-0.43.2` | Linux, Android arm64, Android x86_64 |
| `vendor/libp2p-swarm-0.47.1` | Linux, Android arm64, Android x86_64 |

The Nix `rust-test-sources` check compares each packaged copy byte-for-byte.
Upstream trailing whitespace was normalized in the core changelog and two
generated files; generated protocol contents are unchanged.

## Invariants And Evidence

| Regression source | Intended coverage |
| --- | --- |
| Core hook tests | Nested boxing of non-`Unpin` muxers and both `Either` variants |
| Swarm hook tests | Exact ID, admission order, once-only delivery, denial, wrong/local peers, cancellation, dropped setup |
| `tests/relay_circuit_ownership.rs` | Deferred dial adapters, exact alternatives, cancellation, authenticated inbound/outbound maps, and teardown |
| Relay circuit unit test | Admitted I/O skips pending-status locking and waker replacement |
| Runtime association tests | Nontransferable ownership, conflicting IDs, independent retirement, IPv4/IPv6 concurrent same-peer dials |
| Kernel route tests | Generation fences, destination-specific rules, inventory concurrency, affected-family isolation |

These are contracts and regression targets, not a report of a final verification
run. Loopback TCP ownership tests exercise native association and lifetime
properties; they do not establish physical-route migration. That requires a
separate real-TUN run showing exact replacement ownership, validated overlay
promotion, bidirectional traffic, and observed fallback closure. A requested
close alone is not evidence of retirement.

### Standalone Harness

- Excluded vendored packages cannot run dependency tests through root `cargo test -p`.
- Focused library checks use temporary source copies and the existing shared target cache.
- The published swarm manifest omits cyclic test dependencies; the temporary manifest restores plaintext, Yamux, and QuickCheck dependencies.
- Criterion and trybuild are omitted only from that temporary library-test manifest; benchmarks and UI tests are not claimed as verified.
- Unrelated property generators use equivalent uniform `Gen::choose` ranges for current QuickCheck compatibility in the temporary copy.
- The production hook, pool implementation, and focused hook test bodies remain identical to the packaged source.
- Dependencies fetched for this harness are checksum-verified and bandwidth-limited; production workspace versions remain unchanged.

Root workspace and real-TUN checks exercise the production dependency graph
separately. This document makes no broad automatic-failback completion, Android
device validation, or battery/energy claim.
