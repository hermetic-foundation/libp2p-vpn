# Local libp2p Connection Identity

## Patch Contract

| Property | Contract |
| --- | --- |
| Libraries | Pinned `libp2p-core` 0.43.2 and `libp2p-swarm` 0.47.1 |
| Origin | Local crates.io registry copies, excluding Cargo cache markers |
| Production dependencies | Original versions, requirements, and license notices retained |
| Test dependency | Explicit identity `rand` feature for test peer generation |
| API | Default no-op `StreamMuxer::on_swarm_connection(Pin<&mut Self>, usize)` |
| Forwarding | Safe projections through `Wrap<T>`, `StreamMuxerBox`, and both futures `Either` variants |
| Identity | Exact process-local swarm ID; no endpoint/order inference or display-string conversion |
| Compatibility | No wire, swarm-event, behaviour, key, or user-configuration changes |

The pool calls the hook after extracting an admitted connection and before
spawning its established driver. It reads the existing ID directly within the
connection module; no public ID representation is added.

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

## Source Ownership

| Package path | Included in |
| --- | --- |
| `vendor/libp2p-core-0.43.2` | Linux, Android arm64, Android x86_64 |
| `vendor/libp2p-swarm-0.47.1` | Linux, Android arm64, Android x86_64 |

The Nix `rust-test-sources` check compares each packaged copy byte-for-byte.
Upstream trailing whitespace was normalized in the core changelog and two
generated files; generated protocol contents are unchanged.

## Verification

| Focused check | Coverage |
| --- | --- |
| Two core hook tests | Nested boxing of non-`Unpin` muxers and both `Either` variants |
| Five swarm hook tests | Exact ID, admission order, once-only delivery, denial, wrong/local peers, cancellation, dropped setup |
| Runtime association tests | Nontransferable ownership, conflicting IDs, independent retirement, IPv4/IPv6 concurrent same-peer dials |
| Kernel route tests | Generation fences, destination-specific rules, inventory concurrency, affected-family isolation |

### Standalone Harness

- Excluded vendored packages cannot run dependency tests through root `cargo test -p`.
- Focused library checks use temporary source copies and the existing shared target cache.
- The published swarm manifest omits cyclic test dependencies; the temporary manifest restores plaintext, Yamux, and QuickCheck dependencies.
- Criterion and trybuild are omitted only from that temporary library-test manifest; benchmarks and UI tests are not claimed as verified.
- Two unrelated property generators use equivalent uniform `Gen::choose` ranges for current QuickCheck compatibility in the temporary copy.
- The production hook, pool implementation, and seven focused test bodies remain identical to the packaged source.
- Dependencies fetched for this harness are checksum-verified and bandwidth-limited; production workspace versions remain unchanged.

Root workspace and real-TUN checks validate the production dependency graph
separately. These checks do not constitute completed automatic failback, Android
device validation, or an energy measurement.
