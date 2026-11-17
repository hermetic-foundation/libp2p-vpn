# Android LAN Discovery

## Status

Socket ownership, the LAN observer, and its Android runtime/profile-free pairing
adapters are implemented. Other transport/handoff activation remains local.
This is P3/P7/P9 work, not device certification or a battery-efficiency result.

The broader handoff remains gated by the
[physical-network acceptance matrix](physical-network-policy.md#acceptance-matrix).

## Selection

| Boundary | Contract |
| --- | --- |
| Inventory | Existing bounded NOT_VPN Network records, incarnations, revisions and OS default |
| Eligibility | Wi-Fi, Ethernet or Bluetooth LAN; never cellular, VPN or an inferred private-IP classification |
| First choice | An eligible OS-preferred LAN; no fixed transport ranking |
| Fallback | Check a surviving selected LAN, then bounded stable interface order when the Internet default is not an eligible LAN |
| Proof | Network-bound UDP connect to the multicast destination, without sending a packet |
| IPv6 | Exact interface scope in the kernel lookup; use IPv6 when IPv4 has no usable LAN source |
| Source | Require the kernel-selected source to belong to that Network's current published addresses |
| Return | A usable OS-preferred LAN supersedes fallback; discovery never rewrites Internet preference or packet routes |

Internet validation and a gateway are not prerequisites for local discovery.
Neither discovery socket success nor source selection proves peer reachability
or an external UDP NAT mapping.

## Integration

| Entry point | Ownership |
| --- | --- |
| Android runtime supervisor | Starts an `AndroidDiscovery` inside the runtime for each network instance |
| Profile-free code pairing | Starts the observer before discovery; dropping the pairing future revokes its sockets |
| `RuntimePlatform::with_discovery` | Consumes the observer; replacement or platform drop revokes previous ownership |
| `join_by_code_v2_with_discovery` | Consumes the observer and retains existing pairing validation/error semantics |
| Legacy snapshot APIs | `with_physical_network` and `join_by_code_v2_with_physical_network` keep their receiver signatures |
| Temporary JNI runtime | Bounded shutdown on all return/unwind paths; does not pretend to cancel a running binder operation |

JNI uses the already published NOT_VPN inventory. No JSON/Nix fields, pairing
wire changes, permissions or Android minimum-SDK changes are required.

These adapters activate LAN discovery only. Managed transports, signed endpoint
publication, scoped DNS and authenticated handoff have separate acceptance gaps.

## Ownership

| Resource | Requirement |
| --- | --- |
| Observer | Runtime/profile-free pairing owns the driver; teardown revokes its bindings before aborting work |
| JNI teardown | Temporary control runtimes use one-second bounded shutdown on success, error, cancellation and unwind; live backend work retains its capacity after return |
| Identity | Unique observer, selection generation and Network incarnation; numeric generations cannot alias another observer |
| Sockets | Apply Android Network binding to both RX and TX before address binding or multicast membership |
| Blocking backend | Offload socket binding as well as source lookup; preserve its capacity through cancellation/timeouts |
| IPv4 output | Exact interface index, including when two links share an IP |
| IPv6 output | Specific source, interface and `ff02::fb` scope; never an owned unscoped wildcard sender |
| Receive | Kernel packet-info interface must match the owner; multicast membership alone is insufficient |
| Advertisements | Current selected-LAN addresses only; keep advertisement scope separate from the one kernel-selected sender source |
| Stale results | Reject inventory changes during lookup, obsolete records, retired incarnations and revoked owners |
| Delivery | Queued discovery notifications must retain exact task ownership through native dispatch |
| Duplicate observations | Keep independent source ownership and expiry; withdrawing one legacy interface cannot expire another's observation or lend it a longer TTL |
| Link events | An IP-only event on another link must not retire a still-current explicitly owned source |
| Behaviour replacement | Reapply policy before polling a fresh behaviour, even when enabled presence and inventory generation are unchanged |
| Compatibility | Keep legacy sender APIs and snapshot-based integrations; add no JSON/Nix options or wire fields |

## Bounds

| Resource | Limit |
| --- | --- |
| Inventory | Existing 16 Networks, 64 source addresses and 128 routes per Network |
| Backend | One blocking lookup or binding per observer and four across the process, including stopped/replaced observers; three-second await deadline |
| Cancellation | Capacity remains occupied until the actual backend operation returns |
| Round | At most three inconclusive attempts per inventory opportunity; bounded backoff, then wait for an event |
| Installation | Up to three transient setup attempts with one/two-second backoff; fresh inventory can renew unfinished or exhausted setup without restarting healthy tasks |
| Candidate work | At most two family lookups per eligible Network; no discovery packets sent by selection |
| Active sender | One kernel-selected source per mDNS behaviour; two sockets, not one sender per privacy address |
| Updates | Latest-value inventory and selection channels; unrelated changes do not restart healthy tasks |
| Receive drain | Bounded discard batch for packets from other interfaces; no unbounded readiness loop |

Retry budgets follow consumed inventory/policy opportunities, not the winner of a
timer-versus-event race. Pending preparation is not reported as an installed
interface. A new opportunity cannot be lost between exhaustion and task exit.

## Verification

Stage37 results cover the observer primitives; adapter checks include the runtime
and JNI call sites. Stage36 integration results are historical, not evidence that
the latest Android handoff is complete. Host checks do not certify Android netd.

| Check | Current evidence |
| --- | --- |
| Adapter workspace | 2,464 passed, zero failed, 87 ignored; includes 73 Android host tests and six real connection-recovery cases; transport-controller WIP excluded |
| Stage37 observer core | 2,005 passed, zero failed, 33 ignored; includes 98 passing physical-network tests and no unpublished runtime activation |
| Adapter core | 2,007 passed, zero failed, 33 ignored; includes 100 passing physical-network tests and runtime/pairing observer replacement/cancellation checks |
| JNI teardown model | Real gated blocking work remains live across success, error/cancellation and panic; temporary-runtime destruction returns within its bound and preserves capacity until actual backend exit |
| Earlier integration candidate | Stage36: 2,490 passed, zero failed, 89 ignored; before asynchronous setup/retry review repairs, includes unpublished runtime activation |
| LAN observer | Fifteen models pass: cellular default, OS preference/return, IPv6 scope, source replacement, stale results, lifetime/replacement/cancellation, one sender, shared capacity, offloaded binding and finite revision-owned retries |
| Replacement guard | New same-presence replacement regression passes in the final core suite |
| Standalone mDNS | 50 passed, one opt-in case ignored; includes asynchronous preparation, pending/terminal opportunity races, stale queues, independent observations/TTLs and receive-metadata parsing |
| Duplicate-source IPv4/IPv6 | Both real namespace cases pass in 18.11 seconds; initial transient preparation results, startup, unselected-link exclusion, fallback and return |
| IPv6 red/green | Initial candidate leaked unselected-link discovery despite scoped membership and multicast-all suppression; mandatory receive packet-info checks make the same fixture pass |
| Adapter minimal-config real TUN | QUIC, UDP-only and stream-only peers pass, 30.41 seconds total; no Android netd or latency-benchmark claim |
| Android arm64 release | Final default and diagnostics/demand-lifecycle-trial cross-checks pass; not APK linking or netd execution |
| Static and source parity | Workspace and standalone mDNS denied Clippy correctness/suspicious/performance groups, formatting and Nix source parity pass; advisory warnings remain |
| Review | Independent reviews exposed synchronous binding, lost retry opportunities and unbounded JNI runtime destruction; fixes and regressions reviewed with no remaining actionable findings |
| Storage | One reused target cache, about 7.0 GiB; two jobs, no incremental/debug output or APK build |
| Remaining | Android deployment, callback/netd and interface-level packet evidence; full Linux dual-stack discovery and remaining handoff criteria stay open |
| Energy | Not measured; evaluate separately after functional validation |

The multicast fixtures use a host binding callback. They exercise real kernel
multicast and interface indices, but do not stand in for Android's netd binder.

Owned IPv6 sockets require kernel packet-info and multicast-all socket options.
Unsupported options fail closed; older-kernel/device coverage is unverified.

## Reproduction

Run from the repository root, reusing the existing Cargo target directory.
These checks need no phone, public peers or syscall fault injection.

```sh
nix run .#check-isolated -- --lib runtime::physical_network -- --test-threads=8
nix develop -c cargo test --locked --manifest-path vendor/libp2p-mdns-0.48.0/Cargo.toml --lib --features tokio
nix develop -c cargo test --locked --test mdns_network_policy -- --ignored --test-threads=1
```

The multicast fixture needs Linux user/network namespaces and `ip` from the
development shell. Its binding callback is a host model, not Android netd.
