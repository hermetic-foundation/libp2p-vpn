# Android LAN Discovery

## Status

Socket-ownership and LAN-observer primitives are implemented. Runtime, pairing
and JNI activation remain local. This is P3/P7/P9 work, not Android device
certification or a measured battery-efficiency result.

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

## Ownership

| Resource | Requirement |
| --- | --- |
| Observer | Runtime/profile-free pairing owns the driver; teardown revokes its bindings before aborting work |
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

Component checks exclude the unpublished runtime/JNI activation. Earlier
integration results below are historical, not evidence that the latest Android
handoff is complete. None of these host checks certifies Android netd.

| Check | Current evidence |
| --- | --- |
| Isolated component core | 2,005 passed, zero failed, 33 ignored; includes 98 passing physical-network tests and no unpublished runtime activation |
| Earlier integration candidate | Stage36: 2,490 passed, zero failed, 89 ignored; before asynchronous setup/retry review repairs, includes unpublished runtime activation |
| LAN observer | Thirteen models pass: cellular default, OS preference/return, IPv6 scope, source replacement, stale results, observer lifetime, one sender, shared cancellation capacity, offloaded binding and finite revision-owned retries |
| Replacement guard | New same-presence replacement regression passes in the final core suite |
| Standalone mDNS | 50 passed, one opt-in case ignored; includes asynchronous preparation, pending/terminal opportunity races, stale queues, independent observations/TTLs and receive-metadata parsing |
| Duplicate-source IPv4/IPv6 | Both real namespace cases pass in 18.11 seconds; initial transient preparation results, startup, unselected-link exclusion, fallback and return |
| IPv6 red/green | Initial candidate leaked unselected-link discovery despite scoped membership and multicast-all suppression; mandatory receive packet-info checks make the same fixture pass |
| Earlier minimal-config real TUN | Stage36: QUIC, UDP-only and stream-only peers passed, 64.30 seconds total; not rerun for the isolated observer or a latency benchmark |
| Android arm64 release | Final default and diagnostics/demand-lifecycle-trial cross-checks pass; not APK linking or netd execution |
| Static and source parity | Workspace and standalone mDNS denied Clippy correctness/suspicious/performance groups, formatting and Nix source parity pass; advisory warnings remain |
| Review | Independent source review exposed synchronous binding and lost retry opportunities; repairs and pending/backoff/terminal regressions reviewed with no remaining actionable findings |
| Storage | One reused target cache, about 6.9 GiB; two jobs, no incremental/debug output or APK build |
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
