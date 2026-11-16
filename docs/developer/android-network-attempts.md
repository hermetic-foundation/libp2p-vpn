# Android Network Attempts

## Status

This is a backend component, not Android transport/controller activation.
Existing single-selection preparation remains available and unchanged.
No JSON/Nix options, identity, membership or protocol bytes are added.

## Contract

| Boundary | Requirement |
| --- | --- |
| Ordering | Begin with OS/destination-specific selection; exclude only Networks already tried in this operation |
| Identity | Exclusions use the Network handle and incarnation, not source IP alone |
| Attempts | At most three sequential selected Networks; no persistent blacklist or preference override |
| Budget | Default six seconds per attempt, including lookup and the caller's asynchronous connection/authentication operation |
| Custom budget | Callers may provide a shorter per-attempt deadline; overall request deadlines remain the caller's responsibility |
| Permission | Initial selection is preserved; a runtime-owned permission callback gates additional attempts and their results |
| Staleness | Reject changed epochs before/after lookup and operation completion; do not admit results from withdrawn recovery work |
| Lookup cancellation | If no Network was proven before lookup timeout, stop rather than guessing an exclusion or overlapping another lookup |
| Retry classification | Connectivity errors can retry; invalid input, policy denial, stale ownership and capacity exhaustion remain terminal |
| Incoming/source overrides | This retry API requires an outgoing wildcard source; accepted/fixed-source preparation stays separate |
| Socket construction | TCP/UDP factories consume an exact lease, bind its borrowed descriptor, record actual port/mark, and reject publication races |
| Resource ownership | Source lookups retain their existing four-slot capacity until blocking work finishes; transport callers retain their own connection permits |

The callback must include the actual connection/authentication work. A successful
UDP write is not connectivity proof and must not authorize path promotion.
Application-level one-time bindings must not be repeated after uncertain delivery.

Permission gates additional connection attempts after a known selected Network
fails. It does not remove the existing source-lookup fallback when the first
Network cannot provide a kernel-selected source.

## Verification Scope

| Evidence | What It Proves |
| --- | --- |
| Host async models | Ordering, budgets, stale/cancelled results, permission withdrawal, family preservation and distinct-Network limits |
| Datagram factory tests | Stale rejection and publication races around the borrowed descriptor |
| Isolated Linux namespace | Real IPv4/IPv6 UDP source, ephemeral port, routing mark, descriptor identity and replies, using a fixture binder |
| Android release cross-check | Type/target compatibility, not APK linking or kernel/netd execution |

Host checks do not prove Android Network binding, cellular/CLAT behavior,
incoming reachability, handoff or energy savings. Those remain integration gates
in [Android Transport Policy](android-transport-policy.md).

## Commands

```sh
nix develop -c cargo test --offline --locked --lib \
  runtime::physical_network::android::tests

nix develop -c cargo test --offline --locked --lib \
  runtime::physical_network::android::tests::datagram \
  -- --include-ignored --test-threads=1
```

The explicit namespace case needs Linux user/network namespaces and iproute2.
It runs only in its isolated child namespace and never changes host routes.
No public Internet traffic or syscall fault injection is used.
