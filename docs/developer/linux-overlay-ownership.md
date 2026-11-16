# Linux Overlay Ownership

## Contract

| Concern | Rule |
| --- | --- |
| Native registration | Mark the TUN before installing overlay addresses and routes |
| Marker | Kernel `IFLA_IFALIAS` equals `p2p-vpn:overlay:v1` |
| Classification | Require both the exact marker and kernel `tun` link kind |
| Cross-instance scope | Independent daemons in the same network namespace read the same kernel metadata |
| Naming | Renames preserve ownership; interface-name prefixes and address ranges do not establish it |
| Unrelated VPN | An unmarked TUN can be a legitimate underlay; do not exclude all VPN devices |
| Configuration | No new JSON/Nix field, peer metadata, or registry file |

The alias is reserved runtime-managed interface metadata. It contains no network
name, peer identity, key, or membership authority. Administrators with network
administration privileges can change it, just as they can change routes.

## Lifecycle

1. `TunDevice::open` creates or attaches the native TUN using its existing API.
2. The first Linux `TunRuntimeConfig::route_commands` entry sets the marker.
3. Existing address and route commands run before the forwarding runtime starts.
4. The kernel preserves the alias across renames and removes it with the interface.

- Native CLI and NixOS startup already execute this command sequence.
- A failed marker command fails startup; it does not silently start an unmarked overlay.
- Native startup replaces any manually assigned interface alias with the ownership marker.
- Persistent interfaces retain their marker after handles close; they remain excluded while that kernel interface exists.
- A replacement interface does not inherit a deleted interface's marker, even if its name or index is reused.

## Route And Source Checks

| Check | Implementation |
| --- | --- |
| Selected egress | Read the resolved interface's current kernel link metadata before authorizing the route |
| Query bounds | Route and selected-link requests share one concurrency slot and the existing two-second deadline |
| Ownership rejection | Return `OwnOverlay` without transmitting traffic or poisoning a completed observer request |
| Configured-name fallback | Retain explicit exclusions for the local configured TUN, including older unmarked setups |
| Source inventory | Exclude addresses attached to any marked TUN, not merely this instance's configured name |
| Source bounds | At most 1,024 link records and 4,096 address records; existing lookup and generation fences apply |
| QUIC preparation | Validate both selected egress and assigned underlay source before allowing TLS traffic |
| Discovery fallback | An overlay-selected multicast route does not suppress an otherwise eligible interface-bound LAN route |

No new periodic scan, packet probe, or persistent index cache is introduced.
Incomplete/cancelled kernel requests retain the observer's existing fail-closed
retirement behavior.

## Compatibility And Limits

- Existing wire protocols, identities, membership, addresses, pairing, and minimal configuration are unchanged.
- Older daemons do not add the marker; restart those instances with the new binary for cross-instance recognition.
- Linux embeddings which configure a TUN externally must apply the native startup command sequence, or establish the same marker themselves.
- Explicit source/fixed-port overrides retain their previous transport semantics; this does not silently add policy ownership to bypassing callers.
- Android and Windows do not use this Linux marker contract.
- Unmodified UDP/libp2p transports still need integration with physical-network selection; kernel ownership metadata alone does not bind their sockets.

## Verification

| Check | Result |
| --- | --- |
| Standard workspace set | 2,130 passed; 55 opt-in/platform cases skipped and accounted separately |
| Kernel ownership | 2 passed: exact marker/type classification and real-TUN IPv4/IPv6 cross-instance routes/sources, rename, and recreation |
| Native startup/lifecycle | 2 passed: marker-first command sequence and real-TUN independent devices, rename, name reuse, and last-handle deletion |
| Linux route/discovery set | 32 passed, including the ownership cases and wire-level LAN mDNS fallback from an overlay-selected multicast route |
| QUIC ownership/handover | 6 ownership/error-path checks and 14 handover checks passed |
| Minimal-config real-TUN set | 8 passed in 477 seconds: QUIC, UDP, stream fallback, blocking, movement, and outgoing/accepted route return |
| Peerless code pairing | Passed with resulting overlay connectivity in 13 seconds |
| Android arm64 libraries | Default and diagnostic/demand-lifecycle-trial release cross-checks passed |
| Static/source checks | Clippy correctness/suspicious/performance, formatting, whitespace, and Nix source ownership passed |

- Standard counts are 1,819 core, 161 CLI, 72 Android-native, 11 fixture, 5 pairing-CLI, 1 authorization, and 61 namespace-helper tests.
- Namespace tests mutate only isolated interfaces and routes, never the parent host's network.
- An owned route rejection leaves the observer usable for subsequent parent-VPN routes.
- The rename fixture restores routes removed by taking a TUN down; it does not weaken the ownership assertion or change production routing.
- Independent review found no new scoped issues; existing project-wide advisory warnings remain.
- The existing build target stayed at 3.9 GiB with two jobs and no incremental/debug artifacts or new cache.
- No full NixOS VM/package build, APK deployment, personal flake edit, or energy measurement was performed.
- ADB reported no attached Android device; cross-compilation is not device traffic evidence.

The acceptance boundary remains [Physical Network Policy](physical-network-policy.md).
This shared Linux ownership component does not close the full transport,
Android-device, migration, or energy requirements.

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --lib runtime::physical_network::linux -- --include-ignored

CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --lib runtime::tun::ownership_tests -- --include-ignored
```
