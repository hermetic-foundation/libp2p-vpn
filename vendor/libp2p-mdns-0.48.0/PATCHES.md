# Local mDNS Patch

## Origin

- Crate: `libp2p-mdns` 0.48.0, copied from the Cargo registry source.
- Upstream repository: https://github.com/libp2p/rust-libp2p
- Upstream revision: retained in `.cargo_vcs_info.json`.
- License: upstream MIT notices retained in source files.

## Changes

| Change | Purpose |
| --- | --- |
| Optional source-address allowlist | Reconcile discovery tasks without dropping the behaviour or watcher |
| Available-address inventory | Resume an allowed interface without requiring a second OS interface-up event |
| Active-interface iterator | Expose installed task addresses for tests and diagnostics |
| Explicit multicast sending interface in restricted mode | Avoid relying on source binding alone for multicast routing |
| Shared admission gate and filtered address records | Retiring tasks stop processing, and restricted replies omit non-selected addresses |
| Disable global multicast reception on Linux/Android | Receive only groups joined by this socket, not subscriptions belonging to other sockets/interfaces |
| Abort remaining tasks on behaviour drop | Do not detach discovery work when a behaviour is removed |

## Boundaries

- `None` allowlist preserves upstream interface admission; an empty set admits none.
- This crate does not infer the OS preference or classify cellular/overlay addresses.
- Policy callers must provide validated physical-network source addresses.
- Task cancellation is asynchronous. Path-promotion/retirement code must account for task cleanup rather than claim synchronous socket closure.
- Switching between unrestricted and restricted modes replaces tasks so their multicast socket options match the new mode.
- Android uses the kernel `IP_MULTICAST_ALL` option through a small libc call because socket2 0.5 exposes its safe wrapper only on Linux.
- No new wire protocol or mDNS record format is introduced.

## Testing

- Standalone workspace and lockfile preserve the test dependency versions.
- Dev-only identity and Tokio features make upstream tests executable independently of parent-workspace feature unification.
- `cargo test --manifest-path vendor/libp2p-mdns-0.48.0/Cargo.toml --locked --features tokio --lib` runs deterministic tests.
- Run `assigned_interface_resumes_without_a_new_up_event` with `--ignored` and `P2P_VPN_MDNS_TEST_SOURCE` set to an assigned multicast-capable IPv4 address for the socket-level resume check.
- Cross-interface packet isolation and Android device behavior still require platform integration evidence.
