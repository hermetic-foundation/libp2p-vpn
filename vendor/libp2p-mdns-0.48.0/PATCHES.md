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
| Admission-policy snapshot getter | Verify applied local policy independently of interface polling |
| Explicit multicast sending interface in restricted mode | Avoid relying on source binding alone for multicast routing |
| Shared admission gate and filtered address records | Retiring tasks stop processing, and restricted replies omit non-selected addresses |
| Disable global multicast reception on Linux/Android | Limit group reception; owned sockets additionally require receive-interface packet information |
| Abort remaining tasks on behaviour drop | Do not detach discovery work when a behaviour is removed |
| Optional immutable socket binding | Bind both RX/TX before address binding or group membership; identity/index changes retire only affected tasks |
| Indexed IPv4 and scoped IPv6 | Select the actual link even when multiple links share an IP; owned IPv6 never uses a wildcard sender |
| Kernel receive-interface metadata | Filter IPv4/IPv6 packets by their actual input interface, not a peer-supplied source address |
| Owned queued discovery | Carry exact task ownership through channels, cached observations and pending notifications |
| Independent observations | Preserve duplicate peer/address observations from surviving legacy interfaces, with separate owner/expiry provenance |
| Explicit source inventory | Current bindings survive ambiguous IP-only Down events and can resume without a new Up event |
| Address-family reconciliation | Change IPv4/IPv6 task family without discarding policy or restarting unchanged tasks |
| Asynchronous owned preparation | Permit a platform binder to offload blocking work without blocking policy or swarm polling |
| Bounded setup retries | Retry transient preparation/multicast setup failures with backoff; fresh ownership-policy opportunities can renew unfinished setup, not healthy tasks |

## Boundaries

- `None` allowlist preserves upstream interface admission; an empty set admits none.
- This crate does not infer the OS preference or classify cellular/overlay addresses.
- Policy callers must provide validated physical-network source addresses.
- Task cancellation is asynchronous. Path-promotion/retirement code must account for task cleanup rather than claim synchronous socket closure.
- Switching between unrestricted and restricted modes replaces tasks so their multicast socket options match the new mode.
- Android uses the kernel `IP_MULTICAST_ALL` option through a small libc call because socket2 0.5 exposes its safe wrapper only on Linux.
- `set_interface_bindings(None)` retains legacy mode; `Some(empty)` admits no sockets. The provider owns source availability, immutable identity and revocation.
- Bound discovery requires runtime receive-metadata support. The Tokio Linux/Android implementation discards wrong-interface packets in bounded batches and rejects missing/truncated metadata.
- IPv6 multicast-all suppression alone did not isolate links in the duplicate-source namespace fixture; owned RX also checks `IPV6_PKTINFO`.
- IPv4 owned output uses an indexed `ip_mreqn`; an address-only multicast option is ambiguous when two links share an IP.
- New libc usage is limited to Linux/Android socket options and bounded `recvmsg` metadata; it does not close or retain a caller's borrowed descriptor.
- A policy update fences asynchronous task retirement, but does not claim that every old descriptor closes synchronously.
- `prepare_sockets` defaults to the legacy binding callback; blocking implementations must override it with bounded asynchronous work and retain capacity until the backend actually returns.
- Owned setup retries at most three times per fresh policy opportunity, with one/two-second backoff. Exhausted tasks wait for an interface or policy opportunity; swarm polling alone never restarts setup.
- `active_interfaces` excludes pending preparation. An installed address requires both sockets and multicast configuration to succeed.
- No new wire protocol or mDNS record format is introduced.

## Testing

- Standalone workspace and lockfile preserve the test dependency versions.
- Dev-only identity and Tokio features make upstream tests executable independently of parent-workspace feature unification.
- `cargo test --manifest-path vendor/libp2p-mdns-0.48.0/Cargo.toml --locked --features tokio --lib` runs deterministic tests.
- Run `assigned_interface_resumes_without_a_new_up_event` with `--ignored` and `P2P_VPN_MDNS_TEST_SOURCE` set to an assigned multicast-capable IPv4 address for the socket-level resume check.
- `nix develop -c cargo test --locked --test mdns_network_policy -- --ignored --test-threads=2` exercises real IPv4/IPv6 multicast isolation, duplicate source IPs, fallback and return on isolated Linux links. Each owner first reports a transient preparation result; retry must reach real multicast without another interface event. This is a callback model, not syscall fault injection.
- These namespace callbacks are not Android netd evidence. Device callback, binding and packet-isolation checks remain required before Android certification.
