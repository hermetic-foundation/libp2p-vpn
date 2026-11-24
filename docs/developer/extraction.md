# SDK extraction

Extract the reusable VPN implementation from `p2p-vpn`. A consumer must
be able to join a network and move traffic without importing an application
or reimplementing pairing, authorization, or recovery.

## Baseline

Use upstream browser branch commit `8938e991288438ab0ac7ffc91da05c003b9f923c`.
It includes the Preferred Interface Handoff work ending at `b2d7e4c7`
and the subsequent exact-connection stream admission fixes.

Do not change wire formats, stored identities, checkpoint formats, or
protocol IDs as part of extraction. Preserve authorship and keep the
product's visibility and deployment decisions separate.

## Ownership

| Area | SDK | Application |
| --- | --- | --- |
| Protocol | Identity, pairing, membership, discovery, route authority, forwarding, path handoff, vectors and protocol documentation | User-facing actions and presentation |
| Native | Existing `RuntimePlatform` runner; packet I/O, route and underlay adapters; control transport and private state | CLI, signals, NixOS units, executable packaging |
| Android | JNI, TUN fd ownership, shared packet switch, per-network supervision, socket binding, DNS and underlay inventory ingestion | Consent, activation preferences, foreground notifications, UI and service restart decisions |
| Browser | WASM peer API, WebRTC and relay driver, stream admission, checkpoint validation, userspace packet stack | Screens and site storage policy |
| Windows | Wintun device and route operations, cancellation, named pipe and private-state protections | CLI thread sizing, verified DLL distribution and service packaging |

## Initial embedding contract

Reuse the native `run_config_until_with_runtime_platform` entry and
`RuntimeControlHandle`. The host supplies packet I/O, installed routes,
state locations and shutdown. It can query runtime state and signal a
physical-network change without restarting the runtime.

Publish Android and browser bindings above those existing entry points.
Keep JNI fd ownership and the WASM peer API compatible during the move.
Do not expose swarms, connection tables or protocol internals as a shortcut.

Run the native packet I/O example with:

```sh
nix develop -c cargo run --locked --example native_embedding
```

The example supplies in-memory packet sources and sinks. It sends an IP
packet between two real local runtime peers over TCP without a TUN or root.
This workspace run establishes a baseline for the independent consumer.

### Call paths to preserve

1. Linux: NixOS instance invokes `p2p-vpn up`; CLI prepares the TUN and
   installs routes; `src/runtime/runner.rs` starts the node, packet planes
   and optional control listener. Dry-run does not open a TUN.
2. Android: `P2pVpnService` establishes one TUN; JNI adopts its fd before
   parsing the request; the supervisor gives each enabled overlay a port.
   Publish inventory before signaling a network change. Keep the TUN and
   healthy overlays running through normal handoff.
3. Browser: `BrowserVpn` validates membership, selects direct WebRTC or
   eligible relay, and waits for exact-connection admission. Preserve both
   browser LAN promotion and peer-initiated preferred-interface replacement.

Browser LAN promotion can use a path probe. For a native peer's preferred
interface change, the replacement must carry an authenticated IP packet
accepted by the native TUN before commit. Keep the old circuit until commit.
The existing circuit stays usable with a pre-extension peer.

### Test files to keep together

- Move `tests/protocol_spec.rs` with `docs/developer/protocol/vectors.json`.
  The test reads those vectors at compile time.
- Keep app tests that invoke the `p2p-vpn` executable with the app.
  This includes `pair_cli.rs`, `tun_namespace.rs`, and `windows_platform.rs`.
- The browser fixture currently resolves the app's `web` directory from its
  crate root. Keep UI-serving fixture code with the app or pass it a web root
  explicitly. The SDK must not depend on the application's assets.

## Dependency sources

The upstream workspace patches libp2p, Quinn and WebRTC. A consumer does
not inherit a dependency workspace's `[patch]` table. Cargo must resolve
one compatible source for types exchanged inside the SDK.

A standalone experiment built and ran an external Rust application pinned
to a local Git SDK revision. The SDK's facade and transitive core were
relative path dependencies in that revision. The consumer had no patches.
This proves the Cargo mechanism, not the real dependency graph.

The SDK now uses explicit paths for the modified crates and their reverse
dependencies in the original lockfile. The Linux, Android, and WASM
metadata checks found the same versions, feature selections, and edges.
The relative paths keep the SDK's transport graph together under one Git
revision. Code that exchanges libp2p types with the SDK must use that same
revision for its direct libp2p dependency.

The checksums in `vendor/registry-archives.sha256` record the crates.io
archives added for this graph. Keep their upstream notices. Recompute
the reverse dependency set when the pinned versions or features change.

## Acceptance checks

1. A fresh consumer builds and exercises each adapter from an immutable SDK
   revision or released artifact with no sibling paths or consumer patches.
2. Protocol vectors and mixed-version tests verify identity persistence,
   pairing, membership, and direct and relayed traffic against the baseline.
3. Real Chromium passes payload-before-commit and old-circuit retention
   checks. Android device testing verifies working traffic through a physical
   network change. Test Windows TUN and named-pipe behavior before claiming
   Windows runtime parity.
4. App packages pin the SDK independently and retain a rollback path. Preserve
   the browser app's branch placement and leave deployment separate.
