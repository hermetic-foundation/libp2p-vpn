# Chromium through the Linux companion relay gateway

These tests use the real `browser-serve` API, the browser WASM transport, and
a native Circuit Relay v2 reservation. The Chromium and companion namespace
must start with only loopback. It reaches the fixture over isolated veth
links. The public-looking fixture addresses never leave those namespaces.

## IPv4 manual fallback

The seed returns a signed address record for the native member. Chromium
obtains the loopback circuit address and lease with `POST /api/discovery`,
attempts the unavailable signed direct address, then falls back to the
leased circuit. Both peers authenticate and exchange VPN control and IP
packets. The test closes BrowserVpn, calls `POST /api/relay/release`, and
checks that the loopback UDP port can be bound again. This exercises the
disconnect and release APIs, not the UI's disconnect handler.

## Automatic cross-family fallback

One relay identity listens on IPv4 TCP for Identify, IPv4 WebRTC Direct for
the browser circuit, and IPv6 TCP for the member's reservation. The native
member lives in a separate namespace with IPv6 as its only underlay. After
reserving over IPv6, it signs a relay-only record that names the IPv4 TCP
entrance. The IPv4-facing Kademlia fixture serves that record. Chromium and
the companion have only IPv4 underlay links, and the companion gets no
`--relay-entrance` override.

The test verifies the relay's observed IPv4 WebRTC and IPv6 TCP connections,
the authenticated browser and member peer IDs, the negotiated relay path and
MTU, and accepted VPN IP packets in both directions. It also verifies lease
release. The overlay test packets are IPv4; IPv6 is the member's underlay.
The alternate IPv4 link has a backup route to the fixture. Software egress
counters match TCP and UDP to the fixture address, excluding link traffic
such as ARP and unrelated browser traffic.

Verified on 2026-11-19 with Chromium 156.0.8078.73, the `fc22af6a` parent
companion, and cached test-hook WASM. Both cases passed. The cross-family case
recorded 40 TCP and 113 UDP packets to the fixture address on the default
link, and zero TCP and UDP packets to that address on the alternate link.
These counts are from one isolated run, not performance thresholds.

## Run

From the repository root, with Playwright available in the browser package:

```sh
cargo build --locked -p p2p-vpn --features webrtc --bin p2p-vpn
cargo build --locked -p p2p-vpn-browser --features test-hooks \
  --bin browser-relay-fixture --bin browser-receiver-fixture
bash scripts/build-browser.sh --test-hooks

target_dir=${CARGO_TARGET_DIR:-target}
export P2P_VPN_BIN="$(realpath "$target_dir/debug/p2p-vpn")"
export P2P_VPN_RELAY_FIXTURE="$(realpath "$target_dir/debug/browser-relay-fixture")"
export P2P_VPN_RECEIVER_FIXTURE="$(realpath "$target_dir/debug/browser-receiver-fixture")"
export P2P_VPN_RECEIVER_PKG="$(realpath crates/p2p-vpn-browser/web/pkg)"
export P2P_VPN_TEST_NETNS="$(readlink /proc/self/ns/net)"
unshare --user --map-root-user --mount --net --pid --fork \
  --kill-child=SIGKILL --mount-proc \
  node --test crates/p2p-vpn-browser/tests/relay-gateway.mjs
```

Set `P2P_VPN_CHROMIUM` to an installed Chromium executable to override the
default Chrome channel. The test requires Linux with unprivileged user
namespaces, `ip` and `tc` from iproute2, and `unshare` and `nsenter`.
The cross-family case requires the kernel `clsact` qdisc and `flower` classifier.
