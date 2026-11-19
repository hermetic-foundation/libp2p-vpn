# Chromium through the Linux companion relay gateway

This test uses the real `browser-serve` API, the browser WASM transport, and a
native Circuit Relay v2 reservation. The relay, member, and private Kademlia
seed are across a veth pair in another Linux network namespace. The outer
namespace must be fresh and contain only loopback before the test creates
the veth. The public-looking fixture addresses never leave those namespaces.

The seed returns a signed address record for the native member. Chromium
obtains the loopback circuit address and lease with `POST /api/discovery`,
attempts the unavailable signed direct address, then falls back to the
leased circuit. Both peers authenticate and exchange VPN control and IP
packets. The test closes BrowserVpn, calls `POST /api/relay/release`, and
checks that the loopback UDP port can be bound again. This exercises the
disconnect and release APIs, not the UI's disconnect handler.

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
namespaces and the `ip`, `unshare`, and `nsenter` tools.
