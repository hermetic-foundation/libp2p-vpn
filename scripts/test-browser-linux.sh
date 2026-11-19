#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
browser=crates/p2p-vpn-browser
if [[ ! -d $browser/node_modules/playwright ]]; then
    printf 'Install the locked browser test dependencies with npm ci --prefix %s.\n' "$browser" >&2
    exit 1
fi

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
bash scripts/build-browser.sh
P2P_VPN_BROWSER_OUT_DIR=$scratch/hooks bash scripts/build-browser.sh --test-hooks
cargo build --locked -p p2p-vpn --features webrtc -p p2p-vpn-browser \
    --features p2p-vpn-browser/test-hooks \
    --bin p2p-vpn --bin browser-receiver-fixture --bin browser-relay-fixture

target=$(cargo metadata --locked --no-deps --format-version 1 | jq -er .target_directory)
export P2P_VPN_BIN="$target/debug/p2p-vpn"
export P2P_VPN_RECEIVER_FIXTURE="$target/debug/browser-receiver-fixture"
export P2P_VPN_RELAY_FIXTURE="$target/debug/browser-relay-fixture"
export P2P_VPN_PAIRING_PKG="$PWD/$browser/web/pkg"
export P2P_VPN_RECEIVER_PKG="$scratch/hooks"
export P2P_VPN_RELAY_PKG="$scratch/hooks"
P2P_VPN_TEST_NETNS=$(readlink /proc/self/ns/net)
export P2P_VPN_TEST_NETNS

isolated() {
    timeout 240s unshare --user --map-root-user --mount --net --pid \
        --fork --kill-child=SIGKILL --mount-proc "$@"
}

isolated node --test "$browser/tests/host-app.mjs"
isolated bash -ec '
    ip link set lo up
    ip link add pv-browser type dummy
    ip address add 192.0.2.1/24 dev pv-browser
    ip link set pv-browser up
    node --test --test-concurrency=1 "$1/tests/receiver.mjs" "$1/tests/relay.mjs" \
        "$1/tests/incoming-relay.mjs"
    P2P_VPN_TEST_DISCOVERY=1 node "$1/tests/native-app.mjs"
    node --test "$1/tests/pairing-joiner.mjs"
' bash "$browser"
