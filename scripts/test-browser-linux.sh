#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'usage: %s [all|host|relay|wire|enrollment]\n' "$0" >&2
    exit 2
}
(( $# <= 1 )) || usage
suite=${1:-all}
case "$suite" in
    all|host|relay|wire|enrollment) ;;
    *) usage ;;
esac
runs() {
    [[ $suite == all || $suite == "$1" ]]
}

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
browser=crates/p2p-vpn-browser
if [[ ! -d $browser/node_modules/playwright ]]; then
    printf 'Install the locked browser test dependencies with npm ci --prefix %s.\n' "$browser" >&2
    exit 1
fi

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
build_wasm() {
    CARGO_TARGET_DIR=${P2P_VPN_WASM_TARGET_DIR:-${CARGO_TARGET_DIR:-target}} \
        bash scripts/build-browser.sh "$@"
}
build_wasm
if runs relay || runs wire; then
    P2P_VPN_BROWSER_OUT_DIR=$scratch/hooks build_wasm --test-hooks
fi
if runs wire; then
    wasm_target=${P2P_VPN_WASM_TARGET_DIR:-${CARGO_TARGET_DIR:-target}}
    CARGO_TARGET_DIR="$wasm_target" cargo build --locked -p p2p-vpn-browser \
        --target wasm32-unknown-unknown --features relay-client,test-hooks \
        --bin browser-relay-fixture
    wasm-bindgen --target web --out-dir "$scratch/hooks" \
        "$wasm_target/wasm32-unknown-unknown/debug/browser-relay-fixture.wasm"
fi
native_args=(-p p2p-vpn --features webrtc --bin p2p-vpn)
if [[ $suite != host ]]; then
    native_args+=(-p p2p-vpn-browser --features p2p-vpn-browser/test-hooks
        --bin browser-receiver-fixture --bin browser-relay-fixture)
fi
cargo build --locked "${native_args[@]}"

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

isolated_underlay() {
    isolated bash -ec '
        ip link set lo up
        ip link add pv-browser type dummy
        ip address add 192.0.2.1/24 dev pv-browser
        ip link set pv-browser up
        exec "$@"
    ' bash "$@"
}

if runs host; then
    isolated node --test "$browser/tests/host-app.mjs"
fi
if runs relay; then
    isolated node --test "$browser/tests/relay-gateway.mjs"
    isolated node --test "$browser/tests/browser-to-browser-relay.mjs"
    isolated node --test "$browser/tests/relay-advertisement.mjs"
    isolated node --test "$browser/tests/inviter-reservation-gateway.mjs"
    pairing_seed=$(cargo test --locked -p p2p-vpn --features webrtc \
        --test browser_public_pairing_seed --no-run --message-format=json | jq -er '
            select(.reason == "compiler-artifact" and .target.name == "browser_public_pairing_seed")
            | .executable // empty
        ')
    P2P_VPN_PAIRING_SEED="$pairing_seed" P2P_VPN_APP_ASSETS="$PWD/$browser/web" \
        isolated node --test "$browser/tests/pairing-relay-companion.mjs"
fi
if runs wire; then
    isolated_underlay node --test --test-concurrency=1 "$browser/tests/receiver.mjs" \
        "$browser/tests/relay.mjs" "$browser/tests/incoming-relay.mjs"
fi
if runs host; then
    P2P_VPN_TEST_DISCOVERY=1 isolated_underlay node "$browser/tests/native-app.mjs"
fi
if runs enrollment; then
    isolated_underlay node --test "$browser/tests/pairing-joiner.mjs"
    isolated_underlay node --test --test-concurrency=1 "$browser/tests/file-inviter.mjs" \
        "$browser/tests/file-inviter-ui.mjs"
    isolated_underlay node --test --test-concurrency=1 "$browser/tests/code-inviter.mjs" \
        "$browser/tests/code-inviter-ui.mjs" "$browser/tests/existing-code-inviter.mjs"
fi
