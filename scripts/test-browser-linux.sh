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

if [[ ! -x ${P2P_VPN_BIN:-} ]]; then
    printf 'Set P2P_VPN_BIN to the app CLI built with its webrtc feature.\n' >&2
    exit 2
fi
P2P_VPN_BIN=$(realpath -e -- "$P2P_VPN_BIN")
export P2P_VPN_BIN
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
if runs relay || runs wire || runs enrollment; then
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
if [[ $suite != host ]]; then
    native_args=(-p p2p-vpn-browser --features p2p-vpn-browser/test-hooks
        --bin browser-receiver-fixture --bin browser-relay-fixture)
    if runs enrollment; then
        native_args+=(--example checkpoint_inviter_native)
    fi
    cargo build --locked "${native_args[@]}"
fi

target=$(cargo metadata --locked --no-deps --format-version 1 | jq -er .target_directory)
export P2P_VPN_RECEIVER_FIXTURE="$target/debug/browser-receiver-fixture"
export P2P_VPN_RELAY_FIXTURE="$target/debug/browser-relay-fixture"
export P2P_VPN_PAIRING_PKG="$PWD/$browser/web/pkg"
export P2P_VPN_RECEIVER_PKG="$scratch/hooks"
export P2P_VPN_RELAY_PKG="$scratch/hooks"
P2P_VPN_TEST_NETNS=$(readlink /proc/self/ns/net)
export P2P_VPN_TEST_NETNS

isolated() {
    timeout "${isolation_budget:-240s}" unshare --user --map-root-user --mount --net --pid \
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
    isolated node --test "$browser/tests/automatic-inviter-relay.mjs"
    isolated node --test "$browser/tests/public-code-inviter-gateway.mjs"
    isolated node --test "$browser/tests/native-code-locator.mjs"
    P2P_VPN_LEGACY_RETRY_PKG="$scratch/hooks" isolated node --test \
        --test-name-pattern='lost legacy approval' "$browser/tests/native-code-locator.mjs"
    P2P_VPN_LOCATOR_PKG="$scratch/hooks" isolated bash -ec '
        ip link set lo up
        ip link add pv-locator type dummy
        ip address add 11.255.48.1/24 dev pv-locator
        ip link set pv-locator up
        exec node --test "$1"
    ' bash "$browser/tests/code-locator-publication.mjs"
    P2P_VPN_UNPINNED_PKG="$scratch/hooks" \
        isolated_underlay node --test "$browser/tests/unpinned-code-inviter.mjs"
    pairing_seed=$(cargo test --locked -p libp2p-vpn --features webrtc \
        --test browser_public_pairing_seed --no-run --message-format=json | jq -er '
            select(.reason == "compiler-artifact" and .target.name == "browser_public_pairing_seed")
            | .executable // empty
        ')
    P2P_VPN_PAIRING_SEED="$pairing_seed" P2P_VPN_APP_ASSETS="$PWD/$browser/web" \
        isolated node --test "$browser/tests/pairing-relay-companion.mjs"
    P2P_VPN_PAIRING_SEED="$pairing_seed" P2P_VPN_APP_ASSETS="$PWD/$browser/web" \
        isolated node --test "$browser/tests/preferred-interface-handoff.mjs"
fi
if runs wire; then
    for scenario in receiver relay incoming-relay checkpoint-transfer; do
        isolated_underlay node --test --test-concurrency=1 "$browser/tests/$scenario.mjs"
    done
fi
if runs host; then
    P2P_VPN_TEST_DISCOVERY=1 isolated_underlay node "$browser/tests/native-app.mjs"
fi
if runs enrollment; then
    isolation_budget=360s isolated_underlay node --test "$browser/tests/pairing-joiner.mjs"
    isolated_underlay node --test --test-concurrency=1 "$browser/tests/file-inviter.mjs" \
        "$browser/tests/file-inviter-ui.mjs"
    isolated_underlay node --test --test-concurrency=1 "$browser/tests/code-inviter.mjs" \
        "$browser/tests/code-inviter-ui.mjs" "$browser/tests/existing-code-inviter.mjs"
    wasm_target=${P2P_VPN_WASM_TARGET_DIR:-${CARGO_TARGET_DIR:-target}}
    CARGO_TARGET_DIR="$wasm_target" cargo build --locked -p p2p-vpn-browser \
        --target wasm32-unknown-unknown --features test-hooks --example checkpoint_inviter_fixture
    wasm-bindgen --target web --out-dir "$scratch/checkpoint-issuer" --remove-name-section \
        "$wasm_target/wasm32-unknown-unknown/debug/examples/checkpoint_inviter_fixture.wasm"
    P2P_VPN_CHECKPOINT_INVITER_PKG="$scratch/checkpoint-issuer" \
        isolated_underlay node --test "$browser/tests/checkpoint-inviter.mjs"
    P2P_VPN_CHECKPOINT_INVITER_NATIVE="$target/debug/examples/checkpoint_inviter_native" \
        P2P_VPN_CHECKPOINT_RETRY_PKG="$scratch/hooks" \
        isolated node --test "$browser/tests/checkpoint-inviter-live.mjs"
fi
