#!/usr/bin/env bash
set -euo pipefail

if (( $# < 5 || $# > 6 )); then
    printf 'usage: bash scripts/test-sdk-browser-handoff.sh CLI SEED APP_WEB SDK_PKG LOGO [LEGACY_WEB]\n' >&2
    exit 2
fi

P2P_VPN_BIN=$(realpath -e -- "$1")
P2P_VPN_PAIRING_SEED=$(realpath -e -- "$2")
export P2P_VPN_BIN P2P_VPN_PAIRING_SEED
app_web=$(realpath -e -- "$3")
sdk_pkg=$(realpath -e -- "$4")
logo=$(realpath -e -- "$5")
if (( $# == 6 )); then
    P2P_VPN_LEGACY_APP_ASSETS=$(realpath -e -- "$6")
    export P2P_VPN_LEGACY_APP_ASSETS
else
    unset P2P_VPN_LEGACY_APP_ASSETS
fi
repo=$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")/..")
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

export P2P_VPN_APP_ASSETS=$scratch/web
mkdir -p "$P2P_VPN_APP_ASSETS/pkg"
shopt -s dotglob nullglob
for asset in "$app_web"/*; do
    if [[ ${asset##*/} != pkg ]]; then
        cp -R -- "$asset" "$P2P_VPN_APP_ASSETS/"
    fi
done
for artifact in p2p_vpn_browser.js p2p_vpn_browser_bg.wasm; do
    install -m644 -- "$sdk_pkg/$artifact" "$P2P_VPN_APP_ASSETS/pkg/$artifact"
done
install -m644 -- "$logo" "$P2P_VPN_APP_ASSETS/pkg/logo.svg"

export P2P_VPN_TEST_NETNS=$(readlink /proc/self/ns/net)
unshare --user --map-root-user --mount --net --pid --fork \
    --kill-child=SIGKILL --mount-proc \
    node --test --test-concurrency=1 \
    "$repo/crates/p2p-vpn-browser/tests/preferred-interface-handoff.mjs"
