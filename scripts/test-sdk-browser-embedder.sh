#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
    printf 'usage: bash scripts/test-sdk-browser-embedder.sh CLI SDK_PKG\n' >&2
    exit 2
fi

P2P_VPN_BIN=$(realpath -e -- "$1")
P2P_VPN_BROWSER_SDK_DIR=$(realpath -e -- "$2")
P2P_VPN_TEST_NETNS=$(readlink /proc/self/ns/net)
export P2P_VPN_BIN P2P_VPN_BROWSER_SDK_DIR P2P_VPN_TEST_NETNS

repo=$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")/..")
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export HOME=$scratch TMPDIR=$scratch XDG_CACHE_HOME=$scratch
export XDG_CONFIG_HOME=$scratch XDG_DATA_HOME=$scratch XDG_STATE_HOME=$scratch
cd "$scratch"

unshare --user --map-root-user --mount --net --pid --fork \
    --kill-child=SIGKILL --mount-proc \
    node --test "$repo/crates/p2p-vpn-browser/tests/sdk-embedder.mjs"
