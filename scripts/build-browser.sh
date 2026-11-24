#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )) || { (( $# == 1 )) && [[ $1 != --test-hooks ]]; }; then
    printf 'usage: bash scripts/build-browser.sh [--test-hooks]\n' >&2
    exit 2
fi

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
output=${P2P_VPN_BROWSER_OUT_DIR:-crates/p2p-vpn-browser/web/pkg}
bash scripts/build-browser-sdk.sh "$output" "$@"
cp assets/p2p-vpn-logo.svg "$output/logo.svg"
