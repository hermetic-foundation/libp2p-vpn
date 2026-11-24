#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )) || { (( $# == 2 )) && [[ $2 != --test-hooks ]]; }; then
    printf 'usage: bash scripts/build-browser-sdk.sh OUT_DIR [--test-hooks]\n' >&2
    exit 2
fi

output=$1
[[ $output == /* ]] || output=$PWD/$output
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."

version=$(awk '
    $0 == "name = \"wasm-bindgen\"" { found = 1; next }
    found && /^version = / { gsub(/"/, "", $3); print $3; exit }
' Cargo.lock)
if [[ -z "$version" ]]; then
    printf 'Could not determine the locked wasm-bindgen version.\n' >&2
    exit 1
fi
if ! command -v wasm-bindgen >/dev/null || [[ $(wasm-bindgen --version) != "wasm-bindgen $version" ]]; then
    printf 'Install the matching CLI: cargo install --locked wasm-bindgen-cli --version %s\n' "$version" >&2
    exit 1
fi

args=(--locked --package p2p-vpn-browser --target wasm32-unknown-unknown --lib)
if (( $# == 2 )); then
    args+=(--features test-hooks)
fi
target=$(cargo metadata --locked --no-deps --format-version 1 | jq -er .target_directory)
cargo build "${args[@]}"
# Keep the artifact within the companion's asset budget.
wasm-bindgen --target web --out-dir "$output" --remove-name-section \
    "$target/wasm32-unknown-unknown/debug/p2p_vpn_browser.wasm"
