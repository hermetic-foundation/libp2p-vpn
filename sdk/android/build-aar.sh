#!/usr/bin/env bash
set -euo pipefail

if (( $# < 3 )); then
  echo "usage: bash build-aar.sh OUTPUT.aar NATIVE_LIB_DIR ABI [ABI ...]" >&2
  exit 2
fi

sdk_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output="$1"
native_lib_dir="$(realpath -- "$2")"
shift 2

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
stage="$work/aar"
mkdir -p "$work/classes" "$stage"

entries=(-C "$sdk_dir" AndroidManifest.xml -C "$sdk_dir" proguard.txt)
for abi in "$@"; do
  case "$abi" in
    arm64-v8a|x86_64) ;;
    *) echo "unsupported Android ABI: $abi" >&2; exit 2 ;;
  esac
  entry="jni/$abi/libp2p_vpn_android.so"
  library="$native_lib_dir/$abi/libp2p_vpn_android.so"
  if [[ ! -f "$library" || ! -s "$library" ]]; then
    echo "missing Android JNI library: $library" >&2
    exit 1
  fi
  mkdir -p "$stage/jni/$abi"
  ln -s -- "$library" "$stage/$entry"
  entries+=(-C "$stage" "$entry")
done

bridge=org/hermeticfoundation/p2pvpn/NativeBridge
javac --release 8 -d "$work/classes" "$sdk_dir/java/$bridge.java"
export TZ=UTC
jar_flags=(--create --no-manifest --date=2000-01-01T00:00:00Z)
jar "${jar_flags[@]}" --file "$stage/classes.jar" -C "$work/classes" "$bridge.class"
: > "$stage/R.txt"

jar "${jar_flags[@]}" --file "$work/sdk.aar" \
  "${entries[@]}" -C "$stage" R.txt -C "$stage" classes.jar
mkdir -p -- "$(dirname -- "$output")"
mv -fT -- "$work/sdk.aar" "$output"
