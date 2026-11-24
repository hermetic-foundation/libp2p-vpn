#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if (( $# < 3 )); then
  echo "usage: bash check.sh SDK.aar NATIVE_LIB_DIR ABI [ABI ...]" >&2
  exit 2
fi

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
aar="$1"
native_lib_dir="$2"
shift 2
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

entries=(AndroidManifest.xml R.txt classes.jar proguard.txt)
for abi in "$@"; do
  entries+=("jni/$abi/libp2p_vpn_android.so")
done
unzip -Z1 "$aar" | sort > "$work/actual"
printf '%s\n' "${entries[@]}" | sort | diff -u - "$work/actual"
unzip -p "$aar" AndroidManifest.xml > "$work/manifest"
grep -Fq 'android:minSdkVersion="29"' "$work/manifest"
unzip -p "$aar" proguard.txt > "$work/proguard"
grep -Fxq -- '-keep class org.hermeticfoundation.p2pvpn.NativeBridge {' "$work/proguard"
grep -Fxq '    native <methods>;' "$work/proguard"

bridge=org.hermeticfoundation.p2pvpn.NativeBridge
prefix=Java_org_hermeticfoundation_p2pvpn_NativeBridge_
unzip -p "$aar" classes.jar > "$work/classes.jar"
jar --list --file "$work/classes.jar" | diff -u <(printf '%s\n' "${bridge//.//}.class") -
javac --release 8 -classpath "$work/classes.jar" -d "$work/classes" "$test_dir/AndroidSdkConsumer.java"
javap -public -classpath "$work/classes.jar" "$bridge" > "$work/public"
if grep -Eq 'native(CreateE2eProfile|DebugTransportSnapshot|DiagnosticDhtPause|DiagnosticProbePause|Start|PairRpc)\(' "$work/public"; then
  echo "internal JNI methods must not be public" >&2
  exit 1
fi
javap -private -classpath "$work/classes.jar" "$bridge" \
  | sed -nE "s/.* native String ([A-Za-z0-9]+)\(.*/$prefix\1/p; s/.* native java\.lang\.String ([A-Za-z0-9]+)\(.*/$prefix\1/p" \
  | sort -u > "$work/expected-jni"
test -s "$work/expected-jni"

for abi in "$@"; do
  library="$native_lib_dir/$abi/libp2p_vpn_android.so"
  unzip -p "$aar" "jni/$abi/libp2p_vpn_android.so" | cmp "$library" -
  nm -D --defined-only --format=posix "$library" \
    | awk -v prefix="$prefix" 'index($1, prefix) == 1 { print $1 }' \
    | sort -u | diff -u "$work/expected-jni" -
done
