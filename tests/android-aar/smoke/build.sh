#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 3 || ( $2 != arm64-v8a && $2 != x86_64 ) ]]; then
    printf 'Usage: bash build.sh SDK.aar {arm64-v8a|x86_64} OUTPUT.apk\n' >&2
    exit 2
fi
aar=$1
native=lib/$2/libp2p_vpn_android.so
output=$3
fixture=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
sdk=${ANDROID_HOME:?Set ANDROID_HOME to an installed Android SDK}
tools=$sdk/build-tools/${ANDROID_BUILD_TOOLS:-37.0.0}
platform=$sdk/platforms/android-${ANDROID_COMPILE_SDK:-37.0}/android.jar
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/classes" "$work/dex" "$work/${native%/*}"

unzip -p "$aar" classes.jar > "$work/sdk.jar"
unzip -p "$aar" "jni/${native#lib/}" > "$work/$native"
javac --release 8 -Xlint:all -Werror -cp "$platform:$work/sdk.jar" -d "$work/classes" "$fixture/Smoke.java"
"$tools/d8" --min-api 29 --lib "$platform" --output "$work/dex" \
    "$work/sdk.jar" "$work/classes/example/aarsmoke/Smoke.class"
"$tools/aapt2" link --debug-mode -I "$platform" --manifest "$fixture/AndroidManifest.xml" \
    -o "$work/unsigned.apk"
jar --update --file "$work/unsigned.apk" -C "$work/dex" classes.dex -C "$work" "$native"
"$tools/zipalign" -P 16 -f 4 "$work/unsigned.apk" "$work/aligned.apk"
keytool -genkeypair -keystore "$work/debug.p12" -storetype PKCS12 -storepass android \
    -keypass android -alias androiddebugkey -dname 'CN=Android Debug' -keyalg RSA -keysize 2048 -validity 1
"$tools/apksigner" sign --ks "$work/debug.p12" --ks-pass pass:android \
    --out "$work/smoke.apk" "$work/aligned.apk"
"$tools/apksigner" verify "$work/smoke.apk"
"$tools/zipalign" -c -P 16 4 "$work/smoke.apk"
unzip -p "$work/smoke.apk" "$native" | cmp "$work/$native" -
mv -- "$work/smoke.apk" "$output"
