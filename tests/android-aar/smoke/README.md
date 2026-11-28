# Run the standalone Android AAR smoke test

The test app uses the packaged AAR without the first-party application or a
local Rust build. It verifies that Android loads the JNI library and that
creating, inspecting, and renaming a profile preserve the peer ID.

Use an x86_64 Linux host for the Nix commands. The flake enables Android SDK
license acceptance. From the SDK repository, build the AAR and enter the
Android development shell:

```sh
export SDK_AAR="$(nix build --no-link --print-out-paths .#android-aar)/libp2p-vpn-android.aar"
nix develop .#android
```

Use a booted emulator or a test device running Android 10 (API 29) or later.
Set `serial` to its serial from `adb devices` and `abi` to its primary ABI
(`x86_64` or `arm64-v8a`).

```sh
apk="$(mktemp -d)/smoke.apk"
bash tests/android-aar/smoke/build.sh "$SDK_AAR" "$abi" "$apk"
bash tests/android-aar/smoke/run.sh "$apk" "$serial"
```

A successful run prints `PASS Android AAR preserves peer identity across rename`.
The runner removes the test app afterward. The test does not request VPN access,
start a tunnel, or test network changes.
