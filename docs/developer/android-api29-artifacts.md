# Android API-29 Artifact Evidence

## Status

Stage51 produced a deployment candidate on November 17, 2026. Native builds,
packaging and JVM checks passed. No Android device was attached or updated.
This is not device-routing certification or a battery measurement.

Runtime activation remains local. Published SDK/DNS components and this artifact
record do not mean the complete integration is available from `main`.
The [acceptance ledger](physical-network-acceptance.md) remains authoritative.

## Build Inputs

| Input | Value |
| --- | --- |
| Native source snapshot | `/nix/store/8jpykms95avyz9gkb96a8ps39n7xv2xf-source` |
| Native builds | Nix `android-native-arm64` and `android-native-x86_64`; release profile |
| Extra Rust features | None; not the lifecycle-trial variant |
| ARM64 toolchain | API 29, NDK r27 |
| x86_64 toolchain | API 29, NDK r28c |
| Packaging | Current `android/` project, Gradle 9.5.1, JDK 17, SDK/build tools 37 |
| Concurrency | One Nix build at a time, two cores/jobs; Gradle two workers |
| Dependency policy | Existing caches; approximately 10 Mbps Nix download cap; Gradle offline |

The complete APK was assembled through the existing Gradle dependency cache.
The full Nix APK/check derivations were not run; no such pass is claimed.
Both native libraries were built by their actual Nix derivations, not substituted
from the previous API-26 phone build.

## Results

| Check | Result |
| --- | --- |
| Native ELF metadata | Both ABIs report Android 29 and their expected NDK version |
| Native and packaged LOAD alignment | Four LOAD segments per ABI, each `0x4000` |
| JNI declarations | All 21 Java-generated entry points match both native and packaged libraries |
| Merge provenance | Each merged JNI file equals its current Nix output |
| Package provenance | Each packaged JNI file equals Gradle's stripped output; its `.text` equals the Nix input |
| APK contents | Exactly the intended ARM64 and x86_64 JNI libraries |
| Application ID | `org.hermeticfoundation.p2pvpn.debug` |
| Manifest SDK levels | Minimum 29; target 37 |
| APK signature | Valid v2 signature using the repository's public debug key |
| APK zip alignment | `zipalign -c -P 16 4` passed |
| JVM tests | 196 passed across 38 suites; zero failures, errors or skips |
| Lint | Passed; 12 warnings, zero errors |

Lint warnings cover obsolete SDK guards, launcher shapes, plural formatting and
an accessibility label. They are not hidden or counted as a warning-free lint
result. Unrelated UI/legacy-guard cleanup is outside this goal.

## Artifact Fingerprints

The local APK is `android/app/build/outputs/apk/debug/app-debug.apk`.
Gradle stripping changes complete-library hashes; code-section comparisons
above establish provenance across that transformation.

| Artifact | SHA-256 |
| --- | --- |
| APK | `51d8b720c84c0f7bf5ac63e780f0798b25bed2c57ea92f4c2f182545167141ca` |
| ARM64 Nix input | `f52f6b802628193caa3c94973e725f4f13e552a427d79bf3f5f671e5a4845adc` |
| ARM64 packaged library | `2b040c8566476f1abcd446bc6427a60e818b2727cc271aa8eef2de4c49fc0258` |
| x86_64 Nix input | `2cca077bd88cf5c5a12741cb5c91df81eea2247156918c8946dc1a79d8034e87` |
| x86_64 packaged library | `0dc0205ec5cd187c0a1262e4ae503f270cfa9f294c13e34ec269ab629d12d54b` |

## Pending Acceptance

- Preserve saved identity, profiles and pairing data during an in-place update.
- Verify incoming/outgoing access and OS-preferred failover/validated return.
- Attribute actual Android traffic to interfaces, including DNS and mDNS isolation.
- Check address loss, stale ownership and retired-path quietness on hardware.
- Restore device settings and publish coherent runtime activation after acceptance.

Host and namespace results remain preserved in the ledger. ELF metadata and
JVM tests do not prove Android kernel/netd routing or DNS execution behavior.
