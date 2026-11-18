# Android Physical Handoff: Stage53

## Acceptance Status

| Milestone | Result |
| --- | --- |
| M1 Linux | Remains closed; no Linux milestone reopened |
| Android physical selection | Wi-Fi, cellular selection and automatic Wi-Fi return observed |
| Cellular continuity | Fails: repeated circuit outages after initial recovery |
| Runtime publication | Still local; Stage52 Java callback fixes remain published as `683eb498` |
| Battery evaluation | Not performed; no savings claim |

## Diagnostic Addition

The local candidate adds one bounded, on-demand native `State` request.
It exposes individual peer paths, capabilities, physical socket ownership and
relay inner/outer connection epochs without enabling periodic polling.

See [the snapshot contract](android-live-transport-snapshot.md). This new
endpoint and the additional ownership lines are local candidate functionality,
not yet part of the published runtime integration.

| Guard | Verification |
| --- | --- |
| Main-thread responsiveness | Debug worker runs native control off the broadcast/main thread |
| Admission | One worker; no request queue; idle worker retires |
| Selection contention | Runtime/slot locks use fail-fast reads before control timeout |
| State integrity | One live `State`; no cached-summary substitution or retry |
| Size | Explicit line, byte and escaped-JSON limits; no truncation |
| Health polling | Physical ownership appears only in explicit `State`, not periodic `Status` |

## Build Evidence

| Check | Result |
| --- | --- |
| Android native host boundary | 95 passed; zero failed |
| Core runtime-control views | Six passed; zero failed |
| Connection epoch formatter | One passed; zero failed |
| JVM suite | 198 passed across 39 suites; zero failed/errors/skipped |
| Android lint | Zero errors; 12 existing warnings |
| API-29 Nix outputs | ARM64 and x86_64 built successfully |
| Native contract | 22 matching Java/JNI methods on each ABI |
| ELF alignment | Four LOAD segments per ABI, each `0x4000` |
| Source provenance | 209 application/native source files match the Nix input |
| Phone APK | ARM64-only offline Gradle candidate; minimum SDK 29 |
| APK signature/alignment | Existing debug certificate; 16-KiB zip alignment passed |
| Full Nix APK/workspace | Not rerun; retained Stage50 evidence is not relabeled as this build |

| Artifact | SHA-256 |
| --- | --- |
| Installed ARM64 APK | `99c031c5111547e469e43a1f1b329790377736cb50037d06d1e42b8ace7e4411` |
| ARM64 Nix library | `2998b474686c89b1f55264153581341e44a87a15f3e774f0d50f53c247e65312` |
| Packaged stripped ARM64 library | `14c6de45d2b80146901a2dd93993d31ddc5df7bfccaa14099071a5f1763e41f0` |
| x86_64 Nix library | `333a03a472850e9e2b0009c67587296e712255763dab54a71f97a44c9831cea9` |

Nix native input: `/nix/store/cgax1fji2bh3djk1l8qd898hg2ylhkbw-source`.
The x86_64 library was verified, but was not packaged into the phone APK.

## Device Run

| Item | Observation |
| --- | --- |
| Device | Authorized Pixel 8 Pro, API 37, USB management only |
| Network | Existing `personal-devices` profile; no re-pairing or manual route/dial |
| Capture | LAN baseline, Wi-Fi disabled, eight cellular snapshots, simultaneous bidirectional dual-stack checks, Wi-Fi return |
| Cellular incoming trace | 108/230 delivered; 53.04% loss across transition and repeated outages |
| Final cellular probes | IPv4/IPv6, both directions: 5/5 each |
| LAN return | Wi-Fi preferred, four direct QUIC peers, zero overlay relay paths |
| Returned LAN probes | Incoming IPv4/IPv6: 5/5 each; phone-originating IPv4/IPv6: 3/3 each |
| Runtime continuity | PID `26443` unchanged throughout all capture checkpoints |
| Restoration | Wi-Fi and mobile data enabled; Private DNS unchanged (`off`) |
| Persistence | Encrypted profile and membership hashes unchanged |

The successful final probes do not erase the preceding outages. Collector exit
zero means capture completed and restoration ran, not that acceptance passed.
No ADB forward/reverse tunnel carried VPN test traffic.

## What The Evidence Narrows

1. The first working circuit had an adopted TCP owner on cellular interface 15.
2. Its cached lease was current; inner/outer epochs were usable and not retiring.
3. At later failing snapshots, that circuit and its outer socket owner were gone.
4. New circuit/outer connection IDs restored delivery on cellular generation 9.
5. The process did not restart; cellular stayed selected and validated.
6. Wi-Fi return recovered automatically without resetting the VPN.

This is actual connection/path loss and recreation, not merely misleading
aggregate relay counts. The sampled epoch evidence does not support stale
connection-epoch rejection as the explanation for the observed working circuits.

## Still Unknown

| Question | Required Evidence |
| --- | --- |
| Who closed the cellular outer connection? | Phone-side close cause and explicit local-retirement intent |
| Did the public relay impose a limit? | Negotiated circuit duration/data limits correlated with closure |
| Why did recovery leave repeated gaps? | Exact close/retry/capability sequence and a reproducing fixture |
| Is fallback cleanup correct after preferred return? | Per-owner retirement/traffic proof, not aggregate relay count alone |

Linux sees relayed EOF/closure, which does not establish the phone-side cause.
The generic finite-relay fixtures from Stage52 do not reproduce Android
outer-Network behavior and do not settle these questions.

## Next Deliverable

1. Retain bounded close-cause/local-intent and negotiated-limit evidence.
2. Correlate it with the captured inner/outer IDs and failing packet intervals.
3. Reproduce the identified failure before changing recovery or ownership guards.
4. Apply the smallest required fix, repeat the device cycle and verify cleanup.

Do not raise relay limits, weaken authentication or extend timers merely to
hide these gaps. Keep M1 closed unless a specific regression is reproduced.

## Private Evidence

Raw `cycle3-*` files remain in the owner-only directory:

```text
/tmp/p2p-vpn-battery-build-Qm1dQ1k2/android-policy-device/
```

The collection script passed Bash syntax and ShellCheck checks before execution
and was not edited while running. Its SHA-256 is
`bd12dde39f83c67076343e30f780d6f9cbd4994b1f39e1477ad1e46d587bc759`.
