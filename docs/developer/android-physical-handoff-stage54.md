# Android Physical Handoff: Stage54

## Scope

This record covers the integrated Android physical-network policy on the
authorized Pixel 8 Pro, API 37. It preserves the earlier failure captures and
separates OS-selection correctness from public-relay availability.

The [fixed acceptance ledger](physical-network-acceptance.md) remains the goal
authority. Battery evaluation and early RX-key eviction are outside this work.

## Verification

| Check | Result |
| --- | --- |
| Workspace/all targets | 2,648 passed; zero failed; 89 ignored across 22 suites |
| Core boundary | 2,162 passed; zero failed; 33 ignored |
| Android native boundary | 95 passed; zero failed |
| JVM | 198 passed; zero failed/errors/skipped |
| Android lint | Zero errors; 12 existing warnings |
| Clippy | Correctness, suspicious and performance gates passed; advisory warnings remain |
| Finite relay fixtures | Expiry recovery, overlapping successor and exact limit assertion passed |
| Native builds | ARM64 and x86_64, API 29, 22 matching JNI methods per ABI |
| Native alignment | Four LOAD segments per ABI; all at least 16 KiB |
| Source preflight | 213 application/manifest files match the Nix native input |
| Phone APK | ARM64, minimum API 29, existing debug signature, zip alignment verified |

The final test-only byte-token parser change was checked by rerunning all three
affected relay fixtures. The workspace run covers the identical production
runtime, not a claim that every test file was unchanged afterward.

Full Nix APK construction was not rerun. Packaging used the existing offline
Gradle cache with Nix-built native libraries; no emulator/Gradle cache was added.

## Artifacts

| Artifact | SHA-256 |
| --- | --- |
| Installed ARM64 APK | `580096a74a40fcc8f6b73bcd3777864187bd1de43228f24cc27b5b7d067851aa` |
| ARM64 Nix library | `34c60d41c77a1ae891eb03907a9082098742878d16144f7fb89b72c51f01e130` |
| Packaged ARM64 library | `4a4ff0dc21ce682904ef9a7e6016e9d5d9b529d38fc51e064e3aeac1d9de069e` |
| x86_64 Nix library | `9640446cef62564fa7209d0e61561217cf405041218f1035b17f55de934b3ba4` |

Native source: `/nix/store/dmlc8qa11pvjhiqmg8pmn0npdv0iljin-source`.
The installed APK contains ARM64 only; x86_64 was built and verified separately.

## Relay Failure Isolation

| Run | Observation | Interpretation |
| --- | --- | --- |
| Cycle4 | 138/250 delivered; repeated TCP `ConnectionReset` on the outer relay socket, followed by inner closure | Kernel-reported path reset, not just a missing-path counter |
| Limits | Affected circuits reported 120 seconds / 131,072 bytes | Resets occurred well before the duration allowance; byte exhaustion was not measured |
| Local intent | No matching local close request in the captured affected-relay history | No evidence that the physical-policy controller requested those closes |
| Comparison setup | Restarted only the laptop's `personal-devices` service; it selected another IPv4 relay automatically | Diagnostic intervention; not claimed as autonomous repair of the old public path |
| Cycle5 | 202/250 delivered: sequences 26-145 and 169-250 | Initial convergence, then one 23-packet gap near inner-circuit expiry; automatic recovery |
| Alternate outer | No active outer-TCP reset; same adopted cellular owner survived the comparison | Narrows the repeated reset toward the former relay/path, not all cellular TCP |

A TCP reset does not identify whether the relay host or an intervening network
device generated it. Public-relay administrative policy was not inspected.
The comparison does not claim a new relay-health feedback protocol.

The phone also retained a live cellular IPv6 QUIC control connection. The laptop
had no IPv6 route to that relay. Do not equate a live incoming reservation with
reachability from every other peer or address family.

## Continuous Preferred Return

`return6` warmed the cellular path, then ran continuous source-bound probes
through Wi-Fi restoration. Neither process was restarted during this handoff.

| Direction | IPv4 | IPv6 |
| --- | --- | --- |
| Laptop to phone | 150/150 | 150/150 |
| Phone to laptop | 150/150 | 150/150 |

| Checkpoint | Selected transport | Relay payload counter | Owned UDP counter | Owned QUIC counter |
| --- | --- | --- | --- | --- |
| Cellular ready | Circuit relay | 386 | 0 | 27 |
| Return +5s | Circuit relay | 426 | 0 | 27 |
| Return +15s | Direct QUIC stream | 440 | 0 | 27 |
| Return +30s | Direct UDP datagram | 440 | 35 | 27 |
| Return +60s | Direct QUIC datagram | 440 | 70 | 109 |
| Return +120s | Direct QUIC datagram | 440 | 70 | 349 |
| Return +145s | Direct QUIC datagram | 440 | 70 | 449 |

The fallback carried payload while preferred paths were being validated.
Relay payload then stopped, followed by redundant UDP payload, while preferred
QUIC datagrams continued. No forced transport setting was used.

## Ownership And Retirement

| Item | Before | After |
| --- | --- | --- |
| Relay TCP source | Cellular, interface 15 | Wi-Fi, interface 47 |
| Physical connection | 5448 | 5824 |
| Old owner | Still available while preferred validation ran | Absent at +120s and +145s |
| New owner | Present alongside fallback at +60s | Adopted, current and used on Wi-Fi |
| UDP receive-only retention | One at +60s | Zero at +120s and +145s |
| Process IDs | Phone 28818; laptop 990756 | Unchanged throughout `return6` |

An unrelated peer's necessary relay is not evidence that the tested peer kept
using an old fallback. Likewise, IPv6 control traffic may still use cellular
when Wi-Fi has no route for that destination/family.

## Resources And Restoration

| Item | Result |
| --- | --- |
| Captured snapshots | 47 across Cycle4, Cycle5 and `return6` |
| Physical control owners | Observed range 5-39 |
| Retiring/receive-only sessions | Observed maxima four each; pending UDP validation maximum zero in samples |
| Final process descriptors | 141; a point observation, not a sustained-resource benchmark |
| Profile and membership | Original hashes unchanged; no re-pairing |
| DNS | Original phone A/AAAA records resolve after handoffs |
| Radio settings | Wi-Fi and mobile data enabled; Private DNS unchanged (`off`) |
| Management | USB ADB only; no forward/reverse data tunnel or manual route/config entry |

## Acceptance Mapping

| Requirement | Authoritative evidence |
| --- | --- |
| OS destination/family preference | Backend selection tests; physical source ownership changes in `return6` |
| Preferred loss and automatic fallback | Cellular warm-up and Cycle4/5; non-destructive physical-hint fixtures |
| Validated preferred return | 600/600 continuous probes and the transport/counter sequence above |
| Retry after a blocked attempt | `failed_preferred_validation_retries_without_epoch_change_and_never_selects_an_alternate` and real-control recovery fixtures |
| IPv4/IPv6 address replacement | Android datagram withdrawal/interface-replacement tests and prepared-source/hostname negotiation fixtures |
| Stale completions | Incarnation/record/epoch, cancelled lookup and exact ACK/ticket tests |
| Discovery isolation | Published LAN eligibility/JVM tests and native overlay/pairing mDNS scope tests |
| Bounds and repeated transitions | Existing hard admission limits, full regressions and observed multi-transition resource counts |
| Old-path retirement | Payload plateaus, preferred owner adoption, old cellular-owner removal and original-TTL retention tests |
| Asymmetric Linux ingress | Preserved Stage50 namespace evidence; production routing unchanged by the later diagnostic additions |
| Workflow compatibility | Unchanged profile/member hashes, peer identity, configuration and successful DNS/data delivery |
| Available Android hardware | API-37 kernel/netd ownership and continuous bidirectional dual-stack payload checks |

Real IPv6-only/CLAT carrier behavior and Android 10/11 physical devices were not
available. Those hardware variants are not certified by this run; stacked-source
safety has model coverage, and API-29 artifacts are build evidence, not phone proof.

## Reproduction And Limits

Private raw captures remain under:

```text
/tmp/p2p-vpn-battery-build-Qm1dQ1k2/android-policy-device/
```

- `cycle4-*`: reset/limit evidence with the original relay.
- `cycle5-*`: alternate-relay comparison after the declared laptop restart.
- `return6-*`: uninterrupted probes, owner retirement and counter plateaus.

The collectors were syntax/ShellCheck checked and frozen during execution.
The source preflight snapshots Jujutsu and compares the exported native source
before building; an initial omitted-file packaging failure was not deployed.

These results do not establish battery savings, gap-free public-relay service,
all-OEM compatibility, or production readiness. Proactive circuit renewal and
remote relay-health feedback remain separate potential improvements.
