# Android Physical Callback Verification

## Scope

Stage52 uses an authorized Pixel 8 Pro running API 37. It extends the
[physical-network ledger](physical-network-acceptance.md), not the closed Linux
milestone. Battery measurement is outside this work.

## Confirmed Callback Defects

| Defect | Device evidence | Required correction |
| --- | --- | --- |
| Application default became our VPN | Android assigned the UID's default callback to the VPN despite excluding that UID from VPN routing; the app then cleared physical preference | Observe the OS-selected best eligible non-VPN Internet Network |
| Background inventory was hidden | The listener acquired a framework-added `FOREGROUND` capability and omitted live cellular while Wi-Fi was preferred | Declare `CHANGE_NETWORK_STATE` on all supported versions, not only API 29-30 |

After both corrections, Android reports Wi-Fi and cellular as available while
selecting validated Wi-Fi. The actual inventory and best-match listeners no
longer contain the framework-added foreground-only constraint.

## Registration Contract

| Boundary | Behavior |
| --- | --- |
| Inventory | Existing passive non-VPN listener remains separate; LAN-only Networks are not filtered out by an Internet requirement |
| Preference | `INTERNET` plus `NOT_VPN`; no hardcoded transport order, metering requirement or validation filter |
| API 31 and newer | Passive `registerBestMatchingNetworkCallback` |
| API 29-30 | One service-owned `requestNetwork`, released through existing callback cleanup |
| Callback lifetime | Existing owner/incarnation fences and candidate equality checks remain unchanged |
| Selection | Android scores eligible Networks; this is not necessarily the application's VPN default |

The legacy request is active: it can establish or retain the best matching
Network. Newer versions use passive observation. Neither branch creates one
request per peer or per transport.

## Verified Evidence

| Check | Result |
| --- | --- |
| In-place update | Repository debug signing key accepted; no uninstall or data clearing |
| Identity | Same peer ID and overlay addresses |
| Saved state | Encrypted profile and membership file remain byte-identical |
| Runtime pairing cache | Encrypted runtime file changed; no byte-identical claim is made for it |
| LAN traffic | IPv4 and IPv6 probes passed in both directions |
| Actual interface sample | UID packet counters showed `wlan0` on LAN and `rmnet1` on cellular |
| Registration | Device shows separate `LISTEN` and `LISTEN_FOR_BEST` non-VPN requests |
| JVM coverage | 197 passed, zero failures/errors/skips; includes best-match loss preserving available inventory |
| Lint and packaging | Offline debug assembly and lint passed; native libraries reused from Stage51 |

The retained Java changes are limited to registration, the normal network-state
permission and the regression test. An attempted debug view could not obtain
per-peer paths from cached summary status and was removed before publication.

## First Transition Outcome

This run used the best-match repair with the network-state permission still
limited to API 29-30. It is not acceptance of the final permission repair.

| Observation | Result |
| --- | --- |
| Wi-Fi to cellular | OS-selected cellular, no operator reset or manual route setup |
| Incoming IPv4 trace | 83/120 delivered; startup recovery and a later outage are retained |
| Late failure | Last trace reply was sequence 109; subsequent steady probes failed |
| Queue evidence | 660 aggregate no-supported-path events; 21 expired outbound packets; no recorded inbound drops |
| Aggregate connectivity | Relay paths elsewhere remained visible; this does not prove a usable circuit to the affected peer |
| LAN return | Recovered automatically; 75/90 transition probes delivered, with LAN-latency replies at the end |

Circuit expiry/replacement is under investigation. The default relay circuit
limits are 120 seconds and 128 KiB; actual public-server limits were not captured.
Those defaults are a lead, not a confirmed cause. Do not increase limits or
weaken ownership/authentication checks to hide a failed recovery.

## Second Transition Outcome

This run includes both callback corrections. It confirms that the permission
repair does not, by itself, resolve the late cellular outage.

| Observation | Result |
| --- | --- |
| Incoming cellular IPv4 trace | 91/185 delivered, including transition and late outage |
| Late outbound probes | IPv4 0/10 and IPv6 0/10 |
| Later incoming probes | IPv4 2/10, followed by IPv6 10/10 |
| Target circuit | Linux recorded a replacement connection ID between the early and final cellular snapshots |
| Queue evidence | 502 aggregate no-supported-path events and 20 expired outbound packets |
| LAN return | Linux selected `direct_quic_datagram`, three healthy direct paths and zero relay paths |
| Returned-LAN probes | IPv4 5/5 and IPv6 5/5 |
| Process and configuration | Same process ID across checkpoints, facade generation 1; Wi-Fi restored and profile/membership hashes unchanged |

The later IPv6 success does not erase failed earlier probes. A replacement
circuit and restored delivery show eventual recovery, not stable cellular
acceptance. Checks were sequential; their different outcomes do not prove an
IPv4-specific fault.

## Finite-Circuit Regression

| Fixture | Result and limit |
| --- | --- |
| Real circuit expiry | Passed with a 12-second / 32-KiB limit; new circuit IDs, validated metadata and bidirectional stream payload recovered without a physical event |
| Overlapping successor | Passed; old-circuit expiry preserved the authenticated successor and five fresh bidirectional payload pairs |
| Final focused run | Two passed, zero failed, 66.95 seconds |
| Verification boundary | Host fixtures do not exercise Android outer-Network migration and did not reproduce the prolonged device stall |

These results narrow the next investigation; they do not close Android relay
recovery or justify weakening its ownership checks. Linux M1 remains closed.

## Current Candidate And Pending Work

| Item | Value |
| --- | --- |
| Candidate APK SHA-256 | `a3fc10607342d26b9dd775087e3a420ea1a350c240318bccf97403d9934d6c28` |
| Native source | Unchanged Stage51 Nix outputs; complete runtime activation remains local |
| Second transition | Captured; stable cellular acceptance failed, automatic LAN return passed |
| Completion | Android handoff, interface isolation, retirement and coherent runtime publication remain open |

Probes use overlay addresses; USB is only the management path. Private raw
captures remain outside the repository. Transition loss and steady-state results
are reported separately; a collector exit code is not an acceptance verdict.

## Platform References

- [Public ConnectivityManager APIs](https://developer.android.com/reference/android/net/ConnectivityManager): application defaults may be virtual; best-match observation starts at API 31.
- [AOSP request restrictions](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/main/service/src/com/android/server/ConnectivityService.java): background-network restrictions add `FOREGROUND` to unprivileged listeners.
- [AOSP permission mapping](https://android.googlesource.com/platform/frameworks/base/+/8c702c2d6ae485f71110b9593b25af5367fda220/packages/Connectivity/service/src/com/android/server/connectivity/PermissionMonitor.java): the normal network-state permission grants background-network access.

API 29-30 registration is source/SDK reviewed, not hardware-tested on this Pixel.
No older-device hardware pass or numerical energy improvement is claimed.
