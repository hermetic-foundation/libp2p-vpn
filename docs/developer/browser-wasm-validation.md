# Browser WASM milestone validation

Verdict: **PASS for the local browser/native IPv4 HTTP milestone**.
This is not qualification for a general browser VPN product or public NAT traversal.

## What ran

On 2026-11-13, installed Chrome 156.0.8078.82 ran the Rust VPN core and
smoltcp in `wasm32-unknown-unknown`. WebRTC Direct v2 connected it to the native
Windows daemon on the same computer, using the host's Ethernet IPv4 address.
The native daemon used a real Wintun device; its proof HTTP service bound only
`10.203.0.1`, not the browser asset server's loopback address.

The browser used the existing control and packet codecs, signed legacy
membership, route/source authorization, queue framing, and replay checks.
Both test members held signed authority for their explicit test host routes.
No public bootstrap or relay infrastructure was used.

The recorded run is `target/browser-validation-20261113-212224`.
[Machine-readable evidence](browser-wasm-results.json) retains public peer IDs,
unique response nonces, counters, artifact hashes and the changed-source digest.
Generated private test keys are not in the report.

| Gate | Observed result |
| --- | --- |
| Transport and identity | Actual WebRTC and libp2p identity authentication, then authorized VPN capability exchange. |
| Real application delivery | HTTP 200 with a newly generated nonce, carried as TCP/IP inside `/p2p-vpn/packet/1`. |
| Browser packet counters | Each HTTP transaction: 7 sent/accepted IP packets and 4 received IP packets. |
| Native backend evidence | 10 outbound packets through the selected WebRTC stream backend. |
| Negative authorization | Native returned `Rejected(UnauthorizedSource)`; native source-drop counter was 1. |
| Reconnect | Explicit close, fresh WebRTC/VPN session, same browser identity, different nonce and fresh HTTP 200. |
| JavaScript errors | Zero. |
| Cleanup | Native exit code 0; test adapter and narrowly scoped firewall rule removed. |

The page screenshot was visually inspected after the run. This proves local
browser/native interoperability and real OS IP delivery. It does not prove a
two-computer LAN path, Internet/NAT behavior, or browser background operation.

## Verification

From an elevated Windows PowerShell with Rust, Node.js and installed Chrome:

```powershell
.\scripts\test-browser.ps1
```

The script builds both peers, obtains the matching checksum-verified official
wasm-bindgen CLI, verifies Wintun, creates a disposable test network, runs the
browser checks, validates native counters, and checks cleanup. Use `-SkipBuild`
to qualify existing artifacts. Evidence uses a new timestamped directory.

Other checks completed:

- `cargo check --locked --tests`, with default native features and with `--features webrtc`.
- Browser library tests: real userspace TCP SYN/checksum, bounded packet input
  and HTTP header-injection rejection, supported DTLS curve selection (3 passed).
- Actual native ICE credential parser tests: v2, v1 compatibility, malformed
  credentials and unknown versions (3 passed via `rustc --test tests/webrtc_ice.rs`).
- `scripts/build-browser.ps1 -TestHooks -NativeFixture`, including package generation.
- PowerShell and JavaScript syntax checks, Rust formatting, and whitespace checks.

Existing compiler dead-code warnings remain. The full historical Rust suite,
Nix/Android builds, and Linux runtime qualification were not run in this milestone.
The Nix source fileset includes the new workspace manifest and vendored sources.

## Findings preserved from failed attempts

| Stage | Finding and correction |
| --- | --- |
| Original browser adapter | Timed out before VPN authorization on current Chrome. The replacement uses the [WebRTC Direct r2 handshake](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md), preserving browser-generated ICE credentials. |
| Native DTLS | ICE connected, then DTLS failed with `invalid named curve`. Backported supported-group selection from [upstream WebRTC 0.13](https://github.com/webrtc-rs/webrtc/blob/v0.13.0/dtls/src/flight/flight0.rs), with explicit rejection when no supported group exists. |
| Fixture membership | Custom host-route advertisements were rejected until the fixture granted `RouteAuthority`. Production authorization was retained. |
| Windows HTTP policy | IP SYNs reached Wintun but the service did not respond until a temporary, narrowly scoped inbound firewall rule was applied. |
| Listener recovery | Windows UDP reset after disconnect could leave the listener without a receive waker. The receive loop now consumes recoverable errors and polls again. |
| Browser teardown | Reconnect delivered fresh HTTP, but stale DOM handlers invoked released WASM closures. Final shared owners now detach handlers; reset explicitly waits for connection closure. An attempted early data-channel close caused a control timeout and was removed. |
| Build harness | Windows parallel WASM linking stalled; one linker thread completed. PowerShell needed the child process handle retained to report its exit code reliably. |

Raw attempt logs and reports remain under `target`; they are not replaced by the
successful verdict. The three vendored patches have their own `P2P_VPN_PATCH.md`
and original licenses. The browser/native peers remain on libp2p 0.56; existing
locked package versions were retained while adding the required dependencies.

## Scope and remaining gates

This is a foreground browser-to-native SDK/harness. Its current public operation
is bounded IPv4 HTTP text over the VPN. Operations drive the swarm while pending.
The browser does not install OS routes or redirect normal browser navigation/fetch.

Public NAT/relay fallback, browser-to-browser signaling, Firefox/Safari/mobile,
HTTPS, IPv6 application sockets, durable browser keys, a browser pairing flow,
cooperative checkpoint enrollment, suspension/background recovery, and sustained
multi-flow performance remain unqualified. The fixture's loopback-served disposable
credentials do not establish production key management or onboarding readiness.

The next [split-device LAN harness](browser-lan-validation.md) exports the browser
client for a second device and checks returned evidence against native logs.
Its local smoke verdict does not extend this record to two physical devices.
