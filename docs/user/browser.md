# Browser WebAssembly

The browser package runs the Rust packet forwarder, signed membership and route
authorization, packet codecs, and a userspace TCP/IP stack inside WebAssembly.
WebRTC Direct carries the existing `/p2p-vpn/control/1` and
`/p2p-vpn/packet/1` protocols to a native peer.

The app can connect to a configured peer and send IPv4 HTTP requests inside the
VPN. Browser navigation, ordinary `fetch()`, other tabs, and the host OS do not
acquire VPN routes.

## Connect To Your Network

| Required | What To Use |
| --- | --- |
| Browser config | Its own JSON config and private key, with the native peer authorized. Use MTU 1280. |
| Native peer | A daemon built with `cargo build --locked --features webrtc`, configured to authorize the browser peer. |
| Native endpoint | A reachable WebRTC Direct UDP listener and its complete dial multiaddr. |

On Nix, `nix build .#webrtc` builds the opt-in native package. On NixOS,
set `services.p2p-vpn.package` to that flake package for your system and set
the instance's `listenAddresses` to include the WebRTC Direct listener.

Use `p2p-vpn init-config` twice for a new network, with the same `--network`
but distinct output files. Run `p2p-vpn status --config FILE` for each ID. Add
the other ID to each file's `peers` as `{ "id": "OTHER_PEER_ID" }`.

Add `/ip4/NATIVE_UNDERLAY_IP/udp/4002/webrtc-direct` to the native config's
`network.listen_addresses`. Start the native daemon with `p2p-vpn up` as usual.
Copy the complete `address` from its `webrtc_listener_ready` log event.

Use the actual LAN or publicly reachable underlay IP, not the VPN IP. You may
need to allow the UDP port on the host firewall. Restarting the daemon can
change its certificate hash, so copy the address from the current run.

On Linux or macOS, build and serve the browser package:

```sh
bash scripts/build-browser.sh
python3 -m http.server 8788 --bind 127.0.0.1 --directory crates/p2p-vpn-browser/web
```

The build needs Cargo, the `wasm32-unknown-unknown` Rust target and linker,
`jq`, and the `wasm-bindgen` CLI matching `Cargo.lock`. With rustup,
run `rustup target add wasm32-unknown-unknown`. On Windows, use
`.\scripts\build-browser.ps1` and serve the same directory.

1. Open [the local app](http://127.0.0.1:8788/app.html) in Chromium or Chrome.
2. Select the browser peer's JSON config and paste the native dial address.
3. Connect. Enter the native **overlay** IPv4, service port, and HTTP path.
4. Send a request. Find the default overlay IPv4 in `p2p-vpn status --config FILE`.

The config file is read locally, not uploaded or saved by the page. Keep
configs outside the served directory. Serve only trusted artifacts, over
loopback locally or HTTPS when hosted. Do not enable test hooks for deployment.

## Qualification On Windows

The complete elevated qualification command builds both peers, checks Wintun,
runs Chrome, and verifies native packet counters and adapter cleanup:

```powershell
.\scripts\test-browser.ps1
```

To build separately:

```powershell
.\scripts\build-browser.ps1 -TestHooks -NativeFixture
```

The build script installs the Rust WASM target, builds the package, and obtains the
matching official `wasm-bindgen` CLI with its published SHA-256 checksum.
Generated JavaScript and WASM go to `crates/p2p-vpn-browser/web/pkg`.
`-TestHooks` adds an explicit spoofed-source injection used by the test runner;
omit it from an application build.

The fixture needs elevation and the official signed x64 `wintun.dll` beside
`target/debug/browser-fixture.exe`. The existing Windows build script downloads
and verifies Wintun; its extracted DLL is under
`target/wintun-0.14.1/wintun/bin/amd64` after a Windows build.

## Run the qualification fixture

Use a reachable IPv4 address of the native host for WebRTC:

```powershell
.\target\debug\browser-fixture.exe --webrtc-ip YOUR_LAN_IP
```

Open `http://127.0.0.1:8787`. Connect the browser peer, fetch through the VPN,
and reconnect to fetch again.

The loopback HTTP server serves the page and disposable test credentials. The
proof HTTP service binds only the native test overlay address, `10.203.0.1`.
Do not run this fixture if `10.203.0.1` or `10.203.0.2` is already in use.
It creates a fresh `p2p-wasm-PID` adapter and host routes for the synthetic
network. Stop with Ctrl+C; the daemon stops and releases the test adapter.
It does not load an existing VPN configuration or contact public bootstrap peers.

Automated Chromium qualification, in another terminal:

```powershell
Set-Location crates/p2p-vpn-browser
npm ci
npm run test:e2e
```

The test uses an installed Chrome browser, sends a unique HTTP request through
the overlay, checks bidirectional packet counters, requires native rejection of
a spoofed source address, resets WebRTC, and requests a new response. It shuts
the fixture down afterward. `P2P_VPN_BROWSER_REPORT` can name a JSON evidence
file; `P2P_VPN_BROWSER_SCREENSHOT` can name a screenshot.

On Windows, the complete qualification command temporarily permits its HTTP
service through the firewall, scoped to the fixture executable, fresh test
adapter, service port, and browser overlay address. It removes that rule and
checks adapter removal after the run. Interactive use needs the corresponding
service firewall policy, as with the native VPN.

## Run on two devices over a LAN

The native Windows host needs elevation, Rust and Node.js. The second device
needs Node.js, npm and installed desktop Chrome; it does not need Rust, Wintun,
or administrator privileges. Both devices must permit peer traffic on the LAN
(guest Wi-Fi/client isolation can prevent it). Use their actual private IPv4
addresses, not the synthetic `10.203.0.x` overlay addresses.

On the native host, in elevated PowerShell, replace both example addresses:

```powershell
.\scripts\test-browser.ps1 -Lan -WebRtcIp 192.168.1.6 -ClientIp 192.168.1.20
```

The script builds the artifacts, creates a disposable native peer and exports
`target/browser-lan-TIMESTAMP/client.zip`. It prints that path, its SHA-256 and
the destination for the returned `client-report.json`, then waits up to 30 minutes.
`-SkipBuild` reuses existing artifacts; they must have been built with `-TestHooks`.
`-TimeoutSeconds` accepts 30 to 3300 seconds; credentials expire after one hour.

Copy the ZIP to the second device through your existing trusted transfer method.
The ZIP contains that test browser's private key and signed membership, but no
native private key or shutdown token. Keep it private and use a fresh bundle for
each run. Compare its SHA-256 with the value printed on the host.

On the second Windows device, in ordinary PowerShell:

```powershell
Get-FileHash .\client.zip -Algorithm SHA256
Expand-Archive -LiteralPath .\client.zip -DestinationPath .\browser-client
Set-Location .\browser-client
npm ci --no-audit --no-fund
node client.mjs --test
```

On macOS/Linux, extract the same bundle, enter its directory, then run the last
two commands. Only Windows/Chrome has been exercised locally so far.
The client serves its copied page and WASM on its own `127.0.0.1` HTTP listener;
WebRTC connects to the native host's LAN UDP port. Setup credentials are not
served over LAN HTTP. Loopback origins are
[potentially trustworthy contexts](https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy).

The automated client saves `client-report.json` and `client.png` in its directory.
Copy **only the report** to the exact incoming-report path printed by the host.
The host then shuts down the native peer, verifies TUN and firewall cleanup,
and checks the returned report against its session, build hash, native packet
counters and both fresh HTTP nonces from native TUN-service logs.
It saves `browser.json`, `native-session.json`, native logs and
`lan-verification.json` under the timestamped evidence directory.
`cleanup.json` also records shutdown and resource cleanup on handled failures.
Keep the screenshot alongside these if useful. These reports do not contain keys.

The two temporary firewall rules permit only the browser overlay source at the
TUN HTTP service and the specified LAN client at the exact native WebRTC UDP
port/executable. They are removed on normal success, timeout or handled failure.
Let cleanup finish rather than killing PowerShell. Do not change global firewall
policy. The LAN IP reservation, Wi-Fi isolation and any outbound policy must allow
the selected path; this test does not configure routers or NAT traversal.

The client rejects execution on the native host in LAN mode. An explicit local
smoke mode exercises the exported bundle and cleanup without claiming two devices:

```powershell
.\scripts\test-browser.ps1 -Lan -LocalSmoke -WebRtcIp 192.168.1.6 -ClientIp 192.168.1.6 -SkipBuild
```

Its verdict is `PASS_SAME_HOST_SPLIT_HARNESS_SMOKE`. Only an actual second-device
run with matching native and browser evidence can produce `PASS_TWO_DEVICE_LAN`.
Host/IP metadata and reports are operator-controlled evidence, not cryptographic
proof that a physical machine is distinct. Public NAT/relay remains a separate gate.

## Embed the browser peer

```javascript
import init, { BrowserVpn } from './pkg/p2p_vpn_browser.js';
await init();
const vpn = new BrowserVpn(JSON.stringify(config), nativeWebRtcMultiaddr);
await vpn.connect();
const rawHttpResponse = await vpn.fetch_http('10.203.0.1', 8080, '/health');
console.log(JSON.parse(vpn.snapshot()));
await vpn.reset_connection();
```

`config` uses the existing configuration and signed legacy membership format.
It must contain the browser's own identity, authorize the native peer, grant
the corresponding overlay addresses, and use MTU 1280. Keep private keys in the
browser/application; the fixture's disposable credentials are for local tests.
Custom addresses require signed route grants and the `route_authority` role,
following the native membership rules.
The native address includes its certificate hash and pinned peer ID:

```text
/ip4/HOST/udp/PORT/webrtc-direct/certhash/HASH/p2p/PEER
```

Native daemon builds enable the optional transport with `--features webrtc`
or `scripts/build-windows.ps1 -WebRtc`. Add a WebRTC Direct listening multiaddr
to the native configuration. The native peer needs its own browser-reachable
UDP listener; adding a browser adapter alone cannot connect to TCP/QUIC-only peers.

## Current scope

- Foreground browser-to-native WebRTC Direct; IPv4 HTTP text responses.
- Signed legacy membership and the shared packet/route authorization core.
- Fixed MTU 1280, 32 outstanding packet requests, bounded packet queues,
  30-second HTTP deadline, and a 1 MiB response limit.
- Operations drive the swarm on demand. After tab suspension or a closed path,
  reconnect with the peer config and the daemon's current address.
- Browser-to-browser signaling, NAT/relay fallback, durable browser key storage,
  browser pairing UI, cooperative checkpoint enrollment, IPv6 application
  sockets, HTTPS, and background lifecycle recovery remain later milestones.

The WebRTC transports are locally patched for the
[WebRTC Direct r2 handshake](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md).
The browser leaves its local ICE credentials unchanged; the native listener
accepts v1 and v2. See the developer validation record for tested browsers and
the evidence boundary.
