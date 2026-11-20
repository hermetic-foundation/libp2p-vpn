# Browser WebAssembly

The browser package runs the Rust packet forwarder, signed membership and route
authorization, packet codecs, and a userspace TCP/IP stack inside WebAssembly.
WebRTC Direct carries the existing `/p2p-vpn/control/1` and
`/p2p-vpn/packet/1` protocols to a native peer.

The app can connect to a configured peer and send IPv4 and IPv6 HTTP requests inside the
VPN. Browser navigation, ordinary `fetch()`, other tabs, and the host OS do not
acquire VPN routes.

The app is a foreground VPN peer. On Linux, the discovery companion resolves
member and pairing endpoints. Without the companion, provide an explicit
WebRTC Direct or Circuit Relay address. The page cannot bind physical sockets.

## Join With A Code

| Needed | What To Use |
| --- | --- |
| Inviter | A native p2p-vpn peer reachable over WebRTC Direct or a compatible relay. |
| Code | Run `p2p-vpn pair open --instance NETWORK` on the inviter. |
| Browser | Open the Linux companion URL in Chromium or Chrome. |

1. Select **Pair code**. Enter the code and, optionally, a hostname.
2. Select **Join network**. The companion tries LAN discovery first.
3. Have the inviter approve the request. The app connects after authorization.
4. Download the legacy config or the encrypted checkpoint credentials.

To reopen a checkpoint network, select **Credentials** and provide the
downloaded file and passphrase. Keep both private. The browser does not
send either to the discovery companion.

For an older v1 invitation, open **Pairing protocol**, select **v1 (scoped)**,
and enter the network name. The app never falls back across versions.

## Create An Explicit Code Invitation

Open **Create or join an explicit code invitation** from the browser app, or
open `/code-inviter.html` on the same origin. **Create invitation** creates
a new legacy network for one pre-pinned joiner. The page uses an explicit
relay route and does not publish a public locator.

1. The joiner selects **Join invitation** and sends their public peer ID to
   the inviter. They must keep that tab open to retain the identity.
2. The inviter enters that ID, the network name, a distinct same-family VPN
   address for each peer, and a complete WebRTC Direct relay entrance
   (including the relay certificate hash and peer ID). Select **Reserve relay**.
3. Share the displayed v2 code, inviter peer ID, and circuit address privately
   with the joiner. They enter them in the same tab and select **Request approval**.
4. On the inviter, confirm the verified joiner's peer ID and VPN assignment,
   then select **Approve peer**. The authorized VPN session reuses the
   inviter's original relay reservation.

No config or key upload is required. The page sends no code or key to the
HTTP companion; it uses the explicitly selected relay in the browser. The
new session is foreground-only: **End session**, refreshing, or closing the
tab discards its local identity. This page does not export a reusable config
or turn other tabs into VPN clients.

### Invite To An Existing Legacy Network

Select **Invite to existing network** instead. Close other browser VPN or
invitation sessions for the same issuer identity, then select the original
rooted legacy JSON config for the founder or delegate. The page reads it
locally and does not upload or rewrite it.

For **Pinned browser peer**, enter the joiner's public peer ID and the
explicit pinned relay entrance. On the local Linux companion, select
**Scoped Linux companion** to invite a joiner whose peer ID you do not know.
Choose a configured relay peer ID or leave it blank for automatic selection.
Share the private v2 code with the joiner. The joiner needs a locator lookup
path to the selected relay; wider public DHT propagation is not verified.
Ending a session releases the companion lease, but the relay may still
count the previous reservation against its capacity. If it refuses a new
reservation, retry later or explicitly choose another configured relay.

In either mode, review the verified peer ID, hostname, and built-in VPN address before
selecting **Approve peer**. The signed ledger is saved before approval is
sent, and existing members are preserved in the ledger. If saving fails,
the request stays pending on the same reservation. In scoped mode,
**Deny peer** ends the invitation without changing the ledger. This detached session
serves only the new peer; it does not keep older peer sessions connected.

### Publish Through A Linux Companion

**Publish native invitation** creates a new legacy network for one
joiner. You do not need their peer ID. Leave the relay field blank to
use the companion's configured relay or let it discover one.

Automatic selection requires a Linux companion built with `webrtc`.
An explicitly entered relay peer ID must be configured on the companion.
The relay must support WebRTC Direct, Circuit Relay v2, and Kademlia.

The browser publishes to the selected relay, then waits for explicit
approval. A joiner must be able to find the locator through that DHT.
Publication across the wider public DHT is not verified.

This mode uses profile-free v2 enrollment. Linux `pair join` on an
existing daemon is a different workflow. **End session** releases the
scoped reservation.

## Join With An Invite File

The inviter can export a bearer offer with `p2p-vpn pair offer`.
Treat the offer like a password and transfer it privately.

1. Select **Invite file**, then open the offer or paste its `p2pvpn:` URI.
2. Select **Continue**, then **Join network** to exchange it with the inviter.
3. Enter a WebRTC address only if the signed offer has no compatible one.

For a separate signed-response exchange, select **Download request** and
import the resulting signed response before joining. Leave the tab open
until enrollment finishes so it retains the original identity.

## Create A Detached File Invitation

In the browser app, open **Create a file invitation**, or navigate to
`/file-inviter.html` on the same origin. Disconnect the VPN using the inviter
identity first, including any other tab. The inviter takes the same local
per-identity lock as the VPN.

1. Open the inviter's local JSON config and select **Create offer**.
2. Download the offer and share it privately. Ask the joiner to choose
   **Invite file** and **Download request**. This is the detached path;
   the inviter page does not listen for a network pairing request.
3. Open the returned signed request, select **Verify request**, and confirm
   the previewed peer ID with the requester. Select **Approve peer** only
   after confirming it.
4. Download the signed response and deliver it privately. The joiner imports
   it in the same tab that created the request. When connecting later, the
   joiner still needs an authenticated, reachable endpoint for the inviter.

The page sends no config, signing key, offer, request, or response to the
companion. Only the signed membership ledger is saved in browser storage.
Keep the response private: it can include the network membership key. Download
it before leaving; offers, pending requests, and responses cannot be restored.

This profile accepts a legacy founder bootstrapping an empty ledger or an
active legacy overlay member with a signed issuer chain back to an explicit
root. A delegated inviter must open their original rooted membership config;
the page preserves the native proof and cannot replace the saved root or
create one for a delegated member.

It admits only new identities at built-in addresses, with optional hostname
and overlay membership only. It does not re-enroll former peers, grant custom
routes or addresses, or create code-approval or checkpoint artifacts.
Checkpoint inviters need a separate transaction that commits the approved
membership mutation before releasing a checkpoint grant.

## Pair A Checkpoint Member By Code

1. Open the issuer's checkpoint credentials. Choose **Listen on scoped
   relay** to publish through a configured local companion, or **Listen on
   relay** to pair using an explicit address. Wait for the existing member
   to connect.
2. Under **Checkpoint invitation**, choose **Pair by code**. Share the code
   privately. Also share the displayed pairing address for explicit pairing.
   A scoped publication failure does not switch to explicit pairing.
3. On the joining browser, select **Pair code** and use v2. Enter the code and,
   for manual pairing, the pairing address. Start the request.
4. On the issuer, verify the requested peer ID with the applicant before
   selecting **Approve code request**. Keep both tabs open until the applicant
   connects and finishes checkpoint sync.

**Cancel code invitation** discards an unapproved request. A committed
approval is not undone if the response is lost. The code cannot grant VPN
access until the new member authenticates and synchronizes its checkpoint.

## Connect To Your Network

| Required | What To Use |
| --- | --- |
| Browser config | Its own JSON config and private key, with the native peer authorized. Leave the MTU at its default unless you need to override it. |
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
3. Connect. Enter the native **overlay** address, service port, and HTTP path.
4. Send a request. Find the overlay addresses in `p2p-vpn status --config FILE`.

The page reads the config locally and does not persist your private key.
It keeps verified, signed membership records in browser site storage, so
opening an old config does not undo a revocation. Use one tab per network
and browser identity.

Keep configs outside the served directory. Serve trusted artifacts over
loopback locally or HTTPS when hosted. Do not enable test hooks for deployment.

## Use the Linux Discovery Host

After building the browser assets, run:

```sh
p2p-vpn browser-serve --assets crates/p2p-vpn-browser/web
```

Open [the local app](http://127.0.0.1:8788/app.html). The default origin stays
the same across restarts so the browser can reuse its stored revocations.
Use `--port PORT` to select a different, fixed origin, or `--port 0` for a
free port in tests. A different port has separate browser storage and does
not inherit revocations. Use the exact origin printed at startup.

The server serves only the built app's known assets. Use a trusted asset
directory. The loopback boundary protects against other web origins, not
against other processes on your machine.

The same-origin discovery API accepts a POST to `/api/discovery` with
`Content-Type: application/json`. Send the network name, the ID of a peer
already authorized by your browser config, and the current public membership
tag if the network has one. Never send a membership key or a private key.

```json
{ "network_name": "NETWORK", "peer": "PEER_ID", "membership_tag": "TAG" }
```

The server inserts a `p2p-vpn-discovery` meta tag with the relative API path
in the app page. A statically hosted page has no marker. The same-origin
`GET /api/discovery` reports `{"available":true,"kademlia":true,"lan":true}`
without starting a lookup.
The POST can also include `kademlia_protocol` and `bootstrap` (an array of
`{"id":"PEER_ID","address":"MULTIADDR"}` objects). Any supplied settings must
match the server's startup policy. Both sources are enabled by default.
Set `kademlia: false` for LAN only, or `lan: false` for DHT only. The host
returns eligible LAN hints before querying the DHT. If a LAN hint fails to
connect, retry with `lan: false` for a signed public hint.

The response contains `addresses` and `source` on success, or a JSON
`error` code on failure. The source is `"lan"` for returned mDNS hints,
`"public_dht"` for returned DHT hints, or `null` when no direct or relay
hint is returned. These labels report where the hints came from, not whether
they are still reachable. For example, `409 network_changed` means the route
changed during the lookup, and `429 discovery_busy` means two lookups are
already active. The browser must still authenticate the peer and admit it to
the overlay.

For a command-line lookup without starting an asset server, use:

```sh
p2p-vpn browser-discover --network NETWORK --peer PEER_ID
```

For a tagged network, pass its current public `--membership-tag`, not the
membership key. Both commands use the built-in public IPFS Kademlia contacts.
For a cooperating DHT, set `--kademlia-protocol` and one or more
`--bootstrap` arguments with pinned TCP or QUIC multiaddrs ending in
`/p2p/PEER_ID`. Specifying seeds replaces the built-in list. A private protocol
does not exempt bootstrap addresses from the physical egress policy.

LAN hints come from mDNS on an eligible interface and are unauthenticated.
Public hints require a signed record with a WebRTC Direct endpoint and its
current certificate hash. Neither source proves reachability or membership.
The CLI prints one public hint per line.

The host uses an ephemeral DHT identity and does not read the browser config
or private key. It binds public discovery sockets, including bootstrap DNS, to
the OS default physical network. If no unambiguous default exists or the
network changes, the lookup fails. Use `--owned-interface` to exclude an
additional VPN-owned interface from both sources. The host does not
authenticate the member or make relay reservations. It cannot bind the
browser's WebRTC sockets.

### Enable public relay fallback

The member's signed address record must advertise a circuit through a relay.
For automatic fallback, the companion authenticates the relay peer over a
numeric public TCP or QUIC contact on the default physical network. The relay
must advertise Circuit Relay v2 HOP and a numeric public WebRTC Direct
entrance on that same IP in Identify. For a signed WebRTC-only circuit,
the companion needs a same-IP TCP or QUIC contact from Kademlia, and Identify
must confirm the exact signed entrance.

To override automatic lookup, pass `--relay-entrance MULTIADDR` to
`browser-serve` with the relay's numeric public WebRTC Direct entrance,
certificate hash, and `/p2p/RELAY` suffix. The signed circuit must still
name the relay and the requested member. The old `--public-relay-entrance`
spelling remains an alias.

The `/api/discovery` response can return one `relay_address` and its
`relay_lease_id` alongside direct `addresses`. The relay address is always
loopback. A relay-only reply has an empty `addresses` list and
`source: "public_dht"`. Identify does not prove that the relay is reachable
over WebRTC Direct r2. The browser still performs that handshake and
authenticates the relay and member.

Pending relay candidates expire after 120 seconds. Once the browser has
authorized the exact member circuit, POST
`{"lease_id":"ID","relay_address":"MULTIADDR"}` to `/api/relay/activate`.
The same request renews an active lease for up to 120 more seconds and returns
`{"active":true}`. Requests require the companion's exact origin. Renewal
does not reset traffic limits or the 30-second inactivity timer. Changing the
default network closes the lease. When done or canceled, POST
`{"lease_id":"ID"}` to `/api/relay/release`.

For a pairing that used a companion relay lease, wait until the browser has
verified approval, then POST the pairing lease ID and exact relay address
to `/api/relay/handoff` using the same JSON fields. Use the returned
`relay_address` and `relay_lease_id` for the new member connection. The
handoff retires the old lease and preserves its remaining traffic and time
limits; it does not repeat discovery. Do not send the approval, code, or
credentials to the companion.

### Publish an incoming relay address

On a cooperating DHT, start `browser-serve` with its protocol, pinned
`--bootstrap` peers, and `--relay-advertisement-permit PATH`. The permit
identifies the exact browser, member, scope, and public relay address.

Choose **Listen on relay**, then **Publish relay address** after reservation.
The browser signs only an address confirmed by the relay. The companion
publishes one record valid for 60 seconds.

The option is not available on the public IPFS DHT. A loopback gateway
address is never published. See the [permit reference](../developer/browser-relay-advertisement.md).

### Find a code-pairing inviter

The same server adds a `p2p-vpn-pairing` meta tag with the relative path
`/api/pairing/locator`. When that marker is absent, do not use host pairing
discovery. LAN enrollment uses a separate `p2p-vpn-pairing-lan` meta tag with
the path `/api/pairing/lan`. When it is present, POST `{}` with
`Content-Type: application/json`. Do not send the locator or code. For public fallback,
derive the locator in the browser and POST `{"locator":"LOCATOR"}` to the
marker path for global v2, or to `/api/pairing/locator/scoped` for scoped v1.
Never send the code, private key, or config.

The public phase uses the public IPFS DHT for both key versions, even if
member discovery uses a private DHT. It uses the default physical network and returns
`{"addresses":[...]}` with at most eight public WebRTC Direct hints pinned to
provider peer IDs. An empty list means no compatible hint was found. The
browser must authenticate each selected peer and complete PAKE. A provider
record does not prove that a peer has the code or is an overlay member.

The LAN endpoint also returns `{"addresses":[...]}`. It collects bounded
hints from the eligible interface, excluding
the configured owned interface. It does not query the DHT or send the locator
over mDNS. mDNS records do not identify a pairing locator. Try the returned
LAN candidates through PAKE before requesting the public phase.
For public enrollment, the inviter's provider record must advertise a
WebRTC Direct endpoint with its current certificate hash. The companion does
not return TCP, QUIC, or relay-only addresses.

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
It must contain the browser's own identity and authorize the native peer and
the corresponding overlay addresses. Keep private keys in the browser or
application. The fixture's disposable credentials are for local tests only.
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

## Browser Limits

- IPv4 and IPv6 HTTP text responses inside the app. System routes, browser
  navigation, and other tabs are not tunneled.
- Signed legacy membership and cooperative checkpoint enrollment. Keep
  the applicable config or encrypted credential bundle to reuse your identity.
- The smaller of both peers' advertised MTUs, with a 68-byte IPv4 minimum
  and a 1280-byte IPv6 minimum.
- In-app overlay hostname resolution when the config enables DNS. The app
  uses the authorized zone and never queries public DNS for overlay names.
- 32 outstanding packet requests, bounded packet queues,
  30-second HTTP deadline, and a 1 MiB response limit.
- The visible tab processes incoming control events. It does not guarantee
  reachability while the browser suspends the page.
- The app uses stream transports, not native-owned UDP or QUIC datagrams.
  It does not provide generic browser-to-browser WebRTC signaling.

The WebRTC transports are locally patched for the
[WebRTC Direct r2 handshake](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md).
The browser leaves its local ICE credentials unchanged; the native listener
accepts v1 and v2. See the developer validation record for tested browsers and
the evidence boundary.
