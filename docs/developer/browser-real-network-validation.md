# Browser Real-Network Validation

## Physical LAN

**Passed on November 20, 2026.** Two Linux laptops used the same physical Wi-Fi
LAN. Chromium 156.0.8078.73 ran production WASM from a loopback Linux companion.
The second laptop ran the WebRTC-enabled native daemon from `7e46070a`.

| Check | Result |
| --- | --- |
| Code-only discovery | The companion's LAN lookup returned one matching WebRTC endpoint. The native daemon saw a direct request after 4.1 seconds. |
| Durable enrollment | The browser downloaded encrypted pending credentials and connected after checkpoint sync. The full flow took 20.8 seconds. |
| Overlay HTTP | Both requests returned HTTP 200. The service bound only to the native TUN address and logged both distinct nonces from the browser's overlay IP. |
| Credential reopen | A new Chromium process used the encrypted download without another approval. Reopen through the second successful HTTP request took 16.6 seconds. |
| Observed path | Native logs showed the same authenticated browser peer on direct WebRTC from the other laptop's Wi-Fi address both times. |
| Cleanup | The test unit, control socket, TUN, listeners, and scoped firewall rules were removed. Existing VPN services stayed running. |

The first approval attempt returned a retryable response while the new native
checkpoint was resynchronizing. After the daemon reported `participating`,
an enrollment with a fresh code completed. No protocol change was made.

### Repeat The LAN Run

1. On the native device, use `init-config` to create a disposable network on
   a new TUN. Add a WebRTC Direct UDP listener on the LAN IP and an unused
   port. Disable Kademlia for this LAN test.
2. Run the WebRTC-enabled daemon with explicit `--control-socket`,
   `--pairing-state`, and `--membership-state` in a private test directory.
   Allow the test listener only from the browser device.
3. Bind a test HTTP service only to the native overlay IP. Return the request
   nonce in the body and log the overlay source. Allow that port only on
   the test TUN.
4. Serve production WASM with `p2p-vpn browser-serve`. Follow
   [Join With A Code](../user/browser.md#join-with-a-code) without entering
   an inviter address. Approve the expected peer on the test control socket.
5. Download encrypted credentials before connecting. Request a fresh nonce.
   Close Chromium, reopen with the saved credentials, and request another.
6. Compare both browser responses with native service logs and verify the
   same peer and direct path. Stop the test daemon and remove temporary rules.

## Public Relay Lookup Preflight

Both devices were still on the LAN, but the companion queried public IPFS
for the disposable native invitation. The native daemon used public relay
reservations.

Use `init-config --public-ipfs-profile` for the disposable inviter.
Call the companion's `/api/pairing/locator` with the v2 locator derived by
the WASM SDK. This exercises public lookup without the app's LAN-first step.

| Check | Result |
| --- | --- |
| Baseline | The code located the inviter's relay with a configured pin, but returned no usable route without pins. |
| Updated resolver | The unpinned lookup rejected two unusable candidates, then returned a lease for the exact inviter. A clean rebuild repeated the success. An attempt with only an unusable candidate returned no route. |
| Scoped egress | TCP and QUIC discovery socket records identified the browser host's default Wi-Fi link. No secondary uplink was present. |
| Isolated regression | Pinned and unpinned Chromium enrollment both passed, including relay handoff and overlay HTTP. The unpinned case skipped an unusable preferred hint. |

The lookup result proves discovery and gateway allocation, not payload
delivery across public IPFS relays.

## Public Relay Payload Preflight

Both devices stayed on the same Wi-Fi LAN. Chromium ran the production WASM
with the Linux companion from `5154ddd0`. The test suppressed the browser's
LAN lookup response and left public discovery and relay traffic live.

| Attempt | Result |
| --- | --- |
| First | The companion's public locator request timed out with HTTP 504. |
| Retry | The companion returned HTTP 200 with no usable WebRTC endpoints. |
| Native logs | Public reservations rotated. The Linux egress guard closed two connections to the same relay as stale; the devices did not switch uplinks. |

Neither attempt reached enrollment or overlay HTTP. The logs show the guard
closed those connections, but not which kernel event triggered it or whether
those closures caused either lookup failure.

### Route Cancellation Follow-Up

On the same LAN, an instrumented baseline recorded 216 invalidations after
incomplete Netlink lookups retired the shared observer. The route guard's
reason was `lookup_cancelled`, not a kernel route change.

| Check | Result |
| --- | --- |
| Fix in `ae002620` | Admitted public socket preparations now drain under a fixed concurrency limit even when the dial is dropped. A regression test verifies cancellation does not invalidate the live epoch. |
| Route-change safety | Isolated Linux tests verified real route changes still invalidate old paths and relay traffic does not cross to the secondary interface. |
| Chromium rerun | Across two attempts, the native daemon logged no route-guard connection closures before shutdown. Public lookup still timed out once and once returned no usable endpoints. |
| Relay availability | None of the three ready reservation addresses logged in the rerun were WebRTC addresses. No enrollment or overlay HTTP completed. |

The cancellation defect is distinct from the remaining lookup failures.
Neither run qualifies separate-uplink reachability or return to LAN.

### Configured Public Relay Comparison

The same LAN devices ran `ae002620` with two configured public relay
reservations on the disposable inviter. Both advertised WebRTC aliases.
The browser still used its ordinary code workflow, except where noted.

| Attempt | Result |
| --- | --- |
| Automatic companion lookup | The companion returned no usable inviter route after querying public IPFS. |
| Companion with the two entrances pinned | Public IPFS returned the exact inviter. The companion issued a lease; Chromium entered ICE checking but did not establish WebRTC. |
| Direct WebRTC to each public relay | Entering the exact circuit manually bypassed lookup and the companion forwarder. Both attempts also stalled at ICE checking. |
| Native daemon | No relayed peer connection formed. The longer run logged 218 route-guard closures before shutdown; their trigger was not captured. |

A native reservation and advertised WebRTC address do not prove the WebRTC
entrance is reachable. These results do not isolate the ICE failure to the
companion, and the short cancellation rerun does not qualify relay stability.

### Request Socket Isolation

The instrumented configured-relay trial recorded 22 route-guard closures
after one incomplete Netlink route query retired the observer. The trace
recorded no kernel route-change notification during that interval.

| Check | Result |
| --- | --- |
| Fix in `65cf3cf4` | An incomplete query now replaces only the unicast request socket. The subscribed notification feed stays live. |
| Regression tests | 46 Linux route tests, including the isolated namespace cases, passed. So did 30 browser host and 5 relay egress tests. |
| Four-minute configured-relay rerun | 75 closures occurred as notification generations advanced on the same Wi-Fi interface. The count stayed flat during the later enrollment retry. The exact kernel message was not captured. |
| Enrollment | The first attempt timed out in public discovery. A later lookup returned the exact inviter and a lease, but Chromium again stopped at ICE. |
| Live relay preflight | Two independent bounded searches did not find a public relay that passed WebRTC and HOP authentication. |

The regression verifies query cancellation is isolated; it does not show
stable relay enrollment on the real network.

### Live WebRTC Entrance Check

The next LAN run captured kernel events before daemon startup. It saw only
disposable TUN setup events and no route-guard closures. Chromium timed out
in public discovery. The earlier notification burst was not reproduced.

| Check | Result |
| --- | --- |
| Native TCP control | A public relay accepted a TCP reservation in 208 ms from the browser host. |
| Scoped WebRTC check | The same relay exposed a local handshake panic. `6d654e4a` limits native negotiation to implemented profiles. |
| Rerun | The scoped native probe authenticated the relay and negotiated HOP over WebRTC Direct v1 in 0.77 seconds. A second relay entrance did not pass. |

Use the [live WebRTC check](testing.md#offline-pairing-integration) to qualify an entrance
before testing with Chromium. Native HOP negotiation is not proof of a
Chromium circuit, approval, or overlay traffic.

### Browser-Compatible Relay Qualification

Chromium uses [WebRTC Direct r2](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md)
without rewriting its ICE credentials. The earlier native probe used v1, so
its successful HOP negotiation did not qualify that relay for Chromium.

| Check | Result |
| --- | --- |
| Chromium reservation | With fresh identities and no DHT lookup, reservation failed both directly and through the companion. Neither attempt finished ICE. |
| Same-entrance control | Native v1 authenticated and negotiated HOP in 0.38 seconds. Native r2 timed out in 4.01 seconds. The isolated native r2 fixture passed. |
| Fix in `0a239e0d` | The companion's live entrance probe now uses r2. Ordinary native dials still default to v1. |

Do not select the relay that passed only v1 for a Chromium WAN run.

## Physical LAN With A Public Relay

Both devices stayed on the same physical Wi-Fi LAN. Use a disposable native
reservation through a verified r2 relay and pin that relay's entrance in the
companion. Suppress the initial LAN response to exercise public discovery.

| Check | Result |
| --- | --- |
| Automatic relay qualification | The companion with `0a239e0d` found a public r2 entrance once in 4.90 seconds. A second discovery did not find it. |
| Chromium reservation | With that entrance pinned, the real browser authenticated it and received its exact scoped reservation in 4.58 seconds. |
| Enrollment | The companion found the disposable inviter through public IPFS. Chromium enrolled and synchronized its checkpoint in 38.64 seconds. Native `65cf3cf4` recorded the exact browser peer on an authenticated relayed connection. |
| Overlay HTTP | HTTP 200 took 3.09 seconds. The service bound to the native TUN saw the matching nonce and browser overlay source. Bytes increased in both directions on the browser's gateway connection. |
| Companion egress | The selected browser candidate was loopback. The companion's connected UDP socket to the public relay was bound to `wlp1s0`. |
| Residual | The daemon logged 95 route-guard closures during the run. The successfully tested circuit still carried the HTTP exchange. This does not qualify sustained relay stability. |

This passed real public IPFS discovery and relay payload on one LAN. It is
not separate-uplink evidence. Leave the disposable services inactive until
the ThinkPad's operator is ready to switch networks.

### Browser Pin Removed

A fresh invitation used the same native reservation and both devices stayed
on LAN. The companion first ran without a relay pin, then with the original
pin as a control.

| Attempt | Result |
| --- | --- |
| Automatic companion | The first lookup and its retry returned HTTP 409. A later lookup returned HTTP 200 with no usable route; the capture saw no kernel route events. |
| Pinned control | Public IPFS located the exact inviter. Chromium completed WebRTC to the relay, but no pairing request reached the inviter. |
| Direct relay control | Bypassing the companion also completed WebRTC, but no pairing request reached the inviter. No circuit rejection reason was captured. |

No approval or overlay traffic completed. The native log recorded 83
route-guard closures, but did not link them to the failed circuit. The earlier
pinned pass does not establish repeatability or automatic relay selection.

### Pinned Public Relay Repeat

Production Chromium/WASM `a01b1b98`, companion `0a239e0d`, and native
`65cf3cf4` repeated the pinned control with fresh pairing and membership
state. Both hosts were still on the original Wi-Fi LAN. The native firewall
kept the direct test listener closed; only the browser's LAN lookup response
was simulated. The public IPFS lookup and relay exchange were live.

| Check | Result |
| --- | --- |
| Discovery and enrollment | Public IPFS returned the exact inviter with a relay lease. The native log recorded the expected browser peer over a relay, and Chromium synchronized its checkpoint in 39.93 seconds. |
| Relay path and egress | The browser selected the companion's loopback gateway. The companion's connected UDP socket to `13.143.166.238:4001` was bound to `wlp1s0`. The Wi-Fi route did not change. |
| Overlay HTTP | HTTP 200 took 2.83 seconds. The native TUN-only service saw the matching nonce and browser overlay source. WebRTC bytes increased from 23,587/24,222 to 33,608/34,658. |
| Cleanup | The disposable units, TUN, listeners, socket, and scoped firewall rule were removed. |

No circuit refusal occurred, so the new `transportReason` diagnostic did not
explain the earlier failure. The isolated Chromium fixture verified
`relay_no_reservation` against an actual relay denial. A second pinned pass
does not establish automatic relay selection or separate-uplink recovery.

## Separate-Uplink Procedure

1. Start on the original LAN with a fresh invitation and disposable state.
   Record the build revisions and `ip -j route get` results for the other
   host and the relay. Keep the same browser session through the return.
2. Move the native device to an independent uplink, such as a cellular
   hotspot. Confirm the new uplink with the operator and record the new
   source and gateway for both destinations. Do not infer WAN from a lost ping.
3. With direct transport unavailable, join by code without entering an
   inviter address. Approve only the expected peer after the native daemon
   reports a relayed request. Note whether the relay was discovered or pinned.
4. Send a fresh nonce to the TUN-only HTTP service. Match the response to
   the service log and check traffic on the selected WebRTC route. On the
   companion, match the relay socket to its process and physical interface.
5. Return the native device to the original LAN without restarting either
   VPN client. Record when the route returns and when direct WebRTC and a
   second nonce exchange succeed. Check byte growth on the direct path.
6. Record the topology and timing, not the invitation code or credentials.
   Stop the disposable units and verify listener, TUN, and firewall cleanup.

### Pixel On LTE

On November 21, 2026, Chromium/WASM `a01b1b98` and companion `0a239e0d`
stayed on the original Wi-Fi. The Pixel 8 Pro used validated LTE with Wi-Fi
disabled. USB carried ADB control only. Its existing debug APK had SHA-256
`0a001d53e0a194bd732760177987191f0af6a25abee7cbf1395704192b60a302`.

| Check | Result |
| --- | --- |
| First code lookup | Public IPFS returned no usable route. Chromium did not attempt WebRTC. Its discovery sockets used `wlp1s0`. |
| Same-code retry | Public IPFS found the disposable inviter and returned the pinned public relay. The Pixel approved the expected browser applicant and recorded an inbound circuit. |
| Data connection | The new circuit for browser checkpoint activation failed with `Connect(ConnectionFailed)` after approval. No overlay HTTP or Wi-Fi return was tested. |
| Android completion | The installed app tried to fetch legacy artifacts for a checkpoint enrollment and stayed in its completion loop after the runtime rejected the export. This is not proof of what caused the circuit failure. |
| Cleanup | Cleared only the disposable pairing operation and removed its profile. Verified the original profile identity, enabled state, always-on setting, and LTE VPN connection. |

### Checkpoint Fix On The Pixel

Keep Chromium/WASM `a01b1b98` and companion `0a239e0d` on Wi-Fi. Install a
debug APK built from `62faff1c` in place. The Pixel stays on validated LTE
with Wi-Fi disabled, and USB remains ADB control only.

Use a disposable Android profile with public IPFS bootstrap and a reservation
on the pinned public relay. Start the invitation before waiting for checkpoint
participation. Do not enter an inviter address in Chromium.

| Check | Result |
| --- | --- |
| Enrollment | The actual LAN lookup found nothing. Public IPFS returned the exact inviter and a relay lease. The Pixel approved the expected applicant, then cleared the completed invitation without attempting a legacy export. |
| Browser connection | Chromium entered the VPN session in 32.51 seconds. WebRTC selected the companion's loopback gateway, and the companion's UDP socket to `13.143.166.238:4001` was bound to `wlp1s0`. |
| First HTTP attempt | The harness could not bind the phone listener to the disposable profile's virtual address. Android presents one shared TUN address and translates the per-network address. The test stopped before sending an HTTP request. |
| Public relay retry | A fresh invitation returned `relay_destination_unreachable`. Three later attempts using that same invitation returned the same error. WebRTC reached the relay, and the Pixel retained an established LTE TCP socket to it. No request reached native approval. |
| QUIC reservation control | A new profile configured the QUIC relay address. Android showed current UDP and TCP routes to the relay on its LTE interface. Three Chromium attempts still received `relay_destination_unreachable`; this does not identify which Android reservation transport the relay used. |
| Native circuit control | A same-host native `relay-check --require-dcutr-success` established one outbound circuit on this relay over QUIC. Its separate direct hole-punch check timed out. The relay was not universally unable to open circuits. |
| Cleanup | Reinstalled the initial APK and verified its hash. Removed the disposable profiles and invitations. The original enabled profile, always-on setting, and validated LTE connection were restored. |

For the Android HTTP check, bind the listener to the shared TUN IPv4 address
from `adb shell ip -o -4 addr show scope global`. In Chromium, request the
disposable profile's own overlay address. Answer only the exact test nonce;
do not use ADB forwarding or reverse ports for the data path.

### Matched Relay Controls

Use the same Pixel build, Linux host, pinned relay, and disposable Android
reservation. Keep Wi-Fi disabled on the Pixel. For the native controls,
generate independent one-off identities and leave native listeners disabled.
Configure the exact `/p2p-circuit/p2p/<pixel-peer>` address and run
`bootstrap-check --require-relayed-peer-circuits --timeout-seconds 12`.

| Linux dialer | Result on the same LTE reservation |
| --- | --- |
| Native TCP, port 4001 | Authenticated outbound circuit. The Pixel's inbound circuit counter rose from 0 to 1. |
| Native QUIC, port 4001 | `Connect(ConnectionFailed)`. The Pixel's counter stayed at 1. |
| Chromium WebRTC Direct r2, without the companion gateway or DHT lookup | ICE connected to the relay. The relay returned `relay_destination_unreachable` before approval. |
| Chromium, through the companion | The public locator returned `504 discovery_timeout` before ICE. This is a separate discovery failure, not a circuit refusal. |

The Pixel also obtained a reservation from `85.137.166.175:4001`, which
advertised WebRTC. Chromium could not finish ICE to that relay in the scoped
reservation check. An advertised WebRTC address is not enough to qualify it.

The refusal reproduces outside Chromium and without the companion gateway.
The matched TCP pass shows that the relay could reach the Pixel, but the
observations do not identify the internal cause of the other refusals.

### LTE Overlay HTTP

Use Chromium/WASM `a01b1b98`, companion `0a239e0d`, and the Pixel APK from
`62faff1c`. Serve `app.js` from `1fe956ca`, which allows one retry of a typed
public pairing timeout within a shared 45-second lookup window.

| Check | Result |
| --- | --- |
| Discovery and enrollment | LAN found no inviter. The first public IPFS lookup found the exact Pixel peer through the pinned relay. Approval completed and the VPN session established in 30.65 seconds. |
| LTE payload | A nonce request to the disposable overlay IPv4 returned HTTP 200 from the Android TUN listener in 3.58 seconds. Bytes grew in both directions on the selected WebRTC pair. The Pixel was on validated LTE. |
| Actual egress | Chromium selected the loopback gateway. The companion's connected UDP socket to `13.143.166.238:4001` was bound to `wlp1s0`; Android's relay control route used `rmnet1`. |
| First Wi-Fi return probe | Both clients stayed running. Android selected validated Wi-Fi, but its LTE relay lease was no longer current and no Wi-Fi relay socket was observed before the first HTTP request timed out. This run did not measure eventual recovery. |
| Timeout regression | The fixture recovered on a successful second locator response and stopped after a second typed timeout. All 17 Chromium pairing tests passed. On LTE, two live locator timeouts completed within the shared window; a separate attempt then connected. |

The follow-up connected in 85.08 seconds, including the first two locator
timeouts, but the test listener could not bind. `ss` found the orphaned ADB
listener from the first timed-out request. Removed that exact listener and
verified that a forced probe failure now closes its socket.

With the listener cleanup fixed, the next run found the inviter on three
attempts, but the relay refused all three circuits before approval. It never
reached the handoff. None of those attempts negate the earlier LTE payload
pass or establish that the Wi-Fi return is permanently broken.

### Checkpoint Discovery On Return

The extended run on `1fe956ca` found the inviter using public IPFS, connected
in 30.66 seconds, and served the LTE nonce in 3.10 seconds. After enabling Wi-Fi,
Android opened a current `wlan0` relay socket in 26.30 seconds. The old LTE
circuit continued forwarding until it disconnected.

The browser had no member discovery plan. It had evaluated authorization
before checkpoint activation installed the member. That skipped the
preferred LAN lookup and left recovery dependent on the last endpoint.

`5bbf9205` obtains the member discovery plan after successful activation.
The Chromium regression fails before the change and passes after it: no
lookup before activation, then a LAN-only lookup for the authorized peer.
All 17 Chromium pairing tests passed on the changed app.

| Follow-up check | Result |
| --- | --- |
| Patched live enrollment | Public IPFS discovery and relay enrollment passed. Connected in 31.93 seconds. The authorized member plan issued LAN lookups, and the Android TUN nonce returned in 3.34 seconds over LTE. |
| Android preferred return | `wlan0` had a current relay socket in 26.01 seconds. The old `rmnet1` socket later closed. Android still reported the Wi-Fi relay route as current. |
| Browser after LTE retirement | Chromium logged `null pointer passed to rust` and `attempted to take ownership of Rust value while it was borrowed` as the data circuit closed. No nonce response followed on Wi-Fi. These messages do not identify the failing WASM call. |
| Controlled Chromium loss | Closing the relay connection while an authorized checkpoint HTTP request was in flight triggered discovery of a replacement. The same session served a second request without a page error. This did not reproduce the physical fault. |
| Stack capture repeat | Public IPFS found the inviter on all three attempts, but the relay refused all three circuits. No enrollment or handoff occurred. |

### Native Reservation Loss Regression

The Chromium test resets only the native fixture's TCP socket to the relay
while an overlay HTTP request is in flight. The browser's WebRTC socket is
not reset. The unpatched browser gave up on `NoReservation` before renewal.

With bounded retries for that typed refusal, the relay accepted a new circuit
after renewal. The browser synchronized the same checkpoint and served a new
HTTP request without another pairing. Run the pairing suite with
`scripts/test-browser-linux.sh`.

### Pinned Relay Control After Lookup Failures

| Check | Result |
| --- | --- |
| Automatic pairing discovery | Separate runs stopped before approval. One locator found the inviter, but the retained invitation returned `Unavailable`. Fresh invitations encountered HTTP 504, one followed by HTTP 409. |
| Pinned WAN pairing | Chromium dialed the known public WebRTC relay directly. Fresh code approval completed without an automatic locator lookup. The browser connected in 25.87 seconds. |
| LTE payload | The Android TUN listener returned HTTP 200 with the expected nonce in 3.09 seconds. The Pixel used the TCP reservation on `rmnet2`. This run did not use the companion's UDP relay gateway. |
| Wi-Fi transition | Android logged `Failed to create iface in vendor HAL` on both enable attempts. `wlan0` stayed down, so the run did not exercise the handoff. |

## Not Yet Verified

Separate-uplink overlay traffic is verified through one pinned public relay.
Android's relay socket return to Wi-Fi is verified. Browser payload recovery
after LTE socket retirement and automatic public relay selection remain
unqualified. Do not infer browser recovery from Android's network status.

Use a controlled WAN relay with server-side circuit and STOP events. Capture
the browser stack when the old circuit closes. Require a new nonce response
from the same browser session with the LTE socket absent, without restarts.
