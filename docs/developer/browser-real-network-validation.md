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

## Not Yet Verified

Separate-uplink code discovery, authenticated relay fallback, and recovery
on a real network change remain open. The LAN run does not qualify public
IPFS or automatic return to the preferred link on a multihomed host.
