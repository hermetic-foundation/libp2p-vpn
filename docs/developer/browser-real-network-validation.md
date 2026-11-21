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

## Not Yet Verified

Separate-uplink code discovery, authenticated relay fallback, and recovery
on a real network change remain open. The LAN run does not qualify public
IPFS or automatic return to the preferred link on a multihomed host.
