# Explicit incoming browser circuits

The browser can receive Circuit Relay v2 streams through a selected WebRTC
Direct relay. It does not select relays, start a listener on construction, or
request a reservation during an ordinary outbound connection.

1. Construct `BrowserVpn.with_relay(configJson, directAddress, relayAddress)`.
   The circuit address pins both the relay and the authorized remote member.
   Use an empty direct address to omit direct dialing.
2. After the user or host authorizes listening on that specific relay, call
   `await vpn.reserve_relay()`. This returns the confirmed circuit multiaddress
   ending in the browser's own peer ID. Pass that address to the authorized
   member. Do not publish the member's dial address as the browser's address.
3. Call `await vpn.accept_relay()` while the remote member dials. This
   waits without dialing the member, then runs the normal VPN authorization
   and capability exchange. A reservation by itself grants no VPN authority.
4. Call `await vpn.receive_relay_packet(timeoutMs)` repeatedly to drive the
   accepted stream and service its control traffic. The wait is between 1 and
   5,000 ms. It returns a `Uint8Array` for an authorized IP packet or
   `undefined` if no packet arrives. Call these operations serially; the
   browser swarm is foreground-driven.
5. Call `vpn.release_relay()` to withdraw the listener and close its incoming
   session. `relay_reservation_address()` returns the live address, if any.
   Resetting or closing the BrowserVpn drops the reservation: the caller must
   explicitly authorize and reserve again.

The relay's copy of a source ID is not trusted. The browser checks the remote
identity using end-to-end Noise, then checks that the authenticated circuit is
owned by the exact WebRTC connection carrying its confirmed reservation. The
VPN accepts stream events only from its chosen member connection.

## Local Chromium verification

Build the production browser package with `bash scripts/build-browser.sh`.
Build the native fixtures with:

```sh
cargo build --locked -p p2p-vpn-browser --features test-hooks \
  --bin browser-relay-fixture --bin browser-receiver-fixture
```

Set `P2P_VPN_RELAY_FIXTURE` and `P2P_VPN_RECEIVER_FIXTURE` to those
binaries, and `P2P_VPN_RECEIVER_PKG` to the browser bindings directory
(`crates/p2p-vpn-browser/web/pkg` by default). Run in an isolated Linux
network namespace:

```sh
unshare --user --map-root-user --net sh -ec '
  ip link set lo up
  ip link add pv-relay type dummy
  ip address add 192.0.2.1/24 dev pv-relay
  ip link set pv-relay up
  node --test crates/p2p-vpn-browser/tests/incoming-relay.mjs
'
```

The native member does not reserve an address and only dials after the browser
publishes its reservation. The test checks native-initiated control and IP
traffic, rejection of a duplicate circuit, and listener release. It does not
exercise companion authorization, the host gateway, or public relay selection.
