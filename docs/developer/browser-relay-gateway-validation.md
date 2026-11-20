# Chromium through the Linux companion relay gateway

These tests use the real `browser-serve` API, the browser WASM transport, and
a native Circuit Relay v2 reservation. The Chromium and companion namespace
must start with only loopback. It reaches the fixture over isolated veth
links. The public-looking fixture addresses never leave those namespaces.

## IPv4 manual fallback

The seed returns a signed address record for the native member. Chromium
obtains the loopback circuit address and lease with `POST /api/discovery`,
attempts the unavailable signed direct address, then falls back to the
leased circuit. Both peers authenticate and exchange VPN control and IP
packets. The test closes BrowserVpn, calls `POST /api/relay/release`, and
checks that the loopback UDP port can be bound again. This exercises the
disconnect and release APIs, not the UI's disconnect handler.

## Automatic cross-family fallback

One relay identity listens on IPv4 TCP for Identify, IPv4 WebRTC Direct for
the browser circuit, and IPv6 TCP for the member's reservation. The native
member lives in a separate namespace with IPv6 as its only underlay. After
reserving over IPv6, it signs a relay-only record that names the IPv4 TCP
entrance. The IPv4-facing Kademlia fixture serves that record. Chromium and
the companion have only IPv4 underlay links, and the companion gets no
`--relay-entrance` override.

The test verifies the relay's observed IPv4 WebRTC and IPv6 TCP connections,
the authenticated browser and member peer IDs, the negotiated relay path and
MTU, and accepted VPN IP packets in both directions. It also verifies lease
release. The overlay test packets are IPv4; IPv6 is the member's underlay.
The alternate IPv4 link has a backup route to the fixture. Software egress
counters match TCP and UDP to the fixture address, excluding link traffic
such as ARP and unrelated browser traffic.

Verified on 2026-11-19 with Chromium 156.0.8078.73, the `fc22af6a` parent
companion, and cached test-hook WASM. Both cases passed. The cross-family case
recorded 40 TCP and 113 UDP packets to the fixture address on the default
link, and zero TCP and UDP packets to that address on the alternate link.
These counts are from one isolated run, not performance thresholds.

## Companion default switch and return (D3)

The switch test places the DNS responder, signed-record DHT seed, and relay
behind two isolated veth links. Both links stay up. The fixture changes which
link owns the Linux default route, then restores the original default. Both
links keep a usable route to the fixture throughout.
Separate egress counters on each link distinguish DNS, DHT bootstrap, relay
Identify, relay UDP, and direct-member UDP. The DNS responder serves the
test name at the scoped resolver's usual addresses inside the fixture only.
No public DNS or DHT infrastructure is contacted.

Before Chromium starts, a client uses the loopback discovery API and sends two
datagrams through each granted relay lease. `ss` shows one connected upstream
socket bound to the current default device, with unchanged endpoints across
both datagrams. The test drops bootstrap TCP on the initial default link and
checks that failure does not send any traffic on the other link. After each
route change, the old upstream socket is gone, its loopback port is available,
and a stale sender cannot forward on either link. A new discovery returns a
different lease and sends on the new default. Each lookup starts a new DHT
swarm; this is evidence of relay socket reuse within a lease, not a shared
DHT connection pool or a live Chromium circuit migrating between links.

After return, Chromium and the IPv6-only member authenticate and exchange VPN
packets through a fresh circuit. Chromium uses loopback for its WebRTC leg to
the gateway. The physical relay UDP socket belongs to the companion. A
separate authorized WebRTC Direct member uses the still-secondary link and
accepts an overlay packet. That socket belongs to Chromium. This checks
direct-member eligibility and does not claim that the companion can bind or
attest Chromium-owned sockets.

On 2026-11-19, the test passed with native binaries cached from
`0f5d7cf5c57b0d8ee71c593bc335e679f30a693f`, Chromium 156.0.8078.73, and
cached test-hook WASM. The companion binary SHA-256 was
`f6c761348a301df71ee4ebe99c1f3b55744829383486f7431eb7082fe2200e8f`.
The WASM SHA-256 was
`45935c24c48cf31e9a6ffc3e9c599a7e8aaf845b633b3d8b8d6c78b3814ae891`.

| Phase | Default | DNS UDP | Bootstrap TCP | Identify TCP | Relay UDP |
| --- | --- | ---: | ---: | ---: | ---: |
| Initial | `gateway-peer` | 1 | 18 | 20 | 2 |
| Blocked bootstrap | `gateway-peer` | 1 | 9 | 0 | 0 |
| Switch | `gateway-alt` | 1 | 19 | 21 | 2 |
| Return | `gateway-peer` | 2 | 19 | 21 | 2 |

All four counters were zero on the non-default link in each phase. DNS TCP
was zero on both links. The blocked lookup returned `no_candidates`. The
authenticated circuit after return recorded 113 relay UDP packets on
`gateway-peer` and zero on `gateway-alt`. The authorized direct member
recorded zero direct UDP packets on `gateway-peer` and 107 on `gateway-alt`.
These are observations from one run, not pass thresholds.

### DNS over TCP and secondary-only DNS

The DNS tests return a valid truncated UDP response for the bootstrap name.
The fixture returns the A record only in a length-prefixed TCP response.
Successful signed discovery therefore requires TCP DNS. Counters match only
the fixture resolver addresses and port 53. Both DNS counters must be positive
on the current default and zero on the other link through switch and return.

The secondary-only test routes both resolver addresses through `gateway-alt`
and prevents the primary from reaching them. When the primary is default,
the companion must return no candidates or time out without emitting DNS on
either link. Discovery must succeed with both DNS transports on the
secondary when it becomes default, then fail closed again on return.

### Live mixed-purpose isolation

A native member reserves over unscoped TCP on the secondary, in the
companion's namespace. Chromium requests normal automatic public discovery
for the member's signed relay record. The relay fixture must observe a new
Identify TCP connection on the primary to the same relay from a distinct
probe identity. The companion must return a signed-lookup relay lease,
while the original reservation socket remains established with the same
endpoints. Counters distinguish zero secondary public traffic from an
authorized direct member's accepted keepalive on that link.

## Run

From the repository root, with Playwright available in the browser package:

```sh
cargo build --locked -p p2p-vpn --features webrtc --bin p2p-vpn
cargo build --locked -p p2p-vpn-browser --features test-hooks \
  --bin browser-relay-fixture --bin browser-receiver-fixture
bash scripts/build-browser.sh --test-hooks

target_dir=${CARGO_TARGET_DIR:-target}
export P2P_VPN_BIN="$(realpath "$target_dir/debug/p2p-vpn")"
export P2P_VPN_RELAY_FIXTURE="$(realpath "$target_dir/debug/browser-relay-fixture")"
export P2P_VPN_RECEIVER_FIXTURE="$(realpath "$target_dir/debug/browser-receiver-fixture")"
export P2P_VPN_RECEIVER_PKG="$(realpath crates/p2p-vpn-browser/web/pkg)"
export P2P_VPN_TEST_NETNS="$(readlink /proc/self/ns/net)"
unshare --user --map-root-user --mount --net --pid --fork \
  --kill-child=SIGKILL --mount-proc \
  node --test crates/p2p-vpn-browser/tests/relay-gateway.mjs
```

Set `P2P_VPN_CHROMIUM` to an installed Chromium executable to override the
default Chrome channel. The test requires Linux with unprivileged user
namespaces, `ip` and `tc` from iproute2, and `unshare` and `nsenter`.
The cross-family and switch cases require the kernel `clsact` qdisc and
`flower` classifier. The switch case also uses `ss` from iproute2.
To run only the switch case, pass `--test-name-pattern='companion DNS'` to
`node --test`.
