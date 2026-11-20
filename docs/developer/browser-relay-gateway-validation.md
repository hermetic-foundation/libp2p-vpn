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

### IPv6 caller and IPv4 reservation owner

The reverse case gives Chromium and the Linux companion two IPv6-only
underlay links. IPv4 loopback still serves the app and the companion's
local UDP ingress. An unpeered dummy device owns `192.0.2.19/32` without
installing an IPv4 route in the main table. It lets Chromium start its
mDNS responder with normal privacy settings; neither underlay link has
IPv4 addressing or can carry IPv4 packets. The separate native member
only has an IPv4 underlay. One relay peer accepts its reservation on IPv4
TCP and listens on IPv6 TCP for Identify and IPv6 UDP for WebRTC Direct.

The member signs the IPv6 TCP route to that same relay. The companion reads
it from the local IPv6 Kademlia seed and discovers the WebRTC entrance
without a configured relay override. The fixture uses synthetic
`2001:db9::` addresses because automatic admission excludes both ULA and
`2001:db8::/32`. Only the disconnected veth topology owns those addresses;
the relay namespace has IP forwarding disabled and has no uplink.

Counters separately require IPv6 bootstrap TCP, Identify TCP, and relay
UDP on the OS default link and zero on the usable alternate. The relay
records the accepted reservation, actual IPv4 TCP owner and IPv6 UDP caller
endpoints, and the accepted circuit between those peer IDs. The Chromium
SDK makes an authorized overlay HTTP request. The native fixture admits
the IP packets on the authenticated circuit before delivering them to its
local TCP/IP stack, and Chromium must receive the exact response body over
that circuit. Both directions carry overlay payload, with no operating
system IP forwarding. The test also checks lease release.

Chromium 156.0.8078.73 with normal mDNS policy gathered a masked
`.local` candidate and selected an ICE pair to the IPv4 loopback lease.
One isolated run counted 18 bootstrap, 20 Identify and 99 relay packets
on the IPv6 default link, with zero fixture packets on the alternate and
zero IPv4 packets on both underlay links. The browser received the exact
HTTP response and recorded five acknowledged outbound packets and two
inbound packets. These counts are observations, not thresholds.

The opt-in pure case removes the dummy, leaving no non-loopback IPv4
address. With default mDNS policy, Chromium 156.0.8078.73 fails to start
its responder in this Linux fixture: `bind` to `ff02::fb:5353` with
`sin6_scope_id=0` returns `EINVAL`. The same address bound with an
interface scope succeeds. Adding IPv6 link-local addresses did not
change the Chromium result. ICE remains in gathering without a candidate
pair. The companion completes IPv6 bootstrap and Identify and binds the
IPv6 relay uplink, but receives no UDP on the IPv4 loopback lease.
Disabling Chromium's `WebRtcHideLocalIpsWithMdns` feature for an isolated
diagnostic lets the existing IPv4 loopback lease and IPv6 uplink work. It
does not qualify pure default-policy Chromium. No browser privacy or
companion production settings changed.

Independent verification at `1e8bcb52` passed the reverse-family case
and all six existing gateway cases. With production WASM, the reverse run
observed 19 bootstrap, 20 Identify, and 104 relay packets on the IPv6
default link; the same counters stayed at zero on the alternate. Both
links recorded zero IPv4 egress. The same relay accepted the native
reservation on IPv4 TCP and the companion's caller traffic on IPv6 UDP.
The authorized HTTP response was exact, with five acknowledged outbound
overlay packets and two inbound packets.

The separate stock run without the dummy again stopped during ICE
gathering, before relay traffic. A second run with logging and syscall
tracing confirmed the scope-zero multicast bind failure. This is an open
stock Chromium acceptance check, not a passed release gate. No mDNS
setting was changed for either run. The commands, artifact checks, and
logs are under `/tmp/p2p-reverse-browser-relay-integration.UXC9d0/`.

The exact-tip rerun at `bd91d576732216966beeabc2a61bc5a99cd226a3` used
the same hash-verified artifacts in an isolated Linux namespace. The
host-only control again passed with zero IPv4 underlay egress. Without
the dummy, adding IPv6 link-local addresses and a multicast route still
left stock Chromium 156.0.8078.73 without a candidate pair. The syscall
trace shows `IPV6_MULTICAST_IF` succeeding followed by a scope-zero
`ff02::fb:5353` bind returning `EINVAL`. A standalone WebRTC offer,
without p2p-vpn, WASM, STUN or TURN, reproduced the bind and gathering
failure; a native bind with an explicit interface scope succeeded. This
isolates the observed prerequisite to Chromium's local IPv6 mDNS path.
Correcting the bind alone would not establish the VPN result; the
unchanged pure case must still nominate the loopback pair and pass HTTP,
family, and egress assertions under stock protections.

See `/tmp/p2p-reverse-pure-bd91-report.md`, the gateway trace
`/tmp/p2p-reverse-pure-bd91-fixture-route.strace` at line 5501 and the bare
WebRTC trace `/tmp/p2p-reverse-pure-bd91-gather-route.strace` at line 2446.

**Optional Firefox observation.** In a separate run, Firefox 159 sent
`Origin: null` on the no-referrer same-origin companion POST, which
returned `403 wrong_origin` before discovery. The browser user docs
declare Chromium or Chrome. This is not an ICE result or a reason to
relax the origin guard.

## Companion default switch and return (D3)

The switch test places the DNS responder, signed-record DHT seed, and relay
behind two isolated veth links. Both links stay up. The fixture changes which
link owns the Linux default route, then restores the original default. Both
links keep a usable route to the fixture throughout.
Separate egress counters on each link distinguish DNS, DHT bootstrap, relay
Identify, relay UDP, and direct-member UDP. The DNS responder serves the
test name at the scoped resolver's usual addresses inside the fixture only.
No public DNS or DHT infrastructure is contacted. Broad IPv4 UDP and TCP
port-53 counters include every resolver address; fixture-address counters
also record queries to the expected resolvers. A separate normal DNS lookup
to a secondary resolver not configured for the companion verifies that both
broad counters increase without changing either fixture-address counter.

Before Chromium starts, a client uses the loopback discovery API and sends two
datagrams through each granted relay lease. `ss` shows one connected upstream
socket bound to the current default device, with unchanged endpoints across
both datagrams. The test drops bootstrap TCP on the initial default link and
checks that failure does not send any traffic on the other link. After each
route change, the old upstream socket is gone, its loopback port is available,
and a stale sender cannot forward on either link. A new discovery returns a
different lease and sends on the new default. The companion exposes no route
generation status; a terminal scoped discovery result confirms readiness.
Only `409 network_changed` is retried within a bounded window. The rejected
lookup must return no lease, leave no upstream relay socket, and send nothing
on the non-default link. Counters stay cumulative from before the route
change through all retries. Each lookup starts a new DHT
swarm; this is evidence of relay socket reuse within a lease, not a shared
DHT connection pool or a live Chromium circuit migrating between links.

After return, Chromium and the IPv6-only member authenticate and exchange VPN
packets through a fresh circuit. Chromium discovery mirrors the app's one
`network_changed` retry under the original request deadline, with counters
covering both attempts. Relay release is not retried. Chromium uses loopback for its WebRTC leg to
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
Successful signed discovery therefore requires TCP DNS. Both fixture-address
DNS counters must be positive on the current default, and the broad counters
must be zero on the other link through switch and return.

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
`node --test`. For the reverse-family case alone, pass
`--test-name-pattern='^Chromium on an IPv6-only underlay'`. To reproduce
the pure case with the normal Chromium launcher, set
`P2P_VPN_REVERSE_RELAY_PURE=1` and pass
`--test-name-pattern='^Chromium with no non-loopback IPv4'`. This opt-in
diagnostic currently fails under default mDNS; leave it out of release
gate results.
