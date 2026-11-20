# Browser code inviter

The relay-enabled browser SDK can be the v2 SPAKE2 inviter for a new,
single-peer legacy network or for a detached founder or delegate on a rooted
legacy network. Both normal profiles require a pinned joiner and an explicit
relay. The controlled test profile below can enroll one initially unknown peer.

1. Get the intended joiner's public peer ID from `BrowserPairing.peer_id()`.
2. Create a `BrowserCodeInviter` with a network name, distinct VPN IPs for
   both peers, that joiner ID, and an explicitly selected pinned WebRTC
   Direct relay entrance.
3. Call `reserve()` and share the resulting circuit address, inviter peer ID,
   and `code()` with the intended joiner. The existing `join_v2` can use
   those inputs directly.
4. Drive the inviter with bounded `drive(timeoutMs)` calls. Display
   `pending_candidate()` to the operator. Call `approve(peerId)` only after
   the operator approves that exact candidate. Keep driving until the response
   is sent; the joiner must still verify the response.
5. After delivery, await `into_vpn()` to consume the invitation and install
   its signed authority on the same browser swarm. Call `accept_relay()` on
   the returned VPN; do not reserve again. This keeps the original
   authenticated relay connection and listener, but closes the inner PAKE
   circuit. The joiner can use its verified config and the same circuit
   address with `BrowserVpn.with_relay()` and `connect()`. The new member
   circuit must pass ordinary VPN capability and packet authorization.

Before activation, only the existing v2 responder is dispatched, and only
on the pinned joiner's Noise-authenticated circuit on the browser-owned
reservation. A validated Submit can obtain a pending ticket, not enrollment.
The signed legacy response is accessible only to the pinned joiner after
approval. The invitation cannot move to a replacement reservation if the
original is lost. Free the inviter and its reservation to abandon it.

This API does not publish locators, support a v1 responder, or issue
checkpoint grants. A native joiner would need an explicit route input or
compatible discovery; neither is added here.

The isolated `code-inviter.mjs` test uses Chromium, the existing v2 joiner,
and an actual Circuit Relay v2 server limited to one live reservation. It
checks explicit approval, authenticated member capabilities, and delivery
of the joiner's inner TCP SYN on the original reservation.

## Detached Existing Network

Use `await BrowserCodeInviter.open_existing(configJson, joinerPeerId, relayEntrance)`
in place of the constructor. Close any active VPN using that identity first.
Load the trusted legacy config locally in the SDK caller; this API does not
alter the source config or send it to the companion. It requires the shared
file inviter's rooted founder or delegated issuer proof, merges the saved
ledger while holding the per-identity lock, and rejects peers with prior
membership. It permits only the joiner's built-in address and overlay
membership, without custom routes or a new issuer root.

Approval saves the merged signed ledger before making the response
available. A failed save leaves the request pending and the old ledger
unchanged. Once saved, admission remains in the ledger even if delivery or
activation later fails; do not re-enroll the same identity. `into_vpn()`
transfers the same identity lock and relay reservation into the foreground
VPN. After either peer authorizes, keep it polling so it can serve the
other peer's membership snapshot exchange.

The ledger and configured peers are preserved, but this remains a detached
single-peer session. Other already authorized peers are not served on this
reservation. Simultaneous live service and enrollment would need the live
multi-member connection table and a single owner for the membership store.
The served `/code-inviter.html` page exposes this profile under **Invite to
existing network**. Its file input is local-only, and it uses the same
review and activation flow as the new-network mode. The isolated
`existing-code-inviter.mjs` verifies founder and delegated approval,
failed storage writes, and real TCP traffic. `code-inviter-ui.mjs` tests
the served page in both modes.

## Controlled Locator Publication

The `test-hooks` build exposes `publish_locator_controlled(alias)` on an
inviter with a confirmed reservation. It sends one standard Kademlia
`ADD_PROVIDER` over the exact authenticated relay HOP connection that
owns the reservation. The relay must also serve `/ipfs/kad/1.0.0`.
The key is the same logical v2 provider key read by native lookup (77
bytes, below this protocol path's hashing threshold). The browser sends
its own peer ID and one public TCP or QUIC circuit alias that the relay
already advertised on that listener. Unknown aliases and loopback are
rejected. No extra socket, iterative DHT query, republish, or companion
request is used. Completion means a local substream write, not DHT
acceptance. Remote records can outlive the invitation.

`code-locator-publication.mjs` uses a single-underlay test namespace,
Chromium, and two independent pairs of standard-protocol Kademlia peers. A fresh lookup client
knows only the seed, which has no provider record and refers it to the
publishing relay. The test checks the exact provider and alias, absence
before announcement, and absence for a different locator. A fresh lookup
from the other seed follows a referral to a different DHT server and
misses the same locator without visiting the publishing relay. The relay's
Kademlia receiver accepts the announcement only when the advertised
provider matches the authenticated sender. A provider record is still
only a dial hint, not an issuer proof; PAKE and approval remain required.
This lookup test does not exercise physical default-route binding.

## Controlled Unpinned Enrollment

The `test-hooks` build exposes
`open_unpinned_controlled(networkName, inviterIp, joinerIp, relayEntrance)`.
It creates a fresh legacy network with a locally locked membership store.
The caller supplies an explicit relay and isolates its underlay. The
inviter can use the controlled locator publisher on that same reservation;
there is no automatic lookup or public network permission.

The reservation accepts at most eight provisional Noise circuit attempts,
one authenticated provisional circuit at a time, and at most eight PAKE
Hellos. An unselected circuit has four seconds to prove the code. A signed
v2 Submit must prove possession on that very Noise connection and name its
identity. Only then does the peer appear for explicit review, and the
reservation selects that one identity. Replayed requests cannot select a
different peer or issue another grant. Before activation, the inviter
does not dispatch VPN capability or packet traffic.

Approval saves the signed ledger before the response becomes available.
The approved identity is installed for data on the original reservation.
Cancellation and expiry deny further admission or delivery. Cancellation
does not roll back a grant already saved; the browser-local signer is
not exported by this test profile. Exhaustion requires a new invitation.
`unpinned-code-inviter.mjs` exercises these bounds and actual inner TCP
delivery after approval.

## Public DHT Propagation (Not Implemented)

Public Kademlia accepts `ADD_PROVIDER` only when the provider ID is the
authenticated connection's peer ID. A companion with a separate identity
cannot publish as the browser, even given a browser-signed address. An
application-specific signed record could delegate publishing, but would
require changing the lookup protocol rather than using `GET_PROVIDERS`.

When a browser can prove a default-scoped HOP connection and its relay
also serves Kademlia, the same authenticated connection can carry the
announcement, but the relay cannot forward it as the browser. The current
companion gateway forwards only the UDP flow for a pinned WebRTC Direct
entrance. Circuit Relay v2 is not a TCP proxy: the destination DHT peer
would need its own reservation on the relay. Browser-managed network
sockets do not inherit the companion's physical route scope.

The smallest general transport addition is an invitation-scoped byte
stream to a companion-owned TCP socket. Run libp2p Noise, Yamux, and
Kademlia in WASM with the reservation's browser identity, and authenticate
the expected DHT peer over each stream. Require the exact
same origin and an authorized local session. The companion accepts only
locally approved numeric public endpoints and pinned DHT peer IDs, never
arbitrary TCP or DNS input; WASM authenticates the far peer. A single
companion public-discovery `Scope` owns all
publication sockets and tears them down when the OS-default physical route
epoch is invalidated. Fail closed if an admitted DHT server is not
reachable through that scope. Avoid exporting the code or invitation
signing key to the companion.

Opt in per invitation. Run iterative `FIND_NODE` for the provider key,
then write `ADD_PROVIDER` to the closest authenticated, eligible servers.
Bound dial attempts, concurrent streams, bytes and elapsed time; report
incomplete convergence rather than claiming public visibility. Local
substream completion is not an acknowledgement of storage. Verify
readback from an independent seed that does not route to the reservation
relay. Publish only the verified public circuit address for that browser
peer on the admitted relay. Native joiners also need a confirmed native
transport alias for the same reservation. Never publish the localhost
gateway tuple. Stop publication on approval, expiry, reservation loss, or
route invalidation; remote Kademlia records can still age out on their
server's schedule, while PAKE and approval enforce local expiry.

The [IPFS Kademlia content-routing spec](https://specs.ipfs.tech/routing/kad-dht/#7-provider-record-routing)
specifies a multihash for provider keys. The current v2 wire key is 77
bytes of application data, not a multihash. A transport-only change can
preserve lookup compatibility with the current client and permissive
servers, but cannot guarantee compatibility with servers enforcing the
multihash rule. A standards-conforming key needs a coordinated publisher
and native lookup migration; hashing only at publication would make the
record undiscoverable to existing joiners.

A direct browser WebRTC relay reservation is not itself constrained by
the companion's route scope. The explicit companion profile below uses
the scoped transport and a verified public alias instead; it never
falls back to unscoped WebRTC.

For stock profile-free native code joining, a lookup must reach a
cooperating bootstrap or discover a reachable provider through the DHT.
It must also dial the returned TCP/QUIC circuit on a default-scoped
native Circuit Relay v2 transport, preserving end-to-end inviter
authentication. This fixture verifies the lookup, not that native dial.

## Companion Reservation Egress

On Linux, an operator can pin companion egress with both
`browser-serve --relay-entrance <pinned WebRTC Direct multiaddr>` and
`--relay-native-alias <pinned TCP or QUIC-v1 multiaddr>`. The addresses must
use the same public numeric IP and end in the same relay PeerId. The
companion authenticates the native connection and verifies that Identify
reports both HOP support and the exact configured WebRTC entrance.

On the companion origin with the code-inviter assets installed, send
`POST /api/relay/inviter/reservation` with JSON `{"relay_peer":"<PeerId>"}`.
Send `{}` to use the first `--relay-native-alias` in operator order.
Only that configured pair is probed; a failed probe does not try another
pair or fall back to DHT discovery.
It requires an exact Origin and `Sec-Fetch-Site: same-origin`. Its reply is:

- `relay_entrance`: the loopback WebRTC multiaddr for the browser to dial.
- `native_alias`: the authenticated public relay base. Only after the
  browser confirms the corresponding public circuit on the exact own
  reservation can it publish that route. The public circuit is the alias
  with `/p2p-circuit/p2p/<browser PeerId>` appended.
- `relay_lease_id`: the local bearer for `POST /api/relay/release`. Keep it
  local. This lease cannot be activated, renewed, or handed off.

Preparation and UDP forwarding use the same OS-default physical generation.
The lease shares the gateway's two slots and expires after 120 seconds or
the existing idle or traffic limit; a route-generation change revokes it.
The API does not take a browser identity key, pairing code, or locator,
create a reservation for the browser, or publish anything.

On the served code-inviter page choose **Publish native invitation**.
Leave the relay field blank to use the companion's approved or automatic selection,
or specify an approved relay by peer ID. This creates a fresh legacy
network with one bounded, initially unpinned joiner. The browser dials
the loopback ingress, waits for the exact public circuit on that same
reservation, and writes the locator to the cooperating relay's DHT
substream. Only the public circuit is signed, published, or displayed.
The operator must still approve the verified joiner before the grant
is sent. The browser invitation expires after 110 seconds, within the
companion's maximum lease lifetime. **End session** releases the lease;
the page attempts release on close and the companion enforces its
deadline independently.

The scoped Chromium fixture tests the real companion, exact public alias
readback from a separate native Kademlia client, and enrollment through
VPN authorization with an explicitly routed Chromium joiner. It also
checks release and revocation on default-link changes. It does not
verify a stock native code join or arbitrary public DHT visibility.

### Automatic Relay Selection

On a companion built with `webrtc`, `{}` with **no** configured
`--relay-entrance` or `--relay-native-alias` performs one standard Kademlia
`FIND_NODE` query using the companion's existing bootstrap configuration.
Only peers that answer the query and have a numeric public TCP or QUIC-v1
contact can advance. A DHT result is a hint, not relay authorization or VPN
membership. Automatic selection is bounded to 15 seconds, with at most
eight DHT dial attempts and three relay probes.

Before issuing a lease, the companion authenticates the exact native alias
and validates its same-host WebRTC Direct suggestion, then verifies the
WebRTC certificate, the same Noise PeerId, and the HOP protocol on that
WebRTC connection. All three steps use one OS-default physical generation.
The WebRTC probe cannot reuse its local UDP tuple or outer socket for the
browser lease. A request naming a relay never takes the automatic path.
Builds without `webrtc` retain pinned selection only.

`automatic-inviter-relay.mjs` exercises a real Chromium reservation through
the production HTTP endpoint, using a cooperating standard-protocol DHT
seed that introduces a separate native relay. It does not establish public
Internet availability.

## Scoped Native WebRTC Proof

The ignored Linux test `identify_candidate_requires_scoped_webrtc_proof`
authenticates a cooperating relay's pinned TCP contact and reads its WebRTC
entrance from Identify. It checks the certificate fingerprint and Noise
PeerId, and negotiates HOP without requesting a reservation.

The native dialer binds to loopback. Its temporary ingress accepts only its
exact UDP tuple and forwards over the same default scope as the TCP probe.
The fixture rejects a mismatched certificate or PeerId, missing HOP,
publication after a route change, and fallback to the non-default link.

Run `cargo test --features webrtc --lib -- --ignored identify_candidate_requires_scoped_webrtc_proof`
inside an isolated Linux user and network namespace.

### Linux Native Enrollment Fixture

`native-code-locator.mjs` gives the companion and native joiner different
DHT bootstraps. Chromium requests an automatic relay through the companion
and publishes on its scoped reservation. The joiner gets only the code and
its own seed, not the inviter ID, relay, or companion's bootstrap. The
seed's provider-free reply refers the joiner to the publishing relay.

The fixture uses the production profile-free v2 bootstrap and signed-config
importer, then runs stock `p2p-vpn up` and verifies an HTTP round trip on its
TUN. It checks the relay-side source addresses on both default underlays.
The relay namespace has no external route and disables forwarding.

Both tests use an intentionally connected fixture topology, not public
IPFS infrastructure. The record stays on the publishing relay. Nothing
replicates it to the DHT servers closest to the locator key, and an
unrelated public lookup need not visit that relay. The browser identity
key stays in the browser; only the invitation code is shared with the
joiner.

`p2p-vpn pair join CODE` still starts a network-scoped v1 operation on a
running daemon. It is not the profile-free Linux enrollment entry point.
