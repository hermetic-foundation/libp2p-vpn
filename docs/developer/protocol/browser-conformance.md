# Browser Conformance Audit

Baseline: published `browser-wasm` at `b3dbb7e9b34fc945246bdd47ad934654a3f02250`,
with the legacy receipt stack evaluated separately below.
This audit compares the foreground browser and matching Linux companion
with the [protocol draft](README.md). It records reference implementation
interoperability, not an independent client or a binary release.

## Evidence Revisions

These are prior integrator results, not reruns for this audit. Log names
refer to the integrator's `p2p-vpn-browser-rewrite.DWcocI` run directory.
Fixture source for the listed passes is on the published branch; the
execution revisions differ. Counts overlap and should not be added.

| Run | Verified cases and revision |
| --- | --- |
| Host, 3 | `publication-isolated-browser-linker.log`: separate-link LAN member discovery, LAN-only code pairing, and live checkpoint roster updates and durable exclusion. Credit these three passes, not the entire run. |
| Wire, 17 | `publication-wire-0f5.log`, ancestor `0f5d7cf5`: incoming circuit and shared reservation, foreground Demand, app authorization and survivor, network-change recovery, reliable IP and status, relay-only and fallback, alternate and preferred direct, no fallback after denial and typed wrong network, legacy sync and durable revocation, reauthentication, and circuit substreams. |
| Enrollment, 27 | `publication-enrollment-0f5.log`, ancestor `0f5d7cf5`: 14 joiner cases (direct, relay, v1/v2, file, LAN fallback, bounded retry and lease handoff), two detached file issuer cases, six explicit legacy code issuer cases, one undialed checkpoint admission gate, and four live checkpoint issuer cases. |
| Affected relay, 18 | `publication-relay-031.log`, `031afdc`: gateway fallback and cross-family relay (2), browser-to-browser IP, opt-in publication, default-link selection, automatic authenticated relay, scoped alias publication (5), native v2/TUN, rooted approval and denial, different-seed join (4), provider-free referral (1), unpinned approval/cancel/cancel-after-save/expiry/saturation (5), and pairing lease handoff (1). |
| Live checkpoint, 4 | `publication-checkpoint-live-031.log`, `031afdc`: native joiner on the issuer's reservation, served signed-file approval, served code approval and sync with a native joiner, and served browser-to-browser code enrollment. Not lost-response or issuer-reopen evidence. |

## Published Follow-up Evidence

Browser test files below are under `crates/p2p-vpn-browser/tests/`. These
are prior runs on the indicated published ancestors or tip, not reruns.

| Case | Observed behavior | Source and log |
| --- | --- | --- |
| Fresh and rooted legacy locator storage | The companion published only the confirmed circuit alias and verified it by readback on separate authenticated storage. The native v2 library joiner started from an independent seed: the seed referred it to storage, not to the reservation relay for lookup. Approval and stock TUN traffic used the original circuit. Rooted approval saved first, kept prior signatures, and withheld the grant on save failure; denial kept the prior roster. A busy reservation released resources and the issuer could reissue through another relay. A default change closed an admitted locator stream without secondary fallback. | `native-code-locator.mjs`, `publication-rooted-89f-live.log` (6 passes, `89f18093`); `public-code-inviter-gateway.mjs`, `publication-propagation-e46-gateway.log` (1 pass, `e46d5813`). The earlier single-relay independent-route miss is a negative control, not the current legacy path. |
| Checkpoint exact recovery | A test hook dropped committed Accepted. The issuer reopened after relay reclamation on the same reservation alias and retained the exact checkpoint boundary and snapshot. An outsider and wrong ticket were denied; retry returned the exact saved response, without a second mutation. The native joiner was denied before sync, then activated at the saved minimum and sent an authorized packet. | `checkpoint-inviter-live.mjs`, `p2p-checkpoint-recovery-gate.vddW5M/live.log` (1 test-hooks pass on `5aecaaac`). The production `publication-checkpoint-5ae-live.log` passed four and skipped the hooks-only retry. This is recovery, not independent checkpoint locator storage. |
| D1: LAN-first recovery | The same peer reauthenticated over eligible LAN ahead of the old circuit. With the veth marked VPN-owned, LAN returned no candidates and one bounded circuit fallback succeeded. A late pre-loss LAN response did not update the preferred path. Public results were substituted, not obtained through DHT. | `incoming-relay.mjs`, `publication-evidence-ea6-incoming.log` (2 recovery passes). |
| D3: Companion egress | DNS, bootstrap, Identify and relay counters followed the default on switch and return. Blocked default bootstrap yielded no candidates and zero secondary fixture traffic. Each lease reused its bound upstream UDP socket; old sockets and loopback ports retired without forwarding. After return, authenticated relay used only the primary; eligible browser-owned direct-member traffic still used the secondary. | `relay-gateway.mjs`, `publication-evidence-ea6-gateway.log` (3 passes including fallback and cross-family). |
| D4: Shared reservation close | In the polled SDK fixture, remote graceful close removed only the closed member within the two-second check and rejected outbound traffic to it. The survivor sent and received IP on the same reservation. | `incoming-relay.mjs`, `publication-evidence-ea6-incoming.log` (1 graceful-close pass). |
| N1: In-app name authority | Peer-signed rename, conflict with stable peer fallbacks, stale legacy epoch and revocation suppression passed. Named HTTP selected IPv4, literal IPv6 used IPv6, and no public-name lookup escaped. Not system DNS or A/AAAA parity. | `native-app.mjs`, `publication-evidence-ea6-names.log`. |
| C2: Live checkpoint mutation | Native upsert applied once despite a lost reply; replay received correlated stale-base with the current revision. Other-member removal and self-exclusion persisted; stale credentials could not restore authority. Forced save failure kept prior state and returned persistence failure, not successful revocation ACK. A browser durably excluded the issuer and returned the final ACK without retaining it as a member. | `host-app.mjs`, `publication-evidence-ea6-host.log` (3 passes). |

## Checkpoint Publication Gate

At `f6c2964c`, `publication-checkpoint-distribution-f6c-live.log` records
6/6 Chromium passes, none skipped, plus a separate pass of the successive
locator case. All six cases are in `checkpoint-inviter-live.mjs`.

| Chromium case | Verified result |
| --- | --- |
| Live issuer and native member | New native member received checkpoint authority and sent IP on the issuer's reserved circuit. |
| Served signed-file approval | The app reviewed the request and saved the updated roster before releasing the signed response on the live reservation. |
| Served code approval and native sync | The applicant could not send before durable approval and authenticated checkpoint sync. |
| Two served browser apps | Browser-to-browser code enrollment completed, with the new authority installed and the enrollment floor cleared after sync. |
| Lost committed Accepted | With test hooks, the issuer reopened the reservation and recovered the exact saved response, without a second mutation. Wrong ticket and outsider were denied; the native joiner synced before sending. |
| Successive independent locators | Two distinct locators on the same live reservation resolved to only its confirmed alias through an independent seed and directly from storage. Repeat publication was denied, a cancelled code was rejected despite a cached hint, and the second applicant synced and sent IP after durable approval. Release before delayed start opened no storage connection. Child expiry closed the live WebSocket and upstream TCP stream and freed the slot without retiring the parent or changing saved authority. Default-link change revoked ingress; restoring the link did not revive the lease, and the cached provider remained visible. |

`publication-checkpoint-distribution-f6c-rust.log` records 4/4 passes in
`src/runtime/browser_host/relay/lease.rs`: child deadline is capped by the
lease and does not restart at discovery; retirement overflow refuses new
starts without evicting an active child; release before delayed start spends
no publication budget; staged leases already occupy shared capacity.

These are cooperating-DHT results. Publication-child cancellation and
expiry are not C1 browser snapshot interruption or late-page rejection.
Neither the public-form alias nor the DHT protocol ID establishes public
IPFS acceptance, retention, or unrelated-seed visibility.

## Checkpoint Cancellation Gate

The focused `checkpoint-inviter-live.mjs` cancellation case was tested on the
fix based on published `d6dc0c1680b2`. Production and test-hooks WASM each
passed in a fresh, local-only network namespace. A separate code approval
completed and sent an authorized packet before either cancellation. Late
cancellation left that approval unchanged. The reviewed, uncommitted request
received no grant and left revision 1 unchanged. A second request was saved at
revision 2 without delivering `Accepted`. A forced storage write failure
left both the admission and its cleanup receipt intact, and retry advanced to
revision 3, removed only the owned admission, and cleared the receipt. Neither
cancelled applicant obtained activation credentials. The previously approved
member applied revision 3, then reauthenticated and sent an acknowledged VPN
packet after the issuer reopened the same relay reservation. Both reopens
waited for relay-observed retirement of the old reservation.

Local evidence: `/tmp/p2p-checkpoint-cancel-evidence/live-production.log` and
`live-hooks.log`, with the commands in `run-live.sh` and artifact hashes in
`SHA256SUMS` in the same directory. The baseline hooks build failed the new
gate because cancelling did not attempt the cleanup write. This is ordinary
cancellation coverage, not a rerun of lost-response recovery.

Independent integration at `2d86a95954d2b8639c57a2b5931484405ac0f81b`:

| Gate | Verified result |
| --- | --- |
| Live cancellation and retry | Production and hooks WASM passed the case above independently (`cancel-production.log`, `cancel-hooks.log`). The approved member used successive sessions, not simultaneous member service. |
| Lost committed Accepted | A separate hooks run reopened the same exact reservation alias after relay retirement. Wrong ticket and outsider were denied; the original native applicant recovered the same grant at the saved boundary without readmission, synced, and sent an acknowledged packet (`lost-accepted.log`). The relay and all peers were isolated; the public-form alias does not qualify public IPFS or companion lease recovery. |
| Adjacent issuer behavior | Production served code approval still withheld packet authority until authenticated sync (`served-code-final.log`); all four issuer Rust tests passed (`issuer-unit.log`). |

The independent runner, logs and artifact verification are in
`/tmp/p2p-checkpoint-cancel-integration/`. The cancellation gate applies to a
live, locally committed approval before successful delivery. Reopening a
stored receipt arms a recovery-only invitation, which the UI does not offer
for cancellation. On that state, `cancel_checkpoint_code()` can return success
for retiring the in-memory invitation without clearing the durable receipt
or changing the roster. This is not post-restart administrative cancellation.

## Receiver, Mesh and Locator Gates

| Tested tip and log | Verified result |
| --- | --- |
| `18454847` / `publication-receiver-184-live.log` | **26 Chromium passes** in `receiver.mjs`. S1: wrong version, packet protocol and header length; zero MTU; unknown path; ungranted route and local collision; wrong tag and rotation (configured prior tag accepted, otherwise denied). Denials clear authority; no circuit follows a capability rejection. Direct IP/status and relay cases include MTU, malformed IP, repeated IP acceptance and keepalive/path-probe replay rejection. Alternate direct, preferred return and reauthentication also passed. |
| `18454847` / same live log | L1: two-page sync and durable revocation; failed save, interrupted continuation, invalid page, conflict and churn preserve prior authority; a changed snapshot restarts at zero and commits only the replacement; expired history cannot revive an older grant. The fixture closes the local browser session while holding the legacy continuation. |
| `18454847` / `publication-receiver-184-adjacent.log`, `publication-receiver-184-rust.log` | **3 adjacent Chromium passes**: graceful close and two LAN recovery cases. **3 Rust passes**: shared control codec (malformed JSON/UTF-8, missing required boolean, short body); packet codec (unknown version/type, short header/payload); C1 driver (late final page cannot install after disconnect or deadline, `crates/p2p-vpn-browser/src/checkpoint.rs`). The driver result is not a live Chromium transfer. |
| `1a705028` / `p2p-mesh-1a705028-evidence/{provider,renewal,revoke,egress}.log` | **1 pass each**: member-ID-only discovery and authenticated WebRTC from a scoped provider-only cooperating IPFS-protocol seed; explicit signed circuit publication, renewal of the exact alias past its original expiry, then no renewal on disconnect and lookup rejection at signed expiry; persisted revocation blocks member discovery before dialing; companion default switch/return with no automatic secondary fallback. Sources: `relay-advertisement.mjs`, `receiver.mjs`, `relay-gateway.mjs`. |
| `0b758523` / `publication-stale-0b7-live.log` | **Corrected 4/4 Chromium/native fixture passes** in `native-code-locator.mjs`: browser cancellation, invitation deadline advanced independently of storage, scoped ingress release, and route-generation invalidation followed by restored reachability. A fresh native v2 library lookup read the cached exact alias through the independent seed; enrollment timed out with no delivered grant or imported config. Initial 0/4 attempt used a fixture that rejected the enrollment argument; that is not an authority result. Ingress release is not a relay-side reservation termination notification. |

The regular signed-address expiry is reader eligibility, not deletion of
a provider record or a hard TTL on a remote store. The mesh gate exercised
separate provider and signed-address paths, not a pairing-locator lookup.

## D2: Bounded Member Rendezvous

In isolated Chromium at `f5937b3e`, the real Linux companion returned two
provider hints from a cooperating DHT for the same authorized member. One
endpoint received WebRTC traffic but never answered. The browser kept HTTP
sending disabled until it authenticated the live endpoint, which then sent
an accepted VPN keepalive. Selecting that path closed the losing dial.

After disconnect and native listener shutdown, the same cached provider
hints still resolved. A new connection attempt ended at the approximately
25-second browser dial budget. Both attempts at the now-unreachable endpoints
closed, HTTP sending stayed disabled, and the browser made one companion
lookup per connect with no automatic retry. The fixture observed WebRTC
connection closure and confirmed that UDP traffic to the silent endpoint
stopped after selection and after exhaustion.

This checks member-ID fallback and an explicit reconnect, not automatic
recovery after an established path fails. The stale hint was a provider
address, not a signed peer record in its stale-but-dialable window or an
expired browser relay cache entry. No pairing locator or public IPFS node was
involved. See `relay-advertisement.mjs` and the local
`/tmp/p2p-d2-member-recovery-evidence/` logs, runner, and artifact hashes.

## Automatic Established-Member Recovery

The independent `relay-advertisement.mjs` rerun at
`b936c711c20bac598df28daae84520773447b4db` passed with the existing
production browser and Linux companion artifacts. After the initial
authorized keepalive, the native fixture removed the original listener,
closed the connection, and confirmed no connection to the browser remained.
A cooperating DHT seed replaced the provider address with a different UDP
port for the same member. Without another click, foreground Chromium made
one new companion discovery request, received the replacement address, and
completed a fresh authenticated capability exchange.

The user-facing HTTP request was sent only after reconnection. It received
the exact `recovered-route` body over the VPN. Chromium reported the old
WebRTC connection closed and the replacement connected; no additional dial
or discovery request appeared during the 1.5-second post-response observation.
The adjacent provider-only case passed with the same artifacts.

Evidence: `/tmp/p2p-auto-recovery-integration/` (`automatic.log`,
`provider-only.log`, and artifact checks). This covers foreground Chromium,
the real Linux companion, and a cooperating DHT in isolated namespaces.
It does not qualify physical WAN recovery, preferred LAN, background
recovery, or public IPFS.

## Checkpoint Interruption And Invitation Recovery

| Tested revision and log | Verified result |
| --- | --- |
| `b3dbb7e9` / `/tmp/p2p-browser-c1-real-clock.Bzwg2L/chromium.log` | C1, one Chromium pass with the real clock. Local WebRTC close interrupted an authenticated multi-page sync with the final range held at cursor 8192. Prior disk and in-memory authority survived, the browser stayed unauthorized, and the assembly retired with zero buffered bytes. On a new connection a fresh authenticated sync installed and persisted the offered checkpoint. This is not live delivery of a stale final page; the separate Rust driver above checks late-page rejection after disconnect or deadline. |
| `a17d2723` / `publication-evidence-a17-cellular.log` | One Linux Rust pass: the isolated discovery test exercises rejecting and retiring mDNS bindings for cellular metadata. The test is published as `3912caa5`; this is not a physical cellular modem trial. |
| Test published by `2cd7a6d4` / `/tmp/p2p-vpn-relay-retirement.0F0DSU/retirement-authority.log` | The relay closed the reservation and pending applicant circuit while the exact alias remained cached. The join failed with no grant or imported config, and the ledger was unchanged. Chromium did not observe the loss during the wait and still showed stale review. The stricter earlier attempts in the same directory did not pass; this pass did not attempt local approval after an observed loss or replay the ticket on a replacement reservation. |
| `efa0b27de6ab` / `/tmp/p2p-vpn-legacy-restart-evidence/recovery-final.log` | A2, three Chromium test-hooks passes on the owner's source tip: drop committed Accepted, retire the reservation, reopen on the exact alias, and return the identical signed response to the original applicant's Poll. Replay did not rewrite the roster or receipt, and an unrelated file admission preserved the receipt. Removing the committed grant caused denial; leaving the issuer closed let the original retry expire. The Rust receipt test separately checks wrong peer, ticket, circuit and deadline. |
| `efa0b27de6ab` / `/tmp/p2p-vpn-legacy-restart-evidence/{enrollment,rooted-production}.log` | Seven adjacent production Chromium passes, including rooted issuance over independent storage and native TUN traffic, and denial with the prior roster unchanged. These are not prior/new member packet tests after receipt reopen. |

The five legacy patches were integrated unchanged on the baseline above.
The combined code tip was `e4a8c6f73e023341442ebc45c6ab847d352dc069`.
Logs, the isolated Chromium runner and artifact hashes are in
`/tmp/p2p-browser-conformance-integrator-evidence/`.

| Combined-tip check | Evidence |
| --- | --- |
| Build and Rust | Formatting, production and test-hooks WASM, native daemon and fixtures, 21 browser unit tests including the late-page driver and receipt binding (`build-unit-retry.log`); one native exact-winner/current-issuer unit test (`legacy-authority-unit.log`). |
| A2 and adjacent production | Three receipt cases (`recovery-final.log`); five served and existing-issuer cases plus two rooted native cases (`adjacent-final.log`). |
| C1 and server-side retirement | One C1 interruption and fresh sync pass (`c1.log`); one pending-ticket retirement pass (`retirement.log`). The latter returned `Pairing expired` with no grant or ledger change; browser-side stale review was still visible during the observation window. |

### Shared Framing Boundary

Source inspection of `crates/p2p-vpn-browser/src/browser.rs` and
`src/runtime/p2p.rs` confirms that the browser and native request-response
streams register the same `ControlCodec`, `PacketCodec`, and `ServiceCodec`.
The browser registers service status inbound only; the native registration
is bidirectional. The shared readers check declared lengths before the
body allocation or read. The packet codec cap is configured from the local
MTU, bounded by the wire maximum; negotiated packet admission is separate.

The test-only change at `4cc576a6f50410a676dbe1cd466a29a49741458e`
was independently checked with the cached WebRTC-enabled native test binary.
The logs and binary checksum are under
`/tmp/p2p-vpn-s1-frame-io-integration/`.

| In-memory gate | Verified result |
| --- | --- |
| Control (28 tests) | A 16,384-byte encoded request round-trips; the recorder sees the two-byte prefix and exact body read. A one-byte-over declaration with no body returns `InvalidData` after requesting only the prefix. |
| Packet (8 tests) | A header-only keepalive and a 1,280-byte payload round-trip at a configured cap of 1,280. A 1,281-byte declaration with no body returns `InvalidData` after requesting only the 17-byte header. |
| Service (11 tests) | Existing request/response round trips and the 4 KiB cap check passed. The oversize test uses a cursor and verifies that it consumed only the two-byte length field; it does not use the new read recorder. |

These tests observe read requests or cursor position in memory, not heap
allocations. The earlier Chromium capability, MTU and admission results
remain separate live interoperability evidence. No WASM build or live
malformed or oversized-withheld-body transport test was run for this proof.

## Legacy Approval Recovery Follow-up

The isolated `native-code-locator.mjs` follow-up uses the served code inviter
and the existing **Recover an approved request** control. For fresh scoped
issuance, Chromium downloads the optional private issuer JSON before approval
and imports that file after reload. The test drops the committed Accepted
reply, retires the original reservation, and lets the original browser
applicant retry Poll on the same pinned relay path. It checks the exact grant
in storage and after the rooted merge, equality of the signed response digest
before and after reopen, no locator republish, no roster or receipt rewrite,
and a stock Linux TUN HTTP round trip as the admitted identity.

For an already rooted issuer, the new member uses the recovered reservation.
The prior member exchanges packets through the normal app's explicit relay
listener after the recovered session ends. Both use the same authenticated
relay, not concurrent circuits on the detached invitation. The fixture uses
test hooks to drop and observe the reply, not to reopen or authorize a VPN.
An adjacent production-WASM test approves and carries fresh scoped member
traffic without a backup; native v2 locator enrollment is checked separately.

On `2c602df4`, the namespace-isolated runner and logs are under
`/tmp/p2p-legacy-durability/`: `fresh-recovery-final-pass.log`,
`fresh-normal-final-pass.log`, `rooted-traffic-verified.log`,
`rooted-denied.log`, `rooted-expired.log`, `native-code-only.log`,
`rooted-production.log`, and `rooted-production-denial.log`.

## Scoped Legacy Review Retirement

The scoped legacy issuer review cleanup was independently exercised at
`92d524f53738db7c266879c139904f18ed0deb49` in `native-code-locator.mjs`.
In a Chromium/companion fixture, the relay retired the reservation and
applicant circuit. The issuer cleared the stale code and review, disabled
approval and denial, and returned to the existing issuer form. The durable
ledger was unchanged. The same issuer opened another invitation; a different
applicant kept polling, remained approvable after 31 seconds, and connected.
The saved ledger kept the prior signatures and included the new applicant,
not the retired applicant.

The foreground expiry is 15 seconds of applicant silence for an uncommitted
scoped review. It starts at the verified request and is refreshed only by
authenticated Polls matching the selected peer and ticket on the admitted
circuit. It adds no probes and does not extend the invitation deadline. The
timer does not apply to committed receipts, recovery-only invitations, or
explicit pinned mode. The fixture does not distinguish immediate browser
transport notification from the silence fallback.

Independent logs and artifact checks are under
`/tmp/p2p-browser-invite-cleanup-integration/`: `scoped-issuer-ui.log`,
`ordinary-enrollment.log` (production fresh and rooted, with stock TUN),
`explicit-pinned.log` (ordinary pinned flow), and `receipt-recovery.log`
(matching hooks, fresh and rooted committed receipt recovery). These are
isolated cooperating-DHT and relay fixtures. They do not test public IPFS
or present an old uncommitted ticket on an alternate reservation.

## Live Evidence

| Check | Result |
| --- | --- |
| WebRTC Direct r2 | Passed in Chromium 156.0.8078.73. Initial dial and reconnect preserved the original browser ICE credentials. |
| Static peer and scope | The app rejected an unauthorized peer, a wrong network name, and a mismatched membership tag before overlay HTTP. A native sender also received the browser's typed `CapabilitiesRejected(WrongNetwork)` reply. |
| Control and packet exchange | The app received fresh HTTP responses across disconnect and reconnect on a Linux daemon with a real TUN. |
| IPv6 and overlay names | The production app fetched over IPv6 through a Linux TUN and resolved an authorized overlay hostname for an IPv4 fetch. |
| Alternate member endpoints | The browser connected with an unavailable alternate endpoint and rejected endpoint lists containing a different peer ID. |
| Linux LAN discovery | Chromium and the native daemon used opposite ends of an isolated veth. The browser authenticated the member after mDNS lookup through the companion, with no remote address in its config. |
| LAN code-only enrollment | The companion returned a LAN hint from an empty request. Chromium completed PAKE and native approval without making a public locator request. |
| Explicit relay fallback | Chromium passed relay-only, direct failure with relay fallback, and alternate direct preference. A direct capability rejection did not trigger a circuit. |
| Native-initiated circuit | A native peer dialed the browser's confirmed reservation and exchanged authenticated control and IP traffic. The browser did not dial the member first. |
| Browser-to-browser circuit | Two Chromium peers exchanged VPN capabilities and IP packet acknowledgments in both directions over a real relay. This did not require generic WebRTC signaling. |
| Shared incoming circuit reservation (SDK) | Chromium handled two authorized legacy members with distinct MTUs. Local and remote graceful close left the other circuit usable; the polled remote-close fixture verified prompt authority removal. |
| Shared incoming circuit reservation (app) | The app selected a second authorized member. It showed the selected member's connection loss and disabled its HTTP action while the other circuit kept receiving packets. |
| Scoped companion gateway | On a separate veth path, Chromium tried a dead direct hint, then authenticated over the Linux companion's circuit lease. Lease release freed the loopback port. |
| Cross-family relay | IPv4-only Chromium reached an IPv6-only native member over one dual-stack relay. The companion discovered the relay and sent no fixture traffic over its alternate interface. |
| Relay publication | Chromium published a signed, confirmed reservation with an explicit permit. A separate companion found it on a cooperating DHT and its native member connected. |
| Path recovery | Following loss of its WebRTC connection, Chromium cleared transport authority and authenticated the same peer at a replacement endpoint. Both sides exchanged capabilities again. |
| Preferred return | An authenticated direct connection passed an exact-path probe before taking over from the circuit. A failed or superseded candidate preserved the circuit. |
| Signed legacy membership | A native peer sent an eleven-record snapshot in two pages. The browser validated and merged it, then served the resulting snapshot back. |
| Durable legacy revocation | A new browser peer opened the original config after revocation and refused to dial. A second live instance was denied the ledger lock. |
| Code pairing v2 | Production WASM waited for native approval and connected using the approved legacy config. It also activated a checkpoint grant only after authenticated snapshot sync. The app's code-only flow passed against a controlled lookup response. |
| Pairing compatibility | Explicit scoped v1 worked with the native daemon. Legacy and checkpoint v2 approval and activation both worked over a real circuit. |
| Signed file invitations | A detached legacy founder or rooted delegate reviewed a request in Chromium. The browser released a native-compatible signed response only after explicit approval and a successful ledger save. |
| Explicit code invitations | Chromium enrolled a pre-pinned joiner in a new or existing rooted legacy network. After approval both browser peers used the original relay reservation and exchanged IP traffic. |
| Companion pairing relay | Chromium enrolled over a real companion lease, handed it off after approval, fetched HTTP over the new gateway, and closed the gateway on disconnect. |
| Native v2 bootstrap relay | An isolated Linux joiner followed the DHT's exact reserved-provider hint over its default link. Stale and secondary-link paths were rejected. |
| Companion inviter egress | A Chromium reservation used an operator-approved relay through the Linux default link. A route-generation change revoked the ingress. |
| Scoped browser code publication | The code inviter used the companion gateway. An independent native lookup found only the confirmed public circuit on a cooperating DHT. An explicitly routed browser joined after approval. |
| Automatic inviter relay | With only a DHT bootstrap configured, the Linux companion authenticated a relay on the default network and issued a WebRTC lease. It rejected a secondary route and revoked the lease on a route change. |
| Native v2 code-only join | Earlier runs used a referral to the reservation relay. Published fresh and rooted legacy runs used independently routed storage and exact-alias readback; the native v2 library joiner and stock TUN used the original circuit. |
| Scoped rooted legacy issuance | The production Chromium UI admitted one unknown native v2 applicant through the exact published circuit. A failed ledger write withheld the grant; successful approval preserved prior signatures and enabled an HTTP round trip through the stock TUN. Denial on a separate invitation released the lease without changing its prior roster. |
| Unpinned code admission | The browser accepted a verified v2 applicant for explicit approval. The fixture also checked cancellation, expiry, and admission limits before packet authority. |
| Checkpoint credentials | The app reopened the same encrypted identity in Chromium after closing the prior session. The native peer authenticated it again without another approval. |
| Checkpoint revocation | On a LAN path, native removal reached Chromium. The browser stored the exclusion before acknowledging it and rejected the original credential file after reload. |
| Checkpoint roster changes | Chromium durably installed and acknowledged a native member upsert and another member's removal before its own revocation. |
| Checkpoint-issued invitation | The app released a signed file response only after approval and a durable roster commit. A native joiner was denied before sync, verified the snapshot on the exact reserved circuit, then sent an authorized IP packet. The separate live code cases verified durable approval and sync with native and browser joiners. |
| Demand lifecycle | On an incoming, maintained relay the foreground browser negotiated Demand and exchanged real Idle and Wake messages with a native fixture. Hidden and outgoing cases stayed in legacy mode. |
| Negotiated IPv4 MTU | Segmented HTTP worked at browser MTUs of 1500 and 1200 against native MTU 1400. The browser accepted a probe at the negotiated limit and returned `PacketTooLarge` one byte over it. |
| Packet authorization | A native test peer and the browser both sent typed `UnauthorizedSource` rejections. The browser also sent `UnauthorizedDestination` for a packet not addressed to it. |
| Reliable-stream replay | The same IP frame was accepted twice. A nonempty keepalive returned `UnexpectedPayload`; a repeated valid keepalive returned `Replay`. |
| Optional service status | The browser echoed the request nonce and reported the negotiated stream path MTU. A wrong-scope request returned `MembershipMismatch`. |
| Portable byte vectors | Three tests passed. These are reference-codec and derivation tests, not browser transport tests. |

The runs used Chromium 156.0.8078.73 in isolated Linux user and network
namespaces. The production app used no test hooks.
The separate r2 and inbound wire fixtures used a test-hooks package.

The [earlier Windows smoke](../browser-wasm-validation.md#earlier-windows-qualification)
used Chrome 156.0.8078.82 and a same-machine native daemon with Wintun.
It covered bounded foreground IPv4 HTTP, not IPv6, pairing, checkpoints,
Linux companion discovery, or a two-device physical LAN.

Use the [isolated Linux test harness](../browser-wasm-validation.md#repeatable-linux-tests).
Run the vector check with `cargo test --locked --test protocol_spec`.

## Shared Implementation

The native and browser adapters use the same capability validation, frame
admission, routing authority, packet rejection reasons, and wire codecs.
The browser uses its own in-process IP device, driven during operations,
instead of native TUN I/O.

## Supported Profiles

| Profile or feature | Current browser status |
| --- | --- |
| Static stream | Foreground browser WebRTC Direct r2 or a supported Circuit Relay v2 path with the matching native peer; in-app IP only. |
| Companion-assisted discovery | Eligible LAN, regular member rendezvous and scoped relay discovery on cooperating DHTs, circuit fallback and authenticated direct recovery. Public-IPFS rendezvous is not qualified; no unrestricted Discoverable Mesh claim. |
| Managed legacy membership | Signed snapshots, durable revocation and explicit approval with the matching native peer. Detached issuers support file and explicit code invitations; exact, bounded receipt recovery covers existing rooted and durable fresh scoped issuance with a matching user-held issuer config. |
| Managed checkpoint membership | Authenticated sync, native roster updates and durable exclusion; live file and code approval on a confirmed reservation, including independent locator storage on a cooperating DHT. Not general browser-originated roster administration; exact lost-acceptance retry is verified with test hooks. |
| Datagram and service extensions | No owned UDP or QUIC packet plane. The browser can answer authorized service-status requests while its swarm is running. |
| Demand lifecycle | Negotiated only on a maintained incoming circuit while the foreground browser is polled. No background wake or standalone direct-path guarantee. |
| Host behavior | Only the companion can verify physical-interface binding for the sockets it owns. Browser WebRTC is browser-managed. DNS is in-app only; no browser TUN, OS routes, system DNS/PTR/forwarding or redirection of ordinary navigation. No Full Client claim. |

The standalone page does not perform public infrastructure traffic. In
companion mode, native discovery enforces the [local egress rules](discovery.md)
before returning hints. The browser authenticates the member independently.

## Clause Audit

The evidence below is bounded by the fixtures above. Source requirements
or shared codecs are not themselves behavioral passes. The last column
points to remaining checks where the recorded result is narrower.

| Clause | Published behavior and evidence | Open |
| --- | --- | --- |
| [Conformance and invariants](README.md#invariants) | Authenticate expected transport identity, then check scope and current route authority. Recheck before send, receive and promotion; bound work and never route around denial. Wrong scope and deny-without-fallback are recorded. | S1 |
| [Session setup, encodings and control](stream.md#session-setup) | r2 preserves ICE credentials. Bilateral capabilities constrain version, protocol, header, path, support booleans and nonzero MTU; capped u16 UTF-8 JSON and write half-close. Live capability denials and shared malformed-codec tests passed. | S1 residual |
| [Packet stream and response](stream.md#packet-stream) | v1 17-byte frame, zero sent flags, bound before payload read, typed response and negotiated MTU. Current source and local destination, no transit. Recorded IPv4/IPv6, MTU boundary, repeated IP accepted and keepalive/path-probe replay denied. | S1 residual |
| [Service status](stream.md#service-status) | Optional scoped, authorized 4 KiB framed diagnostics. Nonce, selected MTU and wrong-scope denial recorded. | Optional status edges |
| [Identity, addresses and scope](membership.md#identity-and-addresses) | Binary peer ID derivation, both host routes, explicit grants, null versus keyed scope and configured rotation. Alternate mismatched peer, ungranted routes and local collisions rejected; prior tag accepted only with configured rotation in the live fixture. | Verified cases |
| [Discovery is not admission](discovery.md#discovery-is-not-admission) | Configured, mDNS, Identify and DHT hints require eligible provenance and peer authentication. Separate-veth LAN-first pairing and member recovery recorded. VPN-owned and cellular links are excluded from eligible LAN work. | D1 |
| [Kademlia and keys](discovery.md#kademlia) | Private protocol or public IPFS namespace; global v2 locator independent of overlay DHT, domain-separated keys and provider-only long-key transform. Regular provider-only lookup and signed circuit lookup passed on cooperating DHTs. No public IPFS result. | Broad public claim only |
| [Signed records and scheduling](discovery.md#signed-address-record) | Signed peer/key, scope, target and expiry; 64 KiB and 32-address bounds. Stale data is a hint, not authority; public-only work excludes private/unresolved endpoints. Opt-in exact alias publication, renewal and signed expiry passed. Persisted revocation blocks discovery independently of any old hint. | Verified cases |
| [Relay and direct recovery](discovery.md#relay-and-direct-recovery), [path policy](../shared-path-policy.md) | Real reservations and end-to-end control/IP. Exact-path validation before promotion; failed or superseded return leaves the circuit intact. Native-initiated and browser-to-browser traffic and survivor behavior recorded. | D1 scope |
| [Physical egress](../physical-network-policy.md), [public relay acceptance](../public-discovery-relay-acceptance.md) | Companion-owned automatic infrastructure follows the OS default, not a secondary on failure. LAN, direct peers and explicit relay have separate eligibility. Scoped leases, generation revocation, default switch/return and cross-family HOP passed. | D3 |
| [Legacy records, convergence and exchange](membership.md#legacy-signed-records) | Canonical signatures, issuer authority at signed time, deterministic merge and durable tombstones. Digest/count/cursor, 8 records per page, 256 total, bounded restart and no partial apply. Eleven records in two pages exchanged both ways; invalid, interrupted and failed-save transactions retain prior authority. Durable revocation and bounded restart passed. | L1 gate passed |
| [Checkpoint objects, authentication and rank](checkpoints.md#canonical-objects) | Pinned anchor, authenticated canonical roster, MAC, deterministic branch selection, incarnation and expiry; rank alone grants nothing. Losing branches do not carry legacy tombstone guarantees. Shared vectors do not qualify independent transcripts. | C1, E1 |
| [Checkpoint transfer](checkpoints.md#snapshot-transfer) | Peer-bound challenge/proof, signed publisher and matching digest/cursor/size; 8 KiB ranges and bounded transfer. Activation gates on authenticated install; encrypted reopen and durable exclusion recorded. Chromium interrupted and freshly synced; the Rust driver rejects a late final page. | C1 residual |
| [Checkpoint mutations and enrollment](checkpoints.md#mutations-and-enrollment) | Exact base, authorized issuer, real revision, save before ACK, correlated result and bounded control-only reply. Native upsert, other removal and self-exclusion recorded. No standalone legacy migration or silent replacement of pinned authority. | C2 scope |
| [Names and DNS](membership.md#names-and-dns) | Legacy in-app names use current authority, signed rename, conflict handling and deterministic fallback; no public DNS fallback. IPv4 name fetch and literal IPv6 do not establish A/AAAA parity or checkpoint name-incarnation behavior. | Optional; legacy cases verified |
| [Enrollment versions, codes and discovery](enrollment.md#versions) | Explicit scoped v1; bounded, LAN-first v2 discovery. Fresh/rooted legacy and live checkpoint publication use independently routed storage on a cooperating DHT. A locator is not authority, including after the four tested retirements. | Relay-side loss |
| [Enrollment messages and cryptographic binding](enrollment.md#code-messages) | Bounded versioned frames; signed peer/key/locator/time, SPAKE2, AAD and confirmation, peer-bound ticket and signed grant. Matching v1/v2 and signed-file cases passed. | E1 |
| [Commit and activation](enrollment.md#commit-and-activation) | Save approval before releasing a grant, keep unrelated admissions, establish the checkpoint floor and sync before data. Rooted legacy save failure/denial and checkpoint code approval passed. Separate hooks gates recovered the exact saved checkpoint and legacy responses after reopen. | A2 residual; broader checkpoint cancellation/recovery |
| [Owned datagrams](datagrams.md) | Negotiation, signed handshake, keys, replay and binding are native profile clauses, not browser claims. Companion UDP ingress does not implement browser datagrams; absent support selects streams without bypassing denial. | Not applicable |
| [Demand lifecycle](../demand-lifecycle-wire.md) | Current authority, fresh epochs, bounded scope/revision and reply correlation, response-sent gate and legacy fallback. Real Idle/Wake on a foreground polled incoming circuit; hidden/outgoing fixtures stay legacy. No background, direct or battery guarantee. | Conditional |

## Remaining Acceptance Checks

The open evidence below does not narrow the declared reference target.
Evidence gaps are not by themselves source non-conformance.

| Scope | Remaining acceptance |
| --- | --- |
| **C1: checkpoint transfer** | Chromium interruption, retirement and fresh install are evidenced. A separate production Chromium SDK test restores an approved enrollment floor before first sync and durably installs authenticated exclusion without forwarding. Late final-page rejection is driver-only; live stale/invalid page delivery and broader interrupted-transfer variants are not established. |
| **A2: legacy code approval boundaries** | Exact authenticated Poll recovery and post-reopen packet traffic are evidenced for the detached durable profiles above. The receipt is not a new Submit or PAKE exchange. Fresh scoped recovery requires an actually retained private config and the original origin's ledger and receipt; the pinned in-memory create mode cannot recover after reload. The evidence does not establish simultaneous service of prior members during a detached invitation, or native-applicant Poll recovery. |
| **S1: framing boundary** | Source and in-memory shared-codec tests establish the tested read-before-body bounds. Live capability denials and MTU behavior stand separately; no heap measurement or live malformed/oversize-withheld-body timing claim. |
| **Companion discovery policy** | D1/D2/D3/D4 fixture cases passed; cellular binding exclusion has Linux metadata evidence, not a physical cellular run. Egress applies to the measured companion-owned sockets, not all DNS transports, all connection-reuse paths, or browser-owned sockets. |
| **Regular member rendezvous** | Provider-only discovery, exact signed alias renewal and signed expiry were separate cooperating-DHT tests. D2 adds bounded member-ID fallback and exhaustion with unreachable provider hints; a separate foreground case verifies automatic recovery of an established member through the companion. The full retry and cached-hint matrix, remote withdrawal, and public rendezvous remain unqualified. |
| **Relay-side invitation retirement** | The four cached-hint cases and server-side retirement without a grant are evidenced. The scoped legacy UI clears stale review after relay retirement and accepts a different applicant on a new invitation. Denial of the old uncommitted ticket on a replacement reservation was not tested. Committed receipt recovery is separate. No requirement to erase a remote hint. |
| **Checkpoint enrollment recovery** | Live cancellation preserves the previously approved member through cleanup and reopen; exact lost-response replay is verified separately. The SDK reopen uses owner-supplied provisioning inputs. The app cannot resume a generated pending identity after closing: activation consumes its handle and encrypted credential export requires an authorized session. Post-restart administrative cancellation of a recovery-only receipt is not covered. |
| **Conditional extensions** | Service-status authorization/bounds and foreground incoming Demand apply when advertised, not to basic stream traffic. C2 native upsert/removal, stale base and save failure are verified; qualify policy/prune if declared and do not claim general browser-originated mutation/departure. Legacy in-app name results do not qualify checkpoint name incarnation or system DNS. |
| **Broader claims only** | Refresh and remote TTL/withdrawal of code locators are not established or required by the scoped one-shot publication claim. Do not claim public IPFS, independent stack compatibility, native CLI profile-free enrollment, browser-owned host egress, native datagrams in browser, or Full Client. Those require separate evidence or support declarations. |

The C1 SDK regression in `crates/p2p-vpn-browser/tests/checkpoint-transfer.mjs`
uses a verified native approval and the production `BrowserVpn.open_checkpoint`
store path. It closes the initial session before dialing and reopens the same
origin with the floor omitted from the fixture's provisioning inputs. Chromium
restores the saved floor at revision 1 and stays gated. A normal VPN HTTP
request drives authenticated checkpoint sync; the native authority has removed
the browser at revision 2, and the request terminates with exclusion before
emitting IP. The exclusion survives another reopen. Browser packet counters
and native packet observation both stay at zero, the browser closes the WebRTC
transport, and the publisher has no live transfer or buffered bytes.

The independent rerun at `59ebc830db8f5743a424911358bfaa53855c1a42`
passed both `checkpoint-transfer.mjs` cases: held-page interruption and
fresh sync with test hooks, and SDK restore and exclusion with production
WASM. The separate production `pairing-joiner.mjs` case passed normal
checkpoint activation and encrypted credential reopen after authorization.
See `/tmp/p2p-c1-restore-integration/` for `transfer.log`,
`activation.log`, the isolated runner and artifact checks.

The SDK test supplies the same owner-provisioned identity, checkpoint
bootstrap and capability on each open. It does not recover an app-generated
pending identity or use fixture keys as an app resume flow. The app still
consumes its activation handle and cannot export pending credentials.
Post-activation encrypted reopen is not a substitute for that missing flow.

The Linux test uses the production profile-free v2 library entry point and
the stock daemon; it does not use `p2p-vpn pair join`, which targets a running
daemon's network-scoped v1 pairing operation.
