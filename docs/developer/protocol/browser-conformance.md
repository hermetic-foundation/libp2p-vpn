# Browser Conformance Audit

Reviewed publication base: `browser-wasm` at
`7f5e288d9f4b53f8d2f152f2833d0dd06122a77a`, plus the N1 test at
`025a24a4f19a5a6866c1f88009a21ca5c39d6107`. Earlier results below retain
their individual evidence revisions.
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
| D3: Companion egress | UDP and TCP DNS, bootstrap, Identify and relay followed the default on switch and return. A secondary-only resolver worked only while its link was default. The live mixed-purpose case returned a scoped relay result using a fresh Identify connection on the primary while an unscoped connection to the same relay stayed established on the secondary. Eligible direct member traffic still used the secondary. | `relay-gateway.mjs`, `publication-evidence-ea6-gateway.log` (original cases); `p2p-d3-gateway-final.log` (D3 rerun and follow-up cases on the `20af3e1d` harness base). |
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

### Signed Member Hint After Membership Expiry

On a private fixture DHT, Chromium discovered a signed WebRTC Direct address
by member ID, authenticated that member, and accepted a VPN keepalive. After
an explicit disconnect and real membership expiry, a companion-only diagnostic
lookup still returned the old signed address. The native listener stayed open,
but Chromium rejected a new connect before discovery or WebRTC dialing, kept
HTTP sending disabled, and sent no tunnel IP. Membership gates the peer ID,
so a second listener for that ID was not an alternate way to admit the expired
member.

The fixture then issued a newer membership record and signed address for the
same member. A fresh browser connect selected only the replacement listener
and received overlay HTTP on the authenticated connection. This checks expiry
of membership while a signed hint remains readable, not expiry of the hint's
own signature lifetime or failover after a remote capabilities denial.
See `relay-advertisement.mjs` and the local
`/tmp/p2p-d2-signed-hint-evidence/` run manifest, Chromium logs, and hashes.

The independent rerun at `c33e6e47bd2f3d7773d946179ec48748336f5efb`
passed all four member cases with the hash-verified stripped receiver and
production WASM: provider-only discovery, bounded fallback/exhaustion,
foreground established-member recovery, and the signed-hint case above.
The companion-only readback still returned UDP 48702 while local membership
was expired and the old native listener remained open. The browser made no
new lookup or WebRTC dial on that attempt; no tunnel IP reached the native
fixture. Renewed authority and a newer hint selected only UDP 37036 and
returned the expected overlay HTTP body. This was a fresh connect, not
alternate selection following an authoritative remote denial.

Independent logs and checksums are in `/tmp/p2p-d2-signed-hint-integration/`.
The signed-alias renewal and reader-expiry regression passed separately from
the membership-expiry case. Neither case establishes remote withdrawal or
public IPFS behavior.

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

### A2: Rooted Native Applicant

At base `c92d49f6b1a3e0b4924224bfb68a0fa64e2d680e`, the original native
v2 applicant timed out after the reopened issuer reserved the same relay
alias. The relay saw no second applicant circuit. Pending Polls retried
through request-response, but that path could not create the explicit,
scoped dial required by the Linux bootstrap relay gate.

The native bootstrap retains the exact address and original default-link
scope from the authenticated pending exchange. It reacquires only that
circuit and checks the selected peer, address, scope, and ticket deadline
when a Poll response arrives. It does not rediscover a provider or restart
PAKE for a scoped Poll retry.

In `native-code-locator.mjs`, a pre-existing rooted issuer published its
exact alias through independent DHT storage. The native applicant started
with only the code and an independent seed. The Chromium UI approved via
the normal durable ledger write. The response-loss hook dropped the first
committed Accepted, and the relay retired the original reservation and
circuit. Production Chromium WASM reopened the same issuer using the
original config and retained ledger and receipt. It did not publish a new
invitation. The same native join verified the full signed response, whose
digest matched the committed response exactly. The prior signatures
survived and the ledger bytes stayed unchanged after the retry. Stock
`p2p-vpn up` carried an HTTP 200 round trip with bidirectional TUN packets
over the same relay alias.

The isolated runner, baseline timeout, passing logs, and artifact and
source checksums are in `/tmp/p2p-a2-native-evidence/`. The test uses
ephemeral identities and no public peers. It complements the browser
applicant and prior-member evidence above; it does not cover retry across
a default-link change.

Independent verification at `4fce7205` passed the native recovery,
the no-loss rooted DHT enrollment, and the browser-applicant regression.
The original Linux applicant called the shared native bootstrap through
a fixture, not a stock CLI enrollment command. Only the initial issuer
used the loss hook. The reopened production issuer returned the committed
signed response with a matching serialization digest; the ledger bytes
stayed unchanged through the stock TUN HTTP round trip. The browser
regression exercised the new and prior members in separate sessions.

The 13 focused Rust tests and the isolated Linux route test also passed
from the cached executable. The isolated test accepted a refreshed dial
hint on the still-current scope but refused it after a default-link change.
That is not a live receipt cutover test. The recorded red baseline was
reviewed, not rerun. Commands, checksums and logs are in `/tmp/p2p-a2-native-integration.UuC4q5/`.

### C2: Incoming Policy And Prune

The independent `checkpoint-transfer.mjs` run at
`dfc29a4e29307e441530f49d10dc539bc714b402` used production Chromium WASM
and a native fixture on isolated WebRTC Direct. The fixture sent two
normal, signed mutations from the current authority on the same connection.
It validated each ACK against the exact request; the browser's send observer
read the matching signed snapshot from storage before passing the ACK to
the original transport method.

| Mutation | Verified result |
| --- | --- |
| Policy, revision 0 to 1 | Disabled route grants without changing the three roster entries. After capability refresh and authenticated sync, overlay HTTP returned 200 at revision 1. |
| Prune, revision 1 to 2 | Used revision 1 as its exact base and removed only the expired member. Both active members remained. After reauthorization, overlay HTTP returned 200 at revision 2. |

This is receipt and application of native-originated mutations, not
browser-originated policy or prune. No public IPFS or malformed live
traffic was used. See `/tmp/p2p-c2-integration/chromium.log` and the
artifact checks in the same directory.

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

### In-Memory Retirement Gate

Two focused tests cover the typed state without opening a transport:

- `replacement_reservation_does_not_inherit_retired_circuit_owner` uses the
  relay client's normal connection-close transition. Even with the same
  confirmed address on the replacement, the old authenticated inner circuit
  loses its exact outer owner. Only the new circuit has the replacement owner.
- `uncommitted_invitation_retirement_drops_approval_without_grant` uses
  `CodePairingSessions` with locally authenticated applicants. Cancelling the
  first operation clears its pending approval. The replacement operation
  cannot resolve the old approval, the old ticket remains rejected, and the
  encoded ledger restores no enrollment or completion for that operation.
  Checkpoint storage and forwarding authority remain unchanged until the
  newly approved applicant commits through `PreparedAdmission`.

Browser wiring was checked separately. Legacy `BrowserCodeInviter` selects
the applicant through `InvitationTransport`, which pins the confirmed outer
owner and checks the authenticated circuit before dispatching requests.
Approval requires that reservation to remain confirmed, and cancellation
clears the review and releases the transport. The live
`BrowserCheckpointInvitation` code path instead stores review on the
circuit under its exact listener and outer connection. Retirement takes
that invitation out of the live VPN; approval checks the current ticket,
circuit owner, and reservation before calling the tested checkpoint
admission code. The shared lifecycle test does not instantiate either
WASM review holder, and the relay test does not exercise the browser
listener check.

These tests do not replace the Chromium clean reissue or relay-side
retirement results above. They do not exercise live stale delivery or
remote locator withdrawal. Exact recovery of an already committed receipt
remains permitted under its separate peer, ticket, authority, and lifetime
checks; see the published receipt recovery evidence above.

Independent verification at `7eac5c3e` passed both retirement tests and
`v2_checkpoint_lost_acceptance_recovers_after_reopen_without_readmission`.
The relay test ran from a standalone cached relay unit binary with matching
vendored source; the checkpoint tests ran in the native
`browser_checkpoint_inviter` harness, not the browser crate's host library
target or a WASM package. Commands, artifact hashes, and logs are recorded
in `/tmp/p2p-invitation-retirement-integration.vS60Z2/manifest.md`.

### Chromium Operator Approval on Replacement

These focused production SDK tests complement the earlier relay-only and
legacy UI cleanup evidence:

| Test filter | Reservation and approval checks |
| --- | --- |
| `^legacy SDK refuses retired` in `native-code-locator.mjs` | The relay closes the confirmed reservation and the reviewed applicant's circuit. The test cancels the original `BrowserCodeInviter` and calls its ordinary `approve` method before freeing it. The replacement is a new SDK owner with the same issuer identity and alias, a distinct companion lease, and a new non-renewed relay reservation. It rejects the old peer selection during fresh review without changing the ledger. Only the newly approved applicant receives a grant and connects; the prior signatures remain. |
| `^checkpoint SDK refuses retired` in `checkpoint-inviter-live.mjs` | The operator cancels a pending code review, then releases the confirmed reservation. After relay-observed retirement, the same `BrowserVpn` reserves the same address again, with a new non-renewal acceptance, and reauthenticates its incumbent. The old local approval is unavailable both after cancellation and during fresh review. The stored revision and roster do not change until fresh approval. Then only the new member is added, the applicant receives activation credentials, and the incumbent applies revision 2. |

The focused runs use Chromium 156.0.8078.73 and the cached production
package verified at `b342c253a8f20cbdd1567a7565ae083a8cc0278d`. The
matching native fixture hashes are in the integrator and checkpoint
cancellation evidence. Run each filter with `node --test` in a fresh
isolated network namespace. Node resolves the shared Playwright directory
through `NODE_PATH` without a workspace symlink.

Both filters passed. Local traces are `/tmp/p2p-retirement-legacy-sdk.log`
and `/tmp/p2p-retirement-checkpoint-sdk.log`.

Independent verification at `231e6db9` passed both production SDK filters.
The legacy case retained the prior signatures and added only the fresh
applicant after a distinct companion lease and a new reservation at the
same alias. The checkpoint case left the stored payload unchanged on stale
approval, then reauthorized the same incumbent on the replacement. Only
the fresh approval advanced the roster to revision 2, which the incumbent
applied.

The adjacent production legacy UI reissue and checkpoint cancellation with
the previously verified hooks also passed. The latter removed only the
committed but undelivered approval on retry and verified an acknowledged
incumbent packet after reopen. This is separate from exact lost-response
recovery, which was not rerun here. The isolated runner, package provenance,
and four logs are under `/tmp/p2p-e1-owner-integration.pdZPXJ/`.

The relay events distinguish different reservations even though the
advertised addresses are unchanged; the SDK does not expose internal
listener or connection IDs. These tests exercise explicit operator
cancellation and local stale approval, not automatic browser detection of
remote lease loss or stale wire dispatch on a replacement. Neither sends
the retired applicant's ticket on the replacement. The checkpoint test
stops at credential delivery and incumbent mutation application, before
the new member's sync and packet forwarding. Exact committed receipt
recovery remains separate evidence.

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
| Cross-family relay | Chromium reached an IPv6-only native member from an IPv4-only underlay and an IPv4-only reservation owner from an IPv6-only underlay. The reverse test checks authorized overlay HTTP, one relay peer, actual outer socket families and zero fixture traffic on the alternate link. Default Chromium mDNS uses an unpeered IPv4 dummy in the reverse fixture, with no IPv4 route to either remote. |
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

## Checkpoint In-App Names

The independent N1 run of `checkpoint-transfer.mjs` at `025a24a4` used
production Chromium WASM. A signed name and stable fallback returned the
exact authorized IPv4 and IPv6 addresses. Both disappeared on authenticated
removal. Readmitting the same Peer ID produced a new incarnation and restored
only the fallback; the old signed name stayed absent. A name outside the
overlay failed locally, was absent from the captured Chromium NetLog, and
no VPN packet reached the native fixture. The adjacent policy/prune test
passed using the same verified artifacts. See `/tmp/p2p-n1-integration/`.

These are in-app address results, not an OS DNS service, on-wire DNS
answers, or successful HTTP selected by a name at both address families.

## Linux Companion Egress

The [default-network contract](../public-discovery-relay-acceptance.md#default-network-contract)
includes resolver traffic and connection reuse for companion-owned automatic
public operations. LAN, explicit relay entrances, and direct member paths
retain their separate policy. Browser-managed sockets are not covered by
the companion's binding guarantee.

The D3 Linux veth fixture measured UDP DNS, bootstrap, Identify, and relay
traffic on the selected default during switch and return, with zero
attributable secondary traffic in the measured phases. A blocked default
bootstrap yielded no candidates and no measured secondary traffic. A
direct member still used the secondary. Lease traffic reused its scoped
UDP socket; retired sockets and ingress stopped forwarding. The fixture
recorded `dnsTcp=0` in that original UDP case. Separate DNS cases now
return a valid truncated UDP answer and resolve the bootstrap name over TCP.
Both DNS counters follow the OS default on switch and return. With resolver
routes only on the secondary, discovery returns no candidates with zero DNS
packets on either link until that link becomes the default, then succeeds.
Earlier Linux and Android evidence in the acceptance document is separate,
not coverage of other companion configurations.

The live mixed-purpose case establishes a native relay reservation over
secondary TCP and keeps it open in the companion's namespace. An automatic
signed member lookup returns `public_dht` and a relay lease for that same
relay ID. The relay sees a fresh TCP Identify connection on the primary from
the companion probe's distinct swarm identity. The original secondary TCP
endpoints remain established, with zero scoped-operation packets on the
secondary; an authorized WebRTC Direct member exchanges a keepalive there.
This tests companion probe isolation, not connection reuse inside the native
runtime's shared swarm.

The separate native Kademlia test
`public_discovery_kademlia_dials_around_an_unscoped_connection_and_cleans_failure`
in [managed public tests](../../../src/runtime/p2p/managed_public/tests.rs)
rejects a public RPC on a preexisting unscoped connection, requires a
separate scoped dial, and checks cleanup on dial failure. An earlier
`browser-final-native-unit.log` records the pass.

Independent verification at `a183cf01dda4c1cf0b0b0ffb4e2651586ad86a34`
passed all six `relay-gateway.mjs` cases and one focused TCP repeat with
the hash-verified native fixtures and hooks WASM. The out-of-list resolver
control counted one UDP and six TCP packets on the secondary in the broad
counters, with zero fixture-address counts. The subsequent companion
lookups retained the broad non-default guard. The secondary-only resolver
case failed closed, succeeded when that link became default, and failed
closed again on return. The mixed-purpose case kept the secondary
reservation connection while a distinct scoped Identify probe used the
primary and authorized direct-member traffic used the secondary.

Both independent runs settled without a `409`. The worker's separate
`/tmp/p2p-d3-followup-final-tcp-30x.log` records 30 passes, including two
`network_changed` responses with zero measured non-default traffic.
The Chromium helper permits at most one qualified retry with the same
request body and abort signal; counters cover both attempts. This resolves
the earlier test return-phase race and restores the original wildcard DNS
observation. See `/tmp/p2p-d3-followup-integration/` for the independent
logs and hashes. This does not qualify other shared-swarm paths or platforms.

## Supported Profiles

The [profile requirements](README.md#conformance) are unchanged. These are
reference results for the listed Browser Peer and Linux companion paths,
not a blanket conformance or independent interoperability claim.

| Profile or feature | Current browser status |
| --- | --- |
| Static stream | Foreground browser WebRTC Direct r2 or a supported Circuit Relay v2 path with the matching native peer; in-app IP only. |
| Companion-assisted discovery | Eligible LAN, regular member rendezvous and scoped relay discovery on cooperating DHTs, circuit fallback and authenticated direct recovery. Public-IPFS rendezvous is not qualified; no unrestricted Discoverable Mesh claim. |
| Managed legacy membership | Signed snapshots, durable revocation and explicit approval with the matching native peer. Detached issuers support file and explicit code invitations; exact, bounded receipt recovery covers existing rooted and durable fresh scoped issuance with a matching user-held issuer config. |
| Managed checkpoint membership | Authenticated sync, native roster updates and durable exclusion; live file and code approval on a confirmed reservation, including independent locator storage on a cooperating DHT. Not general browser-originated roster administration; exact lost-acceptance retry is verified with test hooks. |
| In-app names (optional) | Legacy signed names and fallback, and checkpoint IPv4/IPv6 address results with removal and incarnation changes. No system resolver or named HTTP parity claim. |
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
| [Physical egress](../physical-network-policy.md), [public relay acceptance](../public-discovery-relay-acceptance.md) | D3 measures default-only UDP and TCP DNS, bootstrap, Identify and relay. The secondary-only resolver, scoped lease reuse and retirement, and live same-peer mixed-purpose isolation passed. | D3 scope |
| [Legacy records, convergence and exchange](membership.md#legacy-signed-records) | Canonical signatures, issuer authority at signed time, deterministic merge and durable tombstones. Digest/count/cursor, 8 records per page, 256 total, bounded restart and no partial apply. Eleven records in two pages exchanged both ways; invalid, interrupted and failed-save transactions retain prior authority. Durable revocation and bounded restart passed. | L1 gate passed |
| [Checkpoint objects, authentication and rank](checkpoints.md#canonical-objects) | Pinned anchor, authenticated canonical roster, MAC, deterministic branch selection, incarnation and expiry; rank alone grants nothing. Losing branches do not carry legacy tombstone guarantees. Shared vectors do not qualify independent transcripts. | C1, E1 |
| [Checkpoint transfer](checkpoints.md#snapshot-transfer) | Peer-bound challenge/proof, signed publisher and matching digest/cursor/size; 8 KiB ranges and bounded transfer. Activation gates on authenticated install; encrypted reopen and durable exclusion recorded. Chromium interrupted and freshly synced; the Rust driver rejects a late final page. | C1 residual |
| [Checkpoint mutations and enrollment](checkpoints.md#mutations-and-enrollment) | Exact base, authorized issuer, real revision, save before ACK, correlated result and bounded control-only reply. Native upsert, other removal, self-exclusion, policy change and prune recorded. No standalone legacy migration or silent replacement of pinned authority. | C2 scope |
| [Names and DNS](membership.md#names-and-dns) | Legacy signed rename, conflict and fallback passed. Checkpoint in-app lookup returns both address families and rejects the old name after readmission with a new incarnation. The tested unknown name did not reach Chromium networking. | Optional; named HTTP and system DNS limits |
| [Enrollment versions, codes and discovery](enrollment.md#versions) | Explicit scoped v1; bounded, LAN-first v2 discovery. Fresh/rooted legacy and live checkpoint publication use independently routed storage on a cooperating DHT. A locator is not authority, including after the four tested retirements. | Relay-side loss |
| [Enrollment messages and cryptographic binding](enrollment.md#code-messages) | Bounded versioned frames; signed peer/key/locator/time, SPAKE2, AAD and confirmation, peer-bound ticket and signed grant. Matching v1/v2 and signed-file cases passed. | E1 |
| [Commit and activation](enrollment.md#commit-and-activation) | Save approval before releasing a grant, keep unrelated admissions, establish the checkpoint floor and sync before data. Rooted legacy save failure/denial and checkpoint code approval passed. The original browser and Linux native applicants recovered the exact saved legacy response after reopen in their respective fixtures. Separate hooks coverage verifies the exact checkpoint response. | Broader checkpoint cancellation/recovery |
| [Owned datagrams](datagrams.md) | Negotiation, signed handshake, keys, replay and binding are native profile clauses, not browser claims. Companion UDP ingress does not implement browser datagrams; absent support selects streams without bypassing denial. | Not applicable |
| [Demand lifecycle](../demand-lifecycle-wire.md) | Current authority, fresh epochs, bounded scope/revision and reply correlation, response-sent gate and legacy fallback. Real Idle/Wake on a foreground polled incoming circuit; hidden/outgoing fixtures stay legacy. No background, direct or battery guarantee. | Conditional |

## Remaining Acceptance Checks

The dispositions below do not narrow the declared reference target.
An evidence gap is not by itself a production defect. Further checks should
use legitimate operations on isolated fixtures or in-memory driver tests,
not crafted live traffic or public infrastructure.

| Scope | Remaining acceptance |
| --- | --- |
| **S1: static stream bounds** | Supported by shared reader source and in-memory prefix/header checks, plus separate live capability, IPv4/IPv6 and negotiated MTU gates. No heap or live withheld-body timing result. Cover any newly declared framing path with its own bound and admission tests; do not substitute a live malformed-input trial. |
| **D1/D4: LAN and reservation lifecycle** | LAN-first recovery, VPN-owned exclusion and stale LAN hint handling passed; cellular binding exclusion has Linux metadata evidence, not physical cellular traffic. Shared-reservation close and survivor passed. For a physical cellular/default claim, exercise actual link selection and capture mDNS exclusion while eligible LAN still works. |
| **D3: companion public egress** | The isolated Linux DNS, bootstrap, Identify, relay, cutover, failure and live mixed-purpose cases passed. Qualify other resolver and transport configurations and platforms separately. |
| **Cross-family relay** | Reverse IPv6-underlay evidence uses a host-only IPv4 dummy for Chromium mDNS, not an IPv4 underlay. Pure stock Chromium remains open: without any non-loopback IPv4 address it still fails ICE gathering under default mDNS in this fixture. See [relay gateway validation](../browser-relay-gateway-validation.md#ipv6-caller-and-ipv4-reservation-owner) for the independent runs and the multicast bind trace. |
| **D2: regular rendezvous** | Provider-only lookup, bounded fallback/exhaustion and automatic foreground recovery passed on cooperating DHTs. A cached signed member hint remained readable and its listener stayed open after membership expiry, but the browser rejected the attempt before lookup or dial. Fresh authority and a newer signed hint admitted only the replacement path for HTTP. Signed alias renewal and reader expiry are separate coverage; remote withdrawal and public rendezvous are not tested. |
| **Relay-side invitation retirement** | Cached-hint cases, server retirement with no grant, and legacy UI cleanup/reissue are separate from the in-memory owner checks and the Chromium stale operator approval gates. The SDK gates cover explicit cancellation and fresh approval on a confirmed replacement, not live stale wire dispatch or remote hint removal. Committed receipt recovery remains separate. |
| **L1/A2: managed legacy** | Signed snapshot transaction, revocation, exact committed Poll and post-reopen traffic passed for the documented durable profiles. Rooted Linux native v2 recovery verified the exact signed response and unchanged ledger before and after stock TUN traffic. The earlier browser-applicant proof exercised prior and new members in separate sessions. Fresh scoped recovery needs the retained config and same origin/profile; pinned in-memory creation does not recover after reload. |
| **C1: managed checkpoint transfer** | Interruption, bounded retirement, fresh install and authenticated durable exclusion without forwarding passed. The in-memory host driver checks the declared bounds, retirement on Busy or deadline, terminal notification after retirement, and retry under a fresh challenge. The retained authority and enrollment floor survive partial input and stay unchanged until authenticated install commits. Late final-page rejection remains driver-only; no equivalent live result is claimed. |
| **Checkpoint enrollment recovery** | Pending app resume is covered only with the retained encrypted file and passphrase in the same-origin/profile fixture. Live cancellation, unrelated-member preservation and lost-response retry are separate passes. If administrative cancellation after restart is required, define and verify durable receipt/admission semantics in a store-backed test; retiring an armed SDK invitation can return success without removing either. |
| **C2 and optional extensions** | Receiving native mutations, including policy and prune, is evidenced. Do not advertise general browser-originated policy/prune/departure without exercising each signed operation, durable result and reauthorization. For service status and Demand, retain the documented scoped status and maintained foreground incoming circuit gates; other transports, hidden/background wake and system DNS are not implied. |
| **N1: optional in-app names** | Legacy name authority and checkpoint incarnation transitions with both address families are evidenced. To qualify named HTTP at both families, exercise normal requests to named IPv4-only and IPv6-only authorized endpoints. No host DNS, PTR or public resolver parity claim. |
| **Broader claims only** | One-shot locator publication does not establish remote TTL/withdrawal. Independent interoperability needs independent signed transcripts and live traffic; public IPFS, profile-free native CLI, browser host egress, browser datagrams and Full Client would require separate declarations and qualification. None is established here. |

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
`activation.log`, and the contemporaneous artifact checks. That manifest
names a mutable receiver build path whose current binary no longer matches
the recorded hash. The logs stand as historical evidence; the path does
not reproduce the original receiver today.

Independent verification at `6aa05e59` passed both new in-memory driver
tests and all 14 cases in the portable host integration target. The new
tests check declared limits, release of partial assembly on Busy or
deadline, and a fresh challenge at cursor zero after the old request
finishes. The test cancels publisher-side state explicitly. These are
typed driver checks, not a live Busy, late-page, or memory-usage result.

The live interruption/fresh-sync and SDK restore/exclusion cases also
passed at that test revision with an immutable, hash-verified N1 receiver.
The interruption used archived hooks; the SDK case used production WASM
from `b342c253`, which includes the pending export API checked by the
current test. It restored the revision 1 floor and persisted the
authenticated revision 2 exclusion with no VPN packets reaching native.
Commands, artifact hashes, the older package mismatch, and passing logs
are under `/tmp/p2p-c1-driver-integration.6P8DRY/`.

The SDK test supplies the same owner-provisioned identity, checkpoint
bootstrap and capability on each open. Separately, `host-app.mjs` uses a
stock native issuer and the served UI to save the browser-generated identity
in an encrypted bundle at pending floor revision 1, before a member dial.
The app imports the file and passphrase after Chromium relaunches the same profile.
The HTTP request control only enables after authenticated revision 1 installs,
then an overlay-only HTTP request reaches the native namespace. With an
ordinary native removal before import, revision 2 persists as exclusion and
the request control never enables. Neither resume path uploads credentials.
Continuing without a backup and downloading active credentials remain separate
flows; the pending and active bundles share the same import and sync gates.

Independent verification at `b342c253a8f20cbdd1567a7565ae083a8cc0278d`
used the byte-verified production package and the stock native WebRTC binary:

| Gate | Verified result |
| --- | --- |
| Retained pending bundle | Chromium closed and relaunched the same profile on the same origin. Importing the user's encrypted file and passphrase installed revision 1 by authenticated sync before enabling the overlay-only HTTP request (`resume.log`). |
| Exclusion on resume | After ordinary native removal, the imported identity durably installed revision 2 exclusion without enabling sending or credential export (`exclusion.log`). |
| Adjacent flows | Continue without saving and post-authorization encrypted reopen passed, as did legacy LAN code enrollment and served browser-to-browser checkpoint approval by code and signed file (`no-save.log`, `legacy.log`, `code-file.log`). |

Pending export is enabled in memory only for an activation from verified
approval. It reloads and checks the authenticated stored floor and retained
state, then seals locally in the existing version 1 credential format.
Neither the file contents nor passphrase go to the companion, and no
plaintext credentials are written to Web Storage. The backup is optional;
restart requires retaining both the encrypted file and the passphrase.
These are same-origin, same-device fixture results, not cross-device or
public-IPFS qualification. Independent logs, checksums, and the 360px
pending-state capture are in `/tmp/p2p-pending-recovery-integration/`.

The Linux test uses the production profile-free v2 library entry point and
the stock daemon; it does not use `p2p-vpn pair join`, which targets a running
daemon's network-scoped v1 pairing operation.
