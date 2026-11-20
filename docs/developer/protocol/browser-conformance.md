# Browser Conformance Audit

Baseline: published `browser-wasm` at `031afdc879dce58652cf18018d790d7427de16a1`.
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
| Wire, 17 | `publication-wire-0f5.log`, parent `0f5d7cf5`: incoming circuit and shared reservation, foreground Demand, app authorization and survivor, network-change recovery, reliable IP and status, relay-only and fallback, alternate and preferred direct, no fallback after denial and typed wrong network, legacy sync and durable revocation, reauthentication, and circuit substreams. |
| Enrollment, 27 | `publication-enrollment-0f5.log`, parent `0f5d7cf5`: 14 joiner cases (direct, relay, v1/v2, file, LAN fallback, bounded retry and lease handoff), two detached file issuer cases, six explicit legacy code issuer cases, one undialed checkpoint admission gate, and four live checkpoint issuer cases. |
| Affected relay, 18 | `publication-relay-031.log`, tip: gateway fallback and cross-family relay (2), browser-to-browser IP, opt-in publication, default-link selection, automatic authenticated relay, scoped alias publication (5), native v2/TUN, rooted approval and denial, different-seed join (4), provider-free referral (1), unpinned approval/cancel/cancel-after-save/expiry/saturation (5), and pairing lease handoff (1). |
| Live checkpoint, 4 | `publication-checkpoint-live-031.log`, tip: native joiner on the issuer's reservation, served signed-file approval, served code approval and sync with a native joiner, and served browser-to-browser code enrollment. Not lost-response or issuer-reopen evidence. |

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
| Shared incoming circuit reservation (SDK) | Chromium handled two authorized legacy members with distinct MTUs. A local close left the other circuit usable. Prompt detection of remote graceful close was not verified. |
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
| Native v2 code-only join | The published baseline discovered the browser through a referral to the reservation relay. In the separate propagation worktree, Chromium published and read back its confirmed circuit on a different storage peer; a native v2 joiner discovered it from an independent seed and passed HTTP through the original reservation. Rerun the isolated pairing and route-revocation cases on this integration stack. |
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
| Companion-assisted discovery | Eligible LAN, controlled DHT locator and relay discovery, circuit fallback and authenticated direct recovery. This is not full discoverable-mesh qualification: regular member rendezvous and public reachability are not established. |
| Managed legacy membership | Signed snapshots, durable revocation and explicit approval with the matching native peer. Detached issuers support file and explicit code invitations; scoped issuance to an unknown native applicant is verified on a controlled circuit. |
| Managed checkpoint membership | Authenticated sync, native roster updates and durable exclusion; live file and code approval on a confirmed reservation. Not general browser-originated roster administration or durable retry qualification. |
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
| [Session setup, encodings and control](stream.md#session-setup) | r2 preserves ICE credentials. Bilateral capabilities constrain version, protocol, header, path, support booleans and nonzero MTU; capped u16 UTF-8 JSON and write half-close. Typed WrongNetwork and shared vectors cover only part of this boundary. | S1 |
| [Packet stream and response](stream.md#packet-stream) | v1 17-byte frame, zero sent flags, bound before payload read, typed response and negotiated MTU. Current source and local destination, no transit. Recorded IPv4/IPv6, MTU boundary, repeated IP accepted and keepalive replay denied. | S1 |
| [Service status](stream.md#service-status) | Optional scoped, authorized 4 KiB framed diagnostics. Nonce, selected MTU and wrong-scope denial recorded. | S1 if retained |
| [Identity, addresses and scope](membership.md#identity-and-addresses) | Binary peer ID derivation, both host routes, explicit grants, null versus keyed scope and configured rotation. Alternate mismatched peer and unauthorized routes rejected; shared derivation vectors are not collision/rotation tests. | S1 |
| [Discovery is not admission](discovery.md#discovery-is-not-admission) | Configured, mDNS, Identify and DHT hints require eligible provenance and peer authentication. Separate-veth LAN-first pairing recorded. VPN-owned and cellular links are excluded from eligible LAN work. | D1 |
| [Kademlia and keys](discovery.md#kademlia) | Private protocol or public IPFS namespace; global v2 locator independent of overlay DHT, domain-separated keys and provider-only long-key transform. Controlled reservation lookup and shared derivations do not show regular rendezvous or public IPFS. | A1, D2 |
| [Signed records and scheduling](discovery.md#signed-address-record) | Signed peer/key, scope, target and expiry; 64 KiB and 32-address bounds. Stale data is a hint, not authority; public-only work excludes private/unresolved endpoints. Explicit opt-in signed publication and separate-companion lookup passed on a cooperating DHT. | D2 |
| [Relay and direct recovery](discovery.md#relay-and-direct-recovery), [path policy](../shared-path-policy.md) | Real reservations and end-to-end control/IP. Exact-path validation before promotion; failed or superseded return leaves the circuit intact. Native-initiated and browser-to-browser traffic and survivor behavior recorded. | D1, D4 |
| [Physical egress](../physical-network-policy.md), [public relay acceptance](../public-discovery-relay-acceptance.md) | Companion-owned automatic infrastructure follows the OS default, not a secondary on failure. LAN, direct peers and explicit relay have separate eligibility. Scoped leases, generation revocation and cross-family HOP with no alternate fixture traffic passed. | D3 |
| [Legacy records, convergence and exchange](membership.md#legacy-signed-records) | Canonical signatures, issuer authority at signed time, deterministic merge and durable tombstones. Digest/count/cursor, 8 records per page, 256 total, bounded restart and no partial apply. Eleven records in two pages exchanged both ways; original config cannot regain revoked authority. | L1 |
| [Checkpoint objects, authentication and rank](checkpoints.md#canonical-objects) | Pinned anchor, authenticated canonical roster, MAC, deterministic branch selection, incarnation and expiry; rank alone grants nothing. Losing branches do not carry legacy tombstone guarantees. Shared vectors do not qualify independent transcripts. | C1, E1 |
| [Checkpoint transfer](checkpoints.md#snapshot-transfer) | Peer-bound challenge/proof, signed publisher and matching digest/cursor/size; 8 KiB ranges and bounded transfer. Activation gates on authenticated install; encrypted reopen and durable exclusion recorded. Excluded peers must not forward. | C1 |
| [Checkpoint mutations and enrollment](checkpoints.md#mutations-and-enrollment) | Exact base, authorized issuer, real revision, save before ACK, correlated result and bounded control-only reply. Native upsert, other removal and self-exclusion recorded. No standalone legacy migration or silent replacement of pinned authority. | C2, A3 |
| [Names and DNS](membership.md#names-and-dns) | In-app names depend on current authority, signed rename/incarnation, conflict handling and deterministic fallback, never public DNS fallback. Authorized IPv4 name fetch and separate IPv6 fetch do not establish A/AAAA parity. | N1 |
| [Enrollment versions, codes and discovery](enrollment.md#versions) | Explicit scoped v1; bounded, LAN-first v2 discovery. Controlled same- and different-seed exact-alias cases passed. At the tip the legacy inviter makes one announcement attempt per invitation; the locator is not authority. | A1, A2 |
| [Enrollment messages and cryptographic binding](enrollment.md#code-messages) | Bounded versioned frames; signed peer/key/locator/time, SPAKE2, AAD and confirmation, peer-bound ticket and signed grant. Matching v1/v2 and signed-file cases passed. | E1 |
| [Commit and activation](enrollment.md#commit-and-activation) | Save approval before releasing a grant, keep unrelated admissions, establish the checkpoint floor and sync before data. Rooted legacy save failure/denial and checkpoint code happy paths passed; neither proves exact retry after reopen. | A2, A3 |
| [Owned datagrams](datagrams.md) | Negotiation, signed handshake, keys, replay and binding are native profile clauses, not browser claims. Companion UDP ingress does not implement browser datagrams; absent support selects streams without bypassing denial. | Not applicable |
| [Demand lifecycle](../demand-lifecycle-wire.md) | Current authority, fresh epochs, bounded scope/revision and reply correlation, response-sent gate and legacy fallback. Real Idle/Wake on a foreground polled incoming circuit; hidden/outgoing fixtures stay legacy. No background, direct or battery guarantee. | Conditional |

## Remaining Acceptance Checks

Unmerged work and local-only results do not qualify the published baseline.
The following checks state what evidence still needs to be on the integration
target, without requiring reruns of the narrower published passes.

| Work | Pending evidence |
| --- | --- |
| A1: Locator distribution | Independent storage, exact-alias readback, and default-link stream revocation passed in the separate propagation worktree. Rerun on the integrated build. Bounded refresh, withdrawal and remote provider expiry have not been qualified; stopping the local publisher does not remove a cached remote record. Verify that stale hints cannot grant authority after cancellation, expiry, reservation loss or a link change. Real public IPFS acceptance, retention and unrelated-seed visibility remain unverified. |
| A2: Rooted legacy reissue | The tip admits one unknown applicant without address injection, preserves prior signatures, withholds grants on save failure and leaves the roster intact on denial. Reissue on another relay after a busy reservation passed locally (`legacy-scoped-reissue.log`); recovery commit `9c6233a2` is unmerged. Still require evidence that the reopened saved ledger authorizes both prior and new members' traffic. |
| A3: Checkpoint exact retry | The tip proves live code approval and sync, not lost-acceptance recovery. Require exact grant/floor after issuer reopen, no second mutation, unrelated admissions preserved on cancellation, and no joiner data before matching authenticated sync. Recovery and reopen commits `6db9d6a1` and `5eddbc0e` are unmerged. |
| S1: Stream bounds | Browser negative evidence for malformed/oversize control and packet frames, incompatible capabilities, route collisions and ungranted routes, rotation and probe replay; no admission, unbounded buffering or deny-driven fallback. Include service negatives if declaring status support. |
| D1: LAN-first recovery | With eligible LAN and an old circuit hint, authenticated LAN wins; only bounded relay retry when LAN is unavailable. No stale promotion or mDNS on excluded links. |
| D2: Regular mesh rendezvous | Discover an authorized member without a configured endpoint using regular provider/address keys, not a pairing locator. Check current aliases, renewal/withdrawal/expiry, bounded retry and revoked cached-hint denial. |
| D3: Companion physical egress | Attribute DNS, bootstrap/DHT, connection reuse and relay traffic to companion-owned sockets on both links across default switch and return. Retire old leases, resume only eligible work and keep eligible secondary direct-member traffic. |
| D4: Shared circuit close | Promptly clear the graceful-closed SDK member's authority while its sibling continues on the same reservation. Local close and app-selected loss are already recorded. |
| L1: Legacy transaction | Interrupted, changed or invalid pages and conflicting/expired history leave prior authority intact. Prove bounded restart, atomic save failure and durable learned removal as part of the transaction. |
| C1: Checkpoint transfer | Browser multi-page transfer with invalid, stale, cancelled and partial offers: no install, bounded resources retire and excluded requesters can learn exclusion without forwarding. |
| C2: Live mutation | Verify policy/prune, stale base and failed save, and the excluded peer's correlated final reply without readmission. Qualify browser-originated general mutation or departure only if declared. |
| N1: In-app name authority | Signed rename, stable conflict fallback, stale incarnation and revocation suppression, no public resolver fallback and explicit IPv4/IPv6 selection. |
| E1: Independent compatibility | Independently produced signed legacy/checkpoint and SPAKE2/enrollment transcripts and live stream interoperability with a separate implementation. Required only for that additional claim. |

Unmerged work also exists for the stream negatives, LAN recovery, regular
mesh rendezvous, companion route changes, shared-circuit close, legacy
transactions, cancelled checkpoint transfers, live mutations, and in-app
name authority. The open rows describe the acceptance criteria, not a claim
that every criterion has passed in those worktrees.

The Linux test uses the production profile-free v2 library entry point and
the stock daemon; it does not use `p2p-vpn pair join`, which targets a running
daemon's network-scoped v1 pairing operation.
