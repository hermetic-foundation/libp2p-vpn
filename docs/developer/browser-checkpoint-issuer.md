# Browser checkpoint issuer integration

The file-bearer issuer admits a fresh, grant-free member.
`BrowserVpn.checkpoint_invitation()` binds an opaque invitation to the
confirmed reservation and installed checkpoint. Its `offer_json()` is
public; `approve_checkpoint_invitation(invitation, request_json)` consumes
the invitation and returns the sensitive response file. The response grants
the capability and a minimum snapshot rank; it does not activate forwarding.

## Boundary for the live owner

1. Use the live checkpoint owner, its existing `CheckpointStore`, and its
   actual forwarding projection. Reject issuance while startup resync, a live
   refresh, another local edit or handoff, or store reconciliation is pending.
   Capture the exact `CheckpointBoundary` when the operator reviews the signed
   file request. Use an offer config advertising the owner's confirmed relay
   reservation; an expired or replaced reservation invalidates that offer.
2. Supply `FileApproval { expected, offer: &PairingOffer, request: &PairingRequest,
   wall_now }` to `PreparedAdmission::prepare(&Config,
   &mut CooperativeMembershipState, &mut Forwarder, capability_secret, approval)`.
   The driver must lend its installed state exclusively. A detached copy or
   restored bootstrap is not issuing authority.
3. With the owner still exclusively borrowed, call
   `commit_with_store(&mut forwarding_blocked, &CheckpointStore)`. It checks
   the authenticated retained base and that no enrollment floor is pending,
   saves the exact successor, and installs its forwarding projection and core
   state before returning `IssuedEnrollment { response, mutation }`. It leaves
   packets gated. Use only the store the owner already holds for that network
   and identity. Do not acquire a second lock or introduce another storage key.
   On an uncertain write, reload and resync without restoring old grants. A
   crash after the durable write but before response release is not a reusable
   approval: the first implementation has no artifact recovery journal.
4. The browser issuer queues one bounded mutation attempt on its exact
   incumbent connection and refreshes that connection's capabilities.
   It adds only the committed joiner to the confirmed reservation before
   returning the response. Never store the raw response or capability in
   site storage. There is no durable handoff outbox.

## First live acceptance

The additional checkpoint slot is limited to the approved peer, the
reservation's owning relay connection, and the committed checkpoint boundary.
A capability claim, even one matching that boundary, does not grant packets
until the browser has sent the final page of an authenticated transfer on that
same inner connection. Packet authority then requires the exact capability
exchange and the normal forwarding checks. Closing the connection clears the
transfer proof. A change to the installed checkpoint boundary withdraws this
initial issuance slot; the incumbent's sync path remains separate.

`tests/checkpoint-inviter-live.mjs` runs a Chromium issuer and two native
members through a real relay in an isolated network namespace. It checks
durable admission before artifact release, delivery of the signed mutation to
the incumbent, denial of packets before transfer despite a matching capability
claim, and a native joiner fetching and authenticating the exact issued rank
before Chromium accepts an IP packet. No native publisher holds the browser
issuer's key. Build the native `checkpoint_inviter_native` example and
`browser-relay-fixture` with `p2p-vpn-browser`; pass their paths in
`P2P_VPN_CHECKPOINT_INVITER_NATIVE` and `P2P_VPN_RELAY_FIXTURE`. Set
`P2P_VPN_PAIRING_PKG` to the production WASM bundle and
`P2P_VPN_TEST_NETNS="$(readlink /proc/self/ns/net)"` in the parent shell before
running the test under the isolated Linux gate's `unshare` flags.

The production browser joiner already imports this response through
`BrowserOfflineEnrollment` and `BrowserCheckpointActivation`. For a native
joiner fixture, use `CheckpointRuntime::stage_pairing_enrollment` with its real
protected `MembershipStateStore`, then drive native checkpoint sync over the
same circuit. The native file `pair accept --response` path currently invokes
the legacy config importer, which rejects checkpoint grants; that CLI path
is not the native checkpoint activation entry point.

## Chromium proof available now

`tests/checkpoint-inviter.mjs` loads a test-only issuer and the production browser
joiner in Chromium. It exercises the real Web Lock across tabs, the authenticated
issuer commit, and the existing encrypted credential bundle primitives. The
production importer persists the returned grant's exact pending floor at
provisional revision zero and refuses a credential export. The test never dials
and asserts zero connections, no forwarding authority, and a resync-required
descriptor. It is not a snapshot delivery test.

Use an existing production WASM package for `P2P_VPN_PAIRING_PKG`. Build the
fixture in the existing WASM target directory, with the locked wasm-bindgen CLI:

```sh
cargo build --locked -p p2p-vpn-browser --target wasm32-unknown-unknown \
  --features test-hooks --example checkpoint_inviter_fixture
fixture_pkg=$(mktemp -d)
wasm-bindgen --target web --out-dir "$fixture_pkg" --remove-name-section \
  "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/debug/examples/checkpoint_inviter_fixture.wasm"
P2P_VPN_CHECKPOINT_INVITER_PKG="$fixture_pkg" \
  P2P_VPN_PAIRING_PKG=crates/p2p-vpn-browser/web/pkg \
  node --test crates/p2p-vpn-browser/tests/checkpoint-inviter.mjs
```

The `browser_checkpoint_inviter` native unit test also exercises the issued
grant with the shared snapshot transfer in process. It complements the
real-relay acceptance test above.
