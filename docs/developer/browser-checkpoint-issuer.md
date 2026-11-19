# Browser checkpoint issuer integration

The detached file-bearer issuer in `checkpoint_inviter.rs` admits a fresh,
grant-free member. It does not configure a listener or export a production
browser API. A response grants the capability and a minimum snapshot rank;
it does not activate forwarding.

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
4. Refresh the local descriptor and queue the signed mutation for the
   pre-admission roster using the current bounded handoff. Release the
   explicitly exported response only when the reserved endpoint can serve the
   admitted joiner. Never store the raw response or capability in site storage.

## First live acceptance

`BrowserVpn` currently disconnects identities other than its pinned peer.
`claim_incoming_circuit` additionally requires that pinned identity and an
unoccupied reservation slot. The listener milestone must admit the exact
committed joiner identity on a connection owned by the current reservation,
without treating unknown peers or another circuit as equivalent. Until
activation, that path only needs scoped capabilities and checkpoint transfer;
opening it must not bypass existing packet admission or disturb the incumbent
member path. Use the authenticated, challenge-bound snapshot transfer and
normal activation gate, not the response's advertised rank alone.

Once the listener and owner APIs land, run the end-to-end case through a real
relay: start with a participating issuer, reserve and sign its confirmed
locator, approve a fresh joiner under the held lock, and hand off the signed
response. The joiner must start gated, authenticate the issuer on the reserved
circuit, and install a fetched snapshot at or above the signed floor before
packet authorization. Assert that the store clears the pending floor only after
install and that a substituted peer or circuit does not activate. Do not use a
native publisher holding a copy of the browser issuer's key as the live proof.

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

The existing `browser_checkpoint_inviter` native test exercises the issued
grant with the shared snapshot transfer in process. It does not cover
Chromium transport or replace the real-relay acceptance above.
