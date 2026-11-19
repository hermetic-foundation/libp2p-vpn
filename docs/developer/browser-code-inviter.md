# Browser code inviter

The relay-enabled browser SDK can be the v2 SPAKE2 inviter for a new,
single-peer legacy network. This does not grant an existing member authority
to enroll peers in an existing network.

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
5. After delivery, call `into_vpn()` to consume the invitation and retain
   the inviter key inside WASM. Call `reserve_relay()` on the returned VPN
   to establish its own reservation before accepting the enrolled joiner.
   There is no immediate reservation handoff: a relay with one reservation
   slot can refuse the new swarm until it has retired the pairing reservation.
   Uninterrupted activation needs a shared swarm or confirmed reservation
   retirement and bounded retry.

The pairing swarm accepts only the pinned joiner's authenticated circuit
on the browser-owned reservation. It runs the existing v2 codec and
responder and serves no VPN protocols. A validated Submit can obtain a
pending ticket, not enrollment. The signed legacy response is accessible
only to the pinned joiner after approval. To abandon the invitation, free
the inviter and its reservation.

This API does not publish locators, support v1 responder mode, or issue
checkpoint grants. Native code-only joining requires a discovery source
or an explicit route input; neither is added here.

The isolated `code-inviter.mjs` test checks approved enrollment with
Chromium, the existing v2 joiner, and an actual Circuit Relay v2
reservation. It does not qualify the post-enrollment data reservation.
