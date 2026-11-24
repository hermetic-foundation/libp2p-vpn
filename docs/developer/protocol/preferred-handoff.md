# Preferred-Interface Handoff

Status: optional extension on `browser-wasm`. Existing control, packet, and
Circuit Relay v2 formats are unchanged. See
[verification evidence](../preferred-handoff-verification.md) for platform limits.

## Ownership

| Responsibility | Owner |
| --- | --- |
| Choose the preferred physical network | Local OS, not the remote member. |
| Start a handoff after that selection changes | The peer whose physical route changed. |
| Dial a replacement | The route owner when possible; otherwise its authenticated member, upon request. |
| Prove the receiving physical interface | The changed peer, using actual connection ownership. |
| Retire the old member circuit | The dialer, after payload proof and commit acknowledgement. |

Do not wait for the healthy fallback to fail. Advance active work from route
audit, connection, Identify, and reservation-completion events. Deadlines bound
settling and failure recovery; they are not periodic idle probes.

## Wire Format

Protocol: `/p2p-vpn/handoff/1`, over an authenticated libp2p stream to a member.
Each direction sends one u32 big-endian length followed by UTF-8 JSON and EOF.
The length MUST be 1-2048 bytes. Reject trailing bytes and unknown fields.

Request:

```json
{
  "scope": {"network_name": "example", "membership_tag": null},
  "token": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
  "command": "offer"
}
```

| Field | Contract |
| --- | --- |
| `scope` | Current network name and membership tag. Omitted tag means null. Existing previous-tag admission rules apply. |
| `token` | Fresh unpredictable nonzero 16-byte transaction nonce. Never log it. |
| `command` | `offer`, `verify`, or `commit`. |

Response: `{"token": [...], "outcome": "ready"}`. Outcomes are `ready`,
`verified`, `committed`, and `rejected`. Match token, request ID, peer,
and exact transport connection before acting on a reply.

No message supplies new membership authority, remote interface names, or dial
addresses. Reuse the already authenticated peer and approved relay route.

## Transaction

1. The changed peer establishes and confirms a reservation on its preferred
   physical route, retaining the working old member circuit.
2. It sends `offer` on that old circuit. Its local ticket binds the member,
   old circuit, new physical owner, route epoch, token, and expiry.
3. The member replies `ready`, opens a second circuit, and authenticates it
   with the existing capability and membership checks.
4. The member sends `verify` on the candidate. The changed peer replies
   `verified` only if that exact circuit uses the ticket's new relay owner
   and the route epoch is still current.
5. Application IP packets may use the authorized candidate. The old circuit
   remains usable; capability exchange or a synthetic path probe is not proof.
6. After an authorized IP packet passes replay/routing checks and is written
   to TUN on the candidate, the changed peer records payload proof.
7. After receiving that packet's acceptance, the dialer sends `commit` on
   the candidate. The changed peer rechecks current authority and ownership.
8. A matching `committed` response lets the dialer promote the candidate,
   drain pending old work, and close the old member circuit.

Closing a member circuit releases its physical relay dependency. Do not close
the old outer connection while unrelated circuits or control work require it.

## Bounds And Failure

| Reference bound | Value |
| --- | --- |
| Single request timeout | 8 seconds |
| Changed-peer ticket lifetime | 25 seconds |
| Browser candidate attempt | 12 seconds |
| Changed-peer outstanding tickets | At most 64, one per member |
| Browser replacement candidates | One per selected member |
| Recent browser offer tokens | At most 16 |

- Reject wrong scope, unauthorized members, stale epochs, wrong tokens,
  wrong connection owners, and commit without payload proof.
- A rejected, expired, cancelled, or unsupported attempt MUST NOT retire
  a still-usable fallback. Ordinary loss recovery remains available.
- Offers MUST NOT advance the host adapter's discovery generation.
- A lost commit response leaves the dialer's fallback intact. This extension
  does not require successful handoff after a lost response.
- Native peers without this extension retain their existing native handoff.
  Legacy browser peers continue on their existing circuit.

## Relay Requirement

The receiving relay chooses which live reservation accepts a new circuit.
The reference server prefers the most recently confirmed reservation without
moving established circuits. Closing that owner falls back to a surviving one.

Other relays may choose differently. A dial is not evidence of migration:
the changed peer MUST check its actual physical owner. Rejection preserves the
fallback rather than claiming a preferred-interface switch.

## Acceptance

With a healthy old underlay and a relay lifetime longer than the test:

1. Change the OS default and confirm the preferred route is usable.
2. Verify a fresh HTTP nonce traverses the new native interface within 30 seconds.
3. Correlate the payload with exact inner circuit, outer socket, source,
   interface index, and route generation.
4. Require payload proof before commit or old-circuit retirement.
5. Keep both underlays healthy for at least 31 seconds. Do not reset the
   browser, rediscover manually, or force the old circuit to expire.
