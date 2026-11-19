# Cooperative Checkpoints

Checkpoint membership selects a complete authenticated current roster.
It is a separate authority model from the legacy event ledger. Follow the
[consistency rules](../membership-checkpoints.md#consistency-contract).

## Canonical Objects

All objects below list fields in signing order. Use the compact JSON and
encoding rules in [Stream Wire](stream.md). Reject unknown fields.
Digest, MAC, nonce, incarnation and network-ID fields are JSON byte arrays.

| Object | Ordered fields and constraints |
| --- | --- |
| Anchor | `version`, `network_id` (32 nonzero bytes as a whole), `policy_version`, `rank_version`. All versions are 1. |
| Boundary | `authority_revision`, `digest` (32 bytes). |
| Policy | `max_active_members` (1-256), `route_grants_enabled` (boolean). |
| Subject or publisher | `peer_id` (canonical libp2p Peer ID text), `public_key` (canonical standard-base64 libp2p protobuf). The key must derive the ID. |
| Member | `subject`, `incarnation` (nonzero 32-byte value), `roles`, `route_grants`, `expires_at_unix_seconds` (integer or null). |
| Snapshot payload | `version` (2), `anchor`, `authority_revision`, `parent_digest` (null only at revision 0), `policy`, `members`. |
| Authenticated snapshot | `payload`, `mac` (32 bytes). |

Sort members by ascending canonical Peer ID text and reject duplicates. Limit
each member to 32 canonical route grants, strictly ordered by prefix text and
then metric. Roles are `["overlay_member"]` with optional `"route_authority"`
as the second role. A nonempty route grant requires that role.

Limit a snapshot payload to 2 MiB, with at most 256 members subject to the
policy limit. Treat admission expiration as inactive while enforcing access.
Disconnection does not expire a member.

## Authentication And Rank

Define `message(domain, object)` as the domain text including its terminal
newline followed by the compact JSON object. The capability is a separately
conveyed secret of 32-4,096 bytes, never a public network name or tag.

| Value | Computation |
| --- | --- |
| Anchor salt | SHA-256 of `message("p2p-vpn checkpoint anchor v1\n", anchor)`. |
| Snapshot key | HKDF-SHA256 with anchor salt, capability IKM and info `p2p-vpn checkpoint MAC key v1\n`; 32 bytes. |
| Snapshot MAC | HMAC-SHA256 under the snapshot key of `message("p2p-vpn cooperative checkpoint v2\n", payload)`. |
| Boundary digest | SHA-256 over the same snapshot message, not over the envelope or MAC. |

The advertised rank tuple is `(authority_revision, roster count, digest)`,
compared lexicographically. Count roster entries, not connected peers.
The JSON rank fields are `authority_revision`, `active_member_count`,
`digest`. A rank is a lookup hint until authenticated.

## Snapshot Transfer

`/p2p-vpn/checkpoint-sync/1` uses u16-prefixed JSON v1 with a 12 KiB body
limit. The request is a bare object; responses are externally tagged
`Page` or `Rejected`.

| Object | Ordered fields |
| --- | --- |
| Challenge | `anchor`, `nonce` (nonzero 32-byte value). |
| Request | `version`, `challenge`, `offer_digest` (null on initial fetch), `cursor`, `proof`. |
| Page | `version`, `challenge`, `offer_digest`, `cursor`, `total_bytes`, `bytes` (standard padded base64). |
| Rejection | `version`, `challenge`, `cursor`, `reason`. |
| Offer payload | `version` (1), `challenge`, `snapshot` (authenticated envelope), `publisher`, `hostname_claims`. |
| Capability descriptor | `version` (1), `anchor`, `boundary`, `active_member_count`, `sync`. |

Let binary `scope` be u8 anchor version, 32 network-ID bytes, u8 policy
version, u8 rank version. Derive the 32-byte request key via HKDF-SHA256
with `scope` as salt, capability IKM and info
`p2p-vpn checkpoint transfer request key v1\n`.

The request proof is HMAC-SHA256 under that key over
`p2p-vpn checkpoint transfer request proof v1\n`, request version u8,
scope, nonce, u16-length-prefixed authenticated **binary libp2p Peer ID**,
u32 cursor, u8 presence flag and the optional raw 32-byte offer digest.

The offer digest is SHA-256 of `p2p-vpn checkpoint transfer offer bytes v1\n`
and the complete signed offer bytes. The offer signature uses the publisher
key and `message("p2p-vpn checkpoint offer v1\n", offer_payload)`.

Pages carry exact 8 KiB ranges except the final short range, with byte cursors.
Reject inconsistencies or a total above 4 MiB. Match the publisher and challenge,
verify the offer signature and snapshot MAC, and require the publisher to be
active in that snapshot. Never install a partial offer.

Capability `sync` values are `resync_required`, `resyncing`, `participating`
and `excluded`. Response rejection reasons are `Unauthorized`, `Busy`,
`Expired`, `InvalidTransfer`, and `UnsupportedVersion`.

See [transfer bounds and resync](../membership-checkpoint-wire.md).
A valid excluded requester may learn its exclusion without gaining data-plane
authority.

## Mutations And Enrollment

`/p2p-vpn/checkpoint-mutation/1` uses u16-prefixed JSON, at most 16 KiB.
The request contains `version: 1` and `mutation`. The mutation envelope is
`payload` and padded standard-base64 `signature`.

The payload fields are `version` (1), `anchor`, `base`, `issuer`, `change`.
Sign `message("p2p-vpn checkpoint mutation v1\n", payload)`. Authenticate
the issuer's connection and require authority on the exact base boundary.

| Change | JSON |
| --- | --- |
| Upsert | `{"upsert_member":MEMBER}` |
| Remove | `{"remove_member":"PEER_ID"}` |
| Change policy | `{"set_policy":POLICY}` |
| Prune expired | `"prune_expired"` |

A new admission's incarnation is SHA-256 of
`message("p2p-vpn checkpoint admission incarnation v1\n", [anchor, base, subject])`.
Reject no-op authority updates. Apply genuine updates with a new revision
and predecessor digest. Durably install before acknowledging application.

The response has `version: 1`, `mutation_digest`, and `outcome`.
The digest is SHA-256 of `p2p-vpn checkpoint mutation handoff digest v1\n`
and the compact signed mutation envelope. Match it to the request.

Outcomes are `{"applied":BOUNDARY}` or
`{"rejected":{"reason":"...","current":BOUNDARY_OR_NULL}}`.
Reasons: `unauthorized`, `stale_base`, `resync_required`, `invalid`,
`busy`, `persistence_failed`.

The optional signed pairing grant fields are `version` (1), `anchor`,
`capability_secret` (standard padded base64), `minimum` (rank),
`inviter` (member) and `joiner` (member). Stage the secret locally
and prove the approved minimum by authenticated resync before activation.

The checkpoint hostname claim fields are `version` (1), `anchor`,
`subject`, `incarnation`, `sequence`, `hostname`. The subject signs
`message("p2p-vpn checkpoint hostname v1\n", payload)`. Verify the current
incarnation; a prior admission's hostname cannot return.
