# Identity And Membership

## Identity And Addresses

Transport identities are libp2p Peer IDs. Use the SHA-256 of the binary libp2p
Peer ID (not the UTF-8 rendering or public key) as the 32-byte overlay ID.
A textual overlay ID is lowercase hex.

| Built-in address | Derivation from the 32-byte overlay ID |
| --- | --- |
| IPv4 | Start with bytes `[100,64,0,0]`. XOR byte `i` into output byte `2 + i % 2`. |
| IPv6 | Start with `fd 00`, ASCII `hyprspace`, and five zero bytes. Calculate four tail bytes from `de ad be ef` by XORing input byte `i` into tail byte `i % 4`. Put the tail at offsets 12 through 15. |

These are host routes, not authority over their enclosing prefix. Check for
colliding or conflicting ownership. Authority for a custom address or subnet
comes from local configuration or an accepted signed route grant.

## Scope

An unkeyed network uses an absent/null tag. For keyed networks use padded
standard base64 of the SHA-256 of this byte string:

```text
UTF8("p2p-vpn membership tag v1") || UTF8(network_name) || 00 || membership_key_bytes
```

This tag is not a signature or proof of current membership. Do not transmit the
key in a capability or discovery message. Accept previous tags only if
explicitly configured for rotation; unkeyed networks only match an absent tag.

## Legacy Signed Records

An envelope is JSON with `payload` and padded standard-base64 `signature`.
The signature covers `p2p-vpn membership record v1\n` followed by the compact
UTF-8 JSON payload. Here and below `\n` means the single byte `0a`.

| Payload fields in order | Encoding |
| --- | --- |
| `version`, `network_name` | Integer `1`, exact network string. |
| `member_peer`, `member_public_key` | Subject Peer ID string and padded standard-base64 libp2p protobuf key. |
| `issuer_peer`, `issuer_public_key` | Signing Peer ID string and padded standard-base64 libp2p protobuf key. |
| `membership_epoch`, `sequence` | Monotonic version integers; defaults `1`, `0`; emit even when default. |
| `revoked`, `hostname` | Omit when false or absent, respectively. |
| `roles`, `route_grants` | Emit arrays, including empty. Roles: `overlay_member`, `route_authority`. Route objects: `prefix` then `metric`. |
| `issued_at_unix_seconds`, `expires_at_unix_seconds` | Unsigned Unix seconds; emit null expiration when absent. |

Use compact JSON, the specified field order, and no insignificant whitespace.
Decode and reconstruct typed signing bytes; do not verify an arbitrary raw
object ordering. Validate both key-to-ID bindings. Verify with the issuer key.

For legacy records, integer values must fit signed 64-bit range for cross-host
configuration compatibility. A current record is at most 12 KiB encoded.
Do not accept a signature as sufficient proof that its issuer is trusted.

### Authority And Convergence

- An explicit self-issued genesis record anchors authority. Valid legacy
  configurations without an explicit root may trust locally configured issuers.
- Under `any-member`, an active member may admit or revoke another member
  or itself. Evaluate the issuer at the event's accepted signed time.
- Revoking an inviter does not by itself revoke peers it previously admitted.
  Revocation tombstones are non-expiring and must survive restart.
- Reject conflicting payloads at the same version for the same issuer/subject.
  Apply deterministic target ordering and revoked-first conflict rules.
- Merge and validate as a transaction before replacing routes and peer
  authorization. Invalid input must not partially authorize packets.

The detailed [legacy authorization and time rules](../membership.md#ledger-merge)
cover retained history, concurrent issuers, expiry and self-resignation.
An implementation needs compatible ordering and clock bounds to publish records.

### Snapshot Exchange

Sort compact encoded record envelopes lexicographically by their bytes. Hash
`p2p-vpn membership snapshot v1\n` followed by each record's big-endian u32
length and bytes. The snapshot ID is `sha256:` and unpadded base64url digest.

Request `MembershipRecords` with `version: 1`, network name, optional tag,
and `cursor: 0`. Subsequent requests also include the snapshot ID. A page
echoes scope, snapshot and cursor, and carries `total_records`, `records`
and optional `next_cursor`.

Accept at most eight records per page, 256 overall, subject to the control
frame bound. Verify count, snapshot and contiguous cursors before committing.
A changed snapshot requires a bounded restart at cursor zero.

The DHT may expose an eight-record hint bundle of at most 64 KiB.
Its JSON includes version `1`, network, optional tag, records and optional
hostname records. It is not a substitute for authenticated complete sync.

## Checkpoint Membership

The cooperative checkpoint authority model is not the legacy event ledger.
Use the checkpoint descriptor in capabilities and snapshot transfer over
`/p2p-vpn/checkpoint-sync/1`. Never grant authority from an advertised rank.

Implement the [checkpoint wire specification](checkpoints.md),
[transfer lifecycle](../membership-checkpoint-wire.md), and
[migration rules](../checkpoint-migration.md) before opting in.
Checkpoint mutation uses `/p2p-vpn/checkpoint-mutation/1`.

An implementation without checkpoint support must not treat checkpoint
admission as legacy static admission. This draft still needs independent
checkpoint mutation and canonical checkpoint transcript vectors.

## Names And DNS

Names describe authorized routes, not vice versa. A hostname claim uses
`p2p-vpn hostname record v1\n` plus compact JSON in this order:
`version`, `network_name`, `peer`, `public_key`, `sequence`,
`hostname`, `issued_at_unix_seconds`. Sign with the named peer's own key.

Envelope, key encoding and signature encoding match legacy membership above.
Hostnames must be canonical DNS labels. Apply the signed sequence and current
membership; discard names for revoked or expired peers.

Serve `<host>.<network>.p2p-vpn.internal` from the same effective authority
view as routing. Friendly collisions do not resolve to an arbitrary winner.
Construct the stable fallback label as `peer-` plus lowercase Crockford
Base32 of the complete 32-byte overlay ID.

Answer A and AAAA from authorized overlay host addresses. Do not forward
unresolvable overlay names to public resolvers. The
[DNS behavior](../../user/dns.md) defines name precedence, suffix isolation,
and collision handling.
