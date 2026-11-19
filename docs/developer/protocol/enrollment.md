# Enrollment

## Versions

| Surface | Framing | Maximum body |
| --- | --- | ---: |
| `/p2p-vpn/pairing/1` | Big-endian u16 length followed by JSON | 32 KiB |
| `/p2p-vpn/pairing-code/1` | Big-endian u32 length followed by JSON | 64 KiB |
| `/p2p-vpn/pairing-code/2` | Big-endian u32 length followed by JSON | 64 KiB |

The signed offline offer, request, and response can also be exchanged as files.
In a code exchange they are carried inside the authenticated protocol. Local
RPC, approval UI, and generated JSON/Nix files are not peer protocols.

## Codes And Discovery

Use ten random bytes encoded as 16 Crockford Base32 characters. Display four
groups of four. Normalize ASCII case and discard ASCII whitespace and hyphens
before decoding. The PAKE password is the decoded ten bytes, not the text.

Define `LP(x)` as the big-endian u64 byte length of `x` followed by `x`.
The locator is unpadded base64url of SHA-256 over:

| Version | Hash input |
| --- | --- |
| 1 | `"p2p-vpn pairing code locator v1\n" || LP(UTF8(network_name)) || LP(code_bytes)` |
| 2 | `"p2p-vpn pairing code locator v2\n" || LP(code_bytes)` |

Use the matching [provider key version](discovery.md#keys). V2 discovers an
inviter without first knowing the overlay name. The actual network is learned
from the signed encrypted offer, not the public DHT record.

Attempt eligible LAN candidates first. The [reference discovery schedule](../pairing.md#discovery-state-machine)
permits a bounded public fallback while LAN attempts settle. On completion or
cancellation, stop publication and release operation-owned connections.

## Code Messages

Requests use the case-sensitive `kind` discriminator. Responses use `status`.
These are JSON objects, not the externally tagged control-stream format.

| Request | Fields besides `kind` | Normal response |
| --- | --- | --- |
| `hello` | `hello`: signed SPAKE hello | `challenge`: signed challenge with encrypted offer |
| `submit` | `request`: signed pairing request carrying confirmation | `pending`: opaque ticket and `expires_at_unix_seconds`, or `accepted` |
| `poll` | `ticket`: opaque string | `pending` or `accepted`: signed `response` |

A `rejected` response has a `reason`: `unavailable`, `invalid_request`,
`rate_limited`, `busy`, `user_rejected`, or `expired`. V2 rejects
unknown fields on these tagged objects.

### Cryptographic Binding

Use SPAKE2 over Ed25519 with the joiner as A and inviter as B. Public keys
and SPAKE messages use padded standard base64. The decoded SPAKE message
is 33 bytes in the deployed encoding.

For v2, each SPAKE identity starts with `p2p-vpn pairing code spake2 v2\n`.
Append LP fields in order: byte `02`, locator text, role text (`joiner` or
`inviter`), inviter binary Peer ID, joiner binary Peer ID.

For v1 use the corresponding `v1\n` domain and LP fields in order:
network name, role, and that role's binary Peer ID.

| Derived material | Construction |
| --- | --- |
| HKDF-SHA256 IKM | SPAKE2 shared secret. |
| v1 HKDF salt | `p2p-vpn pairing code keys v1\n`, then LP network name, locator, binary inviter ID, binary joiner ID. |
| v2 HKDF salt | `p2p-vpn pairing code keys v2\n`, then LP byte `02`, locator, binary inviter ID, binary joiner ID. |
| Offer and confirmation keys | 32 bytes each; HKDF info strings `encrypted offer` and `pairing request confirmation`, respectively. |
| Encrypted offer | ChaCha20-Poly1305 over the compact signed offer, using a fresh 12-byte nonce and the bound hello/challenge AAD. |
| Submit confirmation | HMAC-SHA256 under the confirmation key, bound to the offer token and both identities. |

Check transport identity against the claimed peer and the decoded signing key.
Validate scope, locator, time and signatures before accepting the encrypted
offer or the request. Bind poll tickets to the authenticated joiner and operation.

### Hello And Challenge

Both envelopes contain `payload` and padded standard-base64 `signature`.
Sign compact JSON of the ordered payload prefixed with
`p2p-vpn pairing code hello vN\n` or `p2p-vpn pairing code challenge vN\n`.

| Version | Payload field order |
| --- | --- |
| Hello v2 | `version`, `locator`, `inviter_peer`, `joiner_peer`, `joiner_public_key`, `issued_at_unix_seconds`, `spake_message` |
| Challenge v2 | `version`, `locator`, `inviter_peer`, `inviter_public_key`, `joiner_peer`, `issued_at_unix_seconds`, `expires_at_unix_seconds`, `spake_message`, `nonce`, `encrypted_offer` |
| V1 variants | Insert `network_name` after `version` in the same respective orders. |

Peer fields are libp2p Peer ID text; key fields hold libp2p public key protobuf
bytes in padded standard base64. Times are Unix seconds. Encode `nonce` and
`encrypted_offer` in unpadded base64url.

For offer AEAD AAD, use `p2p-vpn pairing code encrypted offer vN\n`
followed by compact JSON: `hello` (the complete hello payload, unsigned
envelope omitted), then all challenge payload fields except `encrypted_offer`,
in challenge order.

The confirmation MAC starts with `p2p-vpn pairing code request confirmation vN\n`.
Append LP fields in order: network name, locator, inviter text ID, joiner text ID,
and rendezvous token. Append compact JSON with `offer`, `payload`, `signature`
in that order. Encode absent `offer` as null in this MAC input.

Transmit `code_authentication` in the request envelope with `locator`
and `confirmation`; the latter is the HMAC in padded standard base64. Do not
include this object in the MAC input.

### Signed Enrollment Artifacts

Use compact ordered JSON as below. Each signature domain is
`p2p-vpn pairing {offer|request|response} v1\n` followed by the payload.
Offers and responses are signed by the inviter; requests by the joiner.

| Payload | Ordered fields |
| --- | --- |
| Offer | `version`, `network_name`, `inviter_peer`, `inviter_public_key`, `rendezvous_token`, `issued_at_unix_seconds`, `expires_at_unix_seconds`, `acceptance_mode`, `inviter_addresses`, `bootstrap_peers`, `relay_reservations`, `discovery`, `protocols` |
| Request | `version`, `network_name`, `inviter_peer`, `joiner_peer`, `joiner_public_key`, `rendezvous_token`, `offer_issued_at_unix_seconds`, `offer_expires_at_unix_seconds`, `offer_signature`, `issued_at_unix_seconds`, `requested_hostname`, `requested_vpn_ip`, `requested_routes` |
| Response | `version`, `network_name`, `inviter_peer`, `inviter_public_key`, `joiner_peer`, `rendezvous_token`, `issued_at_unix_seconds`, `expires_at_unix_seconds`, `assigned_vpn_ip`, `membership_key`, `member_records`, `inviter_addresses`, `inviter_routes`, `bootstrap_peers`, `relay_reservations`, `discovery`, `protocols`, `checkpoint` |

- Artifact version is 1 independent of code protocol version. Encode a
  standalone URI as `p2pvpn:` and the base64url unpadded signed offer JSON.
- Omit `acceptance_mode` for the default `file_bearer`. Include
  `"acceptance_mode":"code_approval"` in a code invitation.
- Omit empty offer `relay_reservations`, empty `offer_signature`, absent
  `requested_hostname`, and absent `checkpoint`. Emit other option fields as
  null and array fields as arrays. Absent offer timestamps in a request decode to zero.
- In `bootstrap_peers`, order keys `id`, `address`. Use
  `prefix`, `metric` for routes. In `protocols`, use `control`,
  `packet`, `service`, `wire_version`, `packet_header_len`.
- In `discovery`, order `mdns`, `kademlia`,
  `kademlia_provider_advertisement`, `kademlia_protocol`, `dcutr`, `autonat`.
  The Kademlia protocol is a string; the other fields are booleans.

The [enrollment reference](../pairing.md#authenticated-exchange) covers
approval and failure behavior. Independent SPAKE2 and signed enrollment
transcript vectors are still needed before declaring this profile interoperable.

## Commit And Activation

1. Possession of the code proves eligibility to request admission, not
   network membership. Require explicit approval for a new admission.
2. Bind grants to the requested identity and approved routes. Never give
   route authority just because a joiner requested it.
3. Persist admission and cancellation ownership before making an approval
   visible. An exact retry must not repeat an admission or advance its version.
4. The joiner verifies the complete signed response before activation.
   A checkpoint grant stages protected credentials and requires authenticated
   snapshot sync before forwarding.
5. Expiry, rejection and cancellation release pending resources. Durable
   cleanup must not erase an unrelated prior admission.

For crash recovery and checkpoint enrollment, see the
[durable transaction](../pairing.md#durable-enrollment-transaction) and
[checkpoint credential contract](../membership-checkpoint-wire.md#pairing-credentials).
