# Owned Datagrams

## Negotiation

This is an extension of the [control stream](stream.md), not a replacement for
it. Select it only with mutually supported capabilities and authorized routes.
Use `PacketPlaneHello` and `PacketPlaneAccepted` with JSON byte arrays.

| Profile | Outer transport |
| --- | --- |
| Owned UDP | Direct UDP on an eligible underlay path. |
| Bound owned QUIC | QUIC DATAGRAM on a negotiated connection; bind its first unidirectional stream to the authenticated negotiation. |

Bound QUIC is distinct from libp2p QUIC streams and the older native-datagram
compatibility flag. Verify the negotiated certificate; a public CA or matching
address is not enough. Use stream fallback when a datagram path is unavailable.

## Signed Handshake

Integers are unsigned and big-endian. Serialize fields in this order:

| Field | Encoding |
| --- | --- |
| Magic | Eight ASCII bytes `p2pvpnH1`. |
| Version, kind | u8 each: `1`, then `1` Hello or `2` Accept. |
| Sender session ID, nonce, MTU | u32, u64, u16. |
| Ephemeral key | 32 raw X25519 public-key bytes. |
| Network, endpoint, identity key, signature | Four fields, each prefixed with its u16 byte length. |

The network is UTF-8. The endpoint is the canonical textual IP socket address
including port (IPv6 in brackets). The identity key is the libp2p protobuf.
Reject trailing bytes. Verify the signature over:

```text
ASCII("p2p-vpn packet-plane handshake v1") ||
wire fields from version through length-prefixed identity key
```

Do not sign the magic or the signature field. Bind the decoded signer to its
authenticated transport identity and current overlay membership before
installing session keys. Reject stale, wrong-role, and mismatched responses.

## Directional Keys

Perform X25519 and reject the all-zero shared secret. The HKDF-SHA256 salt is
SHA-256 of the ASCII domain `p2p-vpn packet-plane session keys v1` followed by
the Hello transcript and then the Accept transcript.

Each transcript is the kind byte, the 32-byte overlay ID, the 32-byte
ephemeral key, the big-endian session ID, nonce and MTU, then canonical UTF-8
endpoint bytes. No length prefixes separate these transcript fields.

The HKDF IKM is the X25519 shared secret. Expand 32-byte keys with the ASCII
info strings `hello-to-accept` and `accept-to-hello`. Use only the key
for that direction. Session ID and sequence must never repeat under one key.

## Datagram Frame

| Offset | Size | Value |
| ---: | ---: | --- |
| 0 | 8 | ASCII `p2pvpnD1`. |
| 8 | 1 | Version `1`. |
| 9 | 1 | Flags: send zero. |
| 10 | 4 | Session ID. |
| 14 | 8 | Sequence. |
| 22 | 2 | Ciphertext byte length, including the 16-byte tag. |
| 24 | Variable | ChaCha20-Poly1305 ciphertext of the complete v1 frame. |

Use the 24-byte outer header as AAD, and u32 session ID followed by u64
sequence as the 12-byte nonce. Lengths must match exactly. Require the
inner and outer session ID and sequence to match before accepting delivery.

The format's maximum payload is 65,478 bytes before path MTU limits. Do not
fragment at the overlay layer. Use the current negotiated path budget.
Maintain a bounded per-session 64-packet replay window.

## Binding And Handoff

Bound QUIC's first unidirectional stream begins with ASCII `p2pvpnQ1` and
a 32-byte binding token. Compute the token as SHA-256 of the ASCII domain
`p2p-vpn QUIC connection binding v1` followed by the verified Hello's kind,
overlay ID, ephemeral key, big-endian session ID, and big-endian nonce.

Do not associate a connection by arrival order or address alone. The
[QUIC binding contract](../quic.md#connection-binding) describes timeouts,
token ownership and connection limits.

For UDP replacement, [exact-path proof](../udp-path-proof.md) separates send
and receive authorization. A new send path cannot retire still-authorized
receive keys prematurely. The [shared path policy](../shared-path-policy.md)
specifies preferred return and fallback retirement.

Binding-token vectors, UDP path-validation lifecycle vectors and negative
replay/ownership interoperability fixtures remain draft gaps.
