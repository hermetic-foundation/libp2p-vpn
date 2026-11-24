# Stream Wire

## Session Setup

1. Dial a libp2p multiaddress and authenticate the expected libp2p Peer ID.
2. Negotiate `/p2p-vpn/control/1` and exchange capabilities. Both sides may
   initiate an exchange.
3. Validate scope, framing compatibility, current membership, and advertised
   routes. A supported transport or accepted Identify response is not enough.
4. Send authorized IP frames on `/p2p-vpn/packet/1`. Each request has a response.

The core payload protocol is identical over TCP, QUIC streams, a circuit, or
WebRTC Direct. Identify agent or protocol-version text is not a VPN wire version.

### Connection Admission

Apply a successful exchange to the authenticated member connection that carried
it. A cached capability record for the peer, an infrastructure relay connection,
or a control-only membership exchange MUST NOT authorize a new member stream.

Match a response with its request and connection before using it. A reply
from a closed binding MUST NOT admit a replacement. Use the more restrictive
local and remote MTU for the admitted connection, along with any path limit.

An already-admitted connection can continue carrying data while its replacement
validates. Retiring one connection does not invalidate a different admitted
connection for the same peer. Membership and route checks still apply to every
delivered IP packet.

Before retiring a working direct sibling, the reference runtime confirms the
replacement can carry packets. An accepted probe or authorized IP packet on that
connection provides this evidence; accepting a control message alone does not.

This rule uses the existing v1 messages. Connection and request identifiers
used by the runtime are local; no new fields are encoded in either stream.

## Encodings

Integers in binary frames are unsigned and big-endian. UTF-8 is used for
strings. JSON lengths count UTF-8 bytes, not characters. Byte arrays in JSON
are arrays of integers 0 through 255 unless a field explicitly uses base64.

## Control Stream

Each message is a two-byte length followed by a UTF-8 JSON body of at most
16,384 bytes. Close the write side after each frame. A request variant is a
one-property JSON object. A response uses the same externally tagged shape.

| Request key | Response keys |
| --- | --- |
| `Capabilities` | `CapabilitiesAccepted`, `CapabilitiesRejected` |
| `PacketPlaneHello` | `PacketPlaneAccepted`, `PacketPlaneRejected` |
| `MembershipRecords` | `MembershipRecordsPage`, `MembershipRecordsRejected` |

An acceptance carries the responder's own capabilities; it is not an echo.
A rejection carries a case-sensitive reason string, for example
`{"CapabilitiesRejected":"UnauthorizedPeer"}`.

### Capabilities Body

| Field | Encoding and meaning |
| --- | --- |
| `network_name` | Exact configured UTF-8 name. |
| `membership_tag` | Current scope tag string, or null/absent for unkeyed. |
| `advertised_routes` | Array of `{"prefix":"100.64.1.2/32","metric":0}`; omitted means empty. |
| `wire_version` | Integer `1`. |
| `packet_protocol` | String `/p2p-vpn/packet/1`. |
| `packet_header_len` | Integer `17`. |
| `effective_mtu` | Nonzero unsigned 16-bit payload limit. Use the more restrictive applicable path/peer limit. |
| `preferred_path` | Backend name below; a hint, not an instruction to switch. |
| `supports_quic_datagrams` | Boolean. Required even if false. It does not alone select the owned QUIC extension. |
| `supports_native_quic_datagrams`, `supports_owned_udp_packet_plane`, `supports_owned_quic_packet_plane`, `supports_bound_owned_quic_packet_plane` | Optional booleans; omitted means false. Advertise only implemented behavior. |
| `owned_quic_packet_plane_certificate_der`, `owned_quic_packet_endpoint_candidates`, `packet_endpoint_candidates` | Optional DER bytes and candidate lists for [owned datagrams](datagrams.md). |
| `direct_address_candidates` | Optional multiaddress strings, at most 32. |
| `member_records`, `hostname_records` | Optional arrays of signed records; limits 8 and 16 respectively. |
| `supports_membership_record_pages`, `membership_records_snapshot`, `membership_record_count` | Optional [legacy sync](membership.md) capability, snapshot string and count. |
| `checkpoint`, `checkpoint_hostname_inventory` | Optional [checkpoint](../membership-checkpoint-wire.md) descriptor and advisory digest. |
| `supports_demand_lifecycle`, `demand_lifecycle_epoch` | Optional [idle/wake](../demand-lifecycle-wire.md) capability and epoch. |

Path names are `direct_udp_datagram`, `direct_quic_datagram`,
`direct_quic_stream`, `direct_tcp_stream`, `direct_webrtc_stream`,
and `circuit_relay`. Reject an unknown path name on deployed v1.

`direct_webrtc_stream` is implemented on the experimental `browser-wasm`
branch, not in the native daemon on `main`. A peer that does not recognize
this path rejects the capability; sharing a packet version is not enough.

Example of an unkeyed TCP-stream capability request:

```json
{"Capabilities":{"network_name":"test","wire_version":1,"packet_protocol":"/p2p-vpn/packet/1","packet_header_len":17,"effective_mtu":1280,"preferred_path":"direct_tcp_stream","supports_quic_datagrams":false}}
```

Scope/framing rejection strings are `WrongNetwork`, `MembershipMismatch`,
`UnsupportedWireVersion`, `UnsupportedPacketProtocol`,
`UnsupportedPacketHeaderLength`, `InvalidEffectiveMtu`,
and `UnsupportedPreferredPath`.

Authority and extension validation can reject with `UnauthorizedPeer`,
`UnauthorizedRouteAdvertisement`, `InvalidOwnedQuicCertificate`,
`InvalidMembershipRecord`, or `InvalidHostnameRecord`.

## Packet Stream

A request contains a 17-byte header immediately followed by the payload.
There is no length prefix outside the header. Bound the declared length before
allocating or reading the payload. Unknown types and versions are decode errors.

| Offset | Size | Value |
| ---: | ---: | --- |
| 0 | 1 | Version `1`. |
| 1 | 1 | Flags. Send zero; current readers do not interpret them. |
| 2 | 1 | Type: `0` raw IP, `1` keepalive, `2` path probe. |
| 3 | 4 | Sender session ID. |
| 7 | 8 | Sender sequence. |
| 15 | 2 | Payload byte length. |
| 17 | Variable | Complete IPv4 or IPv6 packet, no bytes for a keepalive, or path-probe payload. |

The reliable stream does not use the owned datagram anti-replay window for IP
delivery. The reference receiver checks keepalive and probe sequences and
rejects duplicates. A probe acknowledgement does not prove overlay IP delivery.

For IP delivery, require an authorized source for the authenticated sender and
an authorized local destination. Do not forward packets to other overlay
members merely because the destination exists in a peer route table.

### Packet Response

| Hex | Result |
| --- | --- |
| `01` | Accepted. The receiving p2p-vpn node accepted the frame, not necessarily the destination application. |
| `02 01` | Malformed packet. |
| `02 02` | Too large. |
| `02 03` | Replay. |
| `02 04` | Unauthorized peer. |
| `02 05` | Unauthorized source. |
| `02 06` | Unauthorized destination. |
| `02 07` | Unexpected payload. |
| `02 08` | Rate limited. |

Reject unknown status and reason bytes. A framing failure may close the stream
without an application response. Keepalive for session 7, sequence 42:

```text
01 00 01 00 00 00 07 00 00 00 00 00 00 00 2a 00 00
```

## Service Status

`/p2p-vpn/service/1` is an authorized, optional diagnostic exchange.
Use the same u16 JSON framing and externally tagged objects as control,
with a 4,096-byte body limit.

```json
{"Status":{"network_name":"test","membership_tag":null,"nonce":42}}
```

The `Status` response echoes the nonce and includes network, tag, wire
version, packet protocol, packet header length, effective MTU, and
`supports_quic_datagrams` with the same types used in capabilities.

Other fields are optional: packet limits, native/owned transport support,
session TTL, replay-window count, and selected path, score, MTU, and RTT.
An unauthorized or wrong-scope request returns `Rejected` with
`UnauthorizedPeer`, `WrongNetwork`, or `MembershipMismatch`.
