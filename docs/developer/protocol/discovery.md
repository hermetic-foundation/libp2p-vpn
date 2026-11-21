# Discovery And Paths

## Discovery Is Not Admission

Discover a transport endpoint, authenticate the expected libp2p Peer ID, then
exchange overlay capabilities and apply [membership](membership.md).
Never turn a provider record or a successful dial into overlay authority.

| Source | Use |
| --- | --- |
| Configured address | Try the operator's endpoint for the configured identity. |
| libp2p mDNS | Try eligible link-local IPv4/IPv6 underlay paths for known members, and bounded candidates for active enrollment. |
| libp2p Identify | Learn advertised addresses and supported protocols after authenticating the connection; filter by the peer's current role and address provenance. |
| Public Kademlia | Find providers, membership hints and signed endpoint records. Restrict automatic dials to the OS default physical network. |
| Configured or learned relay | Use a valid Circuit Relay v2 path as fallback. Its reservation is not evidence of membership. |

Use libp2p mDNS discovery packets and multiaddresses, not overlay DNS names.
Link-local queries and listeners must not use a VPN-owned interface or cellular.
On recovery, try eligible LAN paths before an old public relay path.

## Kademlia

Use `/ipfs/kad/1.0.0` for the default public IPFS DHT. Cooperating private
instances may configure a different libp2p Kademlia protocol ID; they must
share it and start with at least one reachable contact on that DHT.

Bootstrap contacts are discovery infrastructure, not trust roots or reserved
relays. Discover more contacts at runtime through Kademlia. The public
pairing lookup still uses the public IPFS DHT if the main network uses a private DHT.

### Keys

Keys below are UTF-8 bytes. Expand placeholders literally, without URL
encoding or adding a terminator. `scope` is one of:

```text
/p2p-vpn/{network_name}
/p2p-vpn/{network_name}/members/{membership_tag}
```

| Operation | Logical key |
| --- | --- |
| Overlay provider publication and lookup | `{scope}/providers/1` |
| Bounded membership hint bundle | `{scope}/membership-records/1` |
| Signed endpoints for a target peer | `{scope}/peer-addresses/{libp2p_peer_id}/1` |
| Scoped code enrolment | `/p2p-vpn/pairing-code/{locator}/providers/1` |
| Global code enrolment | `/p2p-vpn/pairing-code/{locator}/providers/2` |

For public IPFS **provider operations only**, replace a logical key longer
than 80 bytes by `0x12 0x20 || SHA-256(logical key)`. Keep shorter provider
keys unchanged. Do not apply this transform to value record keys or private DHTs.

Publishing and querying use the same transform. A receiver matches the requested
network and target even if a result was received from an unrelated DHT node.
Discovering a pairing provider only admits a bounded attempt at the PAKE.

For an automatic browser relay, the provider can nominate a relay identity,
not a socket address for the companion to dial. Look up the exact relay
independently on the default physical network. Authenticate it and verify
its HOP role and WebRTC entrance before issuing a gateway lease.

Prefer WebRTC hints within the bounded candidate set. A hint alone does not
verify an entrance. When the operator configures relay pins, only those
entrances are eligible.

### Signed Address Record

The value is UTF-8 JSON with `payload` and `signature`. In v1, signature
input is the compact JSON encoding of the typed payload in this exact key
order. It has no separate domain prefix. The signature is a JSON byte array.

| Field in signing order | Value |
| --- | --- |
| `version` | Integer `1`. |
| `network_name` | Network scope. |
| `membership_tag` | Scope tag, omitted if absent. |
| `peer_id` | Text libp2p Peer ID of the publisher. |
| `public_key_protobuf` | JSON byte array containing the libp2p public key protobuf. |
| `sequence` | Unsigned 64-bit integer. Reference sender uses Unix seconds. |
| `expires_at_unix_seconds` | Unsigned 64-bit expiration. Reference lifetime: 1,800 seconds. |
| `addresses` | Multiaddress strings. At most 32; never publish overlay addresses. |

Bound the value to 65,536 bytes. Check scope, expected target, current
authorization, and expiration before using it. The reference reader accepts
up to 3,600 seconds of staleness only as a **dial hint**.

The decoded public key must derive the signed peer ID, and the signature must
verify over the reconstructed payload. Reject conflicting destination IDs.
A circuit's relay ID is not its destination ID.

Reject malformed and ineligible candidates rather than promoting them.
Private, loopback, link-local, or unresolved DNS addresses learned only from
public infrastructure are not safe to dial. Operator, local-LAN or authenticated
member evidence can admit appropriately scoped private hints.

### Runtime Scheduling

Use bounded lookup, publication, and dial budgets. Prioritize unresolved member
recovery over routine public maintenance, and cancel obsolete queries when a
working path or newer network generation supersedes them.

Avoid public lookups for healthy members. Stop routing on revoked members even
when their old provider record is cached. Do not let cached addresses or an
unrelated infrastructure connection bypass current intent and egress policy.

## Relay And Direct Recovery

1. Obtain a Circuit Relay v2 reservation for incoming relayed connections.
2. Publish reachable relay entrances to the same reservation. A dual-stack
   relay can carry IPv4-only to IPv6-only peer traffic without IP translation.
3. Authenticate the destination end-to-end on the circuit. Use it while there
   is no usable direct route.
4. Try DCUtR where supported to establish a direct path. Keep the circuit
   while testing the replacement. WebRTC Direct r2 is not DCUtR or a TURN relay.
5. Validate the replacement on the exact connection before moving send
   ownership. Retire redundant fallback work once it is safe to do so.

The [shared path policy](../shared-path-policy.md) specifies preferred return,
generation changes, and local interface enforcement. Default-network-only
applies to automatic public infrastructure, not to explicitly authorized
member traffic on a secondary interface.
