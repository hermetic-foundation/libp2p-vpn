# Browser Relay Advertisement

This path publishes a browser's incoming Circuit Relay v2 reservation so an
authorized native member can resolve the browser's known peer ID. It is opt-in,
renewed in the foreground, and available only with a cooperating DHT and pinned bootstrap
contacts. The default public IPFS DHT uses provider discovery; the companion
does not write custom peer-address values there.

Regular companion discovery on the IPFS protocol queries the scoped mesh
provider key for the selected member. Only public WebRTC Direct endpoints
are eligible from provider hints; a signed record is still needed for an
automatically discovered circuit. Merely using the IPFS protocol identifier
with a cooperating seed does not establish public IPFS visibility.

The companion's trusted policy must explicitly permit the browser peer, the
native member, the current network name and public membership tag, the DHT
protocol, and one exact public TCP or QUIC-v1 circuit. Start `browser-serve`
with the cooperating `--kademlia-protocol`, pinned `--bootstrap` contacts, and
`--relay-advertisement-permit PATH`. The permit is a JSON object:

```json
{
  "network_name": "example",
  "membership_tag": null,
  "browser_peer": "BROWSER_PEER_ID",
  "destination": "NATIVE_PEER_ID",
  "address": "/ip4/RELAY_PUBLIC_IP/tcp/PORT/p2p/RELAY_PEER_ID/p2p-circuit/p2p/BROWSER_PEER_ID"
}
```

Use the current public membership tag for a tagged network. Do not include
the membership key, capability secret, browser configuration, or private key.

The companion adds the `p2p-vpn-relay-advertisement` meta tag when enabled.
Its content is `/api/relay/advertisement/challenge`. Send an exact same-origin
JSON POST with body `{}` to that path. The response is the challenge object
with `nonce`, `network_name`, `membership_tag`, `kademlia_protocol`,
`browser_peer`, `destination`, `address`, and `issued_at_unix_seconds`.
Challenges are single-use, valid for 15 seconds, and issued at most once
every 30 seconds.

Pass the challenge and the same exact circuit to the browser's
`sign_relay_advertisement(challenge.address, JSON.stringify(challenge))`
method. The browser checks its current permission
to communicate with the pinned member, the active scope, and whether that
exact address was returned by the authenticated relay on the current
reservation listener. It signs a v1 peer-address value and separately signs
the companion's challenge. POST the returned JSON (`nonce`, `record`, and
`proof`) unchanged to `/api/relay/advertisement/publish`. A successful write
returns `{"published":true}`. The companion forwards only the signed address value under the
existing peer-address key, using its ephemeral DHT connection identity and
the OS default physical network. The signed value has a 60-second lifetime.
After a successful explicit publish, the foreground app requests a new
challenge no sooner than 35 seconds after the previous attempt completes.
Every renewal requires the exact currently confirmed alias and current
membership. The app stops renewal on failure, disconnect, or page exit.
After a failed renewal, publish explicitly to resume. Remote copies
are not recalled; short-lived reservation records lose eligibility at signed
expiry. Native readers must still authorize the browser and authenticate its
Noise identity before accepting overlay traffic.

A loopback WebRTC ingress (including a discovery lease) is not a publishable
address or evidence of a corresponding public TCP or QUIC entrance.
Rewriting that address or substituting a matching relay identity is unsafe:
the same relay peer can have several entrances and reservations may move or
close. Use an explicit public circuit only when the relay itself returned it
on the owned reservation. The companion verifies the browser's attestation
and its own current permit, not an independently signed relay voucher. It
cannot detect a reservation lost after signing or recall a value already
stored remotely; a discovered circuit remains a short-lived hint.
