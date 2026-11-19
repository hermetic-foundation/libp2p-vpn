# Browser Relay Advertisement

This path publishes a browser's incoming Circuit Relay v2 reservation so an
authorized native member can discover the browser's peer ID. It is opt-in,
one-shot, and available only with a cooperating DHT and pinned bootstrap
contacts. The default public IPFS DHT uses provider discovery; the companion
does not write custom peer-address values there.

The companion's trusted policy must explicitly permit the browser peer, the
native member, the current network name and public membership tag, the DHT
protocol, and one exact public TCP or QUIC-v1 circuit. It authorizes a
single-use challenge for 15 seconds and issues at most one every 30 seconds.
An HTTP adapter must use the existing strict same-origin request policy. Do
not turn request-supplied routing, membership or relay fields into a permit.

Pass the challenge and the same exact circuit to the browser's
`sign_relay_advertisement` method. The browser checks its current permission
to communicate with the pinned member, the active scope, and whether that
exact address was returned by the authenticated relay on the current
reservation listener. It signs a v1 peer-address value and separately signs
the companion's challenge. Submit the returned JSON without adding any
credentials. The companion forwards only the signed address value under the
existing peer-address key, using its ephemeral DHT connection identity and
the OS default physical network. The signed value has a 60-second lifetime.
Native readers must still authorize the browser and authenticate its Noise
identity before accepting overlay traffic.

A loopback WebRTC ingress (including a discovery lease) is not a publishable
address or evidence of a corresponding public TCP or QUIC entrance.
Rewriting that address or substituting a matching relay identity is unsafe:
the same relay peer can have several entrances and reservations may move or
close. Use an explicit public circuit only when the relay itself returned it
on the owned reservation. The companion verifies the browser's attestation
and its own current permit, not an independently signed relay voucher. It
cannot detect a reservation lost after signing or recall a value already
stored remotely; a discovered circuit remains a short-lived hint.
