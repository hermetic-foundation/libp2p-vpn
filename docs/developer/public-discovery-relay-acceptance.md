# Public Discovery And Dual-Stack Relay Acceptance

## Scope

These features build on the published
[physical-network policy](physical-network-policy.md). They do not change
overlay identity, membership, IP addressing, or the minimum configuration.

| Track | Change | Not in scope |
| --- | --- | --- |
| Default-network discovery | Constrain automatic public bootstrap, Kademlia and relay infrastructure to the OS-selected default physical network | Applying default-only routing to direct members, LAN discovery or unrelated sockets |
| Cross-family relay | Prefer useful dual-stack HOP relay candidates and publish both usable routes to the same reservation | NAT, arbitrary IP translation or making arbitrary IPv6-only services reachable |

## Default-Network Contract

- Select the default physical network before dialing an automatic public endpoint.
  Reachability through an alternate interface does not make an endpoint eligible.
- Try other eligible addresses and peers. Reevaluate when OS preference changes;
  do not fall back to a secondary interface just because a candidate is unreachable.
- Keep DNS, socket establishment and connection reuse inside the same policy.
  A connection established for another purpose does not authorize public work.
- Apply the same ownership check to automatically learned public circuit
  entrances. Configured entrances and direct member paths keep their policy.
- If cellular is the OS default, cellular is eligible. The policy does not
  hardcode preference for Wi-Fi, Ethernet, IPv4 or IPv6.

| Case | Evidence required |
| --- | --- |
| Default and secondary both have Internet routes | Automatic public discovery succeeds through eligible candidates on the default; zero attributable outbound discovery packets on the secondary |
| A public peer has addresses on both interfaces | Try the eligible address; a successful response must not depend on dialing the alternate |
| A public peer is reachable only via the secondary | No dial, DNS fallback or preexisting secondary socket carries the automatic public operation |
| Default changes during activity | Old selection is invalidated and discovery resumes on the new default; capture distinguishes old-path shutdown from new work |
| Mixed-purpose peer/connection | A direct member reachable on the secondary still passes authenticated overlay traffic; no public work rides that secondary connection |
| LAN and explicit configuration | Preserve existing LAN discovery, member and explicitly configured relay behavior without adding configuration |

Use an isolated two-underlay fixture, an eligible responding discovery peer,
and an otherwise reachable secondary-only candidate. Count packets separately
by fixture destination and interface. Do not equate a failed handshake with zero
packets; include connection setup and resolver traffic.

## Cross-Family Relay Contract

- Associate validated advertised candidates with the authenticated HOP peer ID.
  An advertisement is not proof that both addresses are reachable.
- Keep address and candidate counts bounded. Do not crowd out workable
  single-family candidates or downgrade address-admission rules.
- Publish eligible relay addresses only while the local reservation is live.
  Withdraw them with the reservation, not merely with one advertisement.

| Case | Evidence required |
| --- | --- |
| IPv4-only caller; IPv6-only reservation owner | Authenticated overlay payload both ways through one relay Peer ID |
| IPv6-only caller; IPv4-only reservation owner | Same test with the roles reversed |
| Family isolation | Each member has only its assigned Internet address family; neither a direct path nor a secondary interface can carry the payload |
| Wrong, missing or unreachable advertised address | No cross-family success claim; normal fallback remains available |
| Reservation expires or is removed | Its usable advertised paths are withdrawn; retain unrelated claims and working reservations |

Record the actual outer socket family on each leg and the selected overlay
transport. A relay address, reservation alone, or discovery result is not
end-to-end proof.

## Verification And Publication

| Evidence | Result | Scope |
| --- | --- | --- |
| Fallback authorization unit test | Passed | Automatic pending/accepted relay reservations do not grant alternate-network permission; configured members and explicit relays retain it |
| Dual-underlay bootstrap baseline | Reproduced: 25 outbound bootstrap-port packets on the secondary link | Direct member ping and direct TCP path succeeded on the same secondary link; default-only transport wiring not active in this build |
| Linux dual-underlay cutover | Passed: zero secondary bootstrap-port packets, scoped seed moved when the default changed, no old-link increase after retirement | Production LAN-first startup grace retained; direct-member ICMP passed before and after cutover |
| Linux resolver on wire | Passed: DNS and authenticated seed connection on the default; zero DNS or seed packets on the secondary before cutover | Isolated DNS fixture with a secondary-only resolver route; TCP/UDP port 53 counters, plus direct member pings |
| Linux cross-family relay namespace run | Both reservation/dial roles passed; bidirectional TUN payload through one authenticated relay ID | Disjoint v4/v6 veth networks, learned private-DHT address records, no member addresses in config; no Android device claim |
| Later scoped-reservation rerun | IPv4 reservation passed; IPv6 reservation lost its startup route epoch and did not complete within the initial wait | Earlier cross-family evidence is not a pass for the combined source; existing reservation retry allowed in the next run |
| Integrated cross-family rerun | Both cases passed (90.91 seconds total) | Waited for the relay to receive the address record, including the existing reservation retry after startup epoch invalidation; exact-family payload assertions unchanged |
| Provider alias withdrawal on wire | Passed: both aliases, then one, then none; direct address retained in every publication | Real Kademlia provider messages; stale local swarm relay entry does not reappear in fresh publications |
| Android native build check | ARM64 Rust library type-check passed | API 29 cross-toolchain; not a device or radio capture |
| Scoped circuit and reservation namespace run | Three passed: dual-underlay DNS, bootstrap and accepted auto reservation; both cross-family roles | Real TUN, no secondary public traffic in the dual-underlay fixture; both cross-family paths authenticated |
| Relay renewal compatibility | Seven relay-drain tests and the alias-renewal unit passed | Unchanged entrances still emit renewals. Removed aliases expire only after replacement entrances are reported |

Both tracks are open. Record focused checks, platform checks, isolated
acceptance results, and published commits separately. Physical device
coverage and battery impact are separate from model results.
