# Physical Network Policy

## Status

Implementation in progress. This document defines the acceptance contract, not a claim that the current runtime satisfies it.

## Default Contract

| Traffic | Selection |
| --- | --- |
| Public discovery, relays, and Internet peer paths | Current OS-preferred physical route for the destination and address family |
| Direct LAN peer traffic | OS destination-specific route; do not force a LAN destination through an Internet gateway |
| mDNS queries and replies | Selected eligible physical LAN only; never cellular or p2p-vpn overlay interfaces |
| Fallback maintenance | Only while needed for recovery or incoming reachability; no redundant indefinite maintenance |

- No additional JSON or Nix configuration is required.
- Network preference comes from the OS, not a fixed Ethernet/Wi-Fi/cellular ranking.
- An interface being up does not prove that it has a usable authenticated peer path.
- IPv4 and IPv6 can have different usable routes. A change in one family must not invalidate unrelated healthy paths blindly.
- Preserve explicit listen-address configuration; wildcard listeners do not authorize unsolicited transmission on every interface.

## Selection Inputs

| Platform | Required inputs |
| --- | --- |
| Android | OS default/underlying physical network identity, link addresses, capabilities, availability, and loss events |
| Linux | Link, address, and routing changes; destination-specific route decisions including policy routing and route metrics |
| Shared runtime | Physical-network generation, eligible source addresses, per-peer path ownership, and validation results |

- Exclude our own overlay from underlay selection and discovery.
- Do not classify cellular solely by address ranges: carrier addresses and overlay addresses can overlap.
- Treat a newly available network as inventory, not automatic permission to transmit on it.
- Keep stale callback and connection results from restoring an obsolete selection.

## Path Transitions

| State | Action | Exit condition |
| --- | --- | --- |
| Preferred usable | Send through preferred path; retain only necessary incoming infrastructure | Failure or OS preference change |
| Recovering | Attempt eligible fallback with bounded retries and LAN-first recovery | Authenticated fallback succeeds or no route remains |
| Fallback active | Maintain service; react to preferred-route return | Preferred candidate becomes eligible |
| Preferred validating | Continue fallback service while validating preferred candidate | Authenticated success, failure, timeout, or newer generation |
| Preferred promoted | Stop new fallback application sends and drain bounded in-flight work | Redundant fallback connections and maintenance retired |

- Validation must prove authenticated peer reachability on the candidate physical network.
- Do not promote solely from an interface-up event, cached address, or successful routing-table lookup.
- OS preference changes supersede an originally preferred interface; do not pin that original interface forever.
- Rate-limit flapping and failed validation. Prefer events and bounded retry schedules over periodic probes on all available networks.
- Necessary destination-specific LAN paths and incoming relay anchors are not redundant fallbacks.
- Preserve membership, identity, TUN addresses, DNS, pairing, and protocol compatibility across transitions.

## Native Reconciliation

1. Capture a consistent selection generation and eligible addresses.
2. Reconcile overlay and pairing mDNS tasks, send sockets, multicast reception, and advertised addresses.
3. Associate UDP, QUIC, TCP, public discovery, AutoNAT, and relay work with their selected underlay.
4. Reject stale completions and stop scheduling new work on retired underlays.
5. Validate and promote replacement paths before retiring working fallback service where possible.
6. Expire redundant fallback probes, keepalives, sessions, and connections after bounded cleanup.

Abrupt loss can require invalidation before a replacement exists. Preferred-route return must not use that disruptive loss path as a substitute for validated failback.

## Diagnostics

- Report the selected physical network, eligible discovery interfaces, generation, and last transition reason.
- Count validation attempts, preferred promotions, stale results, and retired fallback resources.
- Expose pending cleanup and its bounded deadline.
- Use bounded snapshots and transition logs; do not add high-frequency diagnostic polling.
- Exclude keys and raw packet contents from evidence.

## Acceptance Matrix

All rows remain open until linked evidence demonstrates the complete behavior described.

| ID | Requirement | Evidence required | State |
| --- | --- | --- | --- |
| P1 | OS preference, not fixed transport priority | Android callback/tracker tests and Linux route-selection tests | Open |
| P2 | Destination-specific and IPv4/IPv6 routing preserved | Multi-route namespace/VM tests | Open |
| P3 | Discovery excludes cellular and overlay | Query/reply tests and interface-level device evidence, including pairing mDNS | Open |
| P4 | Automatic fallback | Induced route loss with successful authenticated recovery and incoming access | Open |
| P5 | Automatic validated return | Preferred path restored while fallback carries traffic; no manual intervention | Open |
| P6 | Full redundant fallback retirement | No new fallback payload/probes/keepalives after cleanup; bounded resource counters | Open |
| P7 | Address replacement and stale events | Tests for same-interface address changes, out-of-order callbacks, and obsolete validation completions | Open |
| P8 | Stable behavior under flapping | Bounded attempts, memory, and timers across repeated transitions | Open |
| P9 | Existing workflows preserved | Minimal config, Nix module, pairing, DNS, membership, LAN-first, and transport regression checks | Open |
| P10 | Android integration | Authorized device deployment, traffic checks, incoming/outgoing access, failover and return | Open |
| P11 | Energy effect evaluated separately | Same-build reversible control, accepted screen-off windows, modem/front-end counters, and explicit uncertainty | Open |

## Energy Investigation

- Previous Wi-Fi-default observations found cellular-source mDNS sends and local multicast receive duplication.
- A VPN-off/on control found substantially different modem/front-end power; it did not isolate the responsible subsystem.
- Syscall fault injection was rejected by Android app seccomp and terminated the app. Do not reuse it or weaken security protections.
- Use a debug-only, automatically expiring, exact-target control for selective testing within one build.
- Verify that the control changes only intended traffic and preserves connectivity before collecting energy windows.
- Use equal settling/measurement durations, reversed or counterbalanced order, and explicit rejection criteria.
- Report hardware rail energy separately from Android app attribution and whole-device discharge.
- No numerical battery target, including 10x, is a prerequisite for completing this network-policy implementation. Report a missed target honestly and re-evaluate afterward.

## Delivery

| Stage | Deliverable |
| --- | --- |
| 1 | Policy, Android OS-directed selection, and platform-independent transition tests |
| 2 | Physical-network snapshots and event-driven Linux/Android native integration |
| 3 | Interface-scoped discovery and transport source/path ownership |
| 4 | Validated promotion, bounded fallback retirement, and reproducible multi-interface tests |
| 5 | Physical-device verification, controlled energy comparison, and final requirement audit |

- Keep builds bounded in job count and retained storage.
- Use atomic Conventional Commits through Jujutsu; verify and push each completed change to `main`.
- Do not count a foundation module or green narrow test as completion of native integration.
