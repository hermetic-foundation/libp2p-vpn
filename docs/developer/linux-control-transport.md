# Linux Control Transport Ownership

## Status

Linux main-host and profile-free pairing TCP connections use checked kernel route selection. This is a
transport-ownership component of the [physical-network policy](physical-network-policy.md),
not completion of automatic control-plane failback.

## Socket Policy

| Operation | Behavior |
| --- | --- |
| Outbound source | Kernel-selected address, then the actual allocated TCP source port |
| Policy lookup | Actual source, destination, protocol, ports, mark, effective UID, and device context |
| Outbound device | Preserve OS routing and receive admission; recheck the concrete route and generation before connect |
| Accepted stream | Validate its established tuple and reply route before Noise; preserve kernel receive routing |
| Shared listener | Keep its existing binding; do not rebind it for an individual peer |
| Same-host physical address | Permit assigned non-overlay IPv4/IPv6 destinations through the kernel's local route |
| Own overlay address | Reject marked TUN destinations and sources, including local routes through loopback |
| Port reuse | Prefer the selected source's listener port, otherwise a compatible family/scope port |
| Reuse collision | Prepare a fresh, fully checked socket with a new port; never use an unscoped fallback |

- TCP establishment occurs in the kernel before an incoming stream is accepted.
- Do not claim that accepted-stream validation precedes incoming SYN/SYN-ACK traffic.
- Device binding also filters received traffic. TCP streams therefore remain OS-routed, not pinned to an egress interface.
- A checked lease records route ownership at validation time; it is not a continuous packet firewall.

### Inventory Concurrency

- A subscribed Netlink socket supports only one active inventory dump.
- Link and address dumps share a bounded, two-second acquisition queue; ordinary route lookups retain their separate four-request limit.
- Sixteen concurrent dual-stack preparations exercise queue release and guard against kernel `EBUSY` failures.

## Protocol Compatibility

| Layer | Implementation |
| --- | --- |
| TCP | Kernel sockets and the public Tokio/libp2p TCP stream wrapper |
| Protocol selection | Existing multistream-select implementation, including lazy outbound negotiation |
| Authentication | Existing libp2p Noise configuration and upgrades |
| Multiplexing | Existing libp2p Yamux configuration and upgrades |
| Simultaneous-open role | Preserve the transport's dialer/listener role override |
| Relay | Existing circuit-relay protocol over the managed underlying TCP connection |

There are no new protocol bytes, keys, pairing artifacts, configuration fields,
or user-managed routes. Non-Linux transport construction remains unchanged.

## Resource Lifecycle

| State | Registry meaning |
| --- | --- |
| Connecting or negotiating | No authenticated route record |
| Authenticated | Exact peer and route record; not yet evidence of swarm adoption |
| Adopted | The swarm begins using the muxer after identity checks |
| Rejected, cancelled, or dropped | Remove the exact record; retained snapshots become retired |

- Bound records by the configured established-connection limit.
- Use checked monotonic identifiers; never wrap or infer ownership from a shared UDP tuple.
- Keep incoming and outgoing handshake budgets separate so silent inbound peers cannot consume outbound capacity.
- Reject obsolete route generations during registration and first swarm adoption.
- Snapshots retain route-monitor metadata, not TCP sockets or live connection ownership.
- Emit bounded connection-transition diagnostics, not periodic peer polling.

## Verification

### Results

| Check | Result |
| --- | --- |
| Standard workspace set | 2,144 passed; 57 opt-in/platform cases skipped |
| Linux route and TCP ownership checks | 43 passed, including isolated packet capture and asymmetric routing |
| Stock TCP interoperability and failure checks | 5 passed; included in the standard set |
| QUIC ownership checks | 6 passed, including selected receive/cancellation paths |
| Real TUN ownership lifecycle | 2 passed |
| Minimal-config real-TUN scenarios | 8 passed in 477 seconds, including both route-return roles and packet-block recovery |
| Peerless code pairing | Passed with resulting overlay connectivity in 13 seconds |
| Forced-relay overlay ping | Passed in 17 seconds |
| Android arm64 libraries | Default and diagnostic/demand-lifecycle-trial release cross-checks passed |
| Static/source checks | Clippy correctness/suspicious/performance, formatting, whitespace, and Nix source ownership passed |
| Storage | One existing target, about 4 GiB after superseded artifacts were removed; two jobs, no incremental/debug artifacts |

- Standard counts: 1,833 core, 161 CLI, 72 Android-native, 11 fixture, 5 pairing-CLI, 1 authorization, and 61 namespace helpers.
- Focused checks overlap the standard set and explicitly exercise selected opt-in cases; they do not cover every skipped test.
- Tests exposed inbound/outbound budget starvation, incompatible reuse selection, local-address rejection, and TCP device-binding regressions.
- Device binding broke same-host connections and asymmetric traffic during route changes. TCP now preserves kernel interface routing on both ends.
- Existing project-wide advisory warnings remain; no new warning is reported in the changed production transport modules.
- No full NixOS VM/package rebuild, APK, device deployment, personal flake change, or energy measurement was performed.
- The separate full Nix dependency tree remains unpopulated; rebuilding it would duplicate the existing Cargo verification cache.

### Coverage

| Test group | Required coverage |
| --- | --- |
| Stock transport interoperability | IPv4/IPv6, managed dialer and acceptor, authenticated ping in both directions |
| Failure cleanup | Wrong peer ID, unpolled dial, cancelled handshake, released sockets and capacity |
| Admission bounds | Full silent inbound budget does not prevent legitimate outbound traffic |
| Registry | Capacity, exact identity, adoption, stale generations, identifier exhaustion, retired snapshots |
| Socket policy | Concrete TCP tuples, reuse collision, IPv6 scope, assigned physical local addresses, own-overlay rejection |
| Namespace capture | Preparation emits no SYN; a control connection proves the capture can see SYN traffic |
| Receive compatibility | Accepted preparation preserves listener, sibling, and asymmetric receive paths |

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --lib runtime::p2p::managed_tcp::tests

CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  nix develop -c cargo test --lib runtime::physical_network::linux \
  -- --include-ignored
```

Use the existing target cache. Namespace tests isolate their changes and send no
Internet traffic. No formal kernel/protocol proof is claimed by these tests.

## Remaining Integration

- Reconcile established control connections when the preferred physical route changes.
- Authenticate and adopt replacements before retiring necessary fallback connections.
- Complete libp2p QUIC/UDP selection and DHT/AutoNAT/relay lifecycle and address reconciliation.
- Verify bounded fallback retirement, IPv6 migration, repeated flapping, and Android integration.
- Perform available-device checks and the separate reversible hardware energy comparison.

No phone deployment, live service replacement, or measured battery improvement
is implied by this component.
