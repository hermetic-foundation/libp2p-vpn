# Android Network DNS

## Status

This component supplies DNS inventory metadata, the native resolver adapter and
the Network-scoped resolver/endpoint backend. Transport activation remains local
implementation, not deployed Android behavior.
The [acceptance ledger](physical-network-acceptance.md) remains authoritative.

## Inventory Contract

| Field | Contract |
| --- | --- |
| `dns_servers` | OS-ordered numeric addresses from this Network's LinkProperties; at most eight, without duplicates |
| `private_dns_active` | API-28-guarded platform observation, not permission to send plaintext DNS |
| Legacy records | Missing DNS fields default to an empty server list and `false` |
| Link-local DNS | Publish an unscoped IPv6 address; socket use restores the owning interface's scope |
| Revisions | A DNS-only or Private-DNS-only change advances the record and inventory revisions, preserving incarnation |

These fields belong to internal Java/Rust inventory, not user JSON/Nix
configuration or peer protocol messages. No additional configuration is required.

## Metadata Verification

| Check | Exact extracted component |
| --- | --- |
| Android backend host tests | 70 passed, zero failed; one existing namespace-only test ignored |
| Java inventory models | 26 passed |
| Android arm64 release | Compilation passed; no APK/link/device claim |
| Java service | Current source and dependencies compiled against existing API-37 SDK/resources |
| Formatting and whitespace | Passed |

## Resolver Backend

### Native Adapter

| Boundary | Contract |
| --- | --- |
| API availability | Discover the public API-29 resolver symbols at runtime; retain minSdk 26 and avoid mandatory newer symbols |
| Network selection | Pass the exact Network handle without changing process routing or bypassing Private DNS |
| Query ownership | Cancel and close an unfinished descriptor once; completion consumes it on success and failure |
| Asynchronous integration | Poll readiness; submit and finish on bounded workers, with epoch checks and cancellation |
| Retry policy | One native submission per Hickory attempt; no nested library retry loop |
| Compatibility gap | Active Private DNS on API 28 still needs a supported implementation; do not silently downgrade to plaintext |

The adapter alone does not activate the resolver or change deployed transport
selection. Host callback tests cover ownership and error paths, not netd routing
on hardware.

| Exact Adapter Component Check | Result |
| --- | --- |
| Callback ownership/error tests | 11 passed, zero failed |
| Existing Android backend host tests | 70 passed, zero failed; one existing namespace-only case ignored |
| Android arm64 release | Compilation passed; no APK/link/device claim |
| Formatting and whitespace | Passed |

### Resolution

| Boundary | Backend behavior |
| --- | --- |
| Selection | Prefer the OS Internet default before the hostname has a destination IP; use eligible fallback Networks only for connectivity failure |
| Servers | Use the selected Network's own DNS servers, in OS order; no process resolver or hardcoded public DNS fallback |
| Binding | Bind each borrowed descriptor to the exact Network before any UDP send or TCP connect |
| DNS parsing | Hickory handles records, caching and TCP fallback; libp2p retains DNS/DNS4/DNS6 and recursive DNSaddr parsing and limits |
| Negative answers | Authoritative negatives do not cause cross-Network DNS fallback |
| Epoch | Reject stale binding, transmission, cached answers and query completion |
| Packet endpoints | Resolve asynchronously and coalesce completion notifications; never block the packet actor on hostname resolution |
| Zero TTL | Deliver a bounded one-time answer, separate from reusable DNS caching; pending negotiations retain epoch-checked evidence |
| QUIC tasks | Expand the copied destination list before spawning; check retained DNS evidence before and after establishment |

Linux retains its existing resolver construction. The vendored libp2p-DNS change
only adds a constructor accepting a caller-owned resolver; upstream parsing and
lookup limits are unchanged.

### Backend Verification

| Exact Resolver Component Check | Result |
| --- | --- |
| Android backend/DNS host tests | 92 passed, zero failed; one existing namespace-only case ignored |
| Native adapter ownership/error tests | 11 passed, zero failed |
| Android arm64 release | Compilation passed; no APK/link/device claim |
| Nix source parity | Passed for packaged Rust tests and vendored sources |
| Clippy gates | Correctness, suspicious and performance passed; advisory warnings remain |
| Formatting and whitespace | Passed |

This verifies the backend, not activation in overlay/pairing transports or
device handoff. Linux resolver construction is unchanged.

## Bounds

| Resource | Limit |
| --- | --- |
| Simultaneous queries | Four per resolver |
| DNS binding workers | Four, retained until blocking work exits even after cancellation |
| Networks per lookup | Three sequential candidates |
| Request / Network / whole-query deadlines | One / two / six seconds |
| Cached records | 64 per Network resolver |
| Endpoint hosts / addresses per host | 64 / 64 |
| Endpoint workers | Four; excess work is rejected, not queued indefinitely |
| Reusable positive / negative TTL caps | 300 / 30 seconds |
| Unconsumed answer handoff | Six seconds; not a minimum DNS-cache TTL |

## Required Before Acceptance

1. Complete older-Android active Private DNS compatibility. The API-29 native
   adapter is implemented locally; unsupported cases fail closed.
2. Finish spawned-QUIC hostname acceptance. Local IPv4/IPv6 zero-TTL UDP
   Hello/Accept tests pass across source preparation, metadata ACKs and payload.
3. Complete advertised-address ownership/withdrawal and remaining ingress and
   transport integration from the fixed acceptance ledger.
4. Verify Android kernel/netd binding, incoming/outgoing access and network
   handoff on authorized hardware before publishing activation.

Host fixtures and Android cross-compilation are not hardware-routing or energy
evidence. No battery saving is inferred from this implementation.
