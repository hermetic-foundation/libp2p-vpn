# Android Transport Policy

## Status

Current milestones and exit conditions are in the
[fixed acceptance ledger](physical-network-acceptance.md). Historical stage
results below do not certify newer working-tree changes.

The coherent activation includes managed TCP/native QUIC, owned UDP/QUIC,
source-bound negotiation, Network-scoped DNS, controller reconciliation and
non-destructive physical notifications. No new user configuration is required.

Stage54 records 2,648 workspace passes and available-device kernel/netd evidence.
Continuous preferred return delivered 600/600 probes across both directions and
IP families, including automatic stream/UDP/QUIC promotion and old-owner retirement.

See [Stage54](android-physical-handoff-stage54.md) for exact scope, fingerprints,
public-relay failures and untested hardware variants. No battery saving is claimed.

## Earlier Component Evidence

The following table preserves earlier component-stage evidence. Current
acceptance is recorded in the fixed ledger; these rows are not new open gates.

| Component | Behavior | Evidence |
| --- | --- | --- |
| Inventory | Published bounded Java/Rust Network records, independent default preference, source addresses and routes | Rust and JVM models; not device callback proof |
| Callback lifetime | Incarnation fencing, coalesced publication and service-teardown withdrawal | JVM tests; no device callback proof |
| Socket binder | Borrowed-descriptor binding contract, route preparation and JNI/NDK adapter | Android arm64 cross-check; not link/device proof |
| Native transports | Working-tree managed TCP/native QUIC use Network leases, authenticated ownership and bounded active-dial retries | Stage32 workspace, loopback and Android default/trial cross-checks pass; device proof remains |
| QUIC companions | Immutable Network identity, bounded weak pooling, shared receive path and drain ownership | Vendor loopback/TLS tests with host callbacks |
| Controllers | Published shared ownership registry; Android controller activation and recovery-intent guards remain local | Stage32 workspace and Android compilation; not device behavior |
| Owned QUIC | Published platform-aware primitives; local request-scoped Network retry, single-winner binding and startup activation | Host regressions and Android compilation; device handoff remains unverified |
| Owned UDP | Published inactive ownership/directional primitives; Runner startup and auditing remain local | Focused suite: 110 passed, one ignored; local integration passes full workspace and three namespace cases |
| Physical-network notification | Local `PhysicalNetworkChanged` request and Android JNI routing reconcile without the legacy global reset; stable-epoch coalescing avoids repeated LAN-grace restart | Two real loopback integration tests passed, preserving eight hints before an explicit legacy reset; epoch/model unit checks green |
| Stacked sources | Published Network-bound UDP connect selects a source without transmitting; no base-family assumption | Host CLAT models and zero-transmission check; not device CLAT proof |
| Diagnostics | Ownership events include Network handle/incarnation/record revision; local status/state counters separate pending UDP validation from receive-only retention | Current workspace and namespace passes include counters; device correlation remains |

The [NDK socket-binding API](https://developer.android.com/ndk/reference/group/networking#android_setsocknetwork)
is available from API 23. UID exclusion from this app's VPN remains unchanged.
No JSON/Nix user configuration, identity, membership or wire format is changed.

## State Contract

| Value | Meaning |
| --- | --- |
| Inventory revision | Current policy observation; fences stale handshake/audit completion |
| Network incarnation | Distinguishes a newly available Network from a retired use of its handle |
| Record revision | Advances for meaningful source, route, interface or eligibility metadata changes |
| Availability | A surviving Network/source can carry fallback traffic after preference changes |
| Unknown stacked source | Metadata changed without proving source loss; retain existing bound fallback I/O, but require fresh proof for socket admission |
| Preference | OS-selected default, with destination-specific LAN routing preserved |
| Fallback candidate | Eligible validated Network after the preferred Network's kernel source lookup fails; not authenticated promotion |
| Stacked-source proof | Network-bound kernel lookup, fenced by incarnation and record revision; no guessed CLAT address or base-interface routing override |

- Ignore unrelated capability churn without revoking unchanged routing data.
- Do not guess a Network from a source IP shared by multiple records.
- New socket binding fails closed on stale state, missing routes or binding failure.
- Existing ownership is not removed merely because a newer preference revision exists.
- Unknown CLAT proof does not authorize new socket binding or candidate promotion. Network withdrawal, reincarnation and interface loss still invalidate the old owner.
- Route audits are event-driven; they send no peer probes or periodic interface scans.
- Source lookups run off the async executor. Cancellation retains lookup capacity until blocking work finishes.
- Incoming unlisted sources require unique Network attribution; overlapping stacked sources fail closed.
- Interface index is diagnostic metadata for Network-bound Internet traffic, not a forced CLAT device.
- Physical preference notifications request reconciliation, not a destructive reset. The explicit legacy `NetworkChanged` recovery path remains separate.
- Repeated notifications in one stable physical epoch do not restart LAN-first grace indefinitely.
- RX and TX authorization are directional. New-key TX proof alone does not prove that the peer has stopped sending with old keys.
- Necessary old RX-key retention is distinct from permission to keep transmitting on the old underlay.

## Resource Bounds

| Resource | Limit |
| --- | --- |
| Inventory JSON | 128 KiB |
| Available Networks | 16 |
| Source addresses per Network | 64 |
| Routes per Network | 128 |
| Socket preparations per owner | 4 |
| Async route lookup wait | 3 seconds; blocking work retains its permit after timeout |
| Connecting sockets per owner | 16 |
| Native QUIC Network companions per endpoint | 32 weak entries |
| Outbound owned-QUIC bindings | 16 per runtime, shared across connector clones; independent of TLS preparation permits |
| Pending audit delivery | One coalesced snapshot and one bounded output channel |
| Raw-UDP retained ownership/admission budget | 64 total slots, reserving two per candidate; capacity rejects new negotiation rather than evicting retained RX owners |

## Historical Acceptance Plan

This earlier P1-P11 plan is retained for traceability. It does not supersede the
fixed ledger or introduce additional hardware gates into the clarified goal.

| Gate | Required next work | Criteria |
| --- | --- | --- |
| IPv6-only cellular | Finish review and regressions for kernel-selected stacked sources and platform routing, then verify real CLAT RX/TX | P2, P7, P9 |
| Native incoming paths | Verify accepted TCP binding, ambiguous addresses and native QUIC ownership against Android's kernel/netd | P2, P4, P10 |
| Complete handoff | Integrate remaining transport policies and controller regressions, then verify available-device handoff before activation is published | P4-P8 |
| Directional key retention | Focused and integration tests pass; complete device/churn checks without premature key eviction or redundant old TX maintenance | P4-P6, P8 |
| Bounded resource retirement | Stop redundant old TX/maintenance; keep necessary RX state within hard bounds and release it at original protocol expiry; early retirement is optional | M2, M3 |
| Stacked-source availability | Host models preserve bound fallback on unknown CLAT metadata and reject stale admission; device source-change and loss evidence remains | P4, P5, P7 |
| Unusable preferred path | Local TCP, native-QUIC and owned-QUIC attempts implemented; raw UDP still needs ACK-proven Network retry selection | P4, P5, P8 |
| DNS and discovery | Network-scoped DNS, eligible-LAN selection independent of a cellular Internet default, mDNS query/reply isolation, pairing scope and advertised-address reconciliation | P2, P3, P9 |
| Device evidence | Incoming/outgoing access, address replacement, network loss/return, flapping and quiet retired paths | P7-P10 |

## Local UDP Retry Integration

At the earlier UDP-retry stage, activation was local and the receive-scope and
socket-cache primitives were published independently. The rows below retain
that stage's verification scope, not the later Stage54 device results.

| Boundary | Local behavior | Evidence or remaining work |
| --- | --- | --- |
| Retry ownership | One bounded cursor survives repeated Hello transcripts; no attempt-budget reset on a timer | Seventeen host ledger models passed |
| Promotion | Exact authenticated ACK and live ticket commit with the synchronous ownership move | Deadline, supersession and exactly-once callback models passed |
| Backend wait | Source lookup and socket binding share four preparation slots; cancellation retains capacity until the backend exits | Host cancellation model and Android compilation passed |
| Receive provenance | Preserve companion identity and kernel IIF through GRO and scoped event selection | Vendor host tests pass; Android kernel/netd attribution remains unverified |
| Authorized RX | Preference churn does not revoke already-authorized cached RX ownership | Host lease models pass; complete Android runtime proof remains open |
| Primary admission | Secondary-listener authorization cannot bypass primary retry-ticket preparation | Local caller guard repaired; device/runtime regression still required |
| Source signing | Prepare, publish and acknowledge the exact selected source before signing; adopt the same owner | Stage44/45 real-control IPv4/IPv6 checks pass; runtime activation remains local |
| Recovery restart | Recent application demand or verified control work can rearm exhausted recovery after bounded backoff; ticks cannot reset the cursor | Stage45 host models pass; Android device proof remains open |
| Preferred revalidation | Validate preference with an independent ticket and exact active fallback anchor, including without a new physical epoch | Stage45 models and real-control/payload checks pass; Android device proof remains open |

### Current Checks

These Stage41 checks remain valid evidence for their snapshot. They do not
certify the newer Stage42 preparation/ingress edits or unrun new tests.

- Repaired local core suite: 2,060 passed, zero failed, 33 ignored.
- Initial focused UDP suite: 59 passed; its Linux symmetry assumption was subsequently corrected by namespace evidence.
- Repaired real-TUN two-underlay suite: both original roles passed in 192.40 seconds total.
- Android arm64 default and diagnostic/lifecycle-trial compilation passed.
- No Android device was attached, APK deployed or battery saving measured.

### Next Gates

1. Complete Android ingress attribution, including ambiguous companion delivery and stacked sources.
2. Select and retain the UDP lease before signing Hello and Accept.
3. Adopt that same ticket at installation; do not select another Network under the signed keys.
4. Require acknowledged endpoint metadata with per-Network/socket provenance.
5. Add real alternate-Network, address-change and available-device evidence.

A kernel-selected local source is not proof of an external NAT mapping.
Defer unsupported endpoint claims explicitly while preserving established
native/stream fallback; do not weaken tuple admission or invent public tuples.

### Asymmetric Ingress Review

The first two-underlay run failed after unblock: the new Linux IIF-equals-egress
check rejected authenticated traffic whose peer correctly kept its own
destination-specific reply route. The fixture routing and assertions are unchanged.

Linux TX ownership and authenticated tuple/token checks remain mandatory, but
incoming IIF is not a symmetry requirement. Android still requires current,
unambiguous Network attribution; Linux route behavior is not Android proof.

Both original roles pass after the repair. The fixture still requires unchanged
fallback payload during blocking, fresh retry after unblock, automatic preferred
return and six-second old-outbound quietness. No timer or routing assertion was relaxed.

These are fixed-endpoint IPv4 Linux results, not default-source migration,
Android/CLAT, full P6 resource retirement or energy evidence.

## Verification Record

### Stage47 Network-Scoped DNS

Ordered DNS-server and Private-DNS metadata now have Java/Rust implementation.
The local resolver binds DNS UDP/TCP to the selected Network, fences old epochs,
and uses the upstream DNSaddr parser through an injected resolver.

- Packet-endpoint resolution is asynchronous, bounded and completion-driven.
- Zero-TTL delivery and negotiation evidence are separate from reusable caching.
- Active Private DNS currently fails closed; its platform adapter is required.
- A hostname-only cross-stage handshake fixture remains required; primitive
  resolver/snapshot passes do not prove that workflow.

See [Android Network DNS](android-network-dns.md) for contracts, limits and
remaining acceptance. Runtime activation remains local and no APK is deployed.

| Check | Result and scope |
| --- | --- |
| Latest Android backend/DNS host suite | 86 passed, zero failed, one existing namespace case ignored; includes retained snapshot and epoch tests |
| Broad core snapshot | 2,128 passed, zero failed, 33 ignored; predates final negotiation-snapshot preservation edits |
| Android release compilation | Default and diagnostic/lifecycle variants pass with snapshot integration; not linking/device proof |
| Java inventory | 26 JVM tests passed |
| Java service | Current service and source dependencies compile against the existing API-37 SDK and resource jar; no APK build |
| Static/package checks | Formatting, Nix source-parity and Clippy correctness/suspicious/performance gates pass; snapshot scopes above still apply |

### Stage45 Recovery Admission and Preferred Return

This is local Android raw-UDP runtime integration. The published preferred-owner
backend does not activate this runtime or close the remaining transport gates.

| Boundary | Implemented behavior |
| --- | --- |
| New work | Admit recent application demand or verified control receipt after exhaustion and cooldown; maintenance alone cannot restart |
| Budget | Keep one cursor across transcripts; backoff grows from 30 seconds to a 300-second cap |
| Preferred return | Use an independent validation ticket anchored to the exact surviving fallback; reject nonpreferred prepared owners |
| Async continuation | An admitted initiator preparation remains eligible after its timer is consumed, even with an unchanged healthy endpoint |
| Physical events | Seed the fallback anchor on an epoch-triggered preferred attempt, so a failed first probe can retry later |
| Promotion | Preserve fallback payload service until authenticated ACK; stale candidate callbacks cannot install new ownership |
| Compatibility | First successful source lookup may use a fallback; generic initial fallback semantics remain unchanged |

| Check | Result and scope |
| --- | --- |
| Focused UDP snapshot | 138 passed, zero failed, three existing namespace cases ignored; predates the final test-adapter cleanup |
| Latest full core | 2,107 passed, zero failed, 33 ignored; includes the final admission path and compatibility correction |
| Real control and payload | IPv4/IPv6 preferred revalidation preserves both active owners and payload until new ACKs, then promotes both |
| Android arm64 release | Default and diagnostic/lifecycle variants passed; compilation only |
| Clippy | Correctness, suspicious and performance gates passed; other warnings remain |

The real-control fixture runs on the host; registry models exercise Android
admission separately. Neither is Android kernel/netd or hardware handoff proof.
Network-scoped DNS/address reconciliation and remaining transport integration
are still required. No battery measurement or improvement is claimed.

### Stage44 Prepared-Source Publication

This is local Runner integration. The independently extracted publication
state does not activate or certify Android handoff.

| Boundary | Local behavior and evidence |
| --- | --- |
| Missing source | Prepare silently; publish the actual selected source before signing |
| Capability barrier | Real IPv4/IPv6 control requests acknowledge newly added metadata before either Hello or Accept |
| Deferred Accept | Preserve the original response channel through source preparation and metadata acknowledgement |
| Ownership | Enumerate address values only; publication does not retain sockets, leases or retry tickets |
| Withdrawal | Remove generated aliases after cancellation, expiry or source retirement; preserve unrelated and configured aliases |
| Fallback | Existing aliases may survive while the original authenticated active owner remains available; retention-only evidence cannot add aliases |
| Bound | At most 32 generated source aliases, shared by fresh and retained sources |
| Idle behavior | Unchanged source snapshots do not restart capability delivery or send new probes |

| Check | Result |
| --- | --- |
| Focused UDP suite | 130 passed, zero failed, three existing namespace tests ignored |
| Full core suite | 2,094 passed, zero failed, 33 ignored |
| Android arm64 release | Default and diagnostic/lifecycle variants passed; compilation, not APK/device proof |
| Clippy | Correctness, suspicious and performance gates passed; advisory warnings remain |

The initial initiator test lacked its claimed direct control connection. The
fixture now opens that connection; no retry deadline or assertion was relaxed.

At this snapshot, Network-scoped DNS/override resolution, fresh recovery
admission, independent preferred revalidation and device/netd/CLAT evidence were
open. Stage45 advances raw-UDP admission/revalidation, not the remaining gates.
Public hints from a different socket do not authorize a raw-UDP NAT mapping.

### Stage43 Source-Bound Negotiation

This is local implementation and host evidence, not Android-device certification.

| Boundary | Local behavior and host evidence |
| --- | --- |
| Pre-signing preparation | Neither Hello nor Accept is produced before source preparation finishes |
| Deferred response | Real loopback libp2p control requests retain and deliver the responder's channel after asynchronous preparation; IPv4 and IPv6 |
| Source/adoption | Use the exact prepared socket/route owner; a different socket's automatic public hint is not source proof |
| Initial promotion | Keep stream fallback until exact authenticated UDP acknowledgements; exchange real payload in both directions |
| Crossed Hello | Transfer the admitted owner before or after signing instead of canceling its recovery ticket; retain the original preparation deadline |
| Peer ordering | Ordering gates new work, not completion of an already-admitted recovery preparation |
| Failure classification | Explicit failure fences all preparation clones in host tests; timeout/transport callsites preserve their reason in source review; Android integration is not device-verified |

The focused UDP suite passes 114 tests, with zero failures and three existing
namespace cases ignored. This does not rerun or reopen the completed M1 milestone.

Android physical-network host models pass 60 tests, with zero failures and one
namespace case ignored. Default and diagnostic/lifecycle arm64 release checks
pass. No attached ADB device, APK deployment or device handoff result is claimed.

Source-appropriate endpoint publication, fresh post-exhaustion recovery intent,
independent preferred validation, Network-scoped DNS/address reconciliation and
Android device handoff remain required. Energy evaluation is outside this goal.

### Stage35 Local Endpoint Publication

Runner now requires acknowledged packet metadata before signing Hello or
Accept. Wildcard direct hints use the exact live, adopted native connection's
source rather than a new unbound UDP default-route lookup.

| Boundary | Local implementation |
| --- | --- |
| Native ownership | Match peer and connection ID; require current ownership or a fresh audit preserving the unchanged route |
| Publication timing | Retry publication after authenticated Identify/adoption and preferred-candidate validation, not only initial connection establishment |
| Packet acknowledgement | Reuse the bounded capability-delivery owner; queueing alone does not open negotiation |
| Ordering | Record accepted delivery before scheduling Hello; an unacknowledged Accept creates no keys or connection task |
| Metadata changes | Endpoint/certificate/protocol/MTU changes require a fresh ACK; unrelated hostname/member updates preserve packet acknowledgement |
| Recovery | Existing expiry/retry owners retain their bounds; no additional polling loop or maintenance demand |
| Compatibility | Fixed listener overrides and existing wire/configuration formats remain unchanged |

The [publication contract](demand-lifecycle-control-delivery.md#packet-metadata-acknowledgement)
does not prove a UDP NAT mapping. Per-Network endpoint evidence, withdrawal and
raw-UDP ACK-driven alternate-Network selection remain unfinished P2/P4/P5/P9 work.

Host ownership tests and Android cross-compilation do not establish device
callback, socket/netd, CLAT or roaming behavior. No energy result is inferred.

| Stage35 check | Result and limit |
| --- | --- |
| Full local workspace | 2,478 passed, zero failed, 87 ignored; includes both new Runner publication gates and acknowledged/unacknowledged renewal/retry cases |
| Control delivery | 25 focused tests pass locally and in the isolated published component; stale/unowned/rejected replies, metadata changes, current authorization and connection reset |
| Native source hints | Three focused tests pass; IPv4/IPv6 constructors, exact owner/adoption, obsolete observer rejection and fresh unchanged-route audit |
| Minimal-config real TUN | QUIC, UDP-only and stream-only modes pass in 29.90 seconds total |
| Owned-QUIC real TUN return | Initiating and accepting roles pass in 125.97 and 121.21 seconds; Linux IPv4 two-underlay evidence only |
| Raw-UDP real TUN return | Both original roles pass in 96.20 seconds each; fixed IPv4 endpoints, not complete source migration or P6 proof |
| Android arm64 release | Default and diagnostics/demand-lifecycle-trial cross-checks pass; not APK link or netd execution |
| Tooling | Formatting, source parity and denied Clippy correctness/suspicious/performance groups pass; advisory warnings remain |
| Independent review | No actionable scoped static findings; not a dynamic Android check |
| Device and energy | ADB lists no device; no deployment, settings change or battery measurement |
| Storage | One reused target cache, about 6.6 GiB; two jobs, no incremental/debug build output or new APK/VM/full package build |

### Stage34 Local UDP Startup Proof

Route-managed first-session startup now stages a candidate instead of bypassing
validation. Runner probes pending startup candidates while keeping payload
traffic on the existing fallback. The proof primitive is published separately;
Runner integration remains local.

| Boundary | Implemented behavior |
| --- | --- |
| Startup | No active session, payload TX or UDP backend selection before the exact ACK |
| Direction | Sending an ACK authorizes necessary peer RX only; the responder still proves its own TX |
| Recovery | Reuse existing expiry/recovery maintenance and pending-request gates; add no polling loop |
| Diagnostics | Session-install logs distinguish `validation_pending` from active path proof |
| Compatibility | Unmanaged APIs retain direct installation; wire format, configuration and key lifetimes are unchanged |

The [proof contract](udp-path-proof.md) covers startup and replacement. Alternate
Network selection and per-Network signed/NAT endpoint ownership remain unfinished.
Startup proof is a prerequisite, not completion of P4-P8 or Android device proof.

| Stage34 Check | Result and limit |
| --- | --- |
| Red regression | New Runner startup test failed because the first session bypassed candidate admission |
| Full local workspace | 2,466 passed across 21 suites, zero failed, 87 ignored; includes six new startup/expiry/directional tests |
| Local packet plane | 119 passed, one ignored; includes existing replacement, replay and retention regressions |
| Isolated proof component | 114 packet-plane tests passed, one ignored; its 21 handoff tests also pass without local Runner/controller activation |
| Minimal UDP-only real TUN | Passed in 10.82 seconds, with automatic startup and payload delivery |
| Raw-UDP real TUN handoff | Both original roles passed in 96.20 seconds each; fixed IPv4 endpoints and two underlays, not full default-source/IPv6/Android or P6 proof |
| Android arm64 release | Local default and diagnostics/demand-lifecycle-trial cross-checks pass; isolated proof component default cross-check also passes |
| Tooling | Local and isolated formatting, source parity and denied Clippy correctness/suspicious/performance checks pass; 752 local library-test advisories remain |
| Device and energy | No device attached; no APK link/deployment, netd execution or battery measurement |
| Storage | One reused target cache, about 6.5 GiB; no new APK, full package or VM build |

### Stage33 Local Owned QUIC Retry Integration

This implementation remains local and unpublished. Host models, loopback TLS
and Linux namespace checks do not establish Android Network/netd behavior.
No APK deployment or energy comparison is part of this stage.

| Boundary | Implemented behavior |
| --- | --- |
| Request intent | Authenticated packet-plane recovery may try alternate Networks; preferred-route validation remains selected-route-only, including alternate peer endpoints |
| Socket factory | Materialize the exact prepared Network lease, update its actual ephemeral port/mark, and reject publication races before use |
| Network attempts | Three sequential distinct Networks at most; each receives one third of its endpoint's allocation, capped at six seconds |
| Endpoint attempts | Preserve preferred-endpoint ordering and race alternatives only within the remaining original connection budget |
| Binding arbitration | Select one unbound TLS winner and drop losing candidates before writing the binding token once |
| Binding failure | Binding-stage errors/timeouts end this negotiation without reverse-direction fallback; a later negotiation uses its own fresh binding |
| Stale routes | Reject before TLS, after TLS, before binding and after binding; binding transmission alone is not promotion proof |
| Resource bounds | Hold a connection-preparation permit across each Network retry chain; separately cap pending outbound bindings at sixteen across connector clones |
| Cancellation | Dropping pending binding writes releases their permits; no retry follows an uncertain binding write |
| Compatibility | Public connector signatures, explicit source overrides, certificates, identities and wire formats remain unchanged; binding overload reports `WouldBlock` |
| Diagnostics | Preserve typed Quinn errors and original I/O errno; binding-stage failures have a distinct internal diagnostic category |
| TCP retry classification | Protocol/Noise authentication rejection is terminal; actual transport I/O retains its kind and errno, including deferred `V1Lazy` failures |

- Network retry covers socket creation and TLS, not repeated binding writes.
- Existing candidate challenge/ACK validation still controls replacement promotion.
- DNS resolution is not yet Network-scoped/asynchronously bounded; elapsed resolution time is deducted from the remaining dial allocation.
- Successful UDP writes are not path proof. Raw UDP still needs exact authenticated ACK-driven Network retry selection.

| Stage33 Check | Result and limit |
| --- | --- |
| Isolated backend publication | 36 passed, including the explicit datagram namespace; Android default cross-check, workspace Clippy, formatting and source parity passed without runtime activation |
| Local workspace | 2,456 passed across 21 suites, zero failed, 87 ignored; precedes the later TCP classification repair |
| Final core suite | 2,000 passed, zero failed, 33 ignored, after that repair; loopback-only namespace |
| TCP classification/interoperability | 11 passed, including four new typed/deferred-error cases; stock Noise/Yamux, both directions and families remain covered |
| Linux monitor | 16 passed, including a real route-change namespace; [notification admission](linux-route-monitor.md) is a separate correction, not a proven explanation of earlier failures |
| Native QUIC namespaces | Eight passed: IPv4/IPv6 DHT, AutoNAT and configured/automatic reservation return |
| Owned QUIC real TUN | Dialing role passed in 116.18 seconds; accepting role in 90.99 seconds; fixed IPv4 endpoints and two underlays, not Android/CLAT proof |
| Final Android arm64 release | Default and diagnostics/demand-lifecycle-trial cross-checks pass; no APK link or kernel/netd execution |
| Final tooling | Formatting and denied Clippy correctness/suspicious/performance checks pass; 746 library-test advisories remain |
| Storage | One reused target cache, about 6.5 GiB; no new APK, full package or VM build |

### Next Integration: Raw UDP

| Requirement | Implementation boundary | Criteria |
| --- | --- | --- |
| Retry intent | Distinguish failed-path recovery from selected-route validation; do not rotate Networks during preferred validation | P4, P5, P8 |
| Signed source | Prepare the exact Network/listener lease before signing each attempt's advertised endpoint; preserve tuple admission | P2, P7, P9 |
| Endpoint ownership | Tie candidate hints to the listener, Network incarnation and observation lifetime; a native observed IP does not prove the raw socket's NAT mapping | P2, P4, P9 |
| Publication order | Select from a peer-acknowledged capability snapshot for Hello and Accept; handle later snapshot changes rather than relying on enqueue order | P5, P7, P9 |
| Attempt identity | Fresh keys, route owner and challenge token; retain necessary authorized RX owners within existing bounds | P6-P8 |
| Proof | Continue receiving while awaiting an exact authenticated ACK; send success alone cannot finish an attempt | P4, P5 |
| Promotion | Recheck epoch, owner, token, listener, tuple and deadline once in Runner; reject late earlier-attempt ACKs | P5, P7, P8 |
| Regressions | Blackholed preferred ACKs, successful alternate, selected-only denial, stale completion and cancellation | P4-P9 |

Stage34 locally removes the first-session candidate-staging bypass. Route slots
remain immutable; alternate recovery needs fresh attempt owners, not in-place
mutation or a send-only wrapper around the generic Network-attempt backend.

### Stage32 Local Native QUIC Retry Integration

The additive vendor dial hook is independent of local Android activation.
Android activation remains unpublished and lacks physical-device evidence.
The retry hook's [contract and fixture limits](libp2p-quic-physical-ownership.md#optional-outgoing-retry-hook)
apply independently of the broader handoff gates.

| Boundary | Implemented behavior | Evidence or limit |
| --- | --- | --- |
| Native operation | Retry an actual native TLS handshake with a fresh immutable Network owner, not a synthetic connect-success callback | Four real/default-policy Linux integration tests pass; not Android netd proof |
| Budget | At most three distinct Network attempts; each includes route lookup and TLS and is capped at the configured handshake timeout or six seconds | Default native timeout gives a fifteen-second aggregate cap; host attempt models cover bounds |
| Recovery eligibility | Same required-peer and preferred-validation guards as managed TCP; no global failed-Network blacklist | Shared policy models; device failback unverified |
| Rejection | Preserve typed native errors; explicit peer close, protocol rejection, local cancellation and policy failure do not authorize alternate-Network retry | Classification regressions; no message-string parsing |
| Existing policies | Default outgoing preparation/operation remains single-attempt with the configured deadline | Compatibility and preparation-failure tests pass |
| Incoming and hole punching | Existing preparation and configured deadlines remain unchanged | Existing regression suite, not Android incoming proof |

- Stage33 adds a separate owned-QUIC retry integration; raw UDP still needs ACK-driven attempt ownership.
- First-time pairing and cold-bootstrap retry still require request-owned eligibility.
- No new APK was installed, device configuration changed, or energy measurement taken.

| Stage32 Check | Result and limit |
| --- | --- |
| Workspace, all targets | 2,446 passed across 21 suites; zero failures, 86 ignored; includes shared controllers and Android host models, not device execution |
| Final retry fixture | Four passed again after simplifying two one-iteration loops found by Clippy |
| Native QUIC namespaces | Eight passed: IPv4/IPv6 DHT source return, AutoNAT, configured/automatic reservation return and incoming access |
| Android arm64 release | Default and diagnostics/demand-lifecycle-trial cross-checks pass; no APK linking or netd execution |
| Tooling | Root/vendor formatting, Nix Rust source parity and denied Clippy correctness/suspicious/performance checks pass; 738 library-test advisories remain |
| Device | No authorized device attached during this stage; available-device handoff evidence remains required |
| Resources | One reused target cache, about 6.5 GiB; no new APK or full package/VM build |

The full-workspace pass precedes the test-only loop simplification; the final
focused rerun and Clippy pass cover that cleanup. Production source is unchanged
after the full run. No battery saving is inferred from these results.

### Stage31 Local TCP Retry Integration

This implementation is local, unpublished, and not device-verified.
Stage30 full-workspace/namespace results below are a baseline, not proof of these
new changes. Battery effects remain unmeasured.

| Boundary | Implemented behavior | Verification |
| --- | --- | --- |
| Ordering | Start with OS/destination-specific preference; exclude only Networks already tried in this dial | Host async models passed |
| Budget | Three sequential attempts, six seconds each including lookup, connect and Noise/Yamux authentication | Host deadline and cancellation models |
| Admission | Configured/learned overlay peers, explicit relays and selected pending/accepted relay owners can retry | Registry and Runner intent tests passed, including address-free configuration |
| Public discovery | Unknown public DHT targets do not gain alternate-Network attempts after connection failure | Permission/source-lookup host models |
| Preferred validation | Overlay and infrastructure rounds suppress additional retry Networks while validating preference; scopes cannot clear each other | Registry and shared-controller tests passed; not Android wire proof |
| Port reuse | Retry a source-port collision on the same selected Network with a fresh port | Seven real Linux TCP regressions and Android compilation passed; device behavior unverified |
| Cancellation | Inventory changes reject stale results; withdrawn recovery intent stops additional attempts | Host epoch, permission and cancellation models |
| Failback | No persistent Network blacklist or preference override; later dials recheck OS preference | Host models, not device failback proof |

- Incoming attribution remains unchanged; attempts require an outgoing wildcard source.
- Existing kernel-lookup fallback remains separate from retry after a known route fails.
- Eligibility refresh uses existing recovery maintenance; it adds no interface polling or peer probes.
- Native QUIC retry was unfinished at Stage31; Stage32 adds it locally. Owned QUIC/raw UDP and device gates remain open for P4/P5/P8.
- First-time pairing targets and cold-bootstrap work still need request-owned retry eligibility; do not permit every public DHT peer as a shortcut.

| Stage31 Check | Result and limit |
| --- | --- |
| Physical-network suite | 82 passed, nine ignored; includes 33 Android host-model tests, not 82 Android device checks |
| Shared controllers | 45 passed, 12 ignored |
| Required-peer intent | One Runner test passed; identity-only members included, public relay candidates excluded |
| Native TCP | Seven Linux socket/Noise/Yamux tests passed; not Android netd proof |
| Native QUIC reservations | Four real namespace cases passed: automatic/configured reservations, IPv4/IPv6 return and incoming access |
| Android arm64 release | Default and diagnostics/demand-lifecycle-trial cross-checks passed; no APK/device execution |
| Tooling | Formatting, Nix source parity and denied Clippy correctness/suspicious/performance checks passed; 736 library-test advisories remain |
| Full workspace | Not rerun after Stage31; the Stage30 2,427-test pass is a baseline only |

### Stage28 and Earlier Baselines

These counts predate Stage29 activation and its directional repair. They are
baseline evidence, not a green result for the current Stage29/30 working tree.

| Check | Result |
| --- | --- |
| Android backend model tests | 23 passed, including CLAT unknown/withdrawn distinction, stale binding rejection, fresh-source audits, family return and cancellation bounds |
| Java main/debug compilation and JVM suite | 172 passed with cached SDK/JDK, including 20 inventory regressions and callback retirement/idempotency |
| Vendor unit harnesses | 63 Quinn and six native-library tests passed; three upstream stress tests ignored |
| Physical-network suite with opt-in Linux namespaces | 76 passed; includes 20 Android models, not 76 Android/device checks |
| Owned QUIC route/handoff tests | 22 passed, including rollback-policy coverage; not Android kernel proof |
| Stage28 packet-plane baseline | 104 passed; one ignored; predates the directional repair |
| Shared overlay controller with opt-in namespaces | 37 passed |
| Shared infrastructure controller with opt-in namespaces | 20 passed |
| Stage28 working-tree workspace regression | 2,412 passed across 20 suites; zero failed, 84 ignored; includes the then-current UDP handoff/replay/deadline fixes |
| Stage28 Android arm64 release cross-check | Diagnostics/demand-lifecycle-trial variant passed after that stage's review |
| Isolated backend foundation | Linux all-target compilation and Android arm64 default release cross-check passed |
| Isolated inventory/JNI bridge | Android arm64 default release cross-check passed without the unpublished transport/controller activation |
| Formatting, Clippy correctness/suspicious/performance, Nix source parity | Passed; advisory warnings remain |

### Current Results and Baselines

Full-workspace and namespace counts below include the unpublished Runner activation.
They are local-integration evidence, not isolated-main certification.
The packet-plane component has its own focused checks and publication boundary.

| Check | Result and limits |
| --- | --- |
| Physical notification and legacy reset integration | Two real loopback integration tests passed; physical reconciliation preserves eight hints, followed by an explicit legacy reset |
| Stable physical epoch and recovery models | Unit checks green; repeated same-epoch notifications do not repeatedly restart LAN grace |
| Raw-UDP namespace initiator | Passed in 103.71 seconds with two real interfaces and fixed IPv4 endpoints |
| Raw-UDP namespace responder | Passed in 98.50 seconds with the same fixed-endpoint constraints |
| Asymmetric key promotion before repair | Deterministic red regression: A uses new TX keys while B rejects candidate DATA; A's old RX drain can end before B proves its reverse direction |
| Stage30 directional repair | Focused packet-plane suite: 110 passed, zero failed, one ignored; original asymmetric failure now green |
| Isolated packet-plane component | 110 passed, one ignored; host all-target compilation, Android arm64 default/trial cross-checks, formatting and Nix source parity passed without runtime activation |
| Stage30 host library check | Passed; compilation is not a repaired-regression result |
| Stage30 Android default/trial cross-checks | Final checks passed, including status/state counters and validation-expiry logging |
| Stage30 Clippy | Denied correctness/suspicious/performance checks passed; 739 library-test advisories remain |
| Stage30 source parity | Passed, including the new Rust source files |
| Workspace attempt | Stopped at root units: 1,970 passed, one failed, 32 ignored; randomized legacy-ledger fixture hit a builtin-IPv4 collision, isolated rerun passed |
| Fixture correction | Six identities now have unique builtin IPv4 addresses; production conflict rejection unchanged. Isolated fixture passed and was published independently |
| Stage30 full workspace | 2,427 passed across 20 suites, zero failed, 86 ignored; includes 1,971 root-library and eight real connection-recovery tests |
| Stage30 updated namespace run | Three passed in 208.17 seconds: minimal UDP config and fixed-endpoint failback for both original peer roles |
| Stage29 Android cross-check | Not performed; earlier Android cross-checks are baseline only |
| Namespace scope | Fixed IPv4 endpoints, two real interfaces; strict active IDs/data through blocked validation, 20-second expiry and no-event retry |
| Namespace limits | Moving-host outbound UDP quietness only; legitimate peer destination-specific RX may remain on the old link. No RX/FD retirement, default-source or Android proof |

These passes do not establish device/CLAT, APK, full Nix package/VM, complete
Android handoff or energy results.

The published backend slice is also checked in isolation from the unpublished
managed-transport, controller and packet-plane wiring. The inventory/JNI bridge
is independently published without activating those unfinished transports.

JVM retirement coverage does not invoke Android framework registration failures
or unregister exceptions. Those lifecycle branches still need device coverage.

The baseline builds reused one target cache, approximately 6.6 GiB, with two build
jobs and incremental/debug artifacts disabled. No energy comparison was performed.

## Publication Contract

- Publish verified additive vendor primitives and the inactive route-backend foundation independently.
- Publish inventory/JNI plumbing independently; do not couple it to unfinished transport activation.
- Publish [packet-plane primitives](packet-plane-physical-ownership.md) without enabling physical-policy startup or Android managed controllers.
- Keep managed transport, controller and packet-plane activation local until complete handoff gates are satisfied.
- Publish coherent startup/handoff wiring only with its source, regression, artifact and available-device evidence.
- Preserve explicit legacy global recovery while routing physical preference updates through non-destructive reconciliation.
- Stage54 records APK deployment and physical-device handoff; battery comparison remains outside this goal.

## Historical Raw UDP Integration

At this earlier stage, primitives were published separately from local Runner
activation. The table preserves its then-open proof boundaries; current device
evidence and publication are recorded in the fixed ledger.

| Boundary | Implemented behavior | Remaining proof |
| --- | --- | --- |
| Socket | Reuse tested shared-port companion I/O; retain original and companion receive paths | Android netd and device RX/TX |
| Receive | Preserve GRO boundaries and the actual destination address; lookup follows authenticated event selection | Host large-aggregate regression passed; device evidence remains |
| Ownership | Exact per-session token, per-listener immutable route, cached source/remote tuple checks | Address changes and withdrawal on a device |
| Preparation | No lookup per cached packet; failures/cancellation use bounded local cooldown | Sustained churn/resource evidence |
| Startup and audit | Local Runner activates physical ownership and route reconciliation on Linux/Android; epoch, token, listener and destination must match | Android cross-checks, full workspace and three Linux namespace cases pass; no device proof |
| Validation | Independent candidate RX authorization after successful matching scoped ACK send, and local TX promotion after its own matching ACK proof | Focused repair and updated namespaces pass; Android kernel/netd remains unverified |
| Notification | Android JNI uses local non-destructive physical reconciliation; stable-epoch handling coalesces repeated recovery signals | Loopback integration and epoch/model checks passed; device callbacks remain unverified |
| Retention and cleanup | Preserve possibly-used RX keys and immutable slots through original TTL; 64-slot budget reserves two per candidate and rejects admission when full | Focused, lifecycle and counter integration pass; early/exact old-socket retirement remains open for P6 |

- GRO backing storage is bounded by the runtime's advertised segment capacity, up to 64 datagrams per listener.
- Each delivered datagram remains bounded to 65,535 bytes; aggregate storage can reach approximately 4 MiB.
- Raw-UDP physical startup and automatic route replacement are enabled in the local Stage29 Runner only, not published.
- Physical notifications no longer request the global reset in that local integration. Explicit legacy reset remains available and tested separately.
- Stopping redundant old outbound traffic does not establish that old receive keys are safe to discard.

### Lifecycle Diagnostics

| Status/state counter | Meaning |
| --- | --- |
| `packet_plane_udp_validation_pending` | Candidates still awaiting TX validation; the updated namespace lifecycle gate waits for zero |
| `packet_plane_udp_receive_only_sessions` | Retained receive-only UDP ownership, not scheduled old-path maintenance; must remain bounded by the 64-slot admission budget |
| `packet_plane_retiring_sessions` | Existing retirement count remains visible; it is not redefined or required to be zero merely because TX validation completed |
| `packet_plane_udp_validation_expired receive_retained=bool` | Validation ended, including when authorized RX archives; fixture timeout proof even after a locally successful but firewall-dropped ACK |
| `packet_plane_udp_handoff_retired` | Actual key retirement, not validation-timeout proof |
| Updated fixture gate | Passed: pending validation zero, one healthy UDP path per peer, retained RX at most 64, not zero |
| Continuity checks | Exact blocked-stage session IDs and six-second moving-host old-outbound quietness |
| Admission invariant | Retained ownership plus two reservations per pending candidate must fit 64; RX count alone does not prove reservation handling |

### Managed UDP Candidate Contract

The published primitives are covered by the focused 110-test pass. Local activation
also passes workspace/namespace checks; complete Android behavior and P6 remain open.

| Phase | Payload path | Promotion or retirement |
| --- | --- | --- |
| Candidate validating | Existing active TX keys and cached route remain installed; candidate DATA has no unconditional admission | Fresh-token ACK on the exact candidate listener and current preferred route |
| Candidate RX authorized | New-key DATA becomes eligible only after successfully sending the exact scoped ACK on that candidate owner | RX authorization does not itself prove or promote local new-key TX |
| Candidate timeout or supersession | Existing active TX continues; an RX-authorized candidate is archived as silent RX ownership | Twenty-second validation expiry or supersession does not evict authorized RX state; unauthorized candidates cannot authorize DATA |
| TX promoted | New application sends use the validated key/route pair | Do not infer that the peer has proved its reverse TX direction or stopped using old keys |
| Old RX retained | Preserve all possibly-used keys, original age, DATA replay state and immutable slots independently of old outbound traffic retirement | Retain through original TTL under hard-bounded admission; no eviction merely to admit a new candidate |
| Archived owner silent | No scheduled old-path payload, probes or keepalives; exact scoped replies use cached slots only | No route/socket reacquisition; original expiry releases ownership, while early/exact socket retirement remains an open P6 gate |

- Candidate DATA must fail closed before exact scoped ACK success; merely preparing, starting or failing an ACK send cannot authorize it.
- Exact route validation precedes replay acceptance. Wrong-interface copies cannot consume the valid packet's replay slot.
- Scoped receive does not await route acquisition; selected-event handling performs validation and replay acceptance.
- Probe replies use the received session owner, not whichever session is now active.
- Promotion ACK freshness is one-time, separate from DATA replay. Validate exact route, listener, token, deadline and current lease first.
- DATA replay protection is unchanged.
- Candidate/reply sends check expiry before every transmission attempt, including writable resumes.
- Link-local scope-zero lookup identifies authentication candidates only; route validation still requires the received scope and local tuple.
- When retention capacity is exhausted, defer or reject new admission rather than evict still-needed old RX keys to make room.
- Retention never extends the original key lifetime or authorizes redundant old-underlay TX. No monotonic handshake/key ordering is assumed and no new wire field is added.
- The blind three-second old-RX eviction is removed. Retaining immutable receive ownership through original TTL is not proof of early/exact old-socket retirement.

| Bound | Value or pending requirement |
| --- | --- |
| Candidate validation | 20 seconds, capped by original key lifetime |
| Retiring-map ownership/admission budget | 64 total slots, with two reserved per candidate; full capacity rejects new negotiation, never evicts possibly-used RX keys |
| Authorized RX retention | Original key TTL, including authorization-preserving archival on candidate timeout or supersession; no blind three-second eviction |
| Archived TX | Cached exact replies only; no socket/route reacquisition or scheduled probes |
| Verification | Focused, workspace/counter and namespace runs pass; P6 early/exact socket retirement remains open |

Stage28's nine encrypted loopback handoff cases and two deadline cases are baseline
evidence. Current results and pending gates are recorded above, not device/netd
routing or energy proof.
