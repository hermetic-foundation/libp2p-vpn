# Physical Network Acceptance Ledger

## Authority

This is the fixed ledger for the clarified physical-network goal. It preserves
completed work rather than restarting it. Earlier P1-P11 tables and stage records
remain historical evidence, not additional completion gates.

- Energy evaluation is outside this goal.
- Necessary receive-only ownership may remain until original protocol expiry, within hard bounds.
- Early receive-key/socket retirement is optional, not required for completion.
- Unavailable Android-device validation remains pending, not complete.
- No percentage is assigned; implementation, verification and publication are tracked separately.
- Android 10 / API 29 is the user-approved minimum. Historical API-26 evidence is retained, not rewritten as API-29 APK verification.

## Milestones

| ID | Milestone | Current state | Concrete exit condition |
| --- | --- | --- | --- |
| M1 | Completed policy/Linux integration baseline | Closed | Preserve the published Linux routing/native-QUIC/circuit migration evidence; reopen only for a named, reproduced regression affecting that behavior |
| M2 | Android integration | Open; substantial local implementation | All required Android paths use OS-directed Network ownership; complete source-bound negotiation, recovery admission, DNS/address reconciliation and validated handoff without additional configuration |
| M3 | Regression acceptance | Open; existing passes retained | The fixed case matrix below passes for the changed integration, with focused checks during iteration and broader checks at integration boundaries |
| M4 | Device validation and publication | Pending | Authorized Android handoff/traffic checks pass, device settings are restored, and verified remaining components are published as atomic Conventional Commits on main |

M1 closes the completed Linux milestone, not untested Android behavior or new
shared-code changes. A new shared-code regression needs a specific failing case;
it does not invalidate unrelated completed Linux evidence.

## Required Android Work

| ID | Requirement | Implementation status | Remaining acceptance |
| --- | --- | --- | --- |
| A1 | OS preference, destination routes, overlay exclusion | Inventory, binder and LAN-discovery foundations published; transport/controller activation local | Finish and verify integrated selection across all listed traffic classes |
| A2 | UDP source selected before Hello/Accept signing | Local preparation/adoption and source publication pass both-role IPv4/IPv6 real-control ACK tests; crossed-Hello, fallback and arm64 checks pass | Publish the coherent runtime slice after remaining recovery/address integration; device proof remains pending |
| A3 | Bounded automatic recovery and preferred revalidation | Local raw-UDP admission/revalidation implemented and host-verified; preferred-owner backend published | Integrate and verify across remaining Android transports; publish coherent runtime activation and obtain device proof |
| A4 | DNS and advertised-address reconciliation | DNS components published; local hostname-only UDP/QUIC workflows and owner-scoped alias reconciliation pass host checks | Verify API-29 artifacts and Android address-loss/handoff behavior; publish coherent activation |
| A5 | Ingress, IPv6 and stacked sources | Ingress attribution helper published independently; local activation and Android host models pass | Resolve unsupported or ambiguous source handling; verify Android kernel/netd behavior and caller integration |
| A6 | Overlay, infrastructure and pairing integration | Managed TCP/native QUIC, owned QUIC, controller and non-destructive notification wiring local | Integrated discovery, DHT, AutoNAT, relay, incoming access and stable-epoch LAN-first recovery checks |

Automatic public hints from a different socket/Network are not raw-UDP NAT proof.
Explicit configured mappings retain their configured-assertion semantics and
still require authenticated path validation before activation.

## Fixed Regression Matrix

| Case | Required result |
| --- | --- |
| Preference change | Follow the OS-selected route for the destination/family, not a hardcoded transport ranking |
| Preferred-path loss | Recover automatically through an eligible fallback; preserve usable incoming/LAN paths |
| Preferred-path return | Keep fallback payload service until authenticated preferred-path validation succeeds |
| Return after a blocked attempt | Retry with bounded fresh work when the path becomes usable, including without another physical event |
| Address replacement | Correct source/advertisement ownership after same-interface address changes, including IPv4/IPv6 |
| Stale completion | Old epochs, incarnations, tokens, callbacks and worker results cannot install or promote stale paths |
| Discovery isolation | Overlay and pairing mDNS queries/replies stay on eligible selected LAN interfaces, never cellular or our overlay |
| Repeated transitions | Bounded work, queues, sockets, retained state and retry/backoff behavior; no connection storm |
| Fallback retirement | Stop redundant old payload, probes, keepalives and connections after promotion; release necessary retained RX state at protocol expiry within hard bounds |
| Asymmetric routing | Do not require Linux incoming routing to mirror local TX selection; preserve destination-specific routes |
| Workflow compatibility | Preserve identity, membership, pairing, DNS, minimal JSON/Nix configuration and existing transport fallbacks |
| Android device | Demonstrate incoming/outgoing access, loss/return and interface-level traffic attribution on authorized hardware |

IPv4 and IPv6 are covered by automated acceptance, not inferred from one another.
Host models and cross-compilation are not substitutes for Android device proof.

## Preserved Evidence

| Evidence | Scope and result | Publication |
| --- | --- | --- |
| Linux native QUIC/circuit milestone | IPv4/IPv6, both original circuit roles, preferred/alternate/return, exact owners and stale/old-tuple checks | Published; `8f55709c1df1` and prerequisites |
| Android foundations | OS inventory/JNI, scoped LAN discovery, bounded Network attempts and socket primitives | Published separately; not full Android activation |
| Receive metadata and Quinn preparation | Low-level suite: 5 passed; Quinn suite: 69 passed, 3 ignored | Published as `1b977fde1388` and `740fb9a5d7c3` |
| Stage41 isolated publication snapshot | Workspace: 2,469 passed, zero failed, 87 ignored | Exact published component source, not the current large WIP |
| Stage41 local integration snapshot | Core: 2,060 passed, zero failed, 33 ignored; both fixed-endpoint IPv4 UDP role fixtures passed in 192.40 seconds | Local evidence; activation unpublished |
| Stage41 Linux scope regression | New IIF-equals-egress check failed; repaired without changing fixture routing, timers or recovery assertions | Repaired local baseline; M1 stays closed |
| Stage42 intermediate source checks | Linux library and Android arm64 release compilation passed | Predates the newest edits/tests; not final-tree certification |
| Stage43 local UDP slice | 114 passed, zero failed, three existing namespace tests ignored; real IPv4/IPv6 deferred control replies, ACK-gated payload, both crossed-Hello phases, peer-order completion, cancellation and bounds | Local only; not full Android certification |
| Stage43 Android host/type checks | Physical-network host models: 60 passed, zero failed, one ignored; default and diagnostic/lifecycle arm64 release compilation passed | Local activation snapshot; no APK/device result |
| Stage43 extracted ingress component | Six focused host tests passed, one existing namespace case ignored; Android arm64 release compilation and format checks passed on the extracted source | Published as `1144adc0e1fa`; not activation or device certification |
| Stage44 local source publication | UDP slice: 130 passed, zero failed, three ignored; full core: 2,094 passed, zero failed, 33 ignored; default and diagnostic/lifecycle arm64 checks plus Clippy correctness/suspicious/performance gates passed | Local integration; generated-source state is extracted separately, not runtime activation |
| Generated-source publication state | Deterministic generated/retained alias handling, explicit overrides and shared 32-alias bound; six focused model tests | Published as `98684d76f409`; not Android activation |
| Stage45 local recovery admission | Latest core: 2,107 passed, zero failed, 33 ignored; IPv4/IPv6 real-control/payload preferred validation, bounded fresh-work/backoff and stale-token models; default and diagnostic/lifecycle arm64 compilation and Clippy correctness/suspicious/performance gates passed | Local runtime snapshot; no APK/device result |
| Preferred-owner identity | Exact extracted component: 49 Android backend host tests passed, zero failed, one namespace-only test ignored; Android arm64 release compilation and formatting passed | Published as `57704a91858d`; not runtime activation |
| Stage47 local DNS integration | Latest backend/DNS suite: 86 passed, zero failed, one ignored; real DNS/DNSaddr, UDP-to-TCP, stale/bounds and cross-scope snapshot checks; Android default and diagnostic/lifecycle compilation passed | Local resolver activation; Private DNS adapter and full hostname-handshake proof remain required |
| Stage47 broad snapshot | Core: 2,128 passed, zero failed, 33 ignored; Clippy correctness/suspicious/performance and Nix source-parity passed | Core snapshot predates final negotiation-snapshot preservation edits; not whole-tree or device certification |
| Network DNS metadata | Exact extracted component: 70 Android backend host tests passed, zero failed, one ignored; 26 JVM tests, Java service source compilation, Android arm64 compilation and formatting passed | Published with this independent metadata component; not resolver activation |
| Stage48 local DNS/negotiation | Focused Android/backend/DNS/UDP suite: 112 passed, zero failed, one ignored; real zero-TTL hostname-only IPv4/IPv6 negotiation, ACK-gated payload, DNS-wait bounds/deadlines and authorization cleanup | Local integration; default and diagnostic/lifecycle Android arm64 compilation passed; no APK/device claim |
| Stage48 integrated core snapshot | Core: 2,139 passed, zero failed, 33 ignored | Includes the new hostname negotiation and DNS deferral edits; not device certification or acceptance of later address-withdrawal changes |
| Native platform DNS adapter | Exact extracted source: 11 callback ownership/error tests and 70 existing Android backend host tests passed, zero failed, one ignored; Android arm64 compilation and formatting passed | Independent adapter component; resolver and runtime activation remain local |
| Network-scoped resolver backend | Exact extracted source: 92 Android backend/DNS and 11 native adapter tests passed, zero failed, one ignored; Android arm64 compilation, Nix source parity, formatting and Clippy correctness/suspicious/performance gates passed | Independent backend component; transport/runtime activation remains local |
| Stage49 restored integration | 11 focused tests passed, zero failed: IPv4/IPv6 hostname-only UDP negotiation, spawned zero-TTL QUIC binding/payload, retired-epoch no-connect and DNS/source queue checks | Local workflow evidence after extraction/rebase; not device or owner-withdrawal proof |
| Stage50 owner-scoped publication | Final focused set: 36 passed, zero failed; native owner/overlap/bounds, real Swarm alias aggregation and ACK state, IPv4/IPv6 payload retention and hostname negotiation | Local implementation; preserves explicit/observed/prepared/fallback claims and does not advertise a client-only QUIC port |
| Stage50 workspace boundary | 2,629 passed, zero failed, 89 ignored across 22 suites; includes 2,157 core tests | Exact local runtime snapshot, not API-29 APK/device verification |
| Stage50 explicit TUN regressions | Three minimal-config QUIC/UDP/stream cases and both raw-UDP failback roles passed; failback pair completed in 192.61 seconds | Existing Linux assertions retained; M1 remains closed |
| Stage50 static/type checks | Cached-toolchain Android arm64 default and diagnostic/lifecycle checks, Clippy correctness/suspicious/performance, formatting and Nix source parity passed | Type/source evidence only; does not certify rebuilt API-29 native artifacts |
| Stage50 Android wiring audit | No concrete A1/A5/A6 missing callsites found; managed transports, both controllers, pairing, ingress and notifications include Android | Read-only source review, not kernel/netd execution proof |
| Android 10 minimum policy | Exact Gradle/Nix minima agree on API 29; fake-device preflight rejects API 26/28 and accepts 29; audit evidence contract, ShellCheck 0.11 and Nix audit-structure check pass | Published policy; rebuilt artifacts are covered separately below |
| Stage51 API-29 artifacts | Both Nix native outputs and an offline dual-ABI APK pass API/SDK, 16 KiB alignment, JNI and source-provenance checks; 196 JVM tests pass; lint has 12 warnings, zero errors | Local deployment candidate; no full Nix APK/check or device-pass claim |
| Stage52 physical callback corrections | API-37 device exposed a VPN-default callback and hidden background inventory; best non-VPN selection plus the network-state permission now show both Networks with Wi-Fi preferred; 197 JVM tests pass | Local corrections; no complete Android-handoff pass |
| Stage52 first WAN transition | Cellular initially recovered, then steady traffic failed despite aggregate relay connectivity; automatic LAN return recovered | Failure retained; investigate target-circuit replacement rather than treating connectivity counters as data-path proof |
| Stage52 corrected-permission transition | Cellular trace 91/185, late outbound IPv4/IPv6 0/10 each; replacement circuit eventually restored incoming traffic. LAN return selected direct QUIC, zero relay paths and passed 5/5 per family with unchanged process/identity | Cellular acceptance still fails; callback corrections and successful LAN return do not close M4 |
| Stage52 finite-circuit regressions | Two real 12-second / 32-KiB relay tests passed in 66.95 seconds: expiry replacement and overlapping-successor preservation | Local host fixtures; no Android outer-Network migration or prolonged-stall reproduction claim |
| Current Android device | Authorized device attached and updated in place during Stage52; profile and membership hashes preserved | Focused handoff/traffic checks in progress; not complete |

See [Linux native QUIC evidence](libp2p-quic-physical-ownership.md),
[Android integration details](android-transport-policy.md), and
[receive-scope contract](udp-receive-scope.md) for the retained stage records.
The [source-publication contract](udp-source-publication.md) separates the
published state model from local transport integration.

## Next Deliverable

Authorized Android handoff evidence using the verified API-29 candidate:

1. Recheck the candidate's recorded fingerprint before installation; reuse the existing bounded build/cache state.
2. Deploy to an authorized supported device without replacing identity, profiles or pairing data.
3. Verify incoming/outgoing access, source/address loss and OS-preferred return, including interface-level traffic and retired-path quietness.
4. Publish remaining coherent runtime changes atomically after their exact-source acceptance gates; preserve the closed Linux milestone.
5. Restore device settings and keep unavailable hardware checks pending, without energy claims.

Source-bound negotiation, recovery, hostname workflows and owner-scoped alias
withdrawal now have local host evidence. The API-29 adapter, resolver backend
and minimum-version policy are published independently. Rebuilt API-29 artifact
checks now pass; coherent activation publication and Android device acceptance
remain open.

The [Stage51 artifact record](android-api29-artifacts.md) records native/APK
fingerprints and exact verification limits. Packaging reused the existing Gradle
cache offline instead of fetching the full Nix APK path's extra 231.4 MiB.
No new Gradle/emulator cache was created. Linux M1 stays closed.

The [Stage52 callback record](android-physical-callbacks.md) separates confirmed
Android registration/permission defects from the still-unconfirmed relay failure.
The original transition failure remains evidence; it is not erased by a later run.

## Commit Boundaries

| Candidate component | Verification before publication |
| --- | --- |
| Coherent runtime activation | Managed transports, controllers, notifications, preparation/adoption, recovery and source publication together with their private-API tests; retain exact-source focused/workspace, Android artifact and device acceptance gates |
| Black-box regression fixtures and policy evidence | Physical-hint integration and both raw-UDP namespace roles with their complete fixture registration; preserve documented scope and closed M1 evidence |

The Stage51 publication review found that source signing, prepared-owner adoption,
retry tickets, DNS snapshots and alias reconciliation share runtime contracts.
Their backend extractions are already published; further unwired fragments would
not be independently meaningful commits.

Existing Linux fixtures are rerun when shared-code risk warrants it, not as a
fresh M1 restart. Unavailable device acceptance does not count as a pass.

## Deferred Work

- Early/exact RX-key or old-socket retirement before original protocol expiry.
- Unrelated refactoring, cleanup and API redesign.
- Battery benchmarking, numerical battery targets and energy experiments.
