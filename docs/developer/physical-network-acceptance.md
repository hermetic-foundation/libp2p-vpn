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
| A2 | UDP source selected before Hello/Accept signing | Local preparation/adoption, both signing roles, real deferred control replies and crossed-Hello tests pass; arm64 compilation passed | Finish source-appropriate acknowledged endpoint publication; device proof and integration-boundary checks remain separate |
| A3 | Bounded automatic recovery and preferred revalidation | Retry cursor and promotion models exist locally | Admit genuinely new demand/control work after exhaustion; independently validate preferred return without repeatedly resetting attempts on Hello/ticks |
| A4 | DNS and advertised-address reconciliation | Existing DNS preserved; endpoint acknowledgement/native-source guards exist | Network-scoped resolution, source ownership/lifetime reconciliation, and correct withdrawal without manual routing configuration |
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
| Current Android device | No ADB device attached during reconciliation | Pending; no deployment or device-pass claim |

See [Linux native QUIC evidence](libp2p-quic-physical-ownership.md),
[Android integration details](android-transport-policy.md), and
[receive-scope contract](udp-receive-scope.md) for the retained stage records.

## Next Deliverable

A verified Android UDP negotiation slice, not publication of the entire WIP:

1. Select and retain the source Network/socket before signing Hello or Accept.
2. Require source-appropriate acknowledged endpoint metadata; preserve explicit overrides without inventing NAT mappings.
3. Install that exact prepared owner; reject stale, canceled, reused or changed-destination work.
4. Verify both roles, deferred replies, cancellation, capacity and fallback continuity with focused tests and Android compilation.
5. Publish coherent independently verified components; leave M2 open for recovery admission, DNS and remaining integration.

## Commit Boundaries

| Candidate component | Verification before publication |
| --- | --- |
| Android ingress attribution | Focused ownership/source/IIF models, Android compilation, review of tuple/authentication/replay ordering |
| UDP pre-signing preparation and adoption | Backend/worker/negotiation tests, both roles, cancellation/stale/bounds checks, Android compilation |
| Recovery-intent and preferred-validation admission | Exhaustion/new-demand/role-switch/backoff regressions; no Hello/tick reset loop |
| DNS/address reconciliation and transport activation | Relevant focused tests followed by broad workspace, minimal-config and affected namespace acceptance |

These are dependency-aware boundaries, not a requirement to publish incomplete
activation or scatter related changes into unusable fragments. Existing Linux
fixtures are rerun when shared-code risk warrants it, not as a fresh M1 restart.

## Deferred Work

- Early/exact RX-key or old-socket retirement before original protocol expiry.
- Unrelated refactoring, cleanup and API redesign.
- Battery benchmarking, numerical battery targets and energy experiments.
