# Physical Packet Ownership

## Scope

This component supplies route-owned packet-plane primitives for Linux and Android.
It does not activate Android managed transports or handoff controllers.
Raw-UDP physical-policy startup and runtime notification integration are separate.

The existing Linux QUIC migration milestone remains available.
See [Physical Network Policy](physical-network-policy.md) for full acceptance gates.

## Ownership Contract

| Boundary | Rule |
| --- | --- |
| Prepared route | Immutable source, destination, interface and platform lease |
| Android socket | Bound to a specific Network incarnation before transmission |
| Cached packet | No fresh route lookup on each send |
| Incoming packet | Authenticate first; validate exact owner and tuple before replay acceptance |
| Audit result | Match observation epoch, session token, listener and destination |
| Candidate promotion | Require authenticated round-trip proof on the current preferred route |
| Retired reply | Use the original cached route; never acquire another old-path socket |

## UDP Directions

Local transmit promotion and remote transmit progress are independent.
A local promotion must not destroy keys that the peer may still use.

| State | Application TX | Application RX | Lifetime |
| --- | --- | --- | --- |
| Active | Current key/route pair | Authenticated, exact tuple, replay checked | Original key lifetime |
| Candidate, unauthorized RX | Existing active pair | Candidate probes only | Validation budget |
| Candidate, authorized RX | Existing active pair | Allowed after matching scoped ACK was successfully sent | Original key lifetime |
| Promoted | Validated candidate pair | Candidate becomes active | Original key lifetime |
| Receive-only | Never selected for normal TX | Original session and replay state retained | Original key lifetime |

- A matching ACK to our own fresh challenge permits local TX promotion only.
- Successfully sending an ACK grants the peer permission to send; ACK loss does not revoke that permission.
- Validation timeout stops candidate promotion/probing, but preserves already-authorized RX keys.
- Supersession moves authorized RX state; it does not duplicate or reset replay windows.
- Expiry of active TX keys does not discard younger, independently live RX keys.
- Revocation and explicit session reset remove all corresponding ownership immediately.

### Delayed ACKs

Application data can overtake its route-validation ACK by more than 64 sequences.
An authenticated ACK matching the outstanding random challenge has a separate,
one-shot freshness proof. It still requires the exact owner, tuple and listener.

- The original validation deadline and current preferred lease must still hold.
- Only that proof may bypass a DATA replay-window age/duplicate rejection.
- It does not deliver application data or rewind/reset the replay window.
- Consumed or superseded candidate proofs cannot promote another owner.

## Bounds

| Resource | Limit |
| --- | --- |
| Candidate peers | 16 |
| Retained ownership budget | 64 slots; each pending candidate reserves two slots |
| Candidate validation | 20 seconds, capped by original key lifetime |
| Authorized RX retention | Original key lifetime; later TTL reductions apply |
| Route-preparation retry | Local exponential cooldown, one to 30 seconds |
| GRO receive storage | At most 64 datagrams per listener; each datagram at most 65,535 bytes |

New negotiation is rejected before ownership mutation when capacity is exhausted.
Existing authorized RX keys are not evicted to make room.
Retained state does not create autonomous old-path probes or keepalives.

## Verification

The focused packet-plane suite passed 110 tests, with one ignored.
It includes encrypted IPv4/IPv6 loopback ownership and asymmetric-promotion cases.

The component was also checked without the unpublished Runner activation:
host all-target compilation, both Android arm64 variants, formatting and Nix
Rust-source parity passed.

```sh
nix develop -c cargo test --locked --lib runtime::packet_plane -- --test-threads=2
```

| Regression | Covered behavior |
| --- | --- |
| Asymmetric promotion | New-key DATA accepted while the reverse challenge remains pending |
| Delayed ACK | More than 64 DATA frames cannot invalidate the outstanding one-shot proof |
| Supersession | Receive keys and replay history survive replacement negotiation |
| Capacity | Admission refusal preserves existing ownership and endpoints |
| Expiry/revocation | Original lifetime, reduced TTL and independent RX/TX cleanup |
| Stale input | Wrong listener, tuple, owner or route cannot promote or consume a valid replay slot |
| Cancellation | Expired sends cannot resume transmission; canceled reads retain datagram boundaries |

## Remaining Evidence

- Host tests and Android cross-compilation do not prove Android kernel/netd routing.
- Receive-key retention does not establish early, exact old-socket retirement.
- Full handoff still requires runtime integration, discovery scope and device validation.
- Battery effects require separate measurements; no energy saving follows from these tests.
