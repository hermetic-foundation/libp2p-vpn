# Android Live Transport Snapshot

Debug API: `transport-snapshot`, schema 1. See
[integrated device evidence](android-physical-handoff-stage54.md) and the
[publication ledger](physical-network-acceptance.md).

## Purpose

Capture one active network's live transport state during a handoff failure.
Unlike the cached health summary, this view includes individual peers,
capabilities, paths, physical owners and relay circuit bindings.

This is an on-demand debug endpoint. It does not change routes, start dials,
refresh leases, pause discovery or schedule periodic captures.

## Request

Use an authorized USB-debugging device and the debug application:

```sh
adb -s "$SERIAL" shell am broadcast --receiver-foreground \
  -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION \
  -n org.hermeticfoundation.p2pvpn.debug/.DebugAutomationReceiver \
  --es command transport-snapshot --es network_id "$NETWORK_UUID"
```

`NETWORK_UUID` identifies an active Android profile, not its display name.
Obtain it from the existing debug `status` response's `networks[].id`.

Decode the ordered broadcast's Base64 `data` as UTF-8 JSON. A successful
response uses the existing automation envelope:

```json
{
  "schema_version": 1,
  "ok": true,
  "value": {
    "schema_version": 1,
    "network_id": "00000000-0000-4000-8000-000000000001",
    "lines": ["daemon state: running"]
  }
}
```

## Bounds

| Boundary | Limit |
| --- | --- |
| Access | Debug receiver; Android `DUMP` permission |
| Selection | One canonical UUID; active runtime required |
| Work | One live `State` request; no retry |
| Deadline | Five-second control timeout; bounded runtime shutdown |
| Java scheduling | One worker; no queued requests; idle worker retires |
| Payload | 4,096 lines; 8 KiB per line; 256 KiB raw and serialized native envelope |
| Oversize | Explicit failure; no partial/truncated snapshot |
| Recent events | At most 96 actor-local records; 1 KiB per record; five-minute visibility |

Concurrent requests return `transport_snapshot_busy`. Inactive networks,
timeouts, oversized data or an incompatible native library return
`transport_snapshot_unavailable`; they do not restart the VPN.

## Interpretation

| Prefix | Evidence |
| --- | --- |
| `peer state:` | Target authentication, selected path and capability state |
| `peer path state:` | Candidate health, protocol and exact connection ID |
| `physical control state:` | Socket owner, source/destination, interface, generation and Android Network identity |
| `physical circuit state:` | Inner circuit, outer relay connection and their epoch usability/retirement |
| `transport event:` | Recent close cause, local close intent or negotiated relay limit; sequence and monotonic age |

Physical lease flags describe recorded ownership and inventory state, not a
fresh authenticated preferred-route probe. Missing circuit bindings are shown
as unknown; aggregate relay connectivity is not proof of a usable peer path.

The event history is a separate bounded diagnostic, not a complete log.
`transport_event_history_overwritten` reports count-based eviction. A capped
record has `truncated=true`; the outer snapshot is still never silently cut.

History belongs to one runtime scope and is not carried across restarts or
network instances. It excludes unrelated pairing events and is not included
in periodic health views. Recording adds no timers or network requests.

Relay-limit events retain the reported duration and byte allowance. The native
relay event does not identify a specific inner connection: correlate its role,
peer and age with circuit-owner evidence instead of inventing an exact binding.

## Evidence Handling

1. Record the APK fingerprint and capture time.
2. Capture both endpoints before, during and after the same failure.
3. Correlate target peer and connection IDs with source-bound traffic results.
4. Keep raw captures private: peer IDs and network addresses are included.
5. Restore radio settings; preserve profiles, membership and pairing state.

Do not use this endpoint as a battery benchmark or enable a permanent polling
loop. Hardware acceptance still requires successful data delivery and cleanup.
