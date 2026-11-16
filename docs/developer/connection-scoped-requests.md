# Connection-Scoped Requests

## Contract

The local `libp2p-request-response` patch adds exact-connection requests without
changing protocol bytes, codecs, configuration, or default connection selection.

| API | Behavior |
| --- | --- |
| `send_request_on_connection_with_deadline` | Send only through the named established connection to the named peer |
| `send_request_on_connection_cancellable` | Same selection, with local cancellation and an absolute deadline |
| `set_connection_outbound_enabled` | Include/exclude a connection from future ordinary outbound selection |
| `has_pending_requests_on_connection` | Inspect exact queued, response, and active-stream ownership without I/O |

## Ownership Rules

- A missing connection returns the original request without allocating an ID, dialing, or queueing work.
- Accepted requests keep their native ID until a terminal response or failure event.
- Closing the selected connection fails the request; it never reroutes to a sibling connection.
- Deadline and cancellation use the existing handler preflight and bounded request operation.
- Exact requests bypass ordinary-selection exclusion so quarantined candidates can be validated.
- Exclusion does not move already queued or in-flight work; drain checks account for that work.

## Ordinary Selection

| State | Result |
| --- | --- |
| All connections enabled | Existing request-ID modulo distribution is preserved |
| Some connections disabled | Select only among enabled connections |
| All connections disabled | Existing dial-and-queue behavior; no disabled connection is selected |
| Connection re-enabled | Future sends may use it; pending dial-queue entries are not moved |

Callers must enable a validated replacement before disabling the last usable
fallback. This API does not implement migration policy or authorize a peer.

## Verification

- Nine focused library tests cover exact selection, missing/mismatched ownership, closure, deadline, cancellation, busy state, and ordinary-selection compatibility.
- The excluded dependency is tested from a temporary source copy using the existing target cache.
- That library-only harness omits unused CBOR and ring-buffer dependencies from its temporary manifest; production manifests retain them.
- The explicit test-only identity `rand` feature permits standalone peer generation. No test source is changed in the harness.
- Workspace and real-TUN checks separately exercise the production dependency graph and runtime integration.
