# Split-device browser LAN qualification

This milestone adds a repeatable two-device qualification harness. Physical
two-device LAN delivery remains **NOT YET QUALIFIED** until the second-device
run produces paired native and browser evidence. A same-host smoke run is a
separate verdict and must not be reported as a LAN pass.

See the [operator commands](../user/browser.md#run-on-two-devices-over-a-lan).

## Architecture and evidence

- `scripts/test-browser.ps1 -Lan` requires explicit private native/client IPv4
  addresses. A client address belonging to the native host is rejected unless
  `-LocalSmoke` is selected. Each run uses a fresh directory and identities.
- The native fixture exports the page, generated WASM/JS, pinned Node package
  lock, client runner and the disposable browser configuration. The bundle
  excludes the native private key and the loopback shutdown token. Membership
  expires after one hour. The host records archive/WASM/executable SHA-256 values.
- The second device runs a loopback-only static server with an exact Host check
  and an allowlist of five page/session/package URLs. It does not expose a
  LAN HTTP listener. Native setup/control also remains on loopback.
- Native firewall policy is scoped to the selected executable, listener port,
  host IP and expected client IP for UDP; HTTP is scoped to the fresh TUN
  interface, overlay endpoints and service port. Normal success, timeout and
  handled failure enter the cleanup path.
- Chrome tests the same signed membership and packet authorization as the local
  harness, obtains a fresh HTTP response through Wintun, sends an unauthorized
  source, explicitly resets the connection, then obtains another fresh response
  with the same browser peer identity. Both selected candidate pairs and byte
  counters are saved.
- The returned report is checked against the exact native peer/session, browser
  peer, WASM hash, validity window, UDP endpoint and operator-selected client IP.
  Its two distinct HTTP nonces must also appear in native TUN-service request
  logs from `10.203.0.2`; both native WebRTC delivery and source-rejection counters
  must be positive. Shutdown, TUN removal and both firewall-rule removals must
  pass before a verification verdict is written.

Outputs are under `target/browser-lan-TIMESTAMP`, or
`target/browser-lan-smoke-TIMESTAMP` for explicit same-host runs. Client keys are
in the ignored client directory/ZIP, not the public reports. A failed attempt's
logs remain in its fresh directory. Do not publish the credential bundle.

Hostnames/IP lists and the report are operator-controlled test evidence. They
guard against accidentally accepting a same-host run, stale report or wrong
path; they do not establish cryptographic device attestation against a malicious
operator. A public Internet path and NAT/relay fallback are outside this gate.

## Verdicts

| Verdict | Required evidence |
| --- | --- |
| `PASS_SAME_HOST_SPLIT_HARNESS_SMOKE` | Exported-client workflow and paired counters/nonces/cleanup, explicitly executed on the native host. |
| `PASS_TWO_DEVICE_LAN` | Matching evidence from a separate device with the selected LAN address, including fresh traffic after reconnect. |

The verifier's unit tests use synthetic reports and logs to check acceptance
boundaries. They are not network evidence. Cases include stale sessions,
different WASM builds, replayed responses, absent native HTTP proofs, wrong UDP
endpoints, missing source-rejection counters and incomplete cleanup.

## Local validation

The native fixture passes `cargo check --locked -j 2 -p p2p-vpn-browser --bin browser-fixture`.
The evidence gate and portable HTTP server pass 11 Node tests:

```powershell
node --test crates/p2p-vpn-browser/tests/verify-lan-report.test.mjs crates/p2p-vpn-browser/tests/lan-client.test.mjs
```

Local runtime validation completed on November 13, 2026 (the evidence paths use
UTC November 14), on desktop Chrome 156.0.8078.82 / Node 24.15.0 / Windows:

| Check | Result |
| --- | --- |
| Final split-client smoke | `target/browser-lan-smoke-20261114-015909`: `PASS_SAME_HOST_SPLIT_HARNESS_SMOKE`. |
| HTTP and reconnect | Both fresh nonces match native TUN-service logs; same authorized browser identity after reset. Each transaction sent/accepted 7 IP packets and received 4. |
| Actual selected path | UDP to native `192.168.255.6:49302`; byte counters positive before and after reset. Chrome redacted the local candidate address; host/IP metadata still identifies this as same-host. |
| Native delivery/rejection | 10 outbound WebRTC packet deliveries; one unauthorized-source drop and the explicit rejection returned to the browser. |
| JavaScript and teardown | Zero browser errors; native exit 0, adapter removed, both firewall rules removed. `cleanup.json` independently records completion. |
| Original local runner | `target/browser-validation-20261114-015642`: passed with the updated fixture and client tests. |
| Failed client launch | `target/browser-lan-smoke-20261114-015800`: intentionally invalid Chrome channel produced host exit 1; `cleanup.json` records native exit 0, adapter removal and no remaining test firewall rules. No pass verdict was written. |
| Host preflight | Same-host addresses without `-LocalSmoke` were rejected before creating a fixture. |

The published report substitutes the fixture hostname and underlay addresses consistently.

The [machine-readable snapshot](browser-lan-results.json) retains the final public
browser report, verdict, native metadata, cleanup checks, artifact hashes and
current build-source digest. Original WASM milestone evidence remains unchanged.
The portable bundle was checked for the expected browser identity and absence
of shutdown authority; only one private-key field exists in its session config.

Rust formatting, PowerShell/JavaScript syntax and whitespace checks pass.
Existing native dead-code warnings remain. No additional full historical Rust,
Linux, Android or Nix build campaign was performed for this harness change.

No physical second-device or public NAT/relay result is asserted here. A fresh
host run and a second device with its actual LAN IP are still required.
