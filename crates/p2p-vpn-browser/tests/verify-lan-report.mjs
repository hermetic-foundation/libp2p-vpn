// Cross-check returned browser evidence against this native run, never a held report.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

export function verifyLanReport(meta, report, nativeLog) {
  assert.ok(['two-device-lan', 'same-host-split-harness-smoke'].includes(meta.scope), 'Unknown qualification scope');
  assert.equal(report.scope, meta.scope, 'Browser/native scope differs');
  assert.equal(report.schema_version, 2);
  assert.equal(report.passed, true, 'Browser checks did not pass');
  assert.deepEqual(report.errors, [], 'Browser reported JavaScript errors');
  assert.equal(report.transport, 'webrtc-direct');
  assert.equal(report.wasm_sha256, meta.wasm_sha256, 'Browser used a different WASM build');
  assert.equal(report.session.id, meta.session_id, 'Wrong or stale test session');
  assert.equal(report.session.native_host, meta.native_host);
  assert.equal(report.session.mode, 'split-lan');
  assert.equal(report.session.dial_address, meta.dial_address);
  assert.equal(report.session.webrtc_ip, meta.webrtc_ip);
  assert.equal(report.session.webrtc_port, meta.webrtc_port);
  assert.equal(report.session.expires_at, meta.expires_at);
  const timestamp = Date.parse(report.timestamp) / 1000;
  assert.ok(Number.isFinite(timestamp) && timestamp < meta.expires_at && timestamp >= meta.expires_at - 3600, 'Report is outside this fixture lifetime');
  assert.equal(typeof report.client.host, 'string');
  assert.ok(Array.isArray(report.client.ipv4) && report.client.ipv4.includes(meta.client_ip), 'Report did not come from the expected client IP');
  const sameHost = report.client.host === meta.native_host || report.client.ipv4.some(ip => meta.native_ipv4.includes(ip));
  assert.equal(sameHost, meta.scope === 'same-host-split-harness-smoke', 'Same-host evidence cannot qualify two-device LAN');
  const connected = report.checks.authorized_webrtc_connection;
  assert.equal(connected.authorized, true);
  assert.equal(connected.local_peer_id, meta.browser_peer_id);
  assert.equal(connected.remote_peer_id, meta.session_id);
  assert.equal(report.checks.native_rejected_spoofed_source, 'Rejected(UnauthorizedSource)');
  const transactions = [report.checks.http_over_vpn_packets, report.checks.fresh_http_after_reconnect];
  assert.notEqual(transactions[0].nonce, transactions[1].nonce, 'Reconnect reused the response nonce');
  const proofs = nativeLog.split(/\r?\n/).filter(line => line.startsWith('BROWSER_HTTP_PROOF ')).map(line => JSON.parse(line.slice('BROWSER_HTTP_PROOF '.length)));
  for (const transaction of transactions) {
    assert.match(transaction.nonce, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    const path = `/vpn-proof?nonce=${transaction.nonce}`;
    assert.match(transaction.response, /^HTTP\/1\.1 200 OK\r\n/);
    assert.equal(transaction.response.split('\r\n\r\n')[1], `p2p-vpn real TUN HTTP proof\n${path}\n`);
    assert.ok(proofs.some(p => p.session_id === meta.session_id && p.path === path && p.remote_ip === '10.203.0.2'), 'HTTP nonce is absent from native TUN service evidence');
    assert.equal(transaction.snapshot.authorized, true);
    assert.equal(transaction.snapshot.local_peer_id, meta.browser_peer_id);
    assert.equal(transaction.snapshot.remote_peer_id, meta.session_id);
    for (const counter of ['outbound_ip_packets', 'inbound_ip_packets', 'accepted_outbound_packets']) {
      assert.ok(transaction.snapshot.counters[counter] > 0, `Missing browser packet evidence: ${counter}`);
    }
    const pair = transaction.candidate_pair;
    assert.equal(pair.state, 'succeeded');
    assert.equal(pair.remote.address, meta.webrtc_ip, 'WebRTC did not use the expected native LAN address');
    assert.equal(pair.remote.port, meta.webrtc_port);
    assert.equal(pair.remote.protocol, 'udp');
    // Some browsers redact local candidate addresses. If present, bind it too.
    if (pair.local.address && !pair.local.address.endsWith('.local')) assert.equal(pair.local.address, meta.client_ip);
    assert.ok(pair.bytesSent > 0 && pair.bytesReceived > 0, 'Selected WebRTC path did not carry bytes');
  }
  const counter = name => {
    const matches = [...nativeLog.matchAll(new RegExp(`^\\s*${name} (\\d+)\\s*$`, 'gm'))];
    const value = Number(matches.at(-1)?.[1] || 0);
    assert.ok(value > 0, `Missing native counter evidence: ${name}`);
    return value;
  };
  assert.equal(report.native_webrtc_outbound_packets, counter('outbound_direct_webrtc_stream_fallback_packets'));
  assert.equal(report.native_unauthorized_source_drops, counter('inbound_drop_unauthorized_source_packets'));
  assert.equal(report.native_exit_code, 0);
  assert.equal(report.native_adapter_removed, true);
  assert.equal(report.test_firewall_rule_removed, true);
  assert.equal(report.test_udp_firewall_rule_removed, true);
  return { verdict: meta.scope === 'two-device-lan' ? 'PASS_TWO_DEVICE_LAN' : 'PASS_SAME_HOST_SPLIT_HARNESS_SMOKE',
    scope: meta.scope, session_id: meta.session_id, native_host: meta.native_host, client_host: report.client.host,
    native_ip: meta.webrtc_ip, client_ip: meta.client_ip, checks: ['session_binding', 'host_separation', 'selected_udp_path', 'native_http_nonces', 'source_rejection', 'reconnect', 'cleanup'],
    limitation: 'Operator-controlled test evidence; host metadata is not cryptographic device attestation. No public NAT/relay qualification.' };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [, , metaPath, reportPath, stdoutPath, stderrPath] = process.argv;
  if (!metaPath || !reportPath || !stdoutPath || !stderrPath) throw Error('Usage: node verify-lan-report.mjs native-session.json browser.json native-stdout.log native-stderr.log');
  const json = async path => JSON.parse((await readFile(path, 'utf8')).replace(/^\uFEFF/, ''));
  const verdict = verifyLanReport(await json(metaPath), await json(reportPath), `${await readFile(stdoutPath, 'utf8')}\n${await readFile(stderrPath, 'utf8')}`);
  await writeFile(resolve(dirname(reportPath), 'lan-verification.json'), JSON.stringify(verdict, null, 2));
  console.log(JSON.stringify(verdict, null, 2));
}
