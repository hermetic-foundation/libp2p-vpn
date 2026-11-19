// Synthetic inputs exercise the evidence gate, not LAN connectivity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyLanReport } from './verify-lan-report.mjs';

function evidence() {
  const meta = { scope: 'two-device-lan', session_id: 'native-test-peer', browser_peer_id: 'browser-test-peer', native_host: 'host-a',
    native_ipv4: ['192.168.1.6', '127.0.0.1'], client_ip: '192.168.1.7', webrtc_ip: '192.168.1.6', webrtc_port: 12345,
    dial_address: '/synthetic-test-address', expires_at: 3600, wasm_sha256: 'synthetic-build-hash' };
  const snapshot = { authorized: true, local_peer_id: meta.browser_peer_id, remote_peer_id: meta.session_id,
    counters: { outbound_ip_packets: 7, inbound_ip_packets: 4, accepted_outbound_packets: 7 } };
  const transaction = suffix => {
    const nonce = `11111111-1111-4111-8111-11111111111${suffix}`;
    return { nonce, response: `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\np2p-vpn real TUN HTTP proof\n/vpn-proof?nonce=${nonce}\n`,
      snapshot: structuredClone(snapshot), candidate_pair: { state: 'succeeded', bytesSent: 300, bytesReceived: 400,
        local: { address: meta.client_ip }, remote: { address: meta.webrtc_ip, port: meta.webrtc_port, protocol: 'udp' } } };
  };
  const report = { schema_version: 2, scope: meta.scope, passed: true, errors: [], transport: 'webrtc-direct', wasm_sha256: meta.wasm_sha256,
    session: { id: meta.session_id, native_host: meta.native_host, mode: 'split-lan', webrtc_ip: meta.webrtc_ip,
      webrtc_port: meta.webrtc_port, dial_address: meta.dial_address, expires_at: meta.expires_at },
    timestamp: '1970-01-01T00:30:00Z', client: { host: 'host-b', ipv4: [meta.client_ip] },
    checks: { authorized_webrtc_connection: structuredClone(snapshot), native_rejected_spoofed_source: 'Rejected(UnauthorizedSource)',
      http_over_vpn_packets: transaction('1'), fresh_http_after_reconnect: transaction('2') },
    native_webrtc_outbound_packets: 10, native_unauthorized_source_drops: 1, native_exit_code: 0,
    native_adapter_removed: true, test_firewall_rule_removed: true, test_udp_firewall_rule_removed: true };
  const log = [report.checks.http_over_vpn_packets, report.checks.fresh_http_after_reconnect].map(t =>
    `BROWSER_HTTP_PROOF ${JSON.stringify({ session_id: meta.session_id, path: `/vpn-proof?nonce=${t.nonce}`, remote_ip: '10.203.0.2' })}`
  ).join('\n') + '\noutbound_direct_webrtc_stream_fallback_packets 10\ninbound_drop_unauthorized_source_packets 1\n';
  return { meta, report, log };
}

test('accepts paired host evidence and preserves the narrower smoke verdict', () => {
  const e = evidence();
  assert.equal(verifyLanReport(e.meta, e.report, e.log).verdict, 'PASS_TWO_DEVICE_LAN');
  e.meta.scope = e.report.scope = 'same-host-split-harness-smoke';
  e.report.client.host = e.meta.native_host;
  assert.equal(verifyLanReport(e.meta, e.report, e.log).verdict, 'PASS_SAME_HOST_SPLIT_HARNESS_SMOKE');
});

for (const [name, mutate] of [
  ['same-host evidence labeled LAN', e => { e.report.client.host = e.meta.native_host; }],
  ['different hostname but native host IP', e => { e.meta.native_ipv4.push(e.meta.client_ip); }],
  ['stale session', e => { e.report.session.id = 'previous-native-peer'; }],
  ['different browser build', e => { e.report.wasm_sha256 = 'other-build'; }],
  ['replayed response', e => { e.report.checks.fresh_http_after_reconnect = e.report.checks.http_over_vpn_packets; }],
  ['browser-only proof', e => { e.log = e.log.replace(/^BROWSER_HTTP_PROOF.*\n/gm, ''); }],
  ['wrong UDP endpoint', e => { e.report.checks.fresh_http_after_reconnect.candidate_pair.remote.port++; }],
  ['missing native source rejection', e => { e.log = e.log.replace('inbound_drop_unauthorized_source_packets 1', 'inbound_drop_unauthorized_source_packets 0'); }],
  ['leftover adapter', e => { e.report.native_adapter_removed = false; }],
]) {
  test(`rejects ${name}`, () => {
    const e = evidence(); mutate(e);
    assert.throws(() => verifyLanReport(e.meta, e.report, e.log));
  });
}
