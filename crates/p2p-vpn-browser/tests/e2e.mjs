import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { hostname, networkInterfaces } from 'node:os';

const url = process.env.P2P_VPN_BROWSER_URL || 'http://127.0.0.1:8787';
const browser = await chromium.launch({ channel: process.env.P2P_VPN_BROWSER_CHANNEL || 'chrome', headless: true });
const page = await browser.newPage();
await page.addInitScript(() => {
  window.webrtcDiagnostics = [];
  window.webrtcPeerConnections = [];
  const Original = window.RTCPeerConnection;
  window.RTCPeerConnection = new Proxy(Original, {
    construct(Target, args) {
      const pc = new Target(...args);
      window.webrtcPeerConnections.push(pc);
      const log = { states: [], candidates: [] };
      const ice = (sdp, name) => sdp?.split(/\r?\n/).find(line => line.startsWith('a=' + name + ':'))?.slice(name.length + 3);
      let originalOffer;
      window.webrtcDiagnostics.push(log);
      for (const name of ['iceconnectionstatechange', 'connectionstatechange', 'signalingstatechange']) {
        pc.addEventListener(name, () => log.states.push({ event: name, ice: pc.iceConnectionState, connection: pc.connectionState, signaling: pc.signalingState }));
      }
      pc.addEventListener('icecandidate', event => { if (event.candidate) log.candidates.push(event.candidate.candidate); });
      const createOffer = pc.createOffer.bind(pc);
      pc.createOffer = async (...args) => {
        const offer = await createOffer(...args);
        originalOffer = offer.sdp;
        return offer;
      };
      const setRemote = pc.setRemoteDescription.bind(pc);
      pc.setRemoteDescription = async description => {
        log.remoteVersion = /libp2p\+webrtc\+(v\d+)\//.exec(description.sdp)?.[1];
        const local = pc.localDescription?.sdp;
        const password = ice(local, 'ice-pwd');
        const remote = 'libp2p+webrtc+v2/' + password;
        log.r2 = log.remoteVersion === 'v2' && !!originalOffer && !!password
          && password === ice(originalOffer, 'ice-pwd')
          && ice(local, 'ice-ufrag') === ice(originalOffer, 'ice-ufrag')
          && ice(description.sdp, 'ice-pwd') === remote
          && ice(description.sdp, 'ice-ufrag') === remote
          && description.sdp.split(/\r?\n/).includes('a=ice-lite')
          && description.sdp.split(/\r?\n/).includes('a=max-message-size:16384');
        return setRemote(description);
      };
      return pc;
    }
  });
});
const errors = [];
page.on('pageerror', error => errors.push(error.stack || String(error)));
page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
let session;
const client = { host: hostname().toLowerCase(), ipv4: Object.values(networkInterfaces()).flat().filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address) };
const report = { schema_version: 2, browser: browser.version(), timestamp: new Date().toISOString(), transport: 'webrtc-direct', scope: 'same-host', client, checks: {}, errors };
if (process.env.P2P_VPN_BROWSER_WASM_SHA256) report.wasm_sha256 = process.env.P2P_VPN_BROWSER_WASM_SHA256;
const candidatePair = () => page.evaluate(async () => {
  const pc = window.webrtcPeerConnections.at(-1);
  const stats = await pc.getStats();
  const values = [...stats.values()];
  const transport = values.find(s => s.type === 'transport' && s.selectedCandidatePairId);
  const pair = transport ? stats.get(transport.selectedCandidatePairId) : values.find(s => s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded');
  if (!pair) throw Error('No selected WebRTC candidate pair');
  const endpoint = id => {
    const c = stats.get(id);
    return { address: c?.address, port: c?.port, protocol: c?.protocol, type: c?.candidateType };
  };
  return { state: pair.state, bytesSent: pair.bytesSent, bytesReceived: pair.bytesReceived, local: endpoint(pair.localCandidateId), remote: endpoint(pair.remoteCandidateId) };
});
try {
  const readyDeadline = Date.now() + 90000;
  while (true) {
    try {
      const ready = await fetch(`${url}/session.json`, { signal: AbortSignal.timeout(2000) });
      if (ready.ok) break;
    } catch {}
    if (Date.now() > readyDeadline) throw Error('Native browser fixture did not become ready');
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  await page.goto(url);
  await page.waitForFunction(() => window.fixtureReady || window.fixtureError, undefined, { timeout: 30000 });
  assert.equal(await page.evaluate(() => window.fixtureError), undefined);
  session = await page.evaluate(() => ({ token: window.session.shutdown_token, device: window.session.packet_device,
    id: window.session.session_id, native_host: window.session.native_host, webrtc_ip: window.session.webrtc_ip,
    webrtc_port: window.session.webrtc_port, mode: window.session.qualification_mode, expires_at: window.session.expires_at,
    dial_address: window.session.dial_address }));
  assert.equal(session.device, 'OS TUN');
  report.session = { ...session, token: undefined };
  assert.ok(Date.now() / 1000 < session.expires_at, 'Test credentials have expired');
  if (session.mode === 'split-lan') {
    const sameHost = client.host === session.native_host || client.ipv4.includes(session.webrtc_ip);
    if (process.env.P2P_VPN_BROWSER_LOCAL_SMOKE === '1') {
      assert.ok(sameHost, 'A local smoke run must execute on the native host');
      report.scope = 'same-host-split-harness-smoke';
    } else {
      assert.ok(!sameHost, 'Run this bundle on a second device; same-host runs cannot qualify LAN');
      report.scope = 'two-device-lan';
    }
  }
  const connected = JSON.parse(await page.evaluate(() => window.vpn.connect()));
  assert.equal(connected.authorized, true);
  report.checks.authorized_webrtc_connection = connected;
  const nonce = randomUUID();
  const first = await page.evaluate(nonce => window.runVpnHttp(nonce), nonce);
  assert.match(first, /^HTTP\/1\.1 200 OK\r\n/);
  assert.ok(first.includes('p2p-vpn real TUN HTTP proof'));
  assert.ok(first.includes(nonce));
  const snapshot = JSON.parse(await page.evaluate(() => window.vpn.snapshot()));
  assert.ok(snapshot.counters.outbound_ip_packets > 0);
  assert.ok(snapshot.counters.inbound_ip_packets > 0);
  assert.ok(snapshot.counters.accepted_outbound_packets > 0);
  report.checks.http_over_vpn_packets = { nonce, response: first, snapshot, candidate_pair: await candidatePair() };
  const rejected = await page.evaluate(() => window.vpn.test_spoofed_source(window.session.overlay_ip));
  assert.equal(rejected, 'Rejected(UnauthorizedSource)');
  report.checks.native_rejected_spoofed_source = rejected;
  const nextNonce = randomUUID();
  const second = await page.evaluate(async nonce => {
    await window.vpn.reset_connection();
    return window.runVpnHttp(nonce);
  }, nextNonce);
  assert.match(second, /^HTTP\/1\.1 200 OK\r\n/);
  assert.ok(second.includes(nextNonce));
  assert.ok(!second.includes(nonce));
  const reconnected = JSON.parse(await page.evaluate(() => window.vpn.snapshot()));
  assert.equal(reconnected.local_peer_id, connected.local_peer_id);
  report.checks.fresh_http_after_reconnect = { nonce: nextNonce, response: second, snapshot: reconnected, candidate_pair: await candidatePair() };
  const r2 = await page.evaluate(() => window.webrtcDiagnostics.map(log => log.r2));
  assert.deepEqual(r2, [true, true], 'both dials use WebRTC Direct r2 without modifying the original offer credentials');
  report.checks.webrtc_direct_r2 = true;
  if (session.mode === 'split-lan') {
    for (const check of [report.checks.http_over_vpn_packets, report.checks.fresh_http_after_reconnect]) {
      assert.equal(check.candidate_pair.remote.address, session.webrtc_ip);
      assert.equal(check.candidate_pair.remote.port, session.webrtc_port);
      assert.equal(check.candidate_pair.remote.protocol, 'udp');
    }
  }
  assert.equal(errors.length, 0, errors.join('\n'));
  report.passed = true;
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  report.passed = false;
  report.failure = String(error.stack || error);
  report.webrtcDiagnostics = await page.evaluate(() => window.webrtcDiagnostics).catch(() => undefined);
  console.error(JSON.stringify(report, null, 2));
  process.exitCode = 1;
} finally {
  if (!session) session = await fetch(`${url}/session.json`).then(r => r.json()).then(s => ({ token: s.shutdown_token })).catch(() => undefined);
  if (process.env.P2P_VPN_BROWSER_REPORT) await writeFile(process.env.P2P_VPN_BROWSER_REPORT, JSON.stringify(report, null, 2));
  if (process.env.P2P_VPN_BROWSER_SCREENSHOT) await page.screenshot({ path: process.env.P2P_VPN_BROWSER_SCREENSHOT, fullPage: true });
  if (session?.token && process.env.P2P_VPN_BROWSER_KEEP_FIXTURE !== '1') {
    await page.request.post(`${url}/shutdown`, { headers: { 'X-Fixture-Token': session.token } }).catch(() => {});
  }
  await browser.close();
}
