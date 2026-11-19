// Use the production browser bindings and the native browser-relay-fixture.
// Set P2P_VPN_PAIRING_PKG and P2P_VPN_RELAY_FIXTURE. In an isolated netns:
// ip link set lo up
// ip link add pv-relay type dummy
// ip address add 192.0.2.1/24 dev pv-relay
// ip link set pv-relay up
// node --test crates/p2p-vpn-browser/tests/code-inviter.mjs
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

test('a browser explicitly approves v2 enrollment on its incoming relay', { timeout: 60_000 }, async t => {
  const { P2P_VPN_PAIRING_PKG: pkg, P2P_VPN_RELAY_FIXTURE: fixture, P2P_VPN_CHROMIUM: executablePath } = process.env;
  assert.ok(pkg && fixture);
  const script = await readFile(join(pkg, 'p2p_vpn_browser.js'));
  const wasm = await readFile(join(pkg, 'p2p_vpn_browser_bg.wasm'));
  const server = createServer((request, response) => {
    const files = {
      '/': ['text/html', '<!doctype html><title>Code invitation</title>'],
      '/p2p_vpn_browser.js': ['text/javascript', script],
      '/p2p_vpn_browser_bg.wasm': ['application/wasm', wasm],
    };
    const file = Object.hasOwn(files, request.url) && files[request.url];
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));

  const relay = spawn(fixture, ['192.0.2.1'], { stdio: ['ignore', 'pipe', 'inherit'] });
  const exited = once(relay, 'close');
  const lines = createInterface({ input: relay.stdout });
  t.after(async () => {
    lines.close();
    relay.kill();
    await exited;
  });
  const [entrance] = await once(lines, 'line');
  assert.match(entrance, /^\/ip4\/192\.0\.2\.1\/udp\/\d+\/webrtc-direct\/certhash\//);

  const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const result = await page.evaluate(async entrance => {
    const { default: init, BrowserCodeInviter, BrowserPairing } =
      await import('/p2p_vpn_browser.js');
    await init();
    const joiner = new BrowserPairing();
    const joinerPeer = joiner.peer_id();
    const inviter = new BrowserCodeInviter('browser-code-inviter', '10.80.0.1', '10.80.0.2',
      joinerPeer, entrance);
    const inviterPeer = inviter.peer_id();
    let beforeReservation;
    try { inviter.code(); } catch (error) { beforeReservation = error.message; }
    const address = await inviter.reserve();
    const other = new BrowserPairing();
    let unpinned = 'running';
    const wrongJoin = other.join_v2(inviter.code(), inviterPeer, address, 1500)
      .then(() => { unpinned = 'joined'; }, () => { unpinned = 'rejected'; });
    const unpinnedDeadline = performance.now() + 4000;
    while (unpinned === 'running' && performance.now() < unpinnedDeadline) {
      await inviter.drive(100);
    }
    if (unpinned !== 'rejected' || inviter.pending_candidate()) {
      throw Error('The correct code must not admit an unpinned Noise identity');
    }
    await wrongJoin;
    other.free();
    let joined;
    let failure;
    let pending = false;
    const exchange = joiner.join_v2(inviter.code(), inviterPeer, address, 20_000,
      'pinned-joiner', () => { pending = true; })
      .then(value => { joined = JSON.parse(value); }, error => { failure = error; });
    const driveUntil = async (predicate, label) => {
      const until = performance.now() + 12000;
      while (!predicate()) {
        if (failure) throw failure;
        if (performance.now() >= until) throw Error(label);
        await inviter.drive(100);
      }
    };
    await driveUntil(() => pending && inviter.pending_candidate(), 'no pending approval');
    const candidate = JSON.parse(inviter.pending_candidate());
    let wrongPeer;
    try { inviter.approve(inviterPeer); } catch (error) { wrongPeer = error.message; }
    const beforeApproval = performance.now() + 1200;
    await driveUntil(() => performance.now() >= beforeApproval, 'approval wait failed');
    const rejectedBeforeApproval = !joined && !inviter.delivered();
    inviter.approve(joinerPeer);
    await driveUntil(() => joined && inviter.delivered(), 'no approved response');
    await exchange;
    const owner = inviter.into_vpn();
    const report = {
      inviterPeer, joinerPeer, address, beforeReservation, wrongPeer,
      candidate, unpinned, rejectedBeforeApproval, kind: joined.kind,
      assignedIp: joined.config.network.vpn_ip,
      granted: joined.config.network.member_records.map(record => ({
        issuer: record.payload.issuer_peer, peer: record.payload.member_peer,
        routes: record.payload.route_grants.map(grant => grant.prefix),
      })),
      inviterIdentityKept: owner.local_peer_id() === inviterPeer,
    };
    owner.free();
    joiner.free();
    return report;
  }, entrance);
  assert.equal(result.address, `${entrance}/p2p-circuit/p2p/${result.inviterPeer}`);
  assert.match(result.beforeReservation, /No confirmed/);
  assert.match(result.wrongPeer, /No pending/);
  assert.deepEqual(result.candidate, {
    peer_id: result.joinerPeer, requested_hostname: 'pinned-joiner', assigned_vpn_ip: '10.80.0.2',
  });
  assert.equal(result.rejectedBeforeApproval, true);
  assert.equal(result.unpinned, 'rejected');
  assert.equal(result.kind, 'legacy');
  assert.equal(result.inviterIdentityKept, true);
  assert.equal(result.assignedIp, '10.80.0.2');
  assert.deepEqual(result.granted, [
    { issuer: result.inviterPeer, peer: result.inviterPeer, routes: ['10.80.0.1/32'] },
    { issuer: result.inviterPeer, peer: result.joinerPeer, routes: ['10.80.0.2/32'] },
  ]);
});
