import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, readlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { chromium } from 'playwright';

async function fixture(t, binary, address) {
  const child = spawn(binary, [address], { stdio: ['pipe', 'pipe', 'pipe'] });
  const closed = once(child, 'close');
  // A failing test may stop a fixture while it is waiting for its next command.
  child.stdin.on('error', () => {});
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  const output = createInterface({ input: child.stdout });
  const lines = output[Symbol.asyncIterator]();
  t.after(async () => {
    output.close();
    child.kill();
    await closed;
  });
  return {
    async line() {
      const { value } = await lines.next();
      assert.ok(value, `Fixture ended without output: ${stderr}`);
      return value;
    },
    send(line) { child.stdin.write(`${line}\n`); },
  };
}

test('Chromium checkpoint issuer serves a new native member on its reserved circuit', {
  timeout: 105_000,
}, async t => {
  const {
    P2P_VPN_CHECKPOINT_INVITER_NATIVE: nativeBinary,
    P2P_VPN_RELAY_FIXTURE: relayBinary,
    P2P_VPN_PAIRING_PKG: pkg,
    P2P_VPN_TEST_NETNS: parentNamespace,
    P2P_VPN_CHROMIUM: executablePath,
  } = process.env;
  assert.ok(nativeBinary && relayBinary && pkg);
  assert.match(parentNamespace ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), parentNamespace);
  const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5000 });
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up');
  ip('link', 'add', 'checkpoint-lan', 'type', 'dummy');
  ip('addr', 'add', '11.250.0.2/24', 'dev', 'checkpoint-lan');
  ip('link', 'set', 'checkpoint-lan', 'up');
  const relay = await fixture(t, relayBinary, '11.250.0.2');
  const entrance = await relay.line();
  assert.match(entrance, /^\/ip4\/11\.250\.0\.2\/udp\/\d+\/webrtc-direct\/certhash\/[^/]+\/p2p\/[^/]+$/);
  const native = await fixture(t, nativeBinary, entrance);
  const seed = JSON.parse(await native.line());
  const files = new Map([['/', ['text/html', '<!doctype html><title>Checkpoint relay issuer test</title>']]]);
  for (const [file, mime] of [['p2p_vpn_browser.js', 'text/javascript'], ['p2p_vpn_browser_bg.wasm', 'application/wasm']]) {
    files.set(`/${file}`, [mime, await readFile(join(pkg, file))]);
  }
  const server = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);

  const reservation = await page.evaluate(async ({ config, first_route, bootstrap, secret }) => {
    const { default: init, BrowserVpn } = await import('/p2p_vpn_browser.js');
    await init();
    window.vpn = await BrowserVpn.open_checkpoint_with_relay(
      JSON.stringify(config), '', first_route, JSON.stringify(bootstrap), new Uint8Array(secret),
    );
    return window.vpn.reserve_relay();
  }, seed);
  assert.equal(reservation, seed.reservation);
  native.send(reservation);
  const issuer = await page.evaluate(async () => {
    const primary = JSON.parse(await window.vpn.accept_relay());
    window.invitation = window.vpn.checkpoint_invitation();
    return { primary, offer: window.invitation.offer_json() };
  });
  assert.equal(issuer.primary.ready, true);
  assert.equal(issuer.primary.checkpoint.sync, 'participating');
  assert.equal(issuer.primary.checkpoint.boundary.authority_revision, 0);
  native.send(issuer.offer);
  const { request } = JSON.parse(await native.line());
  const approval = await page.evaluate(async requestJson => {
    const response = await window.vpn.approve_checkpoint_invitation(window.invitation, requestJson);
    const { payload } = JSON.parse(response);
    const key = `p2p-vpn:checkpoint-membership:1:${JSON.stringify([payload.network_name, payload.inviter_peer])}`;
    const { retained, enrollment_floor } = JSON.parse(localStorage.getItem(key)).payload;
    return {
      response,
      floor: payload.checkpoint.minimum,
      member: payload.checkpoint.joiner.subject.peer_id,
      revision: retained.snapshot.payload.authority_revision,
      savedMember: retained.snapshot.payload.members.some(member => member.subject.peer_id === payload.checkpoint.joiner.subject.peer_id),
      activatedFloor: enrollment_floor,
    };
  }, JSON.stringify(request));
  assert.equal(approval.revision, 1);
  assert.equal(approval.savedMember, true);
  assert.equal(approval.activatedFloor, null);
  native.send(approval.response);

  const [packet, result] = await Promise.all([
    page.evaluate(async () => {
      const deadline = performance.now() + 20_000;
      while (performance.now() < deadline) {
        const bytes = await window.vpn.receive_relay_packet(1000);
        if (bytes) {
          await window.vpn.poll_foreground();
          return Array.from(bytes);
        }
      }
      throw new Error('No authorized IP packet reached the browser');
    }),
    (async () => {
      const facts = {};
      while (!facts.packet_accepted) Object.assign(facts, JSON.parse(await native.line()));
      return facts;
    })(),
  ]);
  assert.equal(result.incumbent_applied, 1);
  assert.deepEqual(result.activated_rank, approval.floor);
  assert.equal(packet.length, 28);
  assert.equal(packet.slice(12, 16).join('.'), seed.joiner_ip);
});
