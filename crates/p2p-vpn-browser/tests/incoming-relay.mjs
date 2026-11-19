import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const glue = 'p2p_vpn_browser.js';
const wasm = 'p2p_vpn_browser_bg.wasm';

function fixture(t, binary, args) {
  const child = spawn(binary, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const reader = createInterface({ input: child.stdout });
  const lines = reader[Symbol.asyncIterator]();
  const exited = once(child, 'close');
  exited.catch(() => {});
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  t.after(async () => {
    reader.close();
    child.kill();
    await exited.catch(() => {});
  });
  return {
    child,
    logs: () => stderr,
    async next() {
      const { value, done } = await lines.next();
      if (done) throw Error(`Native fixture exited (${(await exited)[0]}): ${stderr}`);
      return value;
    },
  };
}

test('native peer initiates VPN control and IP traffic on the browser-owned relay reservation', {
  timeout: 50_000,
}, async t => {
  const { P2P_VPN_RELAY_FIXTURE, P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_RECEIVER_PKG } = process.env;
  assert.ok(P2P_VPN_RELAY_FIXTURE && P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_RECEIVER_PKG);
  const files = new Map([
    ['/', ['text/html', '<!doctype html><title>Incoming circuit</title>']],
    [`/${glue}`, ['text/javascript', await readFile(join(P2P_VPN_RECEIVER_PKG, glue))]],
    [`/${wasm}`, ['application/wasm', await readFile(join(P2P_VPN_RECEIVER_PKG, wasm))]],
  ]);
  const server = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0], 'Cache-Control': 'no-store' }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));

  const browser = await chromium.launch({
    headless: true,
    ...(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: process.env.P2P_VPN_BROWSER_CHANNEL || 'chrome' }),
  });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);

  const relay = fixture(t, P2P_VPN_RELAY_FIXTURE, ['192.0.2.1']);
  const entrance = await relay.next();
  const native = fixture(t, P2P_VPN_RECEIVER_FIXTURE, ['incoming-relay', entrance]);
  const session = JSON.parse(await native.next());
  const browserId = session.config.network.local_peer;
  const memberId = session.native_peer_id;
  const relayId = entrance.split('/').at(-1);
  const expected = `${entrance}/p2p-circuit/p2p/${browserId}`;

  try {
    const before = await page.evaluate(async ({ session, path }) => {
      const { default: init, BrowserVpn } = await import(path);
      await init();
      window.vpn = BrowserVpn.with_relay(JSON.stringify(session.config), '', session.relay_address);
      let rejection;
      try {
        await window.vpn.accept_relay();
      } catch (error) {
        rejection = error.message;
      }
      return { address: window.vpn.relay_reservation_address(), rejection };
    }, { session, path: `/${glue}` });
    assert.equal(before.address, undefined);
    assert.match(before.rejection ?? '', /No confirmed explicit relay reservation/);
    assert.equal(relay.logs(), '');

    const reservation = await page.evaluate(async () => ({
      published: await window.vpn.reserve_relay(),
      current: window.vpn.relay_reservation_address(),
      repeated: await window.vpn.reserve_relay(),
      connected: JSON.parse(window.vpn.snapshot()).counters.connections,
    }));
    assert.deepEqual(reservation, { published: expected, current: expected, repeated: expected, connected: 0 });
    native.child.stdin.end(`${reservation.published}\n`);

    const [wire, received] = await Promise.all([
      native.next().then(JSON.parse),
      page.evaluate(async () => {
        const accepted = JSON.parse(await window.vpn.accept_relay());
        const packets = [];
        const deadline = performance.now() + 5_000;
        while (performance.now() < deadline) {
          const packet = await window.vpn.receive_relay_packet(100);
          if (packet) packets.push(Array.from(packet));
        }
        return { accepted, packets, final: JSON.parse(window.vpn.snapshot()) };
      }),
    ]);
    assert.equal(received.accepted.authorized, true);
    assert.equal(received.accepted.remote_peer_id, memberId);
    assert.equal(received.accepted.transport, 'circuit-relay');
    assert.equal(received.final.counters.connections, 1);
    assert.equal(received.final.counters.inbound_ip_packets, 2);
    assert.equal(received.final.counters.rejected_inbound_packets, 5);
    assert.equal(received.packets.length, 2);
    assert.deepEqual(received.packets[0], received.packets[1]);
    assert.deepEqual(received.packets[0].slice(12, 20), [10, 204, 0, 1, 10, 204, 0, 2]);
    assert.equal(wire.packets.valid_ip, 'Accepted');
    assert.equal(wire.packets.bad_source, 'Rejected(UnauthorizedSource)');
    assert.equal(wire.status.Status.selected_path, 'circuit_relay');
    assert.equal(wire.status.Status.selected_path_mtu, 1200);

    const logs = relay.logs();
    assert.equal(logs.match(/ReservationReqAccepted/g)?.length, 1, logs);
    assert.match(logs, new RegExp(`ReservationReqAccepted.*${browserId}`));
    const incoming = new RegExp(`CircuitReqAccepted.*${memberId}.*${browserId}`, 'g');
    assert.equal(logs.match(incoming)?.length, 2, logs);
    assert.doesNotMatch(logs, new RegExp(`CircuitReqAccepted.*${browserId}.*${memberId}`));
    assert.notEqual(memberId, relayId);

    const released = await page.evaluate(() => ({
      released: window.vpn.release_relay(),
      address: window.vpn.relay_reservation_address(),
      authorized: JSON.parse(window.vpn.snapshot()).authorized,
      repeated: window.vpn.release_relay(),
    }));
    assert.deepEqual(released, { released: true, address: undefined, authorized: false, repeated: false });
    await assert.rejects(page.evaluate(() => window.vpn.accept_relay()), /No confirmed explicit relay reservation/);
  } catch (error) {
    throw new Error(`${error.message}\nNative member: ${native.logs()}\nRelay: ${relay.logs()}`, { cause: error });
  }
});
