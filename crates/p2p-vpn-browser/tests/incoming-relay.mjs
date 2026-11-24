import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const appRoot = process.env.P2P_VPN_APP_ASSETS;
const skipApp = !appRoot && 'set P2P_VPN_APP_ASSETS to run app cases';

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

async function serve(t, files, discovery) {
  const server = createServer((request, response) => {
    if (discovery && request.method === 'POST' && request.url === '/api/discovery') {
      return discovery(request, response);
    }
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0], 'Cache-Control': 'no-store' }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

async function appAssets(pkg, marker = '') {
  const files = new Map();
  for (const [file, type] of [
    ['app.html', 'text/html'], ['app.js', 'text/javascript'], ['app.css', 'text/css'],
  ]) {
    let bytes = await readFile(join(appRoot, file));
    if (file === 'app.html' && marker) bytes = bytes.toString().replace('</head>', marker + '</head>');
    files.set('/' + file, [type, bytes]);
  }
  for (const [file, type] of [[glue, 'text/javascript'], [wasm, 'application/wasm']]) {
    files.set('/pkg/' + file, [type, await readFile(join(pkg, file))]);
  }
  files.set('/pkg/logo.svg', ['image/svg+xml', await readFile(join(appRoot, 'pkg', 'logo.svg'))]);
  return files;
}

async function newPage(t) {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: process.env.P2P_VPN_BROWSER_CHANNEL || 'chrome' }),
  });
  t.after(() => browser.close());
  return browser.newPage();
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
  const url = await serve(t, files);
  const page = await newPage(t);
  await page.goto(url + '/');

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

test('two authorized native members share one reservation across a remote graceful close', {
  timeout: 50_000,
}, async t => {
  const { P2P_VPN_RELAY_FIXTURE, P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_RECEIVER_PKG } = process.env;
  assert.ok(P2P_VPN_RELAY_FIXTURE && P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_RECEIVER_PKG);
  const files = new Map([
    ['/', ['text/html', '<!doctype html><title>Shared incoming circuits</title>']],
    [`/${glue}`, ['text/javascript', await readFile(join(P2P_VPN_RECEIVER_PKG, glue))]],
    [`/${wasm}`, ['application/wasm', await readFile(join(P2P_VPN_RECEIVER_PKG, wasm))]],
  ]);
  const page = await newPage(t);
  await page.goto(await serve(t, files));
  const relay = fixture(t, P2P_VPN_RELAY_FIXTURE, ['192.0.2.1']);
  const entrance = await relay.next();
  const native = fixture(t, P2P_VPN_RECEIVER_FIXTURE, ['shared-incoming', entrance, '--verify-outbound']);
  const session = JSON.parse(await native.next());
  try {
    const reservation = await page.evaluate(async ({ session, path }) => {
      const { default: init, BrowserVpn } = await import(path);
      await init();
      window.vpn = BrowserVpn.with_relay(JSON.stringify(session.config), '', session.route);
      const reservation = await window.vpn.reserve_relay();
      let rejection;
      try {
        await window.vpn.allow_incoming_relay_member(session.outsider);
      } catch (error) {
        rejection = error.message;
      }
      return { reservation, rejection };
    }, { session, path: `/${glue}` });
    assert.match(reservation.rejection ?? '', /not authorized/);
    assert.equal(reservation.reservation,
      `${entrance}/p2p-circuit/p2p/${session.config.network.local_peer}`);
    native.child.stdin.write(reservation.reservation + '\n');
    const first = await page.evaluate(async peer => {
      await window.vpn.accept_relay();
      const packet = await window.vpn.receive_relay_packet(5_000);
      await window.vpn.allow_incoming_relay_member(peer);
      return {
        packet: packet && { source: Array.from(packet.slice(12, 16)), size: packet.length },
        peers: JSON.parse(window.vpn.test_authorized_incoming_members()),
      };
    }, session.additional_peer);
    assert.deepEqual(first, {
      packet: { source: [10, 204, 0, 1], size: 1000 },
      peers: [session.first_peer],
    });
    native.child.stdin.write('start-second\n');
    const live = await page.evaluate(async () => {
      const packets = [];
      const deadline = performance.now() + 15_000;
      while (packets.length < 2 && performance.now() < deadline) {
        const packet = await window.vpn.receive_relay_packet(100);
        if (packet) packets.push({ source: Array.from(packet.slice(12, 16)), size: packet.length });
      }
      return { packets, peers: JSON.parse(window.vpn.test_authorized_incoming_members()) };
    });
    assert.deepEqual(live.peers, [session.first_peer, session.additional_peer]);
    assert.deepEqual(live.packets, [
      { source: [10, 204, 0, 4], size: 28 },
      { source: [10, 204, 0, 1], size: 1000 },
    ]);

    native.child.stdin.write('close-first\n');
    const [closed, survivor] = await Promise.all([
      native.next().then(JSON.parse),
      page.evaluate(async first => {
        const deadline = performance.now() + 2_000;
        while (JSON.parse(window.vpn.test_authorized_incoming_members()).includes(first)
          && performance.now() < deadline) {
          await window.vpn.receive_relay_packet(25);
        }
        return {
          peers: JSON.parse(window.vpn.test_authorized_incoming_members()),
          reservation: window.vpn.relay_reservation_address(),
        };
      }, session.first_peer),
    ]);
    assert.deepEqual(closed, { first_closed: true });
    assert.deepEqual(survivor, {
      peers: [session.additional_peer],
      reservation: reservation.reservation,
    });
    const sendPacket = peer => page.evaluate(peer => {
      // IPv4 ICMP echo from the browser to the additional member.
      const packet = Uint8Array.of(
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0x65, 0x44,
        10, 204, 0, 2, 10, 204, 0, 4, 8, 0, 0xf7, 0xff, 0, 0, 0, 0,
      );
      return window.vpn.test_send_shared_relay_ip(peer, packet);
    }, peer);
    await assert.rejects(sendPacket(session.first_peer), /No authorized shared relay circuit/);
    assert.equal(await sendPacket(session.additional_peer), 'Accepted');
    native.child.stdin.end('send-second\n');
    const [proof, last] = await Promise.all([
      native.next().then(JSON.parse),
      page.evaluate(async () => {
        let last;
        const deadline = performance.now() + 5_000;
        while (performance.now() < deadline) {
          const packet = await window.vpn.receive_relay_packet(100);
          if (packet) last = Array.from(packet.slice(12, 16));
        }
        return last;
      }),
    ]);
    assert.equal(proof.second_used_original_connection, true);
    assert.deepEqual(last, [10, 204, 0, 4]);
    assert.equal(await page.evaluate(() => window.vpn.relay_reservation_address()), reservation.reservation);
    assert.equal(relay.logs().match(/ReservationReqAccepted/g)?.length, 1, relay.logs());
    assert.equal(relay.logs().match(/CircuitReqAccepted/g)?.length, 2, relay.logs());
  } catch (error) {
    throw new Error(`${error.message}\nNative members: ${native.logs()}\nRelay: ${relay.logs()}`, { cause: error });
  }
});

test('native and Chromium negotiate typed Demand only on a visible maintained incoming circuit', {
  timeout: 100_000,
}, async t => {
  const { P2P_VPN_RELAY_FIXTURE, P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_RECEIVER_PKG } = process.env;
  assert.ok(P2P_VPN_RELAY_FIXTURE && P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_RECEIVER_PKG);
  const files = new Map([
    ['/', ['text/html', '<!doctype html><title>Demand conformance</title>']],
    [`/${glue}`, ['text/javascript', await readFile(join(P2P_VPN_RECEIVER_PKG, glue))]],
    [`/${wasm}`, ['application/wasm', await readFile(join(P2P_VPN_RECEIVER_PKG, wasm))]],
  ]);
  const page = await newPage(t);
  await page.goto((await serve(t, files)) + '/');
  const relay = fixture(t, P2P_VPN_RELAY_FIXTURE, ['192.0.2.1', '--demand']);
  const entrance = await relay.next();
  const native = fixture(t, P2P_VPN_RECEIVER_FIXTURE, ['incoming-demand', entrance]);
  const stage = async expected => assert.deepEqual(JSON.parse(await native.next()), { stage: expected });
  const session = JSON.parse(await native.next());
  try {
    const direct = await page.evaluate(async ({ session, path }) => {
      const { default: init, BrowserVpn } = await import(path);
      await init();
      window.makeVpn = direct => BrowserVpn.with_relay(
        JSON.stringify(session.config), direct, session.relay_address,
      );
      window.startPump = vpn => {
        window.running = true;
        window.pollFailure = undefined;
        window.pump = (async () => {
          while (window.running) await vpn.poll_foreground();
        })().catch(error => { window.pollFailure = error.message; });
      };
      window.stopPump = async () => {
        window.running = false;
        await window.pump;
      };
      window.setHidden = hidden => {
        // Chromium headless does not model background tabs consistently. Override
        // only the DOM visibility input, not clocks, transport, or the WASM.
        if (hidden) Object.defineProperty(document, 'visibilityState', {
          configurable: true, value: 'hidden',
        });
        else delete document.visibilityState;
      };
      window.vpn = window.makeVpn(session.dial_address);
      const connected = JSON.parse(await window.vpn.connect());
      window.startPump(window.vpn);
      return connected;
    }, { session, path: `/${glue}` });
    assert.equal(direct.transport, 'webrtc-direct');
    assert.equal(direct.authorized, true);
    await stage('direct-legacy');
    const address = await page.evaluate(async () => {
      await window.stopPump();
      await window.vpn.close();
      window.vpn.free();
      window.vpn = window.makeVpn('');
      window.setHidden(true);
      return await window.vpn.reserve_relay();
    });
    assert.equal(address, `${entrance}/p2p-circuit/p2p/${session.config.network.local_peer}`);
    native.child.stdin.end(`${address}\n`);
    const incoming = await page.evaluate(async () => {
      const connected = JSON.parse(await window.vpn.accept_relay());
      window.startPump(window.vpn);
      return connected;
    });
    assert.equal(incoming.transport, 'circuit-relay');
    assert.equal(incoming.remote_peer_id, session.native_peer_id);
    assert.equal(incoming.authorized, true);
    await stage('hidden-legacy');
    assert.equal(await page.evaluate(() => {
      window.setHidden(false);
      return document.visibilityState;
    }), 'visible');
    await stage('negotiated');
    await stage('idle-and-wake-accepted');
    assert.equal(await page.evaluate(() => window.pollFailure), undefined);
    await page.evaluate(() => window.setHidden(true));
    await stage('hidden-withdrawal');
    await page.evaluate(() => window.stopPump());
  } catch (error) {
    throw new Error(`${error.message}\nNative member: ${native.logs()}\nRelay: ${relay.logs()}`,
      { cause: error });
  }
});

test('the browser app waits for native authorization on an explicit reservation', {
  timeout: 45_000,
  skip: skipApp,
}, async t => {
  const {
    P2P_VPN_RELAY_FIXTURE, P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_PAIRING_PKG,
  } = process.env;
  assert.ok(P2P_VPN_RELAY_FIXTURE && P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_PAIRING_PKG);
  const files = await appAssets(P2P_VPN_PAIRING_PKG);
  const page = await newPage(t);
  await page.goto((await serve(t, files)) + '/app.html');
  const status = page.getByRole('status');
  await status.filter({ hasText: /^Disconnected$/ }).waitFor();
  const relay = fixture(t, P2P_VPN_RELAY_FIXTURE, ['192.0.2.1']);
  const entrance = await relay.next();
  const native = fixture(t, P2P_VPN_RECEIVER_FIXTURE, ['incoming-app', entrance]);
  const session = JSON.parse(await native.next());
  await page.getByLabel('Peer config').setInputFiles({
    name: 'browser.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(session.config)),
  });
  const listen = page.getByRole('button', { name: 'Listen on relay', exact: true });
  assert.equal(await listen.isVisible(), false);
  await page.getByLabel('Native peer address').fill(session.relay_address);
  await listen.click();
  await status.filter({ hasText: /^Waiting for peer$/ }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Send request' }).isDisabled(), true);
  assert.equal(await page.getByRole('combobox', { name: 'Additional incoming member' }).isVisible(), false);
  const reservation = `${entrance}/p2p-circuit/p2p/${session.config.network.local_peer}`;
  assert.equal(await page.locator('#relay-address').textContent(), reservation);
  native.child.stdin.end(reservation + '\n');
  await status.filter({ hasText: /^Connected$/ }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Send request' }).isEnabled(), true);
  assert.equal(JSON.parse(await native.next()).status.Status.selected_path, 'circuit_relay');
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await status.filter({ hasText: /^Disconnected$/ }).waitFor();
  assert.equal(await page.locator('#relay-address').isVisible(), false);
});

test('the browser app receives from two nominated relay members and keeps the survivor', {
  timeout: 50_000,
  skip: skipApp,
}, async t => {
  const { P2P_VPN_RELAY_FIXTURE, P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_RECEIVER_PKG } = process.env;
  assert.ok(P2P_VPN_RELAY_FIXTURE && P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_RECEIVER_PKG);
  const files = await appAssets(P2P_VPN_RECEIVER_PKG);
  const page = await newPage(t);
  await page.setViewportSize({ width: 375, height: 760 });
  await page.goto((await serve(t, files)) + '/app.html');
  const status = page.locator('#state');
  const waitStatus = text => status.filter({ hasText: new RegExp(`^${text}$`) }).waitFor();
  await waitStatus('Disconnected');
  const relay = fixture(t, P2P_VPN_RELAY_FIXTURE, ['192.0.2.1']);
  const entrance = await relay.next();
  const native = fixture(t, P2P_VPN_RECEIVER_FIXTURE, ['shared-incoming', entrance]);
  const session = JSON.parse(await native.next());
  const primary = page.locator('#primary-incoming-status');
  const additional = page.locator('#additional-incoming-status');
  const received = page.locator('#incoming-packets');
  const send = page.getByRole('button', { name: 'Send request' });
  try {
    await page.getByLabel('Peer config').setInputFiles({
      name: 'browser.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(session.config)),
    });
    await page.getByLabel('Native peer address').fill(session.route);
    await page.getByRole('button', { name: 'Listen on relay' }).click();
    const picker = page.getByRole('combobox', { name: 'Additional incoming member' });
    await picker.waitFor();
    assert.deepEqual(await picker.locator('option:not([disabled])').evaluateAll(options => options.map(option => option.value)),
      [session.additional_peer]);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    const reservation = `${entrance}/p2p-circuit/p2p/${session.config.network.local_peer}`;
    assert.equal(await page.locator('#relay-address').textContent(), reservation);
    const allow = page.getByRole('button', { name: 'Allow member' });
    assert.equal(await allow.isDisabled(), true);
    await picker.evaluate((select, peer) => select.add(new Option(peer, peer)), session.outsider);
    await picker.selectOption(session.outsider);
    await allow.click();
    await page.locator('#error').filter({ hasText: /not authorized/ }).waitFor();
    assert.equal(await page.locator('#relay-address').textContent(), reservation);
    await picker.selectOption(session.additional_peer);
    await allow.click();
    await status.filter({ hasText: /^(Listening on relay|Waiting for peers)$/ }).waitFor();
    const reportsBothMembers = await status.textContent() === 'Waiting for peers';
    assert.equal(await picker.isVisible(), false);
    assert.equal(await page.locator('#additional-incoming-peer').textContent(), session.additional_peer);
    assert.equal(await additional.textContent(), reportsBothMembers ? 'Waiting for peer' : 'Selected');
    native.child.stdin.write(`${reservation}\n`);
    await primary.filter({ hasText: /^Connected$/ }).waitFor();
    await received.filter({ hasText: /^1$/ }).waitFor();
    assert.equal(await send.isEnabled(), true);
    native.child.stdin.write('start-second\n');
    await waitStatus(reportsBothMembers ? '2 members connected' : 'Connected');
    await received.filter({ hasText: /^3$/ }).waitFor();
    assert.equal(await additional.textContent(), reportsBothMembers ? 'Connected' : 'Selected');

    native.child.stdin.write('close-first\n');
    assert.deepEqual(JSON.parse(await native.next()), { first_closed: true });
    // The relay need not propagate the dialer's graceful close promptly.
    // Request the real browser-side close between foreground WASM calls if needed.
    await page.evaluate(async peer => {
      const { BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
      const receive = BrowserVpn.prototype.receive_relay_packet;
      BrowserVpn.prototype.receive_relay_packet = function (timeout) {
        BrowserVpn.prototype.receive_relay_packet = receive;
        this.test_close_incoming_member(peer);
        return receive.call(this, timeout);
      };
    }, session.first_peer);
    await waitStatus(reportsBothMembers ? '1 member connected' : 'Listening on relay');
    assert.equal(await primary.textContent(), 'Waiting for peer');
    assert.equal(await additional.textContent(), reportsBothMembers ? 'Connected' : 'Selected');
    assert.equal(await send.isDisabled(), true);
    assert.equal(await status.getAttribute('data-connected'), String(reportsBothMembers));
    assert.equal(await page.locator('#relay-address').textContent(), reservation);
    native.child.stdin.end('send-second\n');
    assert.deepEqual(JSON.parse(await native.next()), { second_used_original_connection: true });
    await received.filter({ hasText: /^4$/ }).waitFor();
    assert.equal(relay.logs().match(/ReservationReqAccepted/g)?.length, 1, relay.logs());
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await waitStatus('Disconnected');
    assert.equal(await page.locator('#additional-incoming').isVisible(), false);
  } catch (error) {
    throw new Error(`${error.message}\nNative members: ${native.logs()}\nRelay: ${relay.logs()}`, { cause: error });
  }
});

test('member recovery retries a network change for the same authorized peer', {
  timeout: 45_000,
  skip: skipApp,
}, async t => {
  const { P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_RECEIVER_PKG } = process.env;
  assert.ok(P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_RECEIVER_PKG);
  const native = fixture(t, P2P_VPN_RECEIVER_FIXTURE, ['recovery']);
  const session = JSON.parse(await native.next());
  const files = await appAssets(P2P_VPN_RECEIVER_PKG,
    '<meta name="p2p-vpn-discovery" content="/api/discovery">');
  const requests = [];
  const origin = await serve(t, files, async (request, response) => {
    let body = '';
    try {
      for await (const chunk of request) {
        body += chunk;
        if (body.length > 8192) throw Error('unexpected discovery lookup body size');
      }
      requests.push({ body, origin: request.headers.origin });
      const conflict = requests.length === 2;
      const result = conflict
        ? { error: 'network_changed' }
        : { addresses: [requests.length === 1 ? session.dial_address : session.recovery_address] };
      return response.writeHead(conflict ? 409 : 200, { 'Content-Type': 'application/json' })
        .end(JSON.stringify(result));
    } catch {
      response.writeHead(400).end();
    }
  });

  const page = await newPage(t);
  await page.goto(origin + '/app.html');
  const status = page.locator('#state');
  await status.filter({ hasText: /^Disconnected$/ }).waitFor();
  // The fixture closes the first transport when it receives this real packet probe.
  // Use the app's request action to exercise its recovery path without a TUN.
  await page.evaluate(async () => {
    const { BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
    BrowserVpn.prototype.fetch_http = BrowserVpn.prototype.test_drive_transport_probe;
  });
  await page.getByLabel('Peer config').setInputFiles({
    name: 'browser.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(session.config)),
  });
  await page.locator('#address').fill(session.native_peer_id);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await status.filter({ hasText: /^Connected$/ }).waitFor();

  await page.getByLabel('Overlay address').fill('10.204.0.1');
  await page.getByLabel('Port').fill('80');
  const conflict = page.waitForResponse(reply => reply.url() === origin + '/api/discovery' && reply.status() === 409);
  await page.getByRole('button', { name: 'Send request' }).click();
  await conflict;
  await status.filter({ hasText: /^(Connected|Disconnected)$/ }).waitFor();
  assert.equal(await status.textContent(), 'Connected', await page.locator('#error').textContent());
  assert.equal(await page.locator('#peer-id').textContent(), session.native_peer_id);
  assert.equal(JSON.parse(await native.next()).reauthenticated, true);
  assert.equal(requests.length, 3);
  assert.equal(JSON.parse(requests[0].body).peer, session.native_peer_id);
  assert.deepEqual(requests, [requests[0], requests[0], requests[0]]);
  assert.equal(requests[0].origin, origin);
});

for (const lanAvailable of [true, false]) {
  test(`member path loss ${lanAvailable ? 'prefers authenticated LAN over the old circuit' : 'uses one bounded circuit fallback without LAN'}`, {
    timeout: 45_000,
    skip: skipApp,
  }, async t => {
    const {
      P2P_VPN_BIN, P2P_VPN_RELAY_FIXTURE, P2P_VPN_RECEIVER_FIXTURE, P2P_VPN_RECEIVER_PKG,
      P2P_VPN_TEST_NETNS,
    } = process.env;
    assert.ok(P2P_VPN_BIN && P2P_VPN_RELAY_FIXTURE && P2P_VPN_RECEIVER_FIXTURE && P2P_VPN_RECEIVER_PKG);
    assert.match(P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
    assert.notEqual(await readlink('/proc/self/ns/net'), P2P_VPN_TEST_NETNS,
      'refusing to configure the parent network');

    const ip = (...args) => execFileSync('ip', args, { timeout: 5000 });
    const relay = fixture(t, P2P_VPN_RELAY_FIXTURE, ['192.0.2.1']);
    const entrance = await relay.next();
    let linkCreated = false;
    t.after(() => {
      if (linkCreated) ip('link', 'del', 'recovery-lan');
    });
    const native = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
      'printf "%s\\n" "$$"',
      'read ready',
      'ip link set lo up',
      'ip addr add 192.168.44.2/24 dev recovery-member',
      'ip link set recovery-member up',
      'ip route add 224.0.0.251/32 dev recovery-member',
      'ip route add 192.0.2.1/32 via 192.168.44.1',
      'exec "$@"',
    ].join('\n'), 'recovery-member', P2P_VPN_RECEIVER_FIXTURE,
      'recovery', entrance, 'relayed', ...(lanAvailable ? ['direct'] : []),
    ]);
    const pid = await native.next();
    assert.match(pid, /^\d+$/);
    ip('link', 'add', 'recovery-lan', 'type', 'veth', 'peer', 'name', 'recovery-member');
    linkCreated = true;
    ip('link', 'set', 'recovery-member', 'netns', pid);
    ip('addr', 'add', '192.168.44.1/24', 'dev', 'recovery-lan');
    ip('link', 'set', 'recovery-lan', 'up');
    ip('route', 'add', '224.0.0.251/32', 'dev', 'recovery-lan');
    native.child.stdin.end('ready\n');

    const session = JSON.parse(await native.next());
    session.config.network.discovery = { mdns: true, kademlia: true };
    const circuit = { addresses: [], relay_address: session.relay_address };
    const lan = { addresses: [session.recovery_address], source: 'lan' };
    const assets = await mkdtemp(join(tmpdir(), 'p2p-vpn-recovery-'));
    t.after(() => rm(assets, { recursive: true, force: true }));
    await mkdir(join(assets, 'pkg'));
    for (const [path, [, bytes]] of await appAssets(P2P_VPN_RECEIVER_PKG)) {
      await writeFile(join(assets, path), bytes);
    }
    const companion = fixture(t, P2P_VPN_BIN, [
      'browser-serve', '--assets', assets, '--port', '0',
      ...(lanAvailable ? [] : ['--owned-interface', 'recovery-lan']),
    ]);
    const app = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/.exec(await companion.next());
    assert.ok(app, 'companion must report the app URL');
    const requests = [];
    const late = Promise.withResolvers();
    const refreshStarted = Promise.withResolvers();

    try {
      const page = await newPage(t);
      const url = new URL('/api/discovery', app[1]).href;
      let companionReply;
      await page.route(url, async route => {
        const query = route.request().postDataJSON();
        requests.push([query.peer, query.lan, query.kademlia]);
        if (!query.kademlia) {
          refreshStarted.resolve();
          await route.fulfill({ json: await late.promise });
        } else if (requests.length === 1) {
          await route.fulfill({ json: circuit });
        } else {
          // Run real companion LAN selection; substitute only the public
          // side's old circuit result so this test does not use DHT.
          const reply = await route.fetch({ postData: { ...query, kademlia: false } });
          companionReply = { status: reply.status(), body: await reply.json() };
          await route.fulfill(lanAvailable ? { response: reply } : { json: circuit });
        }
      });
      await page.goto(app[1]);
      const status = page.locator('#state');
      await status.filter({ hasText: /^Disconnected$/ }).waitFor();
      await page.evaluate(async () => {
        const { BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
        const { set_preferred_member_endpoints: setPreferred, poll_foreground: poll } = BrowserVpn.prototype;
        const observed = window.recoveryObservations = { preferred: [], polls: 0 };
        BrowserVpn.prototype.set_preferred_member_endpoints = function (generation, addresses) {
          observed.preferred.push(JSON.parse(addresses));
          return setPreferred.call(this, generation, addresses);
        };
        BrowserVpn.prototype.poll_foreground = function () {
          observed.polls++;
          return poll.call(this);
        };
        BrowserVpn.prototype.fetch_http = BrowserVpn.prototype.test_drive_transport_probe;
      });
      await page.getByLabel('Peer config').setInputFiles({
        name: 'browser.json', mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify(session.config)),
      });
      await page.locator('#address').fill(session.native_peer_id);
      await page.getByRole('button', { name: 'Connect', exact: true }).click();
      await status.filter({ hasText: /^Connected$/ }).waitFor();
      await Promise.race([
        refreshStarted.promise,
        new Promise((_, reject) => setTimeout(() => reject(Error('No preferred LAN lookup')), 5000).unref()),
      ]);

      const send = page.getByRole('button', { name: 'Send request' });
      await page.getByLabel('Overlay address').fill('10.204.0.1');
      await page.getByLabel('Port').fill('80');
      await send.click();
      await page.getByText('Connection restored. Send the request again.').waitFor();
      assert.deepEqual(JSON.parse(await native.next()), { reauthenticated: true });
      assert.equal(companionReply?.status, 200, JSON.stringify(companionReply));
      if (lanAvailable) {
        assert.equal(companionReply.body.source, 'lan');
        assert.ok(companionReply.body.addresses.includes(session.recovery_address),
          JSON.stringify(companionReply));
      } else {
        assert.deepEqual(companionReply.body, { addresses: [], source: null });
      }

      const lateReply = page.waitForResponse(reply => {
        return reply.url() === url && !reply.request().postDataJSON().kademlia;
      });
      late.resolve(lan);
      assert.equal(await (await lateReply).finished(), null);
      const { polls } = await page.evaluate(() => window.recoveryObservations);
      await page.waitForFunction(count => window.recoveryObservations.polls >= count + 3, polls);
      assert.deepEqual(await page.evaluate(() => window.recoveryObservations.preferred), []);

      await send.click();
      assert.deepEqual(JSON.parse(await native.next()), { recovered_packet: true });
      await page.locator('#response').waitFor();
      const recovered = JSON.parse(await page.locator('#response').textContent());
      assert.equal(recovered.authorized, true);
      assert.equal(recovered.transport, lanAvailable ? 'webrtc-direct' : 'circuit-relay');
      assert.equal(await page.locator('#peer-id').textContent(), session.native_peer_id);
      assert.deepEqual(requests, [
        [session.native_peer_id, true, true],
        [session.native_peer_id, true, false],
        [session.native_peer_id, true, true],
      ]);
    } finally {
      late.resolve({ addresses: [] });
    }
  });
}
