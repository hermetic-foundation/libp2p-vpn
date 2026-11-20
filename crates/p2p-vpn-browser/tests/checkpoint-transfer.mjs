// Run with the receiver fixture and both browser packages under the wire suite's isolated underlay.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

const { chromium } = createRequire(import.meta.url)('playwright');

async function servePackage(pkg) {
  const files = new Map([['/', ['text/html', '<!doctype html><title>Checkpoint transfer</title>']]]);
  for (const [file, type] of [['p2p_vpn_browser.js', 'text/javascript'], ['p2p_vpn_browser_bg.wasm', 'application/wasm']]) {
    files.set(`/${file}`, [type, await readFile(join(pkg, file))]);
  }
  const server = createServer((request, response) => {
    const asset = files.get(request.url);
    if (!asset) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': asset[0], 'Cache-Control': 'no-store' }).end(asset[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, url: `http://127.0.0.1:${server.address().port}/` };
}

function launchChromium() {
  return chromium.launch({
    headless: true,
    ...(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: process.env.P2P_VPN_BROWSER_CHANNEL || 'chrome' }),
  });
}

test('local Chromium close retires a held checkpoint assembly and a fresh sync installs', async () => {
  const fixture = process.env.P2P_VPN_RECEIVER_FIXTURE;
  const pkg = process.env.P2P_VPN_RECEIVER_PKG;
  assert.ok(fixture && pkg, 'Set P2P_VPN_RECEIVER_FIXTURE and P2P_VPN_RECEIVER_PKG (test-hooks)');
  const { server, url } = await servePackage(pkg);
  let browser, child, exited, reader;
  const timeout = new AbortController();
  try {
    browser = await launchChromium();
    const page = await browser.newPage();
    await page.addInitScript(() => {
      window.checkpointTransports = [];
      window.RTCPeerConnection = class extends window.RTCPeerConnection {
        constructor(...args) {
          super(...args);
          window.checkpointTransports.push(this);
        }
      };
    });
    await page.goto(url);
    child = spawn(fixture, ['checkpoint-interrupted'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.on('error', error => { stderr += error.message; });
    child.stderr.setEncoding('utf8').on('data', data => { stderr = (stderr + data).slice(-8192); });
    exited = new Promise(resolve => child.once('close', resolve));
    reader = createInterface({ input: child.stdout });
    const lines = reader[Symbol.asyncIterator]();
    async function next(description) {
      const { value, done } = await lines.next();
      if (done) throw Error(`Native fixture exited (${await exited}) before ${description}: ${stderr}`);
      return JSON.parse(value);
    }
    const session = await next('advertising the checkpoint publisher');
    assert.equal(session.offered.authority_revision, session.prior.authority_revision + 1);
    assert.notDeepEqual(session.offered.digest, session.prior.digest);

    const outcome = page.evaluate(async session => {
      const { default: init, BrowserVpn } = await import('/p2p_vpn_browser.js');
      await init();
      const open = () => BrowserVpn.open_checkpoint(JSON.stringify(session.config), session.address,
        JSON.stringify(session.bootstrap), Uint8Array.from(session.secret));
      window.openTransferCheckpoint = open;
      const { local_peer, name } = session.config.network;
      const key = `p2p-vpn:checkpoint-membership:1:${JSON.stringify([name, local_peer])}`;
      const vpn = await open();
      try {
        if (typeof vpn.test_checkpoint_transfer_stats !== 'function') {
          throw Error('WASM package is missing the checkpoint transfer test hook');
        }
        const before = JSON.parse(vpn.snapshot());
        const savedBefore = localStorage.getItem(key);
        let failure;
        try {
          await vpn.connect();
        } catch (error) {
          failure = error.message;
        }
        const after = JSON.parse(vpn.snapshot());
        const savedAfter = localStorage.getItem(key);
        const stats = JSON.parse(vpn.test_checkpoint_transfer_stats());
        await vpn.close();
        const reopened = await open();
        try {
          return { before, after, stats, savedBefore, savedAfter, failure, reopened: JSON.parse(reopened.snapshot()) };
        } finally {
          reopened.free();
        }
      } finally {
        vpn.free();
      }
    }, session);
    const held = await Promise.race([
      next('holding the authenticated final page'),
      outcome.then(result => { throw Error(`Browser settled before the final page was held: ${result.failure}`); }),
    ]);
    assert.deepEqual(held, { final_cursor: 8192, final_page_held: true });
    await page.evaluate(() => {
      const [transport] = window.checkpointTransports;
      if (window.checkpointTransports.length !== 1 || transport.connectionState !== 'connected') {
        throw Error('Expected one live WebRTC transport with the final page held');
      }
      transport.close();
      if (transport.connectionState !== 'closed') throw Error('Local close did not take effect');
      // Wake the muxer after close(); Chromium need not emit this event itself.
      transport.dispatchEvent(new Event('connectionstatechange'));
    });
    const result = await Promise.race([
      outcome,
      delay(5_000, undefined, { signal: timeout.signal }).then(() => {
        throw Error('Checkpoint connect did not settle within five seconds of the local close');
      }),
    ]);
    assert.match(result.failure, /WebRTC disconnected/);
    for (const state of [result.before, result.after, result.reopened]) {
      assert.deepEqual(state.checkpoint.boundary, session.prior);
      assert.equal(state.checkpoint.sync, 'resync_required');
      assert.equal(state.authorized, false);
      assert.equal(state.ready, false);
    }
    assert.ok(result.savedBefore, 'expected a persisted prior checkpoint');
    assert.equal(result.savedAfter, result.savedBefore, 'interrupted transfer wrote protected state');
    assert.deepEqual(result.stats, {
      assembler_sessions: 0, publisher_sessions: 0, retired_sessions: 1, buffered_bytes: 0,
    });

    const [wire, retry] = await Promise.all([
      next('confirming the fresh transfer on the new connection'),
      page.evaluate(async () => {
        const vpn = await window.openTransferCheckpoint();
        try {
          const installed = JSON.parse(await vpn.connect());
          const [initial, fresh] = window.checkpointTransports;
          if (window.checkpointTransports.length !== 2
            || initial.connectionState !== 'closed' || fresh.connectionState !== 'connected') {
            throw Error('The retry did not use a new live WebRTC transport');
          }
          await vpn.close();
          const reopened = await window.openTransferCheckpoint();
          try {
            return { installed, persisted: JSON.parse(reopened.snapshot()) };
          } finally {
            reopened.free();
          }
        } finally {
          vpn.free();
        }
      }),
    ]);
    assert.deepEqual(wire, { retry_installed: session.offered });
    assert.deepEqual(retry.installed.checkpoint.boundary, session.offered);
    assert.equal(retry.installed.checkpoint.sync, 'participating');
    assert.equal(retry.installed.authorized, true);
    assert.equal(retry.installed.ready, true);
    assert.deepEqual(retry.persisted.checkpoint.boundary, session.offered);
    assert.equal(retry.persisted.checkpoint.sync, 'resync_required');
    assert.equal(retry.persisted.authorized, false);
  } finally {
    timeout.abort();
    reader?.close();
    child?.kill();
    await exited;
    await browser?.close();
    server.close();
  }
});

test('Chromium SDK restores a pending floor and durably learns exclusion before forwarding', {
  timeout: 55_000,
}, async t => {
  const fixture = process.env.P2P_VPN_RECEIVER_FIXTURE;
  const pkg = process.env.P2P_VPN_PAIRING_PKG;
  assert.ok(fixture && pkg, 'Set P2P_VPN_RECEIVER_FIXTURE and P2P_VPN_PAIRING_PKG (production)');
  const { server, url } = await servePackage(pkg);
  const child = spawn(fixture, ['checkpoint-pending-exclusion'], {
    stdio: ['pipe', 'pipe', 'pipe'], signal: t.signal,
  });
  const exited = new Promise(resolve => child.once('close', resolve));
  let stderr = '';
  child.on('error', error => { stderr += error.message; });
  child.stderr.setEncoding('utf8').on('data', data => { stderr = (stderr + data).slice(-8192); });
  const reader = createInterface({ input: child.stdout });
  const lines = reader[Symbol.asyncIterator]();
  async function next() {
    const { value, done } = await lines.next();
    if (done) throw Error(`Native checkpoint fixture exited (${await exited}): ${stderr}`);
    return JSON.parse(value);
  }
  let browser;
  try {
    const session = await next();
    const key = `p2p-vpn:checkpoint-membership:1:${JSON.stringify([
      session.config.network.name, session.config.network.local_peer,
    ])}`;
    browser = await launchChromium();
    const context = await browser.newContext();
    await context.addInitScript(() => {
      window.checkpointTransports = [];
      window.RTCPeerConnection = class extends window.RTCPeerConnection {
        constructor(...args) {
          super(...args);
          window.checkpointTransports.push(this);
        }
      };
    });
    const open = async (withFloor) => {
      const page = await context.newPage();
      await page.goto(url);
      await page.evaluate(async ({ config, address, bootstrap, secret, withFloor }) => {
        const { default: init, BrowserVpn } = await import('/p2p_vpn_browser.js');
        await init();
        if (!withFloor) delete bootstrap.enrollment_floor;
        window.vpn = await BrowserVpn.open_checkpoint(JSON.stringify(config), address,
          JSON.stringify(bootstrap), Uint8Array.from(secret));
      }, { ...session, withFloor });
      return page;
    };
    const snapshot = page => page.evaluate(() => JSON.parse(window.vpn.snapshot()));
    const saved = page => page.evaluate(key => JSON.parse(localStorage.getItem(key)).payload, key);
    const close = async page => {
      const transports = await page.evaluate(async () => {
        await window.vpn.close();
        window.vpn.free();
        return window.checkpointTransports.map(transport => transport.connectionState);
      });
      await page.close();
      return transports;
    };
    const gated = state => {
      assert.equal(state.authorized, false);
      assert.equal(state.ready, false);
      assert.equal(state.stream_mtu, null);
      assert.equal(state.counters.outbound_ip_packets, 0);
      assert.equal(state.counters.inbound_ip_packets, 0);
      assert.equal(state.counters.accepted_outbound_packets, 0);
    };
    const first = await open(true);
    gated(await snapshot(first));
    const pending = await saved(first);
    assert.deepEqual(pending.enrollment_floor, session.floor);
    assert.equal(pending.retained.snapshot.payload.authority_revision, session.prior.authority_revision);
    assert.deepEqual(await close(first), []);

    // The same owner provisioned inputs, but only the protected store can supply the floor.
    const restored = await open(false);
    const before = await snapshot(restored);
    gated(before);
    assert.equal(before.checkpoint.sync, 'resync_required');
    assert.deepEqual(before.checkpoint.boundary, session.prior);
    assert.deepEqual(await saved(restored), pending);
    t.diagnostic(`restored pending floor revision ${session.floor.authority_revision} with IP disabled`);

    child.stdin.write('remove\n');
    const { offered } = await next();
    assert.equal(offered.authority_revision, session.floor.authority_revision + 1);
    const outcome = await restored.evaluate(async ip => {
      try {
        // A normal VPN HTTP request must complete checkpoint sync before it emits IP.
        await window.vpn.fetch_http(ip, 80, '/');
        return null;
      } catch (error) {
        return error.message;
      }
    }, session.native_ip);
    assert.match(outcome, /Excluded/);
    const after = await snapshot(restored);
    gated(after);
    assert.equal(after.checkpoint.sync, 'excluded');
    assert.deepEqual(after.checkpoint.boundary, offered);
    const excluded = await saved(restored);
    assert.equal(excluded.enrollment_floor, null);
    assert.equal(excluded.retained.snapshot.payload.authority_revision, offered.authority_revision);
    assert.ok(!excluded.retained.snapshot.payload.members.some(member =>
      member.subject.peer_id === session.config.network.local_peer));
    assert.deepEqual(await close(restored), ['closed']);

    const reopened = await open(false);
    const durable = await snapshot(reopened);
    gated(durable);
    assert.deepEqual(durable.checkpoint.boundary, offered);
    assert.deepEqual(await saved(reopened), excluded);
    assert.deepEqual(await close(reopened), []);
    child.stdin.end('finish\n');
    assert.deepEqual(await next(), { snapshots_sent: 1, packets_seen: 0 });
    assert.equal(await exited, 0, stderr);
    t.diagnostic(`authenticated removal at revision ${offered.authority_revision} survived reopen; no VPN packet reached native`);
  } finally {
    reader.close();
    child.stdin.end();
    child.kill();
    await browser?.close();
    await exited;
    server.close();
  }
});
