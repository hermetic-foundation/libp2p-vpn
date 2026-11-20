// Run with the receiver fixture and test-hooks package under the wire suite's isolated underlay.
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

test('local Chromium close retires a checkpoint assembly with its final page held', async () => {
  const fixture = process.env.P2P_VPN_RECEIVER_FIXTURE;
  const pkg = process.env.P2P_VPN_RECEIVER_PKG;
  assert.ok(fixture && pkg, 'Set P2P_VPN_RECEIVER_FIXTURE and P2P_VPN_RECEIVER_PKG (test-hooks)');
  const files = new Map([['/', ['text/html', '<!doctype html><title>Checkpoint transfer</title>']]]);
  for (const [file, type] of [['p2p_vpn_browser.js', 'text/javascript'], ['p2p_vpn_browser_bg.wasm', 'application/wasm']]) {
    files.set(`/${file}`, [type, await readFile(join(pkg, file))]);
  }
  const server = createServer((request, response) => {
    const asset = files.get(request.url);
    if (!asset) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': asset[0], 'Cache-Control': 'no-store' }).end(asset[1]);
  });
  let browser, child, exited, reader;
  const timeout = new AbortController();
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    browser = await chromium.launch({
      headless: true,
      ...(process.env.P2P_VPN_CHROMIUM
        ? { executablePath: process.env.P2P_VPN_CHROMIUM }
        : { channel: process.env.P2P_VPN_BROWSER_CHANNEL || 'chrome' }),
    });
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
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
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
  } finally {
    timeout.abort();
    reader?.close();
    child?.kill();
    await exited;
    await browser?.close();
    server.close();
  }
});
