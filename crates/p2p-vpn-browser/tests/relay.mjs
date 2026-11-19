// Build browser-relay-fixture for native and wasm32-unknown-unknown with
// --features relay-client,test-hooks; run wasm-bindgen --target web on its WASM.
// Set P2P_VPN_RELAY_FIXTURE and P2P_VPN_RELAY_PKG to the resulting native binary
// and the wasm-bindgen output directory. On Linux run in an isolated network:
// unshare --user --map-root-user --net sh -ec '
//   ip link set lo up
//   ip link add pv-relay type dummy
//   ip address add 192.0.2.1/24 dev pv-relay
//   ip link set pv-relay up
//   node --test crates/p2p-vpn-browser/tests/relay.mjs
// '
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
const glue = 'browser-relay-fixture.js';
const wasm = 'browser-relay-fixture_bg.wasm';

test('Chromium peers authenticate and exchange substreams through a real Circuit Relay v2', {
  timeout: 80_000,
}, async (t) => {
  const fixture = process.env.P2P_VPN_RELAY_FIXTURE;
  const pkg = process.env.P2P_VPN_RELAY_PKG;
  assert.ok(fixture && pkg, 'set P2P_VPN_RELAY_FIXTURE and P2P_VPN_RELAY_PKG');
  const files = new Map([['/', ['text/html', '<!doctype html><title>Relay fixture</title>']]]);
  for (const [file, mime] of [[glue, 'text/javascript'], [wasm, 'application/wasm']]) {
    files.set(`/${file}`, [mime, await readFile(join(pkg, file))]);
  }
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

  async function newPeer() {
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const id = await page.evaluate(async path => {
      const { default: init, RelayProbe } = await import(path);
      await init();
      window.probe = new RelayProbe();
      return window.probe.peer_id();
    }, `/${glue}`);
    return { page, id };
  }

  const [caller, receiver, other] = await Promise.all([newPeer(), newPeer(), newPeer()]);
  const child = spawn(fixture, [process.env.P2P_VPN_RELAY_BIND_IP || '192.0.2.1'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  const exited = new Promise(resolve => child.once('close', resolve));
  const lines = createInterface({ input: child.stdout });
  t.after(async () => {
    lines.close();
    child.kill();
    await exited;
  });
  try {
    const entrance = await Promise.race([
      lines[Symbol.asyncIterator]().next().then(({ value }) => value),
      once(child, 'error').then(([error]) => { throw error; }),
    ]);
    assert.match(entrance, /^\/ip4\/.*\/webrtc-direct\/certhash\/.*\/p2p\//);
    async function configure(from, to) {
      await from.page.evaluate(args => window.probe.configure(...args), [entrance, to.id]);
    }
    await Promise.all([configure(caller, receiver), configure(receiver, caller), configure(other, receiver)]);
    await receiver.page.evaluate(() => window.probe.reserve());
    assert.deepEqual(await Promise.all([
      caller.page.evaluate(() => window.probe.dial_and_ping()),
      receiver.page.evaluate(() => window.probe.await_ping()),
    ]), [receiver.id, caller.id]);

    const [rejection] = await Promise.all([
      receiver.page.evaluate(() => window.probe.await_rejected_peer()),
      assert.rejects(other.page.evaluate(() => window.probe.dial_and_ping())),
    ]);
    assert.match(rejection, /circuit Noise identity does not match the pinned VPN peer/);
  } catch (error) {
    throw new Error(`Relay verification failed: ${error.message}\nNative relay: ${stderr}`, { cause: error });
  }
});
