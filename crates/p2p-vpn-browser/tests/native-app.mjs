import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

// Run in a disposable Linux user and network namespace with TUN access.
const binary = process.env.P2P_VPN_BIN;
if (!binary) throw Error('P2P_VPN_BIN must point to a native build with the webrtc feature.');
const directory = await mkdtemp(join(tmpdir(), 'p2p-vpn-browser-app-'));
const nativeConfig = join(directory, 'native.json');
const browserConfig = join(directory, 'browser.json');
const control = join(directory, 'control.sock');
const underlay = '192.0.2.1';
const files = new Map([
  ['/app.html', 'text/html'],
  ['/app.css', 'text/css'],
  ['/app.js', 'text/javascript'],
  ['/pkg/logo.svg', 'image/svg+xml'],
  ['/pkg/p2p_vpn_browser.js', 'text/javascript'],
  ['/pkg/p2p_vpn_browser_bg.wasm', 'application/wasm'],
]);
const web = createServer(async (req, res) => {
  const url = req.url;
  if (req.method !== 'GET' || !files.has(url)) {
    res.writeHead(404).end();
    return;
  }
  try {
    const bytes = await readFile(new URL('../web' + url, import.meta.url));
    res.writeHead(200, { 'Content-Type': files.get(url) }).end(bytes);
  } catch {
    res.writeHead(500).end();
  }
});
let daemon, exited, browser, service;
let logs = '';
let listens = 0;
function cli(...args) {
  return execFileSync(binary, args, { encoding: 'utf8', timeout: 10000 });
}
async function waitFor(description, check) {
  for (let attempt = 0; attempt < 80; ++attempt) {
    const found = check();
    if (found) return found;
    if (daemon && (daemon.exitCode !== null || daemon.signalCode)) break;
    await delay(250);
  }
  throw Error(`Did not see ${description} in 20 seconds.\n${logs.slice(-8000)}`);
}
async function listen(server, host) {
  server.listen(0, host);
  await once(server, 'listening');
  return server.address().port;
}

try {
  for (const output of [nativeConfig, browserConfig]) {
    cli('init-config', '--network', 'browser-app-test', '--interface', 'pvbrowser0', '--output', output);
  }
  const native = JSON.parse(await readFile(nativeConfig, 'utf8'));
  const client = JSON.parse(await readFile(browserConfig, 'utf8'));
  const nativeStatus = cli('status', '-c', nativeConfig);
  const clientStatus = cli('status', '-c', browserConfig);
  const peerId = status => /^local peer: (\S+)$/m.exec(status)?.[1];
  const clientId = peerId(clientStatus);
  const nativeId = peerId(nativeStatus);
  assert.ok(clientId && nativeId && clientId !== nativeId);
  native.network.listen_addresses = [`/ip4/${underlay}/udp/0/webrtc-direct`];
  native.network.discovery = {
    mdns: false, kademlia: false, kademlia_provider_advertisement: false, dcutr: false, autonat: false,
  };
  native.network.packet_plane = { listen: [], quic_listen: [] };
  native.peers = [{ id: clientId, addresses: ['/ip4/127.0.0.1/tcp/9'] }];
  client.peers = [{ id: nativeId }];
  await writeFile(nativeConfig, JSON.stringify(native), { mode: 0o600 });
  await writeFile(browserConfig, JSON.stringify(client), { mode: 0o600 });
  const ipv4 = status => /^local overlay ipv4: ((?:\d+\.){3}\d+)/m.exec(status)?.[1];
  const nativeIp = ipv4(nativeStatus);
  const clientIp = ipv4(clientStatus);
  assert.ok(nativeIp && clientIp && nativeIp !== clientIp, 'expected two distinct overlay IPv4 routes');

  daemon = spawn(binary, ['up', '-c', nativeConfig, '--control-socket', control], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  exited = once(daemon, 'exit');
  daemon.stderr.setEncoding('utf8').on('data', chunk => { logs = (logs + chunk).slice(-64 * 1024); });
  const address = await waitFor('a WebRTC Direct dial address', () =>
    /event=webrtc_listener_ready[^\n]* address=(\S+)/.exec(logs)?.[1],
  );
  assert.ok(address.includes('/webrtc-direct/certhash/'));
  assert.ok(address.endsWith('/p2p/' + nativeId));

  // Listening on the overlay, not on the browser HTTP origin or underlay.
  service = createServer((req, res) => {
    ++listens;
    if (req.socket.remoteAddress !== clientIp) {
      res.writeHead(403).end('Unexpected source');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' }).end('overlay-only: ' + req.url);
  });
  const port = await listen(service, nativeIp);
  const webPort = await listen(web, '127.0.0.1');
  browser = await chromium.launch({
    ...(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: 'chrome' }),
  });
  const page = await browser.newPage({ viewport: { width: 360, height: 740 } });
  const failures = [];
  page.on('pageerror', error => failures.push(error.message));
  page.on('request', request => {
    // Only the static application and WASM use HTTP; the VPN request uses WebRTC.
    const url = new URL(request.url());
    if (request.method() !== 'GET' || url.host !== `127.0.0.1:${webPort}` || !files.has(url.pathname)) {
      failures.push('Unexpected browser HTTP request');
    }
  });
  await page.goto(`http://127.0.0.1:${webPort}/app.html`);
  const state = page.locator('#state');
  await state.filter({ hasText: /^Disconnected$/ }).waitFor({ timeout: 10000 });
  assert.equal(await page.locator('#send').isDisabled(), true);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));

  const input = page.getByLabel('Peer config');
  await input.setInputFiles({
    name: 'wrong-network.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ ...client, peers: [] })),
  });
  await page.getByLabel('Native peer address').fill(address);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: 'native peer is not authorized' }).waitFor();
  assert.equal(listens, 0);

  for (const path of ['/first', '/reconnected']) {
    await input.setInputFiles(browserConfig);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await state.filter({ hasText: /^Connected$/ }).waitFor({ timeout: 30_000 });
    assert.equal(await page.locator('#peer-id').textContent(), nativeId);
    await page.getByLabel('Overlay IPv4').fill(nativeIp);
    await page.getByLabel('Port').fill(String(port));
    await page.getByLabel('Path').fill(path);
    await page.getByRole('button', { name: 'Send request' }).click();
    await page.locator('#response').filter({ hasText: 'overlay-only: ' + path }).waitFor();
    assert.match(await page.locator('#response').textContent(), /^HTTP\/1\.1 200 OK\r\n/);
    assert.equal(await page.locator('#error').isVisible(), false);
    if (path === '/reconnected' && process.env.P2P_VPN_BROWSER_SCREENSHOT) {
      await page.setViewportSize({ width: 1024, height: 760 });
      await page.screenshot({ path: process.env.P2P_VPN_BROWSER_SCREENSHOT, fullPage: true });
    }
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await state.filter({ hasText: /^Disconnected$/ }).waitFor();
    assert.equal(await page.locator('#response').isVisible(), false);
  }
  assert.equal(listens, 2);
  assert.deepEqual(failures, []);
  console.log('PASS: browser app authenticated to the native daemon and fetched two overlay HTTP responses across reconnect.');
} finally {
  try {
    await browser?.close();
    if (daemon && daemon.exitCode === null && !daemon.signalCode) {
      daemon.kill('SIGTERM');
      const result = await Promise.race([exited, delay(5000, null, { ref: false })]);
      if (!result) {
        daemon.kill('SIGKILL');
        await exited;
      }
    }
    service?.close();
    web.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
