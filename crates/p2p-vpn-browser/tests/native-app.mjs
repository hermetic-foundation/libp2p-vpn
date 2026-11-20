import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
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
const pkg = process.env.P2P_VPN_BROWSER_PKG;
const directory = await mkdtemp(join(tmpdir(), 'p2p-vpn-browser-app-'));
const nativeConfig = join(directory, 'native.json');
const browserConfig = join(directory, 'browser.json');
const control = join(directory, 'control.sock');
const netLog = join(directory, 'chromium-netlog.json');
const publicName = 'p2p-vpn-n1.example.com';
const underlay = '192.0.2.1';
const testDiscovery = process.env.P2P_VPN_TEST_DISCOVERY === '1';
const discoveryRequests = [];
let discoverableAddress;
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
  if (testDiscovery && url === '/api/discovery' && req.method === 'POST') {
    try {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 8192) throw Error('discovery request exceeds test limit');
      }
      discoveryRequests.push(JSON.parse(body));
      res.writeHead(200, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ addresses: [discoverableAddress] }));
    } catch {
      res.writeHead(400).end();
    }
    return;
  }
  if (req.method !== 'GET' || !files.has(url)) {
    res.writeHead(404).end();
    return;
  }
  try {
    let bytes = await readFile(pkg && url.startsWith('/pkg/')
      ? join(pkg, url.slice('/pkg/'.length))
      : new URL('../web' + url, import.meta.url));
    if (testDiscovery && url === '/app.html') {
      bytes = bytes.toString().replace('</head>',
        '<meta name="p2p-vpn-discovery" content="/api/discovery"></head>');
    }
    res.writeHead(200, { 'Content-Type': files.get(url) }).end(bytes);
  } catch {
    res.writeHead(500).end();
  }
});
let daemon, exited, browser, service, ipv6Service;
let logs = '';
let listens = 0;
function cli(...args) {
  return execFileSync(binary, args, { encoding: 'utf8', timeout: 10000 });
}
function fallbackLabel(peer) {
  // Decode the libp2p ID and hash its binary representation, not its text.
  const base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const value = [...peer].reduce((n, digit) => n * 58n + BigInt(base58.indexOf(digit)), 0n);
  const hex = value.toString(16);
  const bytes = Buffer.concat([
    Buffer.alloc(/^1*/.exec(peer)[0].length),
    Buffer.from(hex.padStart(hex.length + hex.length % 2, '0'), 'hex'),
  ]);
  const bits = [...createHash('sha256').update(bytes).digest()]
    .map(byte => byte.toString(2).padStart(8, '0')).join('').padEnd(260, '0');
  const alphabet = '0123456789abcdefghjkmnpqrstvwxyz';
  return 'peer-' + bits.match(/.{5}/g).map(group => alphabet[parseInt(group, 2)]).join('');
}

async function checkNameAuthority(page, address, client, subjectConfig, subjectAddresses, expected) {
  const browserPublic = join(directory, 'browser-public.json');
  cli('identity-public', '--config', browserConfig, '--output', browserPublic);
  const issue = (...args) => JSON.parse(cli('membership-record-issue',
    '--issuer-config', nativeConfig, '--member-identity', browserPublic, '--output', '-', ...args));
  const old = issue('--hostname', 'retired', '--sequence', '99');
  const current = issue('--membership-epoch', '1', '--sequence', '100', '--hostname', 'renamed');
  const revoked = issue('--membership-epoch', '2', '--sequence', '1', '--revoked');
  const readmitted = issue('--membership-epoch', '3', '--hostname', 'readmitted');
  const names = {
    remoteFallback: fallbackLabel(expected.peer_id),
    localFallback: fallbackLabel(old.payload.member_peer),
  };
  const results = await page.evaluate(async ({ address, client, subjectConfig, old, current, revoked, readmitted, names, publicName }) => {
    const { default: init, BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
    await init();
    const resolve = async (vpn, label) => {
      try {
        return JSON.parse(await vpn.resolve_overlay_name(label.includes('.') ? label
          : label + '.browser-app-test.p2p-vpn.internal'));
      } catch (error) {
        return { error: error.message };
      }
    };
    const withVpn = async (config, check) => {
      const vpn = new BrowserVpn(JSON.stringify(config), address);
      try {
        return await check(vpn);
      } finally {
        await vpn.close();
        vpn.free();
      }
    };
    const signed = await withVpn(client, async vpn => {
      const before = await resolve(vpn, names.remoteFallback);
      const original = await resolve(vpn, 'native-peer');
      await vpn.connect();
      return {
        before, original,
        after: await resolve(vpn, names.remoteFallback),
        previous: await resolve(vpn, 'native-peer'),
        renamed: await resolve(vpn, 'signed-native'),
        public: await resolve(vpn, publicName),
      };
    });
    const collision = await withVpn({
      ...client,
      network: { ...client.network, dns: { ...client.network.dns, hostname: 'signed-native' } },
    }, async vpn => {
      await vpn.connect();
      return {
        friendly: await resolve(vpn, 'signed-native'),
        remote: await resolve(vpn, names.remoteFallback),
        local: await resolve(vpn, names.localFallback),
      };
    });
    // Observe a third-party revocation without losing the selected transport peer.
    const lookup = (records, labels) => withVpn({
      ...subjectConfig,
      peers: [...client.peers, { id: old.payload.member_peer, name: 'static-subject' }],
      network: { ...subjectConfig.network, dns: client.network.dns, member_records: records },
    }, async vpn => {
      const answers = [];
      for (const label of labels) answers.push(await resolve(vpn, label));
      return answers;
    });
    return {
      signed, collision,
      old: await lookup([old], ['retired']),
      stale: await lookup([current, readmitted, old, revoked], ['readmitted', 'retired', 'renamed']),
      revoked: await lookup([old, revoked, current], ['retired', 'renamed', 'static-subject', names.localFallback]),
    };
  }, { address, client, subjectConfig, old, current, revoked, readmitted, names, publicName });
  const missing = { error: 'Overlay hostname not found' };
  const fqdn = label => label + '.browser-app-test.p2p-vpn.internal.';
  const fallback = { ...expected, name: fqdn(names.remoteFallback) };
  assert.deepEqual(results.signed, {
    before: fallback, original: { ...expected, name: fqdn('native-peer') },
    after: fallback, previous: missing,
    renamed: { ...expected, name: fqdn('signed-native') }, public: missing,
  });
  assert.deepEqual(results.collision, {
    friendly: { error: 'Overlay hostname has conflicting owners' },
    remote: fallback,
    local: { ...subjectAddresses, name: fqdn(names.localFallback), peer_id: old.payload.member_peer },
  });
  assert.deepEqual(results.old, [
    { ...subjectAddresses, name: fqdn('retired'), peer_id: old.payload.member_peer },
  ]);
  assert.deepEqual(results.stale, [
    { ...subjectAddresses, name: fqdn('readmitted'), peer_id: old.payload.member_peer },
    missing, missing,
  ]);
  assert.deepEqual(results.revoked, [missing, missing, missing, missing]);
  console.log('PASS: peer-signed rename, conflict with stable fallbacks, and legacy epoch/revocation authority.');
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
async function listen(server, host, port = 0) {
  server.listen(port, host);
  await once(server, 'listening');
  return server.address().port;
}

try {
  const observerConfig = join(directory, 'observer.json');
  for (const output of [nativeConfig, browserConfig, observerConfig]) {
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
  // The native TUN also carries IPv6, so Linux requires at least MTU 1280.
  native.interface.mtu = 1400;
  client.interface.mtu = 1500;
  native.network.listen_addresses = [`/ip4/${underlay}/udp/0/webrtc-direct`];
  native.network.discovery = {
    mdns: false, kademlia: false, kademlia_provider_advertisement: false, dcutr: false, autonat: false,
  };
  native.network.packet_plane = { listen: [], quic_listen: [] };
  native.network.dns = { enabled: false, hostname: 'signed-native' };
  native.peers = [{ id: clientId, addresses: ['/ip4/127.0.0.1/tcp/9'] }];
  client.peers = [{ id: nativeId, name: 'native-peer' }];
  client.network.dns = { enabled: true, hostname: 'browser-peer' };
  await writeFile(nativeConfig, JSON.stringify(native), { mode: 0o600 });
  const ipv4 = status => /^local overlay ipv4: ((?:\d+\.){3}\d+)/m.exec(status)?.[1];
  const nativeIp = ipv4(nativeStatus);
  const clientIp = ipv4(clientStatus);
  assert.ok(nativeIp && clientIp && nativeIp !== clientIp, 'expected two distinct overlay IPv4 routes');
  const ipv6 = status => /^local overlay ipv6: (\S+)$/m.exec(status)?.[1];
  const nativeIpv6 = ipv6(nativeStatus);
  const clientIpv6 = ipv6(clientStatus);
  assert.ok(nativeIpv6 && clientIpv6 && nativeIpv6 !== clientIpv6, 'expected two distinct overlay IPv6 routes');

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
  discoverableAddress = address;

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
  ipv6Service = createServer((req, res) => {
    ++listens;
    if (req.socket.remoteAddress !== clientIpv6 || req.headers.host !== `[${nativeIpv6}]:${port}`) {
      res.writeHead(403).end('Unexpected IPv6 endpoint');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' }).end('overlay-only-v6: ' + req.url);
  });
  // Both families can serve the named request, so its response proves which won.
  await listen(ipv6Service, nativeIpv6, port);
  const webPort = await listen(web, '127.0.0.1');
  browser = await chromium.launch({
    args: [`--log-net-log=${netLog}`],
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
    if (testDiscovery && request.method() === 'POST'
        && url.host === `127.0.0.1:${webPort}` && url.pathname === '/api/discovery') return;
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
  const peerAddress = page.getByLabel(testDiscovery ? 'Peer ID or address' : 'Native peer address');
  async function expectOverlayResponse(text) {
    await page.locator('#response:visible, #error:visible').first().waitFor();
    assert.equal(await page.locator('#error').isVisible(), false, await page.locator('#error').textContent());
    const body = await page.locator('#response').textContent();
    assert.match(body, /^HTTP\/1\.1 200 OK\r\n/);
    assert.ok(body.includes(text), 'overlay response body did not match');
  }
  await peerAddress.fill(address);
  const membershipKey = Buffer.alloc(32, 0xa5).toString('base64');
  const rejectedCases = [
    ['unauthorized-peer', { ...client, peers: [] }, 'native peer is not authorized'],
    ['wrong-network', { ...client, network: { ...client.network, name: 'other-network' } }, 'WrongNetwork'],
    ['wrong-scope', { ...client, network: { ...client.network, membership_key: membershipKey } }, 'MembershipMismatch'],
  ];
  for (const [name, profile, reason] of rejectedCases) {
    await input.setInputFiles({
      name: name + '.json', mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(profile)),
    });
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: reason }).waitFor({ timeout: 30_000 });
    await state.filter({ hasText: /^Disconnected$/ }).waitFor();
    assert.equal(await page.locator('#send').isDisabled(), true);
    assert.equal(listens, 0);
  }
  console.log('PASS: unknown peer, wrong overlay name, and mismatched membership scope rejected.');
  if (testDiscovery) await peerAddress.fill('');

  for (const [path, mtu] of [
    ['/first/' + 'x'.repeat(3000), client.interface.mtu],
    ['/reconnected/' + 'x'.repeat(2400), 1200],
  ]) {
    await writeFile(
      browserConfig, JSON.stringify({ ...client, interface: { ...client.interface, mtu } }),
      { mode: 0o600 },
    );
    await input.setInputFiles(browserConfig);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await state.filter({ hasText: /^Connected$/ }).waitFor({ timeout: 30_000 });
    assert.equal(await page.locator('#peer-id').textContent(), nativeId);
    await page.getByLabel('Overlay address').fill(
      mtu === client.interface.mtu ? 'signed-native.browser-app-test.p2p-vpn.internal' : nativeIp,
    );
    await page.getByLabel('Port').fill(String(port));
    await page.getByLabel('Path').fill(path);
    await page.getByRole('button', { name: 'Send request' }).click();
    await expectOverlayResponse('overlay-only: ' + path);
    if (mtu === client.interface.mtu) {
      await page.getByLabel('Overlay address').fill(nativeIpv6);
      await page.getByLabel('Path').fill('/ipv6');
      await page.getByRole('button', { name: 'Send request' }).click();
      await expectOverlayResponse('overlay-only-v6: /ipv6');
      await page.getByLabel('Overlay address').fill(publicName);
      await page.getByRole('button', { name: 'Send request' }).click();
      await page.locator('#error').filter({ hasText: 'Overlay hostname not found' }).waitFor();
      assert.equal(await page.locator('#response').isVisible(), false);
    }
    if (mtu === 1200 && process.env.P2P_VPN_BROWSER_SCREENSHOT) {
      await page.setViewportSize({ width: 1024, height: 760 });
      await page.screenshot({ path: process.env.P2P_VPN_BROWSER_SCREENSHOT, fullPage: true });
    }
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await state.filter({ hasText: /^Disconnected$/ }).waitFor();
    assert.equal(await page.locator('#response').isVisible(), false);
  }
  await checkNameAuthority(page, address, client, JSON.parse(await readFile(observerConfig, 'utf8')),
    { ipv4: [clientIp], ipv6: [clientIpv6] },
    { peer_id: nativeId, ipv4: [nativeIp], ipv6: [nativeIpv6] });
  assert.equal(listens, 3);
  assert.deepEqual(failures, []);
  await browser.close();
  browser = undefined;
  const { events } = JSON.parse(await readFile(netLog, 'utf8'));
  assert.ok(events.length, 'Chromium must capture network activity');
  assert.ok(!events.some(event => JSON.stringify(event.params)?.includes(publicName)),
    'unknown overlay name must not reach Chromium networking');
  if (testDiscovery) {
    assert.equal(discoveryRequests.length, 2);
    for (const request of discoveryRequests) {
      assert.deepEqual(Object.keys(request).sort(),
        ['bootstrap', 'kademlia', 'kademlia_protocol', 'lan', 'membership_tag', 'network_name', 'peer']);
      assert.equal(request.peer, nativeId);
      assert.equal(request.network_name, 'browser-app-test');
    }
    console.log('PASS: address-free connect used scoped host discovery without sending the config or private key.');
  }
  console.log('PASS: browser app fetched segmented HTTP responses with browser MTUs of 1500 and 1200 against native MTU 1400.');
  console.log('PASS: named HTTP selected IPv4, literal IPv6 used IPv6, and no public-name lookup escaped.');
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
    ipv6Service?.close();
    web.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
