import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readlink, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

const { chromium } = createRequire(import.meta.url)('playwright');
const DHT = '/p2p-vpn/browser-gateway-test/1';
const CHALLENGE = '/api/relay/advertisement/challenge';
const PUBLISH = '/api/relay/advertisement/publish';
const MARKER = 'meta[name="p2p-vpn-relay-advertisement"]';

function fixture(t, command, args) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(child, 'close');
  exited.catch(() => {});
  const reader = createInterface({ input: child.stdout });
  const lines = reader[Symbol.asyncIterator]();
  let logs = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { logs = (logs + chunk).slice(-8192); });
  t.after(async () => {
    reader.close();
    child.kill();
    await exited.catch(() => {});
  });
  return {
    child,
    logs: () => logs,
    async next(stage) {
      const { value, done } = await lines.next();
      if (done) throw Error(`${stage}: ${command} exited (${(await exited)[0]}): ${logs}`);
      return value;
    },
  };
}

function ip(...args) {
  return execFileSync('ip', args, { encoding: 'utf8', timeout: 5_000 });
}

async function assets(t, pkg) {
  const root = await mkdtemp(join(tmpdir(), 'p2p-vpn-advertisement-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'pkg'));
  for (const file of ['app.html', 'app.js', 'app.css']) {
    await copyFile(new URL(`../web/${file}`, import.meta.url), join(root, file));
  }
  for (const file of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm', 'logo.svg']) {
    await copyFile(join(pkg, file), join(root, 'pkg', file));
  }
  return root;
}

async function post(origin, path, value) {
  const result = await fetch(origin + path, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
    signal: AbortSignal.timeout(22_000),
  });
  return { status: result.status, body: await result.json() };
}

async function underlay(t, ...command) {
  const env = process.env;
  assert.ok(env.P2P_VPN_BIN && env.P2P_VPN_RELAY_FIXTURE
    && env.P2P_VPN_RECEIVER_FIXTURE && env.P2P_VPN_PAIRING_PKG);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up');

  const relay = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
    'printf "%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'ip addr add 192.0.2.1/32 dev lo',
    'ip addr add 11.250.0.2/24 dev fixture-peer',
    'ip -6 addr add fd42:250::1/64 dev fixture-peer nodad',
    'ip link set fixture-peer up',
    'exec "$@"',
  ].join('\n'), 'fixture-namespace', ...command]);
  const pid = await relay.next('relay namespace');
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'physical', 'type', 'veth', 'peer', 'name', 'fixture-peer', 'netns', pid);
  // This side is IPv4-only; late IPv6 address setup invalidates route scopes.
  ip('link', 'set', 'physical', 'addrgenmode', 'none');
  ip('addr', 'add', '11.250.0.1/24', 'dev', 'physical');
  ip('link', 'set', 'physical', 'up');
  ip('route', 'add', 'default', 'dev', 'physical');
  relay.child.stdin.write('ready\n');
  return {
    relay,
    spawnPeer: (binary, args) => fixture(t, 'nsenter', ['--target', pid, '--net', '--', binary, ...args]),
  };
}

test('Chromium opts into regular relay publication, renews the exact alias, then lets it expire', {
  timeout: 130_000,
}, async t => {
  const env = process.env;
  const assetRoot = await assets(t, env.P2P_VPN_PAIRING_PKG);
  const { relay, spawnPeer: inFixtureNamespace } =
    await underlay(t, env.P2P_VPN_RELAY_FIXTURE, '11.250.0.2', 'fd42:250::1');
  const entrances = JSON.parse(await relay.next('relay listeners'));
  assert.match(entrances.webrtc, /^\/ip4\/11\.250\.0\.2\/udp\//);
  assert.match(entrances.identify, /^\/ip4\/11\.250\.0\.2\/tcp\//);

  const native = inFixtureNamespace(env.P2P_VPN_RECEIVER_FIXTURE, ['incoming-app', entrances.identify]);
  const session = JSON.parse(await native.next('native member configuration'));
  const network = session.config.network;
  network.discovery = { ...network.discovery, kademlia: true, mdns: false, kademlia_protocol: DHT };
  const browserPeer = network.local_peer;
  const member = session.native_peer_id;
  const relayPeer = entrances.webrtc.split('/').at(-1);
  const circuit = `${entrances.identify}/p2p-circuit/p2p/${browserPeer}`;
  const ingress = `${entrances.webrtc}/p2p-circuit/p2p/${member}`;
  const seed = inFixtureNamespace(env.P2P_VPN_RECEIVER_FIXTURE, ['relay-gateway-seed']);
  // The stock fixture requires a seed record; it is unrelated to the browser's key.
  seed.child.stdin.end(JSON.stringify({ network: 'unrelated', member, value: [0] }));
  const bootstrap = await seed.next('cooperating DHT listener');

  const permit = join(assetRoot, 'publication.json');
  await writeFile(permit, JSON.stringify({
    network_name: network.name, membership_tag: null,
    browser_peer: browserPeer, destination: member, address: circuit,
  }));
  const serve = async allow => {
    const host = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assetRoot, '--port', '0',
      '--kademlia-protocol', DHT, '--bootstrap', bootstrap,
      ...(allow ? ['--relay-advertisement-permit', permit] : [])]);
    const line = await host.next('companion listener');
    const origin = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
    assert.ok(origin, line);
    return origin;
  };
  const publisher = await serve(true);
  const reader = await serve(false);
  const lookup = () => post(reader, '/api/discovery', {
    network_name: network.name, peer: browserPeer, kademlia: true, lan: false,
  });
  assert.equal((await post(reader, CHALLENGE, {})).status, 404);

  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  page.setDefaultTimeout(15_000);
  const publicationRequests = [];
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path === CHALLENGE || path === PUBLISH) publicationRequests.push({ path, request });
  });
  const status = page.locator('#state');
  const waitFor = text => status.filter({ hasText: new RegExp(`^${text}$`) }).waitFor();
  const button = page.getByRole('button', { name: 'Publish relay address', exact: true });
  await page.goto(reader + '/app.html');
  await waitFor('Disconnected');
  assert.equal(await page.locator(MARKER).count(), 0);
  assert.equal(await button.isVisible(), false);

  try {
    await page.goto(publisher + '/app.html');
    await waitFor('Disconnected');
    assert.equal(await page.locator(MARKER).getAttribute('content'), CHALLENGE);
    assert.equal(await button.isVisible(), false);
    await page.getByLabel('Peer config').setInputFiles({
      name: 'browser.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(session.config)),
    });
    await page.locator('#address').fill(ingress);
    await page.getByRole('button', { name: 'Listen on relay', exact: true }).click();
    await waitFor('Waiting for peer');
    assert.equal(await page.locator('#relay-address').textContent(),
      `${entrances.webrtc}/p2p-circuit/p2p/${browserPeer}`);
    assert.equal((await lookup()).status, 404, 'reserving must not publish');
    assert.equal(publicationRequests.length, 0);

    await button.click();
    await page.locator('#relay-publication-result')
      .filter({ hasText: /^Relay address published$/ }).waitFor();
    assert.deepEqual(publicationRequests.map(({ path }) => path), [CHALLENGE, PUBLISH]);
    assert.deepEqual(publicationRequests[0].request.postDataJSON(), {});
    const submission = publicationRequests[1].request.postDataJSON();
    assert.deepEqual(Object.keys(submission).sort(), ['nonce', 'proof', 'record']);
    const { payload } = JSON.parse(submission.record);
    assert.equal(payload.peer_id, browserPeer);
    assert.equal(payload.network_name, network.name);
    assert.deepEqual(payload.addresses, [circuit]);
    assert.ok(!submission.record.includes(network.private_key), 'no private key in the wire value');

    // A fresh companion must read the signed value from the DHT and authenticate
    // the published TCP entrance before it can prepare a browser-compatible lease.
    const found = await lookup();
    assert.equal(found.status, 200, JSON.stringify(found.body));
    assert.equal(found.body.source, 'public_dht');
    assert.deepEqual(found.body.addresses, []);
    assert.match(found.body.relay_address, /^\/ip4\/127\.0\.0\.1\/udp\//);
    assert.ok(found.body.relay_address.endsWith(`/p2p/${relayPeer}/p2p-circuit/p2p/${browserPeer}`));
    assert.equal((await post(reader, '/api/relay/release', { lease_id: found.body.relay_lease_id })).status, 200);
    assert.equal((await post(publisher, CHALLENGE, {})).status, 429);

    const renewal = await page.waitForResponse(response =>
      new URL(response.url()).pathname === PUBLISH, { timeout: 45_000 });
    assert.equal(renewal.status(), 200);
    assert.equal((await renewal.json()).published, true);
    const refreshed = JSON.parse(renewal.request().postDataJSON().record).payload;
    assert.deepEqual(refreshed.addresses, [circuit]);
    assert.ok(refreshed.sequence > payload.sequence);
    assert.ok(refreshed.expires_at_unix_seconds > payload.expires_at_unix_seconds);
    assert.deepEqual(publicationRequests.map(({ path }) => path),
      [CHALLENGE, PUBLISH, CHALLENGE, PUBLISH]);
    assert.equal(await page.locator('#relay-address').textContent(),
      `${entrances.webrtc}/p2p-circuit/p2p/${browserPeer}`);

    // The native fixture dials the exact TCP circuit emitted by the browser.
    native.child.stdin.end(payload.addresses[0] + '\n');
    await waitFor('Connected');
    assert.equal(JSON.parse(await native.next('native VPN status')).status.Status.selected_path, 'circuit_relay');
    assert.match(relay.logs(), new RegExp(`ReservationReqAccepted.*${browserPeer}`));
    assert.doesNotMatch(relay.logs(), new RegExp(`ReservationReqAccepted.*${member}`));
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await waitFor('Disconnected');
    assert.equal(await button.isVisible(), false);
    // Check after the original record has expired, but before the refreshed one has.
    await delay(Math.max(0, (payload.expires_at_unix_seconds + 1) * 1000 - Date.now()));
    const renewed = await lookup();
    assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
    assert.equal((await post(reader, '/api/relay/release', { lease_id: renewed.body.relay_lease_id })).status, 200);
    await delay(Math.max(0, (refreshed.expires_at_unix_seconds + 1) * 1000 - Date.now()));
    assert.equal((await lookup()).status, 404);
    assert.equal(publicationRequests.length, 4, 'disconnect stops renewal');
  } catch (error) {
    const visibleError = await page.locator('#error').textContent().catch(() => null);
    throw Error(`${error.message}\nBrowser: ${visibleError}\nNative: ${native.logs()}\nRelay: ${relay.logs()}`, {
      cause: error,
    });
  }
});

test('Chromium connects by member ID through a provider-only cooperating IPFS-protocol seed', {
  timeout: 55_000,
}, async t => {
  const env = process.env;
  const assetRoot = await assets(t, env.P2P_VPN_PAIRING_PKG);
  const { relay: native, spawnPeer } = await underlay(t, env.P2P_VPN_RECEIVER_FIXTURE, 'member-provider');
  const session = JSON.parse(await native.next('native member configuration'));
  assert.ok(!JSON.stringify(session.config).includes(session.dial_address));
  const seed = spawnPeer(env.P2P_VPN_RECEIVER_FIXTURE, ['member-provider-seed']);
  seed.child.stdin.end(JSON.stringify({
    network: session.config.network.name,
    member: session.native_peer_id,
    address: session.dial_address,
  }));
  const bootstrap = await seed.next('provider-only DHT listener');
  const host = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assetRoot, '--port', '0',
    '--bootstrap', bootstrap]);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/
    .exec(await host.next('companion listener'))?.[1];
  assert.ok(url);
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  let lookups = 0;
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/discovery') lookups++;
  });
  await page.goto(url);
  await page.getByLabel('Peer config').setInputFiles({
    name: 'browser.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(session.config)),
  });
  await page.locator('#address').fill(session.native_peer_id);
  const result = page.waitForResponse(response => new URL(response.url()).pathname === '/api/discovery');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  const lookup = await result;
  assert.equal(lookup.request().postDataJSON().peer, session.native_peer_id);
  assert.equal(lookup.status(), 200);
  const reply = await lookup.json();
  assert.equal(reply.source, 'public_dht');
  assert.deepEqual(reply.addresses, [session.dial_address]);
  assert.equal(reply.relay_address, undefined);
  await page.locator('#state').filter({ hasText: /^Connected$/ }).waitFor();
  const wire = JSON.parse(await native.next('authenticated packet exchange'));
  assert.equal(wire.keepalive, 'Accepted');
  assert.equal(lookups, 1);
  const wrongScope = await post(new URL(url).origin, '/api/discovery', {
    ...lookup.request().postDataJSON(), network_name: 'other-mesh',
  });
  assert.equal(wrongScope.status, 404);
});

test('Chromium member rendezvous bounds work when a cached route is unreachable', {
  timeout: 75_000,
}, async t => {
  const env = process.env;
  const root = await assets(t, env.P2P_VPN_PAIRING_PKG);
  const { relay: native, spawnPeer } = await underlay(t, env.P2P_VPN_RECEIVER_FIXTURE, 'member-provider');
  const session = JSON.parse(await native.next('native member configuration'));
  const sink = spawnPeer(process.execPath, ['-e', `
    const socket = require('node:dgram').createSocket('udp4');
    let count = 0;
    socket.on('message', () => count++);
    socket.bind(0, '11.250.0.2', () => console.log(socket.address().port));
    require('node:readline').createInterface({ input: process.stdin })
      .on('line', () => console.log(count));
  `]);
  const count = async () => {
    sink.child.stdin.write('count\n');
    return Number(await sink.next('unreachable endpoint packet count'));
  };
  const deadPort = Number(await sink.next('unreachable UDP endpoint'));
  assert.ok(deadPort > 0);
  const unreachable = session.dial_address.replace(/\/udp\/\d+\//, `/udp/${deadPort}/`);
  assert.notEqual(unreachable, session.dial_address);

  const seed = spawnPeer(env.P2P_VPN_RECEIVER_FIXTURE, ['member-provider-seed']);
  seed.child.stdin.end(JSON.stringify({
    network: session.config.network.name, member: session.native_peer_id,
    address: session.dial_address, unreachable,
  }));
  const bootstrap = await seed.next('cooperating DHT listener');
  const host = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', root, '--port', '0',
    '--bootstrap', bootstrap]);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/
    .exec(await host.next('companion listener'))?.[1];
  assert.ok(url);
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const isDiscovery = message => new URL(message.url()).pathname === '/api/discovery';
  await page.addInitScript(() => {
    window.closedDialPorts = [];
    const closedPeers = new WeakSet();
    const close = RTCPeerConnection.prototype.close;
    RTCPeerConnection.prototype.close = function () {
      const port = /^m=application (\d+) /m.exec(this.remoteDescription?.sdp ?? '')?.[1];
      if (port && !closedPeers.has(this)) window.closedDialPorts.push(Number(port));
      closedPeers.add(this);
      return close.call(this);
    };
  });
  const closed = () => page.evaluate(() => window.closedDialPorts);
  let lookups = 0;
  page.on('request', request => { if (isDiscovery(request)) lookups++; });
  const state = text => page.locator('#state').filter({ hasText: new RegExp(`^${text}$`) });
  await page.goto(url);
  const configFile = {
    name: 'browser.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(session.config)),
  };
  assert.ok(!configFile.buffer.includes(session.dial_address));
  await page.locator('#address').fill(session.native_peer_id);
  const connect = page.getByRole('button', { name: 'Connect', exact: true });
  const start = async () => {
    await page.getByLabel('Peer config').setInputFiles(configFile);
    const response = page.waitForResponse(isDiscovery);
    await connect.click();
    const lookup = await response;
    assert.equal(lookup.status(), 200);
    assert.equal(lookup.request().postDataJSON().peer, session.native_peer_id);
    const reply = await lookup.json();
    assert.equal(reply.source, 'public_dht');
    assert.deepEqual(reply.addresses.sort(), [unreachable, session.dial_address].sort());
    assert.equal(reply.relay_address, undefined);
  };
  const send = page.locator('#send');
  try {
    // Hold the eligible endpoint until the browser has spent work on the stale hint.
    assert.ok(native.child.kill('SIGSTOP'));
    await start();
    for (let i = 0; i < 30 && await count() === 0; i++) await delay(100);
    assert.ok(await count() > 0, 'browser tried the unreachable endpoint');
    assert.equal(await state('Connected').count(), 0);
    assert.ok(await send.isDisabled());
  } finally {
    native.child.kill('SIGCONT');
  }
  await state('Connected').waitFor({ timeout: 15_000 });
  assert.equal(await page.locator('#peer-id').textContent(), session.native_peer_id);
  assert.deepEqual(JSON.parse(await native.next('authenticated packet exchange')), { keepalive: 'Accepted' });
  assert.ok(await send.isEnabled());
  assert.deepEqual(await closed(), [deadPort], 'selection closed only the losing dial');
  await delay(500);
  const afterSuccess = await count();
  await delay(1_500);
  assert.equal(await count(), afterSuccess, 'losing UDP attempt stopped after selection');
  assert.equal(lookups, 1);

  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await state('Disconnected').waitFor();
  const exited = once(native.child, 'close');
  assert.ok(native.child.kill());
  await exited;
  await start();
  const started = performance.now();
  await state('Disconnected').waitFor({ timeout: 28_000 });
  const dialMillis = performance.now() - started;
  assert.ok(await page.locator('#error').isVisible(), 'exhaustion is reported as a failure');
  assert.ok(await send.isDisabled());
  const afterFailure = await count();
  assert.ok(afterFailure > afterSuccess, 'exhaustion tried the still-cached endpoint');
  await delay(1_500);
  assert.equal(await count(), afterFailure, 'UDP work stopped at the end of the dial budget');
  assert.equal(lookups, 2, 'one lookup per attempt with no automatic retry');
  const livePort = Number(/\/udp\/(\d+)\//.exec(session.dial_address)[1]);
  assert.deepEqual((await closed()).sort(), [deadPort, deadPort, livePort, livePort].sort());
  t.diagnostic(`all-unreachable dial ended in ${Math.round(dialMillis)} ms`);
});

test('Chromium automatically recovers an established member through the Linux companion', {
  timeout: 55_000,
}, async t => {
  const env = process.env;
  const root = await assets(t, env.P2P_VPN_PAIRING_PKG);
  const { relay: native, spawnPeer } = await underlay(t,
    env.P2P_VPN_RECEIVER_FIXTURE, 'member-provider-recovery');
  const session = JSON.parse(await native.next('native member configuration'));
  const { config, native_peer_id: member, dial_address: initial, recovery_address: replacement } = session;
  const port = address => Number(/\/udp\/(\d+)\//.exec(address)[1]);
  assert.notEqual(port(initial), port(replacement));
  const configJson = JSON.stringify(config);
  assert.ok(!configJson.includes(initial) && !configJson.includes(replacement));

  const seed = spawnPeer(env.P2P_VPN_RECEIVER_FIXTURE, ['member-provider-seed']);
  seed.child.stdin.write(JSON.stringify({
    network: config.network.name, member, address: initial, switch_route: true,
  }) + '\n');
  const bootstrap = await seed.next('cooperating DHT listener');
  const host = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', root, '--port', '0',
    '--bootstrap', bootstrap]);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/
    .exec(await host.next('companion listener'))?.[1];
  assert.ok(url);
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.addInitScript(() => {
    window.observedRoutes = [];
    const setRemoteDescription = RTCPeerConnection.prototype.setRemoteDescription;
    RTCPeerConnection.prototype.setRemoteDescription = function (description, ...args) {
      const port = /^m=application (\d+) /m.exec(description?.sdp ?? '')?.[1];
      if (port) window.observedRoutes.push({ port: Number(port), connection: this });
      return setRemoteDescription.call(this, description, ...args);
    };
  });
  const routes = () => page.evaluate(() => window.observedRoutes.map(({ port, connection }) => ({
    port, state: connection.connectionState,
  })));
  const isDiscovery = message => new URL(message.url()).pathname === '/api/discovery';
  const lookups = [];
  page.on('request', request => { if (isDiscovery(request)) lookups.push(request.postDataJSON()); });
  const connected = page.locator('#state').filter({ hasText: /^Connected$/ });
  const assertLookup = async (response, address) => {
    assert.equal(response.status(), 200);
    assert.equal(response.request().postDataJSON().peer, member);
    const reply = await response.json();
    assert.equal(reply.source, 'public_dht');
    assert.deepEqual(reply.addresses, [address]);
    assert.equal(reply.relay_address, undefined);
  };
  try {
    await page.goto(url);
    assert.equal(await page.evaluate(() => document.visibilityState), 'visible');
    await page.getByLabel('Peer config').setInputFiles({
      name: 'browser.json', mimeType: 'application/json', buffer: Buffer.from(configJson),
    });
    await page.locator('#address').fill(member);
    const initialLookup = page.waitForResponse(isDiscovery);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await assertLookup(await initialLookup, initial);
    await connected.waitFor();
    assert.equal(await page.locator('#peer-id').textContent(), member);
    assert.deepEqual(JSON.parse(await native.next('initial VPN keepalive')), { initial_keepalive: 'Accepted' });
    assert.deepEqual(await routes(), [{ port: port(initial), state: 'connected' }]);
    assert.equal(lookups.length, 1);

    // Change only the underlay. The visible foreground poll must notice the
    // loss and ask the companion for the same member again.
    const recoveryLookup = page.waitForResponse(isDiscovery, { timeout: 30_000 });
    native.child.stdin.end('retire\n');
    assert.deepEqual(JSON.parse(await native.next('retired initial transport')), { retired: true });
    seed.child.stdin.end(replacement + '\n');
    assert.equal(await seed.next('updated provider route'), 'provider switched');
    await assertLookup(await recoveryLookup, replacement);
    assert.deepEqual(JSON.parse(await native.next('fresh capabilities')), { reauthenticated: true });
    await connected.waitFor();
    assert.equal(await page.locator('#peer-id').textContent(), member);
    const expected = [
      { port: port(initial), state: 'closed' },
      { port: port(replacement), state: 'connected' },
    ];
    assert.deepEqual(await routes(), expected);
    await page.locator('#ip').fill('10.204.0.1');
    await page.locator('#port').fill('8080');
    await page.locator('#path').fill('/recovery-proof');
    await page.locator('#send').click();
    const response = page.locator('#response').filter({ hasText: 'recovered-route' });
    await response.waitFor({ timeout: 12_000 });
    assert.equal(await response.textContent(),
      'HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nrecovered-route');
    await delay(1_500);
    assert.deepEqual(await routes(), expected, 'no obsolete dial or surviving old connection');
    assert.equal(lookups.length, 2, 'one initial lookup and one automatic recovery lookup');
    await connected.waitFor();
    t.diagnostic(`same member reauthorized on UDP ${port(initial)} -> ${port(replacement)}; received overlay HTTP body`);
  } catch (error) {
    throw Error(`${error.message}\nBrowser: ${await page.locator('#error').textContent()}`
      + `\nRoutes: ${JSON.stringify(await routes())}\nNative: ${native.logs()}`
      + `\nSeed: ${seed.logs()}\nCompanion: ${host.logs()}`, { cause: error });
  }
});

test('Chromium gates a cached signed member hint on current membership', {
  timeout: 55_000,
}, async t => {
  const env = process.env;
  const root = await assets(t, env.P2P_VPN_PAIRING_PKG);
  const binary = env.P2P_VPN_RECEIVER_FIXTURE;
  const { relay: native, spawnPeer } = await underlay(t, binary, 'member-signed-hint');
  const { config, native_peer_id: member, dial_address: old, recovery_address: current,
    initial_expiry: expiry, initial_hint: oldHint } =
    JSON.parse(await native.next('signed member configuration'));
  const port = address => Number(/\/udp\/(\d+)\//.exec(address)[1]);
  assert.notEqual(port(old), port(current));
  const seed = spawnPeer(binary, ['member-signed-seed']);
  seed.child.stdin.write(JSON.stringify(oldHint) + '\n');
  const bootstrap = await seed.next('isolated signed-record seed');
  const host = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', root, '--port', '0',
    '--bootstrap', bootstrap, '--kademlia-protocol', config.network.discovery.kademlia_protocol]);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/
    .exec(await host.next('companion listener'))?.[1];
  assert.ok(url);
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.addInitScript(() => {
    window.dials = [];
    const setRemoteDescription = RTCPeerConnection.prototype.setRemoteDescription;
    RTCPeerConnection.prototype.setRemoteDescription = function (description, ...args) {
      const port = /^m=application (\d+) /m.exec(description?.sdp ?? '')?.[1];
      if (port) window.dials.push(Number(port));
      return setRemoteDescription.call(this, description, ...args);
    };
  });
  const dials = () => page.evaluate(() => window.dials);
  const discovery = '/api/discovery';
  const isDiscovery = message => new URL(message.url()).pathname === discovery;
  const lookups = [];
  page.on('request', request => { if (isDiscovery(request)) lookups.push(request.postDataJSON()); });
  const connected = page.locator('#state').filter({ hasText: /^Connected$/ });
  const disconnected = page.locator('#state').filter({ hasText: /^Disconnected$/ });
  const connect = page.getByRole('button', { name: 'Connect', exact: true });
  const send = page.locator('#send');
  const selectConfig = async authority => {
    const buffer = Buffer.from(JSON.stringify(authority));
    assert.ok(!buffer.includes(old) && !buffer.includes(current));
    await page.getByLabel('Peer config').setInputFiles({
      name: 'browser.json', mimeType: 'application/json', buffer,
    });
    await page.locator('#address').fill(member);
  };
  const assertHint = (status, reply, address) => {
    assert.equal(status, 200, JSON.stringify(reply));
    assert.equal(reply.source, 'public_dht');
    assert.deepEqual(reply.addresses, [address]);
    assert.equal(reply.relay_address, undefined);
  };
  const connectVia = async address => {
    const result = page.waitForResponse(isDiscovery);
    await connect.click();
    const response = await result;
    assert.equal(response.request().postDataJSON().peer, member);
    assert.equal(response.status(), 200);
    assertHint(response.status(), await response.json(), address);
    await connected.waitFor();
    assert.equal(await page.locator('#peer-id').textContent(), member);
  };
  try {
    await page.goto(url);
    await selectConfig(config);
    await connectVia(old);
    assert.equal(await native.next('initial packet exchange'), 'initial keepalive accepted');
    assert.deepEqual(await dials(), [port(old)]);
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await disconnected.waitFor();
    native.child.stdin.write('disconnect\n');
    assert.equal(await native.next('initial transport close'), 'initial session closed');
    assert.ok(Date.now() < expiry * 1000, 'initial session authenticated before expiry');

    await delay(Math.max(0, expiry * 1000 - Date.now()) + 1_000);
    // The companion can still read the hint; this diagnostic does not dial it.
    const cached = await post(new URL(url).origin, discovery, lookups[0]);
    assertHint(cached.status, cached.body, old);
    await selectConfig(config);
    await connect.click();
    await page.locator('#error').filter({ hasText: /not an authorized overlay peer|membership has expired/ })
      .waitFor({ timeout: 5_000 });
    await disconnected.waitFor();
    assert.ok(await send.isDisabled());
    assert.equal(lookups.length, 1, 'expired membership blocks lookup, not just packet sending');
    assert.deepEqual(await dials(), [port(old)], 'no dial on the denied attempt');

    native.child.stdin.write('publish\n');
    const { config: renewed, hint } = JSON.parse(
      await native.next('renewed authority and current hint; original listener still open'));
    const payload = record => JSON.parse(Buffer.from(record.value)).payload;
    assert.ok(payload(hint).sequence > payload(oldHint).sequence);
    assert.deepEqual(payload(hint).addresses, [current]);
    seed.child.stdin.end(JSON.stringify(hint) + '\n');
    assert.equal(await seed.next('updated signed-record seed'), 'signed hint updated');
    await selectConfig(renewed);
    await connectVia(current);
    assert.deepEqual(await dials(), [port(old), port(current)]);
    await page.locator('#ip').fill('10.204.0.1');
    await page.locator('#port').fill('8080');
    await page.locator('#path').fill('/recovery-proof');
    await send.click();
    const response = page.locator('#response').filter({ hasText: 'recovered-route' });
    await response.waitFor({ timeout: 12_000 });
    assert.equal(await response.textContent(),
      'HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nrecovered-route');
    assert.deepEqual(await dials(), [port(old), port(current)]);
    assert.equal(lookups.length, 2);
    t.diagnostic(`signed hint UDP ${port(old)} survived membership expiry with no lookup, dial or IP on the denied attempt; fresh authority and hint UDP ${port(current)} carried HTTP`);
  } catch (error) {
    throw Error(`${error.message}\nBrowser: ${await page.locator('#error').textContent()}`
      + `\nDials: ${JSON.stringify(await dials())}\nNative: ${native.logs()}`
      + `\nSeed: ${seed.logs()}\nCompanion: ${host.logs()}`, { cause: error });
  }
});
