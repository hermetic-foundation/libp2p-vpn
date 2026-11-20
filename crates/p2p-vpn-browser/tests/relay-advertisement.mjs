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
  relay.child.stdin.end('ready\n');
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
