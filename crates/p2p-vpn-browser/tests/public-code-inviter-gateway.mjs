import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readlink, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const RESERVE = '/api/relay/inviter/reservation';
const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5_000 });

function canBind(port) {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4');
    socket.once('error', error => {
      socket.close();
      if (error.code === 'EADDRINUSE') resolve(false);
      else reject(error);
    });
    socket.bind(port, '127.0.0.1', () => socket.close(() => resolve(true)));
  });
}

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
    async next() {
      const { value, done } = await lines.next();
      if (done) throw Error(`${command} exited (${(await exited)[0]}): ${logs}`);
      return value;
    },
  };
}

test('the served Chromium inviter publishes the confirmed public alias over scoped ingress', {
  timeout: 40_000,
}, async t => {
  const env = process.env;
  assert.ok(env.P2P_VPN_BIN && env.P2P_VPN_RELAY_FIXTURE && env.P2P_VPN_PAIRING_PKG);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up');

  const assets = await mkdtemp(join(tmpdir(), 'p2p-vpn-inviter-egress-'));
  t.after(() => rm(assets, { recursive: true, force: true }));
  await mkdir(join(assets, 'pkg'));
  for (const file of ['app.html', 'app.js', 'app.css', 'code-inviter.html', 'code-inviter.js']) {
    await copyFile(new URL(`../web/${file}`, import.meta.url), join(assets, file));
  }
  for (const file of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm', 'logo.svg']) {
    await copyFile(join(env.P2P_VPN_PAIRING_PKG, file), join(assets, 'pkg', file));
  }

  const relay = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
    'printf "%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'ip addr add 11.250.0.2/24 dev fixture-peer',
    'ip link set fixture-peer up',
    'exec "$@"',
  ].join('\n'), 'fixture-namespace', env.P2P_VPN_RELAY_FIXTURE, '11.250.0.2', '--locator-dht']);
  const pid = await relay.next();
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'physical', 'type', 'veth', 'peer', 'name', 'fixture-peer', 'netns', pid);
  ip('link', 'set', 'physical', 'addrgenmode', 'none');
  ip('addr', 'add', '11.250.0.1/24', 'dev', 'physical');
  ip('link', 'set', 'physical', 'up');
  ip('route', 'add', 'default', 'dev', 'physical');
  ip('link', 'add', 'secondary', 'type', 'dummy');
  ip('link', 'set', 'secondary', 'addrgenmode', 'none');
  ip('addr', 'add', '11.251.0.1/24', 'dev', 'secondary');
  ip('link', 'set', 'secondary', 'up');
  relay.child.stdin.end('ready\n');
  const { webrtc, tcp: identify } = JSON.parse(await relay.next());
  const relayPeer = webrtc.split('/').at(-1);
  assert.equal(identify.split('/').at(-1), relayPeer);
  const serve = async (entrance, allow) => {
    const companion = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assets,
      '--port', '0', '--relay-entrance', entrance, ...(allow ? ['--relay-native-alias', identify] : [])]);
    const line = await companion.next();
    const origin = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
    assert.ok(origin, line);
    return origin;
  };
  const origin = await serve(webrtc, true);
  const unapproved = await serve(webrtc, false);
  const wrongEntrance = await serve(webrtc.replace(
    /\/udp\/(\d+)\//, (_, port) => `/udp/${port === '1' ? 2 : 1}/`), true);
  const request = { relay_peer: relayPeer };
  const http = async (host, body, from = host, site = 'same-origin') => {
    const result = await fetch(host + RESERVE, {
      method: 'POST',
      headers: { Origin: from, 'Sec-Fetch-Site': site, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8_000),
    });
    return [result.status, await result.json()];
  };
  assert.deepEqual(await http(origin, request, unapproved), [403, { error: 'wrong_origin' }]);
  assert.deepEqual(await http(origin, request, origin, 'cross-site'), [403, { error: 'wrong_origin' }]);
  assert.deepEqual(await http(unapproved, request), [404, { error: 'no_candidates' }]);
  assert.deepEqual(await http(wrongEntrance, request), [404, { error: 'no_candidates' }]);
  assert.deepEqual(await http(origin, { ...request, address: webrtc }), [413, { error: 'request_too_large' }]);
  assert.deepEqual(await http(origin, { ...request, address: 'x' }), [400, { error: 'invalid_request' }]);

  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const sent = [];
  page.on('request', request => {
    if (request.method() !== 'GET') {
      sent.push([new URL(request.url()).pathname, request.postDataJSON()]);
    }
  });
  assert.equal((await page.goto(origin + '/code-inviter.html#scoped')).status(), 200);
  const post = (path, fields) => page.evaluate(async ({ path, fields }) => {
    const response = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(fields),
      signal: AbortSignal.timeout(8_000),
    });
    return { status: response.status, body: await response.json() };
  }, { path, fields });
  const form = page.locator('#scoped-form');
  for (const [label, value] of [
    ['Network name', 'egress-fixture'], ['Inviter VPN address', '10.83.0.1'],
    ['Joiner VPN address', '10.83.0.2'], ['Approved relay peer ID', relayPeer],
  ]) await form.getByLabel(label, { exact: true }).fill(value);
  const reserved = page.waitForResponse(response => new URL(response.url()).pathname === RESERVE);
  await page.getByRole('button', { name: 'Reserve and publish' }).click();
  const lease = await reserved;
  assert.equal(lease.status(), 200);
  const { relay_entrance: entrance, relay_lease_id: id, native_alias: alias } = await lease.json();
  assert.equal(alias, identify);
  assert.match(entrance, /^\/ip4\/127\.0\.0\.1\/udp\/\d+\/webrtc-direct\//);
  assert.equal(entrance.split('/').at(-1), relayPeer);
  await page.getByRole('status').filter({ hasText: 'Waiting for joiner' }).waitFor({ timeout: 12_000 });
  const peer = await page.locator('#inviter-peer').textContent();
  const address = await page.locator('#invite-address').textContent();
  assert.equal(address, `${identify}/p2p-circuit/p2p/${peer}`);
  assert.doesNotMatch(address, /127\.0\.0\.1/);
  const deniedAddresses = await page.evaluate(async ({ relayPeer, entrance, identify, webrtc }) => {
    const { BrowserCodeInviter } = await import('/pkg/p2p_vpn_browser.js');
    return Promise.all([[webrtc, identify], [entrance, entrance]].map(async ([ingress, alias]) => {
      try {
        const unexpected = await BrowserCodeInviter.open_unpinned_scoped(
          'invalid-scope', '10.84.0.1', '10.84.0.2', relayPeer, ingress, alias);
        unexpected.free();
        return false;
      } catch {
        return true;
      }
    }));
  }, { relayPeer, entrance, identify, webrtc });
  assert.deepEqual(deniedAddresses, [true, true]);
  const locator = await page.evaluate(async () => {
    const { pairing_code_v2_global_locator } = await import('/pkg/p2p_vpn_browser.js');
    return pairing_code_v2_global_locator(document.getElementById('invite-code').textContent);
  });
  const lookup = execFileSync(env.P2P_VPN_RELAY_FIXTURE, ['--lookup-locator', identify, locator],
    { encoding: 'utf8', timeout: 8_000 });
  assert.deepEqual(JSON.parse(lookup), [{ peer, addresses: [address] }]);
  assert.deepEqual(sent, [[RESERVE, request]]);

  // The native process above proves discovery. This controlled browser
  // joiner separately proves scoped activation via an explicit WebRTC route.
  const joiner = await browser.newPage();
  assert.equal((await joiner.goto(origin + '/code-inviter.html#join')).status(), 200);
  await joiner.getByRole('status').filter({ hasText: 'Ready' }).waitFor();
  const joinerPeer = await joiner.locator('#local-joiner').textContent();
  await joiner.getByLabel('Private v2 code').fill(await page.locator('#invite-code').textContent());
  await joiner.getByLabel('Inviter peer ID').fill(peer);
  await joiner.getByLabel('Circuit address').fill(`${webrtc}/p2p-circuit/p2p/${peer}`);
  await joiner.getByRole('button', { name: 'Request approval' }).click();
  await page.getByRole('status').filter({ hasText: 'Approval required' }).waitFor();
  assert.equal(await page.locator('#candidate-peer').textContent(), joinerPeer);
  assert.equal(await joiner.locator('#active').isVisible(), false);
  await page.getByRole('button', { name: 'Approve peer' }).click();
  for (const current of [page, joiner]) {
    await current.getByRole('status').filter({ hasText: 'VPN connected' }).waitFor();
  }
  assert.equal(await page.locator('#active-address').textContent(), address);
  assert.equal(await page.locator('#active-remote').textContent(), joinerPeer);
  assert.equal(await joiner.locator('#active-remote').textContent(), peer);
  assert.deepEqual(sent, [[RESERVE, request]]);

  const accepted = new RegExp(`ReservationReqAccepted.*${peer}.*renewed: false`);
  const reservationDeadline = performance.now() + 8_000;
  while (!accepted.test(relay.logs())) {
    assert.ok(performance.now() < reservationDeadline, relay.logs());
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.match(relay.logs(), new RegExp(`relay-hop ${peer} /ip4/11\\.250\\.0\\.1/udp/`));
  assert.equal([...relay.logs().matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1);
  const control = { lease_id: id, relay_address: entrance };
  const denied = await Promise.all(['activate', 'handoff'].map(op => post('/api/relay/' + op, control)));
  assert.deepEqual(denied, Array(2).fill({
    status: 404, body: { error: 'relay_lease_unavailable' },
  }));
  const released = page.waitForResponse(response => new URL(response.url()).pathname === '/api/relay/release');
  await page.getByRole('button', { name: 'End session' }).click();
  const release = await released;
  assert.equal(release.status(), 200);
  assert.deepEqual(sent.slice(-1), [['/api/relay/release', { lease_id: id }]]);
  const firstPort = Number(entrance.split('/')[4]);
  const releaseDeadline = performance.now() + 3_000;
  while (!(await canBind(firstPort))) {
    assert.ok(performance.now() < releaseDeadline, 'End session did not release scoped UDP ingress');
    await new Promise(resolve => setTimeout(resolve, 25));
  }

  // The relay's connected subnet still exists on physical, but the companion
  // cannot use it once another link owns the default route.
  await new Promise(resolve => setTimeout(resolve, 1_050));
  const [staged, second] = await http(origin, request);
  assert.equal(staged, 200, JSON.stringify(second));
  const heldPort = Number(second.relay_entrance.split('/')[4]);
  assert.ok(heldPort > 0);
  assert.equal(await canBind(heldPort), false, 'the lease must own the local port');
  ip('route', 'replace', 'default', 'dev', 'secondary');
  const deadline = performance.now() + 3_000;
  while (!(await canBind(heldPort))) {
    assert.ok(performance.now() < deadline, 'route change did not revoke the existing ingress');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  await new Promise(resolve => setTimeout(resolve, 1_050));
  const [status] = await http(origin, request);
  assert.ok([404, 503, 504].includes(status), `unexpected secondary path result: ${status}`);
});
