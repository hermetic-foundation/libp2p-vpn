import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5_000 });

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

test('a default-link change closes an admitted locator stream without falling back',
  { timeout: 40_000 }, async t => {
    const { env, origin, relayPeer, storage } = await separateSeedFixture(t);
    const crossOrigin = await fetch(origin + '/api/relay/inviter/locator', {
      method: 'POST',
      headers: {
        Origin: 'http://127.0.0.1:1',
        'Sec-Fetch-Site': 'cross-site',
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    assert.equal(crossOrigin.status, 403);
    const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
      ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Network.enable');
    const websocket = [];
    cdp.on('Network.webSocketWillSendHandshakeRequest', ({ request }) => {
      const headers = Object.fromEntries(Object.entries(request.headers).map(([name, value]) => [name.toLowerCase(), value]));
      websocket.push({ origin: headers.origin, site: headers['sec-fetch-site'] });
    });
    cdp.on('Network.webSocketHandshakeResponseReceived', ({ response }) => websocket.push(response.status));
    await page.goto(origin + '/code-inviter.html');
    await page.evaluate(async ({ relayPeer, storagePeer }) => {
      const { default: init, BrowserCodeInviter, pairing_code_v2_global_locator } =
        await import('/pkg/p2p_vpn_browser.js');
      await init();
      const post = (path, body) => fetch(path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      const response = await post('/api/relay/inviter/reservation', {});
      if (!response.ok) throw Error(`reservation: ${response.status}`);
      const { relay_entrance, native_alias, relay_lease_id } = await response.json();
      const inviter = await BrowserCodeInviter.open_unpinned_scoped('locator-revocation',
        '10.84.0.1', '10.84.0.2', relayPeer, relay_entrance, native_alias);
      await inviter.reserve();
      window.fixtureInviter = inviter;
      const locator = pairing_code_v2_global_locator(inviter.code());
      const request = {
        lease_id: relay_lease_id, relay_entrance,
        provider_key: `/p2p-vpn/pairing-code/${locator}/providers/2`,
      };
      const mismatch = await post('/api/relay/inviter/locator', {
        ...request, relay_entrance: relay_entrance.replace('/udp/', '/tcp/'),
      });
      if (mismatch.ok) throw Error('Mismatched relay entrance was authorized');
      const extra = await post('/api/relay/inviter/locator', {
        ...request, destination: '/ip4/11.250.0.4/tcp/1',
      });
      if (extra.status !== 400) throw Error('Browser-supplied destination was not rejected');
      const selected = await post('/api/relay/inviter/locator', request);
      if (!selected.ok) throw Error(`locator admission: ${selected.status}`);
      const index = (await selected.json()).indexOf(storagePeer);
      if (index === -1) throw Error('Storage peer was not admitted');
      const connect = (suffix = '') => new WebSocket(
        `ws://${location.host}/api/relay/inviter/locator/stream/${index}${suffix}`,
        `p2p-vpn-locator.${relay_lease_id}`);
      const earlyRead = await new Promise(resolve => {
        const stream = connect('/readback');
        stream.onopen = () => { stream.close(); resolve(true); };
        stream.onclose = () => resolve(false);
      });
      if (earlyRead) throw Error('Readback stream was admitted before publication');
      const stream = connect();
      window.fixtureStream = stream;
      window.fixtureReconnect = connect;
      await new Promise((resolve, reject) => {
        stream.onopen = resolve;
        stream.onerror = () => reject(Error('Locator stream failed to open'));
      });
    }, { relayPeer, storagePeer: storage.split('/').at(-1) })
      .catch(error => { throw Error(`${error.message}; handshake: ${JSON.stringify(websocket)}`); });
    const destination = `11.250.0.4:${storage.split('/')[4]}`;
    await until(() => execFileSync('ss', ['-Htn', 'state', 'established'], { encoding: 'utf8' })
      .includes(destination), 'Host did not open a default-bound storage socket');
    ip('route', 'replace', 'default', 'dev', 'secondary');
    await until(() => page.evaluate(() => window.fixtureStream.readyState === WebSocket.CLOSED),
      'Route change did not close the running locator stream', 3_000);
    await until(() => !execFileSync('ss', ['-Htn', 'state', 'established'], { encoding: 'utf8' })
      .includes(destination), 'Revoked storage TCP socket stayed open', 3_000);
    assert.equal(await page.evaluate(() => new Promise(resolve => {
      const retry = window.fixtureReconnect();
      retry.onopen = () => { retry.close(); resolve(true); };
      retry.onclose = () => resolve(false);
    })), false);
  });
async function scopedFixture(t, { withAlternate = false, withStorage = false } = {}) {
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
    ...(withStorage ? [
      'ip addr add 11.250.0.3/24 dev fixture-peer',
      'ip addr add 11.250.0.4/24 dev fixture-peer',
    ] : []),
    'ip link set fixture-peer up',
    'exec "$@"',
  ].join('\n'), 'fixture-namespace', env.P2P_VPN_RELAY_FIXTURE,
  ...(withStorage ? ['--auto-relay-dht', '11.250.0.3', '11.250.0.2', '11.250.0.4']
    : ['11.250.0.2', '--locator-dht'])]);
  const pid = await relay.next();
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'physical', 'type', 'veth', 'peer', 'name', 'fixture-peer', 'netns', pid);
  ip('link', 'set', 'physical', 'addrgenmode', 'none');
  ip('addr', 'add', '11.250.0.1/24', 'dev', 'physical');
  ip('link', 'set', 'physical', 'up');
  ip('route', 'add', 'default', 'dev', 'physical');
  ip('link', 'add', 'secondary', 'type', 'dummy');
  t.after(() => ip('link', 'del', 'secondary'));
  ip('link', 'set', 'secondary', 'addrgenmode', 'none');
  ip('addr', 'add', '11.251.0.1/24', 'dev', 'secondary');
  ip('link', 'set', 'secondary', 'up');
  relay.child.stdin.end('ready\n');
  const { webrtc, tcp, native, bootstrap } = JSON.parse(await relay.next());
  const identify = withStorage ? native : tcp;
  const joinSeed = withStorage ? bootstrap : identify;
  const relayPeer = webrtc.split('/').at(-1);
  assert.equal(identify.split('/').at(-1), relayPeer);
  let alternate;
  const args = ['browser-serve', '--assets', assets, '--port', '0', '--bootstrap', identify];
  if (withAlternate) {
    const process = fixture(t, 'nsenter', ['-t', pid, '-n', env.P2P_VPN_RELAY_FIXTURE, '11.250.0.2', '--locator-dht']);
    alternate = { ...JSON.parse(await process.next()), logs: process.logs };
    args.push('--relay-entrance', webrtc, '--relay-native-alias', identify,
      '--relay-entrance', alternate.webrtc, '--relay-native-alias', alternate.tcp);
  }
  const companion = fixture(t, env.P2P_VPN_BIN, args);
  const line = await companion.next();
  const origin = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
  assert.ok(origin, line);
  return { env, origin, relay, relayPid: pid, identify, joinSeed, relayPeer, scopedWebrtc: webrtc, companion, alternate };
}

async function until(check, label, timeout = 12_000) {
  const deadline = performance.now() + timeout;
  while (performance.now() < deadline) {
    const result = await check();
    if (result) return result;
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  throw Error(typeof label === 'function' ? label() : label);
}

async function seedLegacyIssuer(page, env, addressPrefix) {
  const keys = execFileSync(env.P2P_VPN_BIN, ['keygen', '--output', '-'], { encoding: 'utf8' });
  const network = {
    name: 'rooted-native-enrollment',
    local_peer: /^peer_id: (\S+)$/m.exec(keys)[1],
    private_key: /^private_key: (\S+)$/m.exec(keys)[1],
    vpn_ip: '10.83.0.1',
  };
  const seeded = await page.evaluate(async ({ network, addressPrefix }) => {
    const { BrowserFileInviter, BrowserPairing } = await import('/pkg/p2p_vpn_browser.js');
    network.external_addresses = [`${addressPrefix}/p2p-circuit/p2p/${network.local_peer}`];
    const issuer = await BrowserFileInviter.open(JSON.stringify({ network }));
    const prior = new BrowserPairing();
    const enrollment = prior.begin_offline(issuer.create_offer(), 'prior-member');
    issuer.review_request(enrollment.request_json());
    issuer.approve(prior.peer_id());
    const oldPeer = prior.peer_id();
    enrollment.free();
    prior.free();
    await issuer.close();
    const key = 'p2p-vpn:legacy-membership:1:' + JSON.stringify([network.name, network.local_peer]);
    return { config: { network }, key, oldPeer, prior: localStorage.getItem(key) };
  }, { network, addressPrefix });
  seeded.config.network.member_records = JSON.parse(seeded.prior);
  assert.ok(seeded.config.network.member_records.some(record => record.payload.member_peer === seeded.oldPeer));
  return seeded;
}

async function submitLegacyIssuer(page, seeded, relayPeer = '') {
  await page.getByLabel('Invitation route').selectOption('scoped');
  await page.locator('#existing-scoped-relay').fill(relayPeer);
  await page.getByLabel('Issuer legacy JSON config').setInputFiles({
    name: 'issuer.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(seeded.config)),
  });
  await page.getByRole('button', { name: 'Open issuer and reserve relay' }).click();
}

async function openLegacyIssuer(page, seeded, relayPeer) {
  await submitLegacyIssuer(page, seeded, relayPeer);
  await page.getByText('Waiting for joiner', { exact: true }).waitFor({ timeout: 20_000 }).catch(async failure => {
    throw Error(`${await page.locator('#state').textContent()}: ${await page.locator('#error').textContent()}`, { cause: failure });
  });
}

async function nativeCodeEnrollment(t, legacy) {
    const { env, origin, relay, relayPid, identify, joinSeed, relayPeer, scopedWebrtc } =
      await scopedFixture(t, { withStorage: legacy });
    const scratch = await mkdtemp(join(tmpdir(), 'p2p-vpn-native-invitation-'));
    t.after(() => rm(scratch, { recursive: true, force: true }));
    const configPath = join(scratch, 'enrolled.json');
    const socketPath = join(scratch, 'control.sock');
    const native = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
      'printf "%s\\n" "$$"',
      'read ready',
      'ip link set lo up',
      'ip addr add 11.252.0.1/24 dev native-wire',
      'ip link set native-wire addrgenmode none',
      'ip link set native-wire up',
      'ip route add default via 11.252.0.2 dev native-wire',
      'printf "joiner-ready\\n"',
      '"$1" --enroll-locator "$2" "$3"',
      'shift 3',
      'exec "$@"',
    ].join('\n'), 'native-enrollment', env.P2P_VPN_RELAY_FIXTURE, joinSeed, configPath,
    env.P2P_VPN_BIN, 'up', '-c', configPath, '--control-socket', socketPath]);
    const nativePid = await native.next();
    assert.match(nativePid, /^\d+$/);
    const inNamespace = (pid, ...args) => execFileSync('nsenter', ['-t', pid, '-n', ...args],
      { encoding: 'utf8', timeout: 3_000 });
    ip('link', 'add', 'native-wire', 'type', 'veth', 'peer', 'name', 'relay-native');
    ip('link', 'set', 'native-wire', 'netns', nativePid);
    ip('link', 'set', 'relay-native', 'netns', relayPid);
    inNamespace(relayPid, 'ip', 'addr', 'add', '11.252.0.2/24', 'dev', 'relay-native');
    inNamespace(relayPid, 'ip', 'link', 'set', 'relay-native', 'addrgenmode', 'none');
    inNamespace(relayPid, 'ip', 'link', 'set', 'relay-native', 'up');
    inNamespace(relayPid, 'sysctl', '-w', 'net.ipv4.ip_forward=0');
    inNamespace(relayPid, 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=0');
    // A default path through this relay namespace cannot reach public seeds.
    assert.deepEqual(JSON.parse(inNamespace(relayPid, 'ip', '-j', 'route', 'show', 'default')), []);
    assert.deepEqual(JSON.parse(inNamespace(relayPid, 'ip', '-6', '-j', 'route', 'show', 'default')), []);
    assert.equal(inNamespace(relayPid, 'sysctl', '-n', 'net.ipv4.ip_forward').trim(), '0');
    assert.equal(inNamespace(relayPid, 'sysctl', '-n', 'net.ipv6.conf.all.forwarding').trim(), '0');
    native.child.stdin.write('ready\n');
    assert.equal(await native.next(), 'joiner-ready');
    assert.match(inNamespace(nativePid, 'ip', 'route', 'get', '11.250.0.2'), /via 11\.252\.0\.2 dev native-wire/);

    const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
      ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage(legacy ? { viewport: { width: 360, height: 800 } } : {});
    const state = (label, timeout = 20_000) => page.getByText(label, { exact: true }).waitFor({ timeout });
    const ledger = key => page.evaluate(key => localStorage.getItem(key), key);
    const posts = [];
    page.on('request', request => {
      if (request.method() === 'POST') posts.push([new URL(request.url()).pathname, request.postDataJSON()]);
    });
    assert.equal((await page.goto(origin + '/code-inviter.html' + (legacy ? '#existing' : ''))).status(), 200);
    await state('Ready');
    const seeded = legacy ? await seedLegacyIssuer(page, env, scopedWebrtc) : null;
    if (legacy) await openLegacyIssuer(page, seeded);
    if (legacy) {
      await page.evaluate(async () => {
        const { BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
        // The UI owns the active handle. Park its foreground loop so the test
        // can use the same authorized session for a userspace HTTP round trip.
        BrowserVpn.prototype.poll_foreground = function () {
          window.fixtureVpn = this;
          return new Promise(() => {});
        };
      });
    }
    const invitation = legacy ? await page.evaluate(async () => {
      const { pairing_code_v2_global_locator } = await import('/pkg/p2p_vpn_browser.js');
      const read = id => document.getElementById(id).textContent;
      const code = read('invite-code');
      return { code, peer: read('inviter-peer'), address: read('invite-address'),
        locator: pairing_code_v2_global_locator(code) };
    }) : await page.evaluate(async relay_peer => {
      const { default: init, BrowserCodeInviter, pairing_code_v2_global_locator } =
        await import('/pkg/p2p_vpn_browser.js');
      await init();
      const reply = await fetch('/api/relay/inviter/reservation', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
      });
      if (!reply.ok) throw Error(`reservation: ${reply.status}`);
      const { relay_entrance, native_alias, relay_lease_id } = await reply.json();
      if (native_alias.split('/').at(-1) !== relay_peer) throw Error('unexpected automatic relay');
      const inviter = await BrowserCodeInviter.open_unpinned_scoped('native-code-acceptance',
        '10.83.0.1', '10.83.0.2', relay_peer, relay_entrance, native_alias);
      const address = await inviter.reserve();
      await inviter.publish_locator_scoped();
      window.fixtureInviter = inviter;
      window.fixtureLease = relay_lease_id;
      const code = inviter.code();
      return { code, peer: inviter.peer_id(), address, locator: pairing_code_v2_global_locator(code) };
    }, relayPeer);
    assert.equal(invitation.address, `${identify}/p2p-circuit/p2p/${invitation.peer}`);
    const replyMarker = legacy ? 'fixture storage GET_PROVIDERS closer=0 providers=1' : 'locator-dht reply providers=1';
    const providerReplies = () => relay.logs().split('\n').filter(line => line === replyMarker).length;
    const beforeLookup = providerReplies();
    const lookup = inNamespace(nativePid, env.P2P_VPN_RELAY_FIXTURE, '--lookup-locator', joinSeed, invitation.locator);
    assert.deepEqual(JSON.parse(lookup), [{ peer: invitation.peer, addresses: [invitation.address] }]);
    await until(() => providerReplies() > beforeLookup, 'Independent lookup did not get a provider reply');
    const beforeEnrollment = providerReplies();
    native.child.stdin.end(invitation.code + '\n');
    const { joining_peer: nativePeer } = JSON.parse(await native.next());
    const candidate = legacy ? await (async () => {
      await state('Approval required', 62_000).catch(failure => {
        throw Error(`Native v2 did not reach approval. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`, { cause: failure });
      });
      return { peer_id: await page.locator('#candidate-peer').textContent(),
        ip: await page.locator('#candidate-ip').textContent() };
    })() : await page.evaluate(async () => {
      const inviter = window.fixtureInviter;
      const deadline = performance.now() + 62_000;
      while (performance.now() < deadline) {
        const candidate = inviter.pending_candidate();
        if (candidate) return JSON.parse(candidate);
        await inviter.drive(100);
      }
      return null;
    });
    assert.ok(providerReplies() > beforeEnrollment, `DHT did not answer the native bootstrap. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`);
    if (legacy) {
      assert.match(relay.logs(), /fixture seed GET_PROVIDERS closer=1 providers=0/);
      assert.doesNotMatch(relay.logs(), /fixture relay GET_PROVIDERS/);
    }
    assert.ok(candidate, `Native v2 did not reach approval. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`);
    assert.equal(candidate.peer_id, nativePeer);
    await assert.rejects(readFile(configPath), { code: 'ENOENT' });

    const approve = page.getByRole('button', { name: 'Approve peer' });
    if (legacy) {
      assert.equal(await ledger(seeded.key), seeded.prior);
      assert.match(candidate.ip, /^100\.64\.\d+\.\d+$/);
      assert.equal(await page.evaluate(() =>
        document.documentElement.scrollWidth <= window.innerWidth), true);
      await page.evaluate(key => {
        const write = Storage.prototype.setItem;
        Storage.prototype.setItem = function (name, value) {
          if (name === key) {
            Storage.prototype.setItem = write;
            throw new DOMException('Test quota', 'QuotaExceededError');
          }
          return write.call(this, name, value);
        };
      }, seeded.key);
      await approve.click();
      await page.getByRole('alert').filter({ hasText: 'Approval was not sent' }).waitFor();
      assert.equal(await ledger(seeded.key), seeded.prior);
      await assert.rejects(readFile(configPath), { code: 'ENOENT' });
      assert.equal(await page.locator('#active').isVisible(), false);
      await approve.click();
    }
    const activating = legacy ? state('VPN connected').then(async () => ({
      remote_peer_id: await page.locator('#active-remote').textContent(),
    })) : page.evaluate(async peer => {
      const inviter = window.fixtureInviter;
      inviter.approve(peer);
      const deadline = performance.now() + 8_000;
      while (!inviter.delivered()) {
        if (performance.now() >= deadline) throw Error('Approved response not delivered');
        await inviter.drive(100);
      }
      window.fixtureVpn = await inviter.into_vpn();
      return JSON.parse(await window.fixtureVpn.accept_relay());
    }, nativePeer);
    activating.catch(() => {});
    assert.deepEqual(JSON.parse(await native.next()), { enrolled_peer: nativePeer });
    const enrolled = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(enrolled.network.local_peer, nativePeer);
    const nativeIp = legacy ? candidate.ip : '10.83.0.2';
    if (!legacy) assert.equal(enrolled.network.vpn_ip, nativeIp);
    assert.deepEqual(enrolled.peers.map(peer => [peer.id, peer.addresses]), [[invitation.peer, [invitation.address]]]);
    await until(() => JSON.parse(inNamespace(nativePid, 'ip', '-j', 'address', 'show')).some(link =>
      link.ifname === 'pv-native' && link.addr_info.some(address => address.local === nativeIp)),
    () => `The stock daemon did not create the enrolled TUN: ${native.logs()}`);
    const accepted = await activating;
    if (!legacy) {
      assert.equal(accepted.authorized, true);
      assert.equal(accepted.transport, 'circuit-relay');
    }
    assert.equal(accepted.remote_peer_id, nativePeer);
    assert.equal(await page.evaluate(() => window.fixtureVpn.relay_reservation_address()), invitation.address);

    const httpd = fixture(t, 'nsenter', ['-t', nativePid, '-n', 'node', '--input-type=module', '-e', [
      "import { createServer } from 'node:http';",
      "const server = createServer((req, res) => res.end('native TUN ' + req.url));",
      'server.listen(0, process.argv[1], () => console.log(server.address().port));',
    ].join('\n'), nativeIp]);
    const port = Number(await httpd.next());
    assert.ok(port > 0);
    const counters = () => {
      const [tun] = JSON.parse(inNamespace(nativePid, 'ip', '-s', '-j', 'link', 'show', 'dev', 'pv-native'));
      return tun.stats64 ?? tun.stats;
    };
    const before = counters();
    const response = await page.evaluate(({ nativeIp, port }) =>
      window.fixtureVpn.fetch_http(nativeIp, port, '/round-trip'), { nativeIp, port });
    assert.match(response, /^HTTP\/1\.[01] 200/);
    assert.match(response, /native TUN \/round-trip/);
    const after = counters();
    assert.ok(after.rx.packets > before.rx.packets && after.tx.packets > before.tx.packets);
    assert.equal([...relay.logs().matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1);
    assert.ok(relay.logs().split('\n').filter(line => line.includes('CircuitReqAccepted')
      && line.includes(nativePeer) && line.includes(invitation.peer)).length >= 2);
    if (legacy) {
      const saved = await ledger(seeded.key);
      const records = JSON.parse(saved);
      const prior = JSON.parse(seeded.prior);
      assert.equal(records.length, prior.length + 1);
      assert.ok(prior.every(record => records.some(entry => entry.signature === record.signature)));
      const grant = records.find(record => record.payload.member_peer === nativePeer);
      assert.equal(grant.payload.issuer_peer, invitation.peer);
      assert.ok(enrolled.network.member_records.some(record => record.signature === grant.signature));
      await page.getByRole('button', { name: 'End session' }).click();
      await state('Ready');
      assert.equal(await ledger(seeded.key), saved);
      const requests = posts.filter(([path]) => path !== '/api/relay/release');
      assert.deepEqual(requests.map(([path]) => path), [
        '/api/relay/inviter/reservation', '/api/relay/inviter/locator',
      ]);
      assert.deepEqual(requests[0][1], {});
      const publication = requests[1][1];
      assert.deepEqual(Object.keys(publication).sort(), ['lease_id', 'provider_key', 'relay_entrance']);
      assert.equal(publication.provider_key, `/p2p-vpn/pairing-code/${invitation.locator}/providers/2`);
      assert.match(publication.lease_id, /^[A-Za-z0-9_-]{32}$/);
      assert.match(publication.relay_entrance, /^\/ip4\/127\.0\.0\.1\/udp\//);
      assert.equal(posts.filter(([path]) => path === '/api/relay/release').length, 1);
      return;
    }
    const released = await page.evaluate(async () => (await fetch('/api/relay/release', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lease_id: window.fixtureLease }),
    })).status);
    assert.equal(released, 200);
}

test('automatic browser relay, native v2 code-only enrollment, and stock TUN interoperate',
  { timeout: 105_000 }, t => nativeCodeEnrollment(t, false));
test('rooted legacy publishes to independent storage, saves before granting, and carries native TUN traffic',
  { timeout: 105_000 }, t => nativeCodeEnrollment(t, true));

test('production rooted legacy denial retires the scoped invitation without editing the prior roster',
  { timeout: 40_000 }, async t => {
    const { env, origin, identify, scopedWebrtc } = await scopedFixture(t, { withStorage: true });
    const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
      ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage();
    assert.equal((await page.goto(origin + '/code-inviter.html#existing')).status(), 200);
    await page.getByText('Ready', { exact: true }).waitFor();
    const seeded = await seedLegacyIssuer(page, env, scopedWebrtc);
    await openLegacyIssuer(page, seeded);
    const peer = seeded.config.network.local_peer;
    assert.equal(await page.locator('#invite-address').textContent(), `${identify}/p2p-circuit/p2p/${peer}`);
    const pending = await page.evaluate(async ({ webrtc, peer, code }) => {
      const { BrowserPairing } = await import('/pkg/p2p_vpn_browser.js');
      const applicant = new BrowserPairing();
      const applicantPeer = applicant.peer_id();
      window.deniedExchange = applicant.join_v2(code, peer,
        `${webrtc}/p2p-circuit/p2p/${peer}`, 10_000, 'denied-applicant')
        .then(() => 'granted', () => 'rejected').finally(() => applicant.free());
      return applicantPeer;
    }, { webrtc: scopedWebrtc, peer, code: await page.locator('#invite-code').textContent() });
    await page.getByText('Approval required', { exact: true }).waitFor();
    assert.equal(await page.locator('#candidate-peer').textContent(), pending);
    const released = page.waitForResponse(response => new URL(response.url()).pathname === '/api/relay/release');
    await page.getByRole('button', { name: 'Deny peer' }).click();
    await page.getByText('Request denied', { exact: true }).waitFor();
    assert.equal((await released).status(), 200);
    assert.equal(await page.evaluate(() => window.deniedExchange), 'rejected');
    assert.equal(await page.evaluate(key => localStorage.getItem(key), seeded.key), seeded.prior);
    assert.equal(await page.evaluate(key => navigator.locks.request(key, { ifAvailable: true }, Boolean),
      seeded.key), true);
  });

async function separateSeedFixture(t) {
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
    'ip addr add 11.250.0.3/24 dev fixture-peer',
    'ip addr add 11.250.0.4/24 dev fixture-peer',
    'ip link set fixture-peer up',
    'exec "$@"',
  ].join('\n'), 'fixture-namespace', env.P2P_VPN_RELAY_FIXTURE,
  '--auto-relay-dht', '11.250.0.3', '11.250.0.2', '11.250.0.4']);
  const pid = await relay.next();
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'physical', 'type', 'veth', 'peer', 'name', 'fixture-peer', 'netns', pid);
  ip('link', 'set', 'physical', 'addrgenmode', 'none');
  ip('addr', 'add', '11.250.0.1/24', 'dev', 'physical');
  ip('link', 'set', 'physical', 'up');
  ip('route', 'add', 'default', 'dev', 'physical');
  ip('link', 'add', 'secondary', 'type', 'dummy');
  t.after(() => ip('link', 'del', 'secondary'));
  ip('link', 'set', 'secondary', 'addrgenmode', 'none');
  ip('addr', 'add', '11.251.0.1/24', 'dev', 'secondary');
  ip('link', 'set', 'secondary', 'up');
  relay.child.stdin.end('ready\n');
  const { webrtc, native: identify, bootstrap: joinSeed, storage } = JSON.parse(await relay.next());
  const relayPeer = webrtc.split('/').at(-1);
  assert.equal(identify.split('/').at(-1), relayPeer);
  assert.notEqual(joinSeed.split('/').at(-1), relayPeer);
  assert.match(storage, /^\/ip4\/11\.250\.0\.4\/tcp\/\d+\/p2p\//);
  // The companion starts at the relay; only the native joiner uses joinSeed.
  const companion = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assets,
    '--port', '0', '--bootstrap', identify]);
  const line = await companion.next();
  const origin = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
  assert.ok(origin, line);
  return { env, origin, relay, relayPid: pid, identify, relayPeer, joinSeed, storage };
}

for (const retirement of ['cancel', 'expire', 'release', 'generation']) {
  test(`cached distributed locator grants no authority after ${retirement}`, { timeout: 55_000 }, async t => {
    const { env, origin, relayPeer, joinSeed, relay } = await separateSeedFixture(t);
    const scratch = await mkdtemp(join(tmpdir(), 'p2p-vpn-stale-locator-'));
    t.after(() => rm(scratch, { recursive: true, force: true }));
    const config = join(scratch, 'enrolled.json');
    const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
      ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage();
    await page.goto(origin + '/code-inviter.html');
    const invitation = await page.evaluate(async relayPeer => {
      const { default: init, BrowserCodeInviter, pairing_code_v2_global_locator } =
        await import('/pkg/p2p_vpn_browser.js');
      await init();
      const response = await fetch('/api/relay/inviter/reservation', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      });
      if (!response.ok) throw Error(`reservation: ${response.status}`);
      const { relay_entrance, native_alias, relay_lease_id } = await response.json();
      const inviter = await BrowserCodeInviter.open_unpinned_scoped('stale-locator',
        '10.85.0.1', '10.85.0.2', relayPeer, relay_entrance, native_alias);
      const address = await inviter.reserve();
      await inviter.publish_locator_distributed(relay_lease_id);
      window.fixtureInviter = inviter;
      const code = inviter.code();
      return { code, locator: pairing_code_v2_global_locator(code), peer: inviter.peer_id(),
        address, lease: relay_lease_id, ingressPort: Number(relay_entrance.split('/')[4]) };
    }, relayPeer);
    const lookup = () => JSON.parse(execFileSync(env.P2P_VPN_RELAY_FIXTURE,
      ['--lookup-locator', joinSeed, invitation.locator], { encoding: 'utf8', timeout: 8_000 }));
    const record = [{ peer: invitation.peer, addresses: [invitation.address] }];
    assert.deepEqual(lookup(), record);

    if (retirement === 'generation') {
      ip('route', 'replace', 'default', 'dev', 'secondary');
      await until(() => !execFileSync('ss', ['-Hlun', 'sport', '=', `:${invitation.ingressPort}`],
        { encoding: 'utf8' }).trim(), 'Default-link change did not revoke inviter ingress', 3_000);
      // Restore reachability to storage, not the old lease or reservation.
      ip('route', 'replace', 'default', 'dev', 'physical');
    } else {
      const retired = await page.evaluate(async ({ retirement, lease }) => {
        const inviter = window.fixtureInviter;
        if (retirement === 'release') {
          const response = await fetch('/api/relay/release', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ lease_id: lease }),
          });
          return response.ok && (await response.json()).released;
        }
        if (retirement === 'cancel') inviter.cancel();
        if (retirement === 'expire') {
          const now = Date.now.bind(Date);
          Date.now = () => now() + 111_000;
        }
        return inviter.drive(50).then(() => '', error => error.message);
      }, { retirement, lease: invitation.lease });
      if (retirement === 'release') assert.equal(retired, true);
      else assert.match(retired, retirement === 'expire' ? /expired/ : /cancelled/);
    }
    assert.deepEqual(lookup(), record, 'retirement must not be mistaken for removal from the DHT');

    const replies = () => relay.logs().split('\n')
      .filter(line => line === 'fixture storage GET_PROVIDERS closer=0 providers=1').length;
    const before = replies();
    const native = spawn(env.P2P_VPN_RELAY_FIXTURE, ['--enroll-locator', joinSeed, config, '25'],
      { stdio: ['pipe', 'ignore', 'pipe'] });
    t.after(() => native.kill());
    let stderr = '';
    native.stderr.setEncoding('utf8').on('data', data => { stderr += data; });
    const exited = once(native, 'close');
    native.stdin.end(invitation.code + '\n');
    const [status] = await exited;
    assert.equal(status, 1, stderr);
    assert.match(stderr, /TimedOut/, stderr);
    assert.ok(replies() > before, `The native joiner did not read the cached provider:\n${relay.logs()}`);
    assert.equal(await page.evaluate(() => window.fixtureInviter.delivered()), false);
    await assert.rejects(readFile(config), { code: 'ENOENT' });
  });
}

test('native v2 discovers the browser code through a different seed and uses the scoped relay',
  { timeout: 105_000 }, async t => {
    const { env, origin, relay, relayPid, identify, relayPeer, joinSeed } = await separateSeedFixture(t);
    const scratch = await mkdtemp(join(tmpdir(), 'p2p-vpn-native-invitation-'));
    t.after(() => rm(scratch, { recursive: true, force: true }));
    const configPath = join(scratch, 'enrolled.json');
    const socketPath = join(scratch, 'control.sock');
    const native = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
      'printf "%s\\n" "$$"',
      'read ready',
      'ip link set lo up',
      'ip addr add 11.252.0.1/24 dev native-wire',
      'ip link set native-wire addrgenmode none',
      'ip link set native-wire up',
      'ip route add default via 11.252.0.2 dev native-wire',
      'printf "joiner-ready\\n"',
      '"$1" --enroll-locator "$2" "$3"',
      'shift 3',
      'exec "$@"',
    ].join('\n'), 'native-enrollment', env.P2P_VPN_RELAY_FIXTURE, joinSeed, configPath,
    env.P2P_VPN_BIN, 'up', '-c', configPath, '--control-socket', socketPath]);
    const nativePid = await native.next();
    assert.match(nativePid, /^\d+$/);
    const inNamespace = (pid, ...args) => execFileSync('nsenter', ['-t', pid, '-n', ...args],
      { encoding: 'utf8', timeout: 3_000 });
    ip('link', 'add', 'native-wire', 'type', 'veth', 'peer', 'name', 'relay-native');
    ip('link', 'set', 'native-wire', 'netns', nativePid);
    ip('link', 'set', 'relay-native', 'netns', relayPid);
    inNamespace(relayPid, 'ip', 'addr', 'add', '11.252.0.2/24', 'dev', 'relay-native');
    inNamespace(relayPid, 'ip', 'link', 'set', 'relay-native', 'addrgenmode', 'none');
    inNamespace(relayPid, 'ip', 'link', 'set', 'relay-native', 'up');
    inNamespace(relayPid, 'sysctl', '-w', 'net.ipv4.ip_forward=0');
    inNamespace(relayPid, 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=0');
    // A default path through this relay namespace cannot reach public seeds.
    assert.deepEqual(JSON.parse(inNamespace(relayPid, 'ip', '-j', 'route', 'show', 'default')), []);
    assert.deepEqual(JSON.parse(inNamespace(relayPid, 'ip', '-6', '-j', 'route', 'show', 'default')), []);
    assert.equal(inNamespace(relayPid, 'sysctl', '-n', 'net.ipv4.ip_forward').trim(), '0');
    assert.equal(inNamespace(relayPid, 'sysctl', '-n', 'net.ipv6.conf.all.forwarding').trim(), '0');
    native.child.stdin.write('ready\n');
    assert.equal(await native.next(), 'joiner-ready');
    assert.match(inNamespace(nativePid, 'ip', 'route', 'get', '11.250.0.2'), /via 11\.252\.0\.2 dev native-wire/);

    const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
      ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage();
    assert.equal((await page.goto(origin + '/code-inviter.html')).status(), 200);
    const invitation = await page.evaluate(async relay_peer => {
      const { default: init, BrowserCodeInviter } =
        await import('/pkg/p2p_vpn_browser.js');
      await init();
      const reply = await fetch('/api/relay/inviter/reservation', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
      });
      if (!reply.ok) throw Error(`reservation: ${reply.status}`);
      const { relay_entrance, native_alias, relay_lease_id } = await reply.json();
      if (native_alias.split('/').at(-1) !== relay_peer) throw Error('unexpected automatic relay');
      const inviter = await BrowserCodeInviter.open_unpinned_scoped('native-code-acceptance',
        '10.83.0.1', '10.83.0.2', relay_peer, relay_entrance, native_alias);
      const address = await inviter.reserve();
      await inviter.publish_locator_distributed(relay_lease_id);
      for (const repeat of [
        () => inviter.publish_locator_distributed(relay_lease_id),
        () => inviter.publish_locator_scoped(),
      ]) {
        const outcome = await repeat().then(() => 'accepted', error => error.message);
        if (!/already attempted/.test(outcome)) throw Error(`Repeated publication: ${outcome}`);
      }
      window.fixtureInviter = inviter;
      window.fixtureLease = relay_lease_id;
      const code = inviter.code();
      return { code, peer: inviter.peer_id(), address };
    }, relayPeer).catch(error => {
      throw Error(`${error.message}\nRelay:\n${relay.logs()}`, { cause: error });
    });
    assert.equal(invitation.address, `${identify}/p2p-circuit/p2p/${invitation.peer}`);
    await until(() => relay.logs().includes(`storage-hop ${invitation.peer} /ip4/11.250.0.1/tcp/`),
      () => `Browser did not authenticate to storage on the default link: ${relay.logs()}`);
    const referral = /fixture seed GET_PROVIDERS closer=1 providers=0[\s\S]*fixture storage GET_PROVIDERS closer=0 providers=1/;
    assert.doesNotMatch(relay.logs(), referral);
    native.child.stdin.end(invitation.code + '\n');
    const { joining_peer: nativePeer } = JSON.parse(await native.next());
    const candidate = await page.evaluate(async () => {
      const inviter = window.fixtureInviter;
      const deadline = performance.now() + 62_000;
      while (performance.now() < deadline) {
        const candidate = inviter.pending_candidate();
        if (candidate) return JSON.parse(candidate);
        await inviter.drive(100);
      }
      return null;
    });
    await until(() => referral.test(relay.logs()), () => `Native bootstrap did not follow the referral. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`);
    assert.doesNotMatch(relay.logs(), /fixture relay GET_PROVIDERS/);
    assert.ok(candidate, `Native v2 did not reach approval. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`);
    assert.equal(candidate.peer_id, nativePeer);
    assert.ok(relay.logs().includes(`relay-hop ${invitation.peer} /ip4/11.250.0.1/udp/`));
    assert.ok(relay.logs().includes(`relay-hop ${nativePeer} /ip4/11.252.0.1/tcp/`));
    await assert.rejects(readFile(configPath), { code: 'ENOENT' });

    const activating = page.evaluate(async peer => {
      const inviter = window.fixtureInviter;
      inviter.approve(peer);
      const deadline = performance.now() + 8_000;
      while (!inviter.delivered()) {
        if (performance.now() >= deadline) throw Error('Approved response not delivered');
        await inviter.drive(100);
      }
      window.fixtureVpn = await inviter.into_vpn();
      return JSON.parse(await window.fixtureVpn.accept_relay());
    }, nativePeer);
    activating.catch(() => {});
    assert.deepEqual(JSON.parse(await native.next()), { enrolled_peer: nativePeer });
    const enrolled = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(enrolled.network.local_peer, nativePeer);
    assert.equal(enrolled.network.vpn_ip, '10.83.0.2');
    assert.deepEqual(enrolled.peers.map(peer => [peer.id, peer.addresses]), [[invitation.peer, [invitation.address]]]);
    await until(() => JSON.parse(inNamespace(nativePid, 'ip', '-j', 'address', 'show')).some(link =>
      link.ifname === 'pv-native' && link.addr_info.some(address => address.local === '10.83.0.2')),
    () => `The stock daemon did not create the enrolled TUN: ${native.logs()}`);
    const accepted = await activating;
    assert.equal(accepted.authorized, true);
    assert.equal(accepted.transport, 'circuit-relay');
    assert.equal(accepted.remote_peer_id, nativePeer);
    assert.equal(await page.evaluate(() => window.fixtureVpn.relay_reservation_address()), invitation.address);

    const httpd = fixture(t, 'nsenter', ['-t', nativePid, '-n', 'node', '--input-type=module', '-e', [
      "import { createServer } from 'node:http';",
      "const server = createServer((req, res) => res.end('native TUN ' + req.url));",
      "server.listen(0, '10.83.0.2', () => console.log(server.address().port));",
    ].join('\n')]);
    const port = Number(await httpd.next());
    assert.ok(port > 0);
    const counters = () => {
      const [tun] = JSON.parse(inNamespace(nativePid, 'ip', '-s', '-j', 'link', 'show', 'dev', 'pv-native'));
      return tun.stats64 ?? tun.stats;
    };
    const before = counters();
    const response = await page.evaluate(port => window.fixtureVpn.fetch_http('10.83.0.2', port, '/round-trip'), port);
    assert.match(response, /^HTTP\/1\.[01] 200/);
    assert.match(response, /native TUN \/round-trip/);
    const after = counters();
    assert.ok(after.rx.packets > before.rx.packets && after.tx.packets > before.tx.packets);
    assert.equal([...relay.logs().matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1);
    assert.ok(relay.logs().split('\n').filter(line => line.includes('CircuitReqAccepted')
      && line.includes(nativePeer) && line.includes(invitation.peer)).length >= 2);
    const released = await page.evaluate(async () => (await fetch('/api/relay/release', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lease_id: window.fixtureLease }),
    })).status);
    assert.equal(released, 200);
  });

test('production scoped legacy issuer can reissue on another relay after a busy reservation',
  { timeout: 65_000 }, async t => {
    const { env, origin, identify, joinSeed, scopedWebrtc, relay, companion, alternate } =
      await scopedFixture(t, { withAlternate: true, withStorage: true });
    const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
      ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
    t.after(() => browser.close());
    const issuer = await browser.newPage();
    const publications = [];
    issuer.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/relay/inviter/locator') {
        publications.push(request.postDataJSON());
      }
    });
    const trace = [];
    const log = (step, outcome) => { trace.push({ step, outcome }); };
    issuer.on('console', message => log('browser', message.text()));
    const ready = label => issuer.getByText(label, { exact: true }).waitFor({ timeout: 15_000 });
    await issuer.goto(origin + '/code-inviter.html#existing');
    await ready('Ready');
    const seeded = await seedLegacyIssuer(issuer, env, scopedWebrtc);
    const peer = seeded.config.network.local_peer;
    const circuit = prefix => `${prefix}/p2p-circuit/p2p/${peer}`;
    const installTrace = () => issuer.evaluate(async () => {
      const { BrowserCodeInviter } = await import('/pkg/p2p_vpn_browser.js');
      const fetchRequest = window.fetch;
      window.fetch = async (path, ...args) => {
        const response = await fetchRequest(path, ...args);
        if (path === '/api/relay/release') {
          console.info('lease release: ' + JSON.stringify(await response.clone().json()));
        }
        return response;
      };
      for (const name of ['reserve', 'publish_locator_distributed']) {
        const original = BrowserCodeInviter.prototype[name];
        BrowserCodeInviter.prototype[name] = async function (...args) {
          try {
            const value = await original.apply(this, args);
            console.info(name + ': ok');
            return value;
          } catch (error) {
            console.info(name + ': ' + error.message);
            throw error;
          }
        };
      }
    });
    try {
      let saved = JSON.parse(seeded.prior);
      for (let attempt = 1; attempt <= 2; attempt++) {
        await installTrace();
        const firstRelay = scopedWebrtc.split('/').at(-1);
        let prefix = scopedWebrtc;
        let alias = identify;
        if (attempt === 2) {
          const released = issuer.waitForResponse(response => new URL(response.url()).pathname === '/api/relay/release');
          await submitLegacyIssuer(issuer, seeded, firstRelay);
          await ready('Not opened');
          assert.match(await issuer.getByRole('alert').textContent(), /choose another configured relay/);
          assert.equal(await issuer.locator('#invitation').isVisible(), false);
          assert.equal((await released).status(), 200);
          assert.equal(publications.length, 1, 'the refused reservation must not publish');
          assert.match(relay.logs(), new RegExp(`ReservationReqDenied.*${peer}.*ResourceLimitExceeded`));
          assert.equal(await issuer.evaluate(key => navigator.locks.request(key, { ifAvailable: true }, Boolean),
            seeded.key), true);
          assert.deepEqual(await issuer.evaluate(key => JSON.parse(localStorage.getItem(key)), seeded.key), saved);
          log('busy retry', 'remote denied reservation; lease released and ledger unlocked');
          prefix = alternate.webrtc;
          alias = alternate.tcp;
          // The companion intentionally paces inviter probes one second apart.
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
        const prepared = issuer.waitForResponse(response => new URL(response.url()).pathname === '/api/relay/inviter/reservation');
        const opening = openLegacyIssuer(issuer, seeded, prefix.split('/').at(-1));
        opening.catch(() => {});
        const preparation = await prepared;
        log(`attempt ${attempt} lease`, preparation.status());
        assert.equal(preparation.status(), 200);
        await opening;
        assert.equal(await issuer.locator('#invite-address').textContent(), circuit(alias));
        assert.equal(publications.length, attempt);
        const locator = await issuer.evaluate(async () => {
          const { pairing_code_v2_global_locator } = await import('/pkg/p2p_vpn_browser.js');
          return pairing_code_v2_global_locator(document.getElementById('invite-code').textContent);
        });
        assert.equal(publications.at(-1).provider_key, `/p2p-vpn/pairing-code/${locator}/providers/2`);
        const found = execFileSync(env.P2P_VPN_RELAY_FIXTURE, ['--lookup-locator', joinSeed, locator],
          { encoding: 'utf8', timeout: 8_000 });
        assert.deepEqual(JSON.parse(found), [{ peer, addresses: [circuit(alias)] }]);
        const applicant = await browser.newPage();
        await applicant.goto(origin + '/code-inviter.html#join');
        await applicant.getByText('Ready', { exact: true }).waitFor();
        const candidate = await applicant.locator('#local-joiner').textContent();
        await applicant.getByLabel('Private v2 code').fill(await issuer.locator('#invite-code').textContent());
        await applicant.getByLabel('Inviter peer ID').fill(peer);
        await applicant.getByLabel('Circuit address').fill(circuit(prefix));
        await applicant.getByLabel('Hostname (optional)').fill('applicant-' + attempt);
        await applicant.getByRole('button', { name: 'Request approval' }).click();
        await ready('Approval required');
        assert.equal(await issuer.locator('#candidate-peer').textContent(), candidate);
        log(`attempt ${attempt} pairing`, 'verified applicant');
        await issuer.getByRole('button', { name: 'Approve peer' }).click();
        await Promise.all([ready('VPN connected'),
          applicant.getByText('VPN connected', { exact: true }).waitFor({ timeout: 15_000 })]);
        log(`attempt ${attempt} activation`, 'both authorized');
        const released = issuer.waitForResponse(response => new URL(response.url()).pathname === '/api/relay/release');
        await issuer.getByRole('button', { name: 'End session' }).click();
        const reply = await released;
        log(`attempt ${attempt} release status`, reply.status());
        assert.equal(reply.status(), 200);
        await ready('Ready');
        assert.equal(trace.filter(event => event.outcome === 'lease release: {"released":true}').length,
          attempt === 1 ? 1 : 3);
        const unlocked = await issuer.evaluate(key => navigator.locks.request(key, { ifAvailable: true }, Boolean), seeded.key);
        log(`attempt ${attempt} ledger unlocked`, unlocked);
        assert.equal(unlocked, true);
        const records = await issuer.evaluate(key => JSON.parse(localStorage.getItem(key)), seeded.key);
        assert.equal(records.length, saved.length + 1);
        assert.ok(saved.every(record => records.some(entry => entry.signature === record.signature)));
        assert.ok(records.some(record => record.payload.member_peer === candidate));
        saved = records;
        await applicant.close();
      }
    } finally {
      if (process.env.P2P_VPN_REISSUE_TRACE) {
        t.diagnostic(JSON.stringify(trace));
        t.diagnostic(relay.logs());
        t.diagnostic(alternate.logs());
        t.diagnostic(companion.logs());
      }
    }
  });
