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

async function scopedFixture(t) {
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
  t.after(() => ip('link', 'del', 'secondary'));
  ip('link', 'set', 'secondary', 'addrgenmode', 'none');
  ip('addr', 'add', '11.251.0.1/24', 'dev', 'secondary');
  ip('link', 'set', 'secondary', 'up');
  relay.child.stdin.end('ready\n');
  const { webrtc, tcp: identify } = JSON.parse(await relay.next());
  const relayPeer = webrtc.split('/').at(-1);
  assert.equal(identify.split('/').at(-1), relayPeer);
  const companion = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assets,
    '--port', '0', '--bootstrap', identify]);
  const line = await companion.next();
  const origin = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
  assert.ok(origin, line);
  return { env, origin, relay, relayPid: pid, identify, relayPeer };
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

test('automatic browser relay, native v2 code-only enrollment, and stock TUN interoperate',
  { timeout: 105_000 }, async t => {
    const { env, origin, relay, relayPid, identify, relayPeer } = await scopedFixture(t);
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
    ].join('\n'), 'native-enrollment', env.P2P_VPN_RELAY_FIXTURE, identify, configPath,
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
    const lookup = inNamespace(nativePid, env.P2P_VPN_RELAY_FIXTURE, '--lookup-locator', identify, invitation.locator);
    assert.deepEqual(JSON.parse(lookup), [{ peer: invitation.peer, addresses: [invitation.address] }]);
    const providerReplies = () => relay.logs().split('\n').filter(line => line === 'locator-dht reply providers=1').length;
    await until(() => providerReplies() === 1, 'Independent lookup did not get exactly one provider reply');
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
    assert.ok(providerReplies() > 1, `DHT did not answer the native bootstrap. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`);
    assert.ok(candidate, `Native v2 did not reach approval. Native:\n${native.logs()}\nRelay:\n${relay.logs()}`);
    assert.equal(candidate.peer_id, nativePeer);
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
