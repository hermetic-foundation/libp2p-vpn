import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readlink, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const RESERVE = '/api/relay/inviter/reservation';
const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5_000 });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function child(t, command, args) {
  const proc = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(proc, 'close');
  exited.catch(() => {});
  const reader = createInterface({ input: proc.stdout });
  const lines = reader[Symbol.asyncIterator]();
  let logs = '';
  proc.stderr.setEncoding('utf8').on('data', chunk => { logs = (logs + chunk).slice(-8192); });
  t.after(async () => {
    reader.close();
    proc.kill();
    await exited.catch(() => {});
  });
  return {
    proc,
    logs: () => logs,
    async next() {
      const { value, done } = await lines.next();
      if (done) throw Error(`${command} exited (${(await exited)[0]}): ${logs}`);
      return value;
    },
  };
}

async function until(predicate, message) {
  const deadline = performance.now() + 5_000;
  while (!(await predicate())) {
    if (performance.now() >= deadline) throw Error(message());
    await delay(25);
  }
}

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

test('Chromium gets an authenticated relay from a cooperating DHT with only a bootstrap configured', {
  timeout: 50_000,
}, async t => {
  const env = process.env;
  assert.ok(env.P2P_VPN_BIN && env.P2P_VPN_RELAY_FIXTURE && env.P2P_VPN_PAIRING_PKG);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up');

  const assets = await mkdtemp(join(tmpdir(), 'p2p-vpn-auto-relay-'));
  t.after(() => rm(assets, { recursive: true, force: true }));
  await mkdir(join(assets, 'pkg'));
  for (const file of ['app.html', 'app.js', 'app.css', 'code-inviter.html', 'code-inviter.js']) {
    await copyFile(new URL(`../web/${file}`, import.meta.url), join(assets, file));
  }
  for (const file of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm', 'logo.svg']) {
    await copyFile(join(env.P2P_VPN_PAIRING_PKG, file), join(assets, 'pkg', file));
  }

  const first = child(t, 'unshare', ['--net', 'sh', '-ec', [
    'printf "%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'sysctl -qw net.ipv4.conf.all.arp_ignore=1',
    'ip link set seed addrgenmode none',
    'ip link set alternate addrgenmode none',
    'ip addr add 11.250.0.2/24 dev seed',
    'ip addr add 11.251.0.2/24 dev alternate',
    'ip link set seed up',
    'ip link set alternate up',
    'exec "$@"',
  ].join('\n'), 'auto-relay-namespace', env.P2P_VPN_RELAY_FIXTURE, '--auto-relay-dht',
  '11.250.0.2', '11.250.0.2']);
  const pid = await first.next();
  assert.match(pid, /^\d+$/);
  for (const [local, remote, address] of [
    ['physical', 'seed', '11.250.0.1/24'], ['secondary', 'alternate', '11.251.0.1/24'],
  ]) {
    ip('link', 'add', local, 'type', 'veth', 'peer', 'name', remote, 'netns', pid);
    ip('link', 'set', local, 'addrgenmode', 'none');
    ip('addr', 'add', address, 'dev', local);
    ip('link', 'set', local, 'up');
  }
  ip('route', 'add', 'default', 'dev', 'physical');
  first.proc.stdin.end('ready\n');
  const good = JSON.parse(await first.next());
  assert.notEqual(good.bootstrap.split('/').at(-1), good.relay_peer);
  const second = child(t, 'nsenter', ['--target', pid, '--net', '--',
    env.P2P_VPN_RELAY_FIXTURE, '--auto-relay-dht', '11.250.0.2', '11.251.0.2']);
  const alternate = JSON.parse(await second.next());
  assert.match(ip('route', 'get', '11.251.0.2'), /dev secondary/);
  const tcp = createConnection({
    host: '11.251.0.2', port: Number(alternate.native.split('/')[4]), timeout: 3_000,
  });
  tcp.on('timeout', () => tcp.destroy(new Error('alternate TCP route is not reachable')));
  await once(tcp, 'connect');
  tcp.destroy();

  const serve = async (bootstrap, pins = []) => {
    const companion = child(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assets,
      '--port', '0', '--bootstrap', bootstrap, ...pins]);
    const line = await companion.next();
    const origin = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
    assert.ok(origin, line);
    return origin;
  };
  const origin = await serve(good.bootstrap);
  const blockedOrigin = await serve(alternate.bootstrap);
  const wrongEntrance = good.webrtc.replace(
    /\/udp\/(\d+)\//, (_, port) => `/udp/${port === '1' ? 2 : 1}/`);
  const pinnedOrigin = await serve(good.bootstrap,
    ['--relay-entrance', wrongEntrance, '--relay-native-alias', good.native]);
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const reserve = fields => page.evaluate(async ({ path, fields }) => {
    const response = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fields), signal: AbortSignal.timeout(17_000),
    });
    return { status: response.status, body: await response.json() };
  }, { path: RESERVE, fields });

  await page.goto(pinnedOrigin + '/app.html');
  assert.deepEqual(await reserve({}), { status: 404, body: { error: 'no_candidates' } });
  assert.doesNotMatch(first.logs(), /fixture FIND_NODE/, 'a failed pin must not use the DHT');
  await page.goto(origin + '/app.html');
  assert.deepEqual(await reserve({ relay_peer: good.relay_peer }),
    { status: 404, body: { error: 'no_candidates' } });
  assert.doesNotMatch(first.logs(), /fixture FIND_NODE/, 'explicit selection must not do automatic discovery');
  const lease = await reserve({});
  assert.equal(lease.status, 200, `${JSON.stringify(lease.body)}\n${first.logs()}`);
  assert.match(first.logs(), /fixture FIND_NODE/);
  assert.equal(lease.body.native_alias, good.native);
  const relayUdp = /relay-hop (\S+) \/ip4\/11\.250\.0\.1\/udp\/(\d+)/g;
  const [[, probePeer, probePort], ...otherProbes] = [...first.logs().matchAll(relayUdp)];
  assert.equal(otherProbes.length, 0, 'one WebRTC proof should precede the browser lease');
  const entrance = lease.body.relay_entrance;
  assert.equal(entrance.replace(/^\/ip4\/127\.0\.0\.1\/udp\/\d+/, ''),
    good.webrtc.replace(/^\/ip4\/11\.250\.0\.2\/udp\/\d+/, ''));
  const browserPeer = await page.evaluate(async entrance => {
    const { default: init, BrowserCodeInviter, BrowserPairing } = await import('/pkg/p2p_vpn_browser.js');
    await init();
    const joiner = new BrowserPairing();
    const inviter = new BrowserCodeInviter('automatic-egress', '10.83.0.1', '10.83.0.2',
      joiner.peer_id(), entrance);
    const peer = inviter.peer_id();
    // A real HOP reservation must be accepted even if this cached actor
    // still expects a direct rather than a gateway listen address.
    void inviter.reserve().catch(() => {}).finally(() => { inviter.free(); joiner.free(); });
    return peer;
  }, entrance);
  await until(() => new RegExp(`ReservationReqAccepted.*${browserPeer}.*renewed: false`).test(first.logs()),
    first.logs);
  const browserHop = [...first.logs().matchAll(relayUdp)].find(([, peer]) => peer === browserPeer);
  assert.ok(browserHop, first.logs());
  assert.notEqual(browserPeer, probePeer);
  assert.notEqual(browserHop[2], probePort, 'the probe outer socket must not be reused');

  // The second seed answers on the default link, but its relay is only on the secondary link.
  await page.goto(blockedOrigin + '/app.html');
  assert.deepEqual(await reserve({}), { status: 404, body: { error: 'no_candidates' } });
  assert.match(second.logs(), /fixture FIND_NODE/);
  assert.doesNotMatch(second.logs(), /relay-hop .*\/ip4\/11\.251\.0\.1\//);

  const port = Number(entrance.split('/')[4]);
  assert.equal(await canBind(port), false, 'published ingress must still bind its port');
  ip('route', 'replace', 'default', 'dev', 'secondary');
  await until(() => canBind(port), () => 'route change did not close the automatic lease');
});
