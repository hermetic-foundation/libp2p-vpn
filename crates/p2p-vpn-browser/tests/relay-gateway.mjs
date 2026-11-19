import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const LOCAL = '11.250.0.1';
const REMOTE = '11.250.0.2';

function fixture(t, command, args) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(child, 'close');
  exited.catch(() => {});
  const reader = createInterface({ input: child.stdout });
  const lines = reader[Symbol.asyncIterator]();
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  t.after(async () => {
    reader.close();
    child.kill();
    await exited.catch(() => {});
  });
  return {
    child,
    logs: () => stderr,
    async next(stage) {
      const { value, done } = await lines.next();
      if (done) throw Error(`${stage}: ${command} exited (${(await exited)[0]}): ${stderr}`);
      return value;
    },
  };
}

function ip(...args) {
  return execFileSync('ip', args, { encoding: 'utf8', timeout: 5_000 });
}

async function udpPortAvailable(port) {
  const socket = createSocket('udp4');
  try {
    socket.bind({ address: '127.0.0.1', port, exclusive: true });
    await once(socket, 'listening');
    return true;
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
    return false;
  } finally {
    socket.close();
  }
}

async function assets(t, pkg) {
  const web = new URL('../web/', import.meta.url);
  const root = await mkdtemp(join(tmpdir(), 'p2p-vpn-gateway-assets-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'pkg'));
  for (const file of ['app.html', 'app.js', 'app.css']) {
    await copyFile(new URL(file, web), join(root, file));
  }
  for (const file of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm']) {
    await copyFile(join(pkg, file), join(root, 'pkg', file));
  }
  const logo = new URL('../../../assets/p2p-vpn-logo.svg', import.meta.url);
  await copyFile(fileURLToPath(logo), join(root, 'pkg', 'logo.svg'));
  return root;
}

test('Chromium falls back through a companion-issued relay lease and closes its UDP gateway', {
  timeout: 60_000,
}, async t => {
  const env = process.env;
  assert.ok(env.P2P_VPN_BIN && env.P2P_VPN_RELAY_FIXTURE
    && env.P2P_VPN_RECEIVER_FIXTURE && env.P2P_VPN_RECEIVER_PKG);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/,
    'capture the parent network namespace before unshare');
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo'],
    'use a fresh namespace with no external interfaces');

  const assetRoot = await assets(t, env.P2P_VPN_RECEIVER_PKG);
  ip('link', 'set', 'lo', 'up');
  const relay = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
    'printf "%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'ip link set relay-peer addrgenmode none',
    `ip addr add ${REMOTE}/24 dev relay-peer`,
    'ip link set relay-peer up',
    'exec "$@"',
  ].join('\n'), 'relay-namespace', env.P2P_VPN_RELAY_FIXTURE, REMOTE]);
  const pid = await relay.next('relay namespace');
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'gateway-peer', 'type', 'veth', 'peer', 'name', 'relay-peer', 'netns', pid);
  ip('link', 'set', 'gateway-peer', 'addrgenmode', 'none');
  ip('addr', 'add', `${LOCAL}/24`, 'dev', 'gateway-peer');
  ip('link', 'set', 'gateway-peer', 'up');
  ip('route', 'add', 'default', 'dev', 'gateway-peer');
  relay.child.stdin.end('ready\n');
  const entrance = await relay.next('actual WebRTC relay entrance');
  assert.ok(entrance.startsWith(`/ip4/${REMOTE}/udp/`));
  const native = fixture(t, 'nsenter', ['--target', pid, '--net', '--',
    env.P2P_VPN_RECEIVER_FIXTURE, 'relay-gateway', entrance]);
  const session = JSON.parse(await native.next('member reservation and signed DHT seed'));
  const { bootstrap, unavailable_direct: deadDirect } = session.gateway_record;
  const host = fixture(t, env.P2P_VPN_BIN, ['browser-serve', '--assets', assetRoot, '--port', '0',
    '--kademlia-protocol', session.config.network.discovery.kademlia_protocol,
    '--bootstrap', bootstrap, '--public-relay-entrance', entrance]);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/
    .exec(await host.next('companion listener'))?.[1];
  assert.ok(url);

  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(url);

  try {
    const reply = await page.evaluate(async ({ config, peer }) => {
      const { default: init, BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
      await init();
      window.BrowserVpn = BrowserVpn;
      window.configJson = JSON.stringify(config);
      window.postCompanion = async (path, body) => {
        const response = await fetch(path, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
        });
        const value = await response.json();
        if (!response.ok) throw Error(`${path} returned ${response.status}: ${JSON.stringify(value)}`);
        return value;
      };
      return window.postCompanion('/api/discovery', BrowserVpn.discovery_query(window.configJson, peer));
    }, { config: session.config, peer: session.native_peer_id });
    assert.equal(reply.source, 'public_dht');
    assert.deepEqual(reply.addresses, [deadDirect]);
    assert.notEqual(deadDirect, session.dial_address);
    assert.match(reply.relay_lease_id ?? '', /^[A-Za-z0-9_-]{32}$/);
    const loopback = /^\/ip4\/127\.0\.0\.1\/udp\/(\d+)(\/.*)$/.exec(reply.relay_address);
    assert.ok(loopback, reply.relay_address);
    const [, port, suffix] = loopback;
    assert.equal(suffix, session.relay_address.replace(/^\/ip4\/[^/]+\/udp\/\d+/, ''));
    assert.equal(await udpPortAvailable(Number(port)), false, 'lease owns the loopback UDP socket');

    const [wire, browserProof] = await Promise.all([
      native.next('authenticated control and packet responses').then(JSON.parse),
      page.evaluate(async ({ direct, relay, lease }) => {
        const vpn = window.BrowserVpn.with_relay(window.configJson, direct, relay);
        try {
          return JSON.parse(await vpn.test_drive_receiver());
        } finally {
          try {
            await vpn.close();
          } finally {
            vpn.free();
            window.released = await window.postCompanion('/api/relay/release', JSON.stringify({ lease_id: lease }));
          }
        }
      }, { direct: reply.addresses[0], relay: reply.relay_address, lease: reply.relay_lease_id }),
    ]);
    assert.equal(wire.gateway_direct_attempted, true, 'the dead direct WebRTC endpoint saw a datagram');
    assert.equal(wire.status.Status.selected_path, 'circuit_relay');
    assert.equal(wire.status.Status.selected_path_mtu, 1200);
    assert.equal(wire.packets.valid_ip, 'Accepted');
    assert.equal(wire.packets.bad_source, 'Rejected(UnauthorizedSource)');
    assert.equal(browserProof.transport, 'circuit-relay');
    assert.equal(browserProof.local_peer_id, session.config.network.local_peer);
    assert.equal(browserProof.remote_peer_id, session.native_peer_id);
    assert.equal(browserProof.authorized, true);
    assert.equal(browserProof.counters.connections, 1);
    assert.equal(browserProof.counters.inbound_ip_packets, 2);
    assert.match(relay.logs(), new RegExp(
      `CircuitReqAccepted.*${session.config.network.local_peer}.*${session.native_peer_id}`));
    assert.deepEqual(await page.evaluate(() => window.released), { released: true });

    const releaseDeadline = performance.now() + 2_000;
    while (!(await udpPortAvailable(Number(port)))) {
      assert.ok(performance.now() < releaseDeadline, 'released lease did not close its UDP socket');
      await delay(10);
    }
    assert.deepEqual(await page.evaluate(lease =>
      window.postCompanion('/api/relay/release', JSON.stringify({ lease_id: lease })), reply.relay_lease_id),
    { released: false });
  } catch (error) {
    throw Error(`${error.message}\nCompanion: ${host.logs()}\nNative member: ${native.logs()}\nRelay: ${relay.logs()}`,
      { cause: error });
  }
});
