import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const RELAY_IP = '11.250.0.2';
const LISTENER_IP = '10.204.0.1';
const DIALER_IP = '10.204.0.2';
const LISTENER_PORT = 18081;
const DIALER_PORT = 18082;

function exec(command, ...args) {
  return execFileSync(command, args, { encoding: 'utf8', timeout: 5_000 });
}

async function peerConfigs(t, binary) {
  const root = await mkdtemp(join(tmpdir(), 'p2p-vpn-browser-circuit-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const network = `browser-circuit-${randomUUID()}`;
  const listener = join(root, 'listener.json');
  const dialer = join(root, 'dialer.json');
  for (const [file, address, mtu] of [
    [listener, LISTENER_IP, '1200'], [dialer, DIALER_IP, '1280'],
  ]) {
    exec(binary, 'init-config', '--output', file, '--network', network,
      '--vpn-ip', address, '--mtu', mtu, '--disable-mdns', '--disable-kademlia');
  }
  const dialerPublic = join(root, 'dialer-public.json');
  exec(binary, 'identity-public', '--config', dialer, '--output', dialerPublic);
  const issue = (address, ...subject) => JSON.parse(exec(binary, 'membership-record-issue',
    '--issuer-config', listener, '--role', 'overlay-member', '--role', 'route-authority',
    '--route-grant', `${address}/32`, '--output', '-', ...subject));
  const records = [
    issue(LISTENER_IP, '--issuer-as-member'),
    issue(DIALER_IP, '--member-identity', dialerPublic),
  ];
  return Promise.all([listener, dialer].map(async (file, index) => {
    const config = JSON.parse(await readFile(file, 'utf8'));
    config.network.local_peer = records[index].payload.member_peer;
    config.network.member_records = records;
    config.network.listen_addresses = [];
    return config;
  }));
}

async function serve(t, pkg) {
  const files = new Map([
    ['/', ['text/html', '<!doctype html><title>Browser circuit test</title>']],
    ['/p2p_vpn_browser.js', ['text/javascript', await readFile(join(pkg, 'p2p_vpn_browser.js'))]],
    ['/p2p_vpn_browser_bg.wasm', ['application/wasm', await readFile(join(pkg, 'p2p_vpn_browser_bg.wasm'))]],
  ]);
  const server = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0], 'Cache-Control': 'no-store' }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}/`;
}

async function relayFixture(t, binary) {
  const child = spawn(binary, [RELAY_IP], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = once(child, 'close');
  exited.catch(() => {});
  const output = createInterface({ input: child.stdout });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  t.after(async () => {
    output.close();
    child.kill();
    await exited.catch(() => {});
  });
  const { value: entrance } = await output[Symbol.asyncIterator]().next();
  assert.match(entrance ?? '', /^\/ip4\/11\.250\.0\.2\/udp\/\d+\/webrtc-direct\/certhash\/[^/]+\/p2p\/[^/]+$/);
  return { entrance, logs: () => stderr };
}

async function openPeer(t, origin, config, target) {
  const browser = await chromium.launch(process.env.P2P_VPN_CHROMIUM
    ? { executablePath: process.env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(origin);
  await page.evaluate(async ({ config, target }) => {
    const { default: init, BrowserVpn } = await import('/p2p_vpn_browser.js');
    await init();
    window.vpn = BrowserVpn.with_relay(JSON.stringify(config), '', target);
  }, { config, target });
  return page;
}

function probeOverlay(page, address, port) {
  return page.evaluate(async ({ address, port }) => {
    let error;
    try {
      await window.vpn.fetch_http(address, port, '/');
    } catch (failure) {
      error = failure.message;
    }
    return { error, snapshot: JSON.parse(window.vpn.snapshot()) };
  }, { address, port });
}

test('two BrowserVpn peers authenticate and carry inner IP packets over Circuit Relay v2', {
  timeout: 70_000,
}, async t => {
  const { P2P_VPN_BIN, P2P_VPN_RELAY_FIXTURE, P2P_VPN_PAIRING_PKG, P2P_VPN_TEST_NETNS } = process.env;
  assert.ok(P2P_VPN_BIN && P2P_VPN_RELAY_FIXTURE && P2P_VPN_PAIRING_PKG);
  assert.match(P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), P2P_VPN_TEST_NETNS);
  assert.deepEqual(JSON.parse(exec('ip', '-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  exec('ip', 'link', 'set', 'lo', 'up');
  exec('ip', 'link', 'add', 'p2p-browser', 'type', 'dummy');
  exec('ip', 'addr', 'add', `${RELAY_IP}/24`, 'dev', 'p2p-browser');
  exec('ip', 'link', 'set', 'p2p-browser', 'up');

  const [listenConfig, dialConfig] = await peerConfigs(t, P2P_VPN_BIN);
  const listenerId = listenConfig.network.local_peer;
  const dialerId = dialConfig.network.local_peer;
  assert.notEqual(listenerId, dialerId);
  const origin = await serve(t, P2P_VPN_PAIRING_PKG);
  const relay = await relayFixture(t, P2P_VPN_RELAY_FIXTURE);
  const circuit = peer => `${relay.entrance}/p2p-circuit/p2p/${peer}`;
  const listener = await openPeer(t, origin, listenConfig, circuit(dialerId));
  const dialer = await openPeer(t, origin, dialConfig, circuit(listenerId));

  try {
    assert.equal(await listener.evaluate(() => window.vpn.reserve_relay()), circuit(listenerId));
    const [accepted, connected] = await Promise.all([
      listener.evaluate(async () => JSON.parse(await window.vpn.accept_relay())),
      dialer.evaluate(async () => JSON.parse(await window.vpn.connect())),
    ]);
    for (const [snapshot, local, remote] of [
      [accepted, listenerId, dialerId], [connected, dialerId, listenerId],
    ]) {
      assert.equal(snapshot.local_peer_id, local);
      assert.equal(snapshot.remote_peer_id, remote);
      assert.equal(snapshot.transport, 'circuit-relay');
      assert.equal(snapshot.authorized, true);
      assert.equal(snapshot.ready, true);
      assert.equal(snapshot.stream_mtu, 1200);
      assert.equal(snapshot.counters.connections, 1);
    }

    const outbound = probeOverlay(dialer, LISTENER_IP, LISTENER_PORT);
    outbound.catch(() => {});
    const { packet, authorized } = await listener.evaluate(async () => {
      const packet = await window.vpn.receive_relay_packet(5_000);
      return {
        packet: packet ? Array.from(packet) : null,
        authorized: JSON.parse(window.vpn.snapshot()).authorized,
      };
    });
    assert.equal(authorized, true);
    assert.ok(packet?.length >= 40, 'listener did not receive an IPv4 TCP packet');
    assert.equal(packet[0] >> 4, 4);
    assert.equal(packet[9], 6);
    assert.deepEqual(packet.slice(12, 20), [10, 204, 0, 2, 10, 204, 0, 1]);
    const tcp = (packet[0] & 0xf) * 4;
    assert.equal((packet[tcp + 2] << 8) | packet[tcp + 3], LISTENER_PORT);
    assert.equal(packet[tcp + 13] & 0x12, 0x02, 'the first packet is a TCP SYN, not a response');

    // Neither browser exposes an HTTP service. The existing overlay client's
    // connection attempt supplies actual IP packets and PacketResponse ACKs.
    const result = await Promise.all([outbound, probeOverlay(listener, DIALER_IP, DIALER_PORT)]);
    for (const { error, snapshot } of result) {
      assert.ok(error, 'the test does not expose an HTTP responder');
      assert.ok(snapshot.counters.outbound_ip_packets > 0, JSON.stringify(snapshot.counters));
      assert.ok(snapshot.counters.accepted_outbound_packets > 0, JSON.stringify(snapshot.counters));
      assert.ok(snapshot.counters.inbound_ip_packets > 0, JSON.stringify(snapshot.counters));
    }
    const logs = relay.logs();
    assert.match(logs, new RegExp(`ReservationReqAccepted.*${listenerId}`));
    assert.equal(logs.match(new RegExp(`CircuitReqAccepted.*${dialerId}.*${listenerId}`, 'g'))?.length, 1);
    assert.doesNotMatch(logs, new RegExp(`CircuitReqAccepted.*${listenerId}.*${dialerId}`));
    t.diagnostic(`accepted IP packets: dialer=${result[0].snapshot.counters.accepted_outbound_packets}, listener=${result[1].snapshot.counters.accepted_outbound_packets}`);
  } catch (error) {
    throw Error(`${error.message}\nRelay: ${relay.logs()}`, { cause: error });
  }
});
