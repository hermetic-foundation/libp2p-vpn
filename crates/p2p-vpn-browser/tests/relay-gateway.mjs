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
const RELAY_V6 = 'fd42:250::1';
const MEMBER_V6 = 'fd42:250::2';
const ALT_LOCAL = '11.251.0.1';
const ALT_REMOTE = '11.251.0.2';
const PRIMARY_GATEWAY = '11.249.0.2';
const PRIMARY_LOCAL = '11.249.0.1';
const DIRECT_MEMBER = '192.0.2.1';
const SEED_NAME = 'seed.egress.test';
// Hickory's scoped Linux resolver uses its built-in Google configuration.
// These addresses exist only in the disconnected fixture namespace.
const DNS_SERVERS = ['8.8.8.8', '8.8.4.4'];
const LINKS = ['gateway-peer', 'gateway-alt'];

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

function tc(...args) {
  return execFileSync('tc', args, { encoding: 'utf8', timeout: 5_000 });
}

function namespaceTc(pid, ...args) {
  execFileSync('nsenter', ['--target', pid, '--net', '--', 'tc', ...args], { timeout: 5_000 });
}

function countEgress(name, flows) {
  tc('qdisc', 'add', 'dev', name, 'clsact');
  for (const [index, { destinations = [REMOTE], protocol, port }] of flows.entries()) {
    for (const destination of destinations) {
      tc('filter', 'add', 'dev', name, 'egress', 'protocol', 'ip', 'pref', String(index + 1),
        'flower', 'dst_ip', `${destination}/32`, 'ip_proto', protocol,
        ...(port ? ['dst_port', String(port)] : []), 'action', 'pass');
    }
  }
}

function egressPackets(name, keys) {
  const filters = JSON.parse(tc('-j', '-s', 'filter', 'show', 'dev', name, 'egress'));
  return Object.fromEntries(keys.map((key, i) => {
    const matching = filters.filter(filter => filter.pref === i + 1 && filter.options?.actions);
    assert.ok(matching.length, `missing ${key} egress counter on ${name}`);
    return [key, matching.reduce((sum, filter) => sum + filter.options.actions[0].stats.packets, 0)];
  }));
}

function namespaceAddresses(pid, family) {
  const args = ['-j', family, 'addr', 'show', 'scope', 'global'];
  const json = pid
    ? execFileSync('nsenter', ['--target', pid, '--net', '--', 'ip', ...args],
      { encoding: 'utf8', timeout: 5_000 })
    : ip(...args);
  return JSON.parse(json).flatMap(link => link.addr_info.map(address => address.local));
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

async function startDns(t, pid, tcpFallback) {
  const dns = fixture(t, 'nsenter', ['--target', pid, '--net', '--', process.execPath, '-e', `
    const { createSocket } = require('node:dgram');
    const { createServer } = require('node:net');
    const name = Buffer.from(${JSON.stringify(SEED_NAME.split('.').flatMap(label =>
      [label.length, ...Buffer.from(label)]).concat(0))});
    const end = 12 + name.length;
    function response(query, truncated) {
      if (query.length < end + 4 || !query.subarray(12, end).equals(name)) return;
      const a = !truncated && query.readUInt16BE(end) === 1;
      const header = Buffer.from([query[0], query[1], truncated ? 0x83 : 0x81,
        0x80, 0, 1, 0, Number(a), 0, 0, 0, 0]);
      const answer = Buffer.from([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ${REMOTE.split('.').join(', ')}]);
      return Buffer.concat([header, query.subarray(12, end + 4), ...(a ? [answer] : [])]);
    }
    for (const server of ${JSON.stringify(DNS_SERVERS)}) {
      const socket = createSocket('udp4');
      socket.on('message', (query, sender) => {
        const reply = response(query, ${tcpFallback});
        if (reply) socket.send(reply, sender.port, sender.address);
      });
      const tcp = createServer(stream => {
        let pending = Buffer.alloc(0);
        stream.on('error', () => stream.destroy());
        stream.on('data', chunk => {
          pending = Buffer.concat([pending, chunk]);
          while (pending.length >= 2) {
            const end = 2 + pending.readUInt16BE(0);
            if (pending.length < end) break;
            const reply = response(pending.subarray(2, end), false);
            pending = pending.subarray(end);
            if (!reply) continue;
            const length = Buffer.alloc(2);
            length.writeUInt16BE(reply.length);
            stream.write(Buffer.concat([length, reply]));
          }
        });
      });
      socket.bind(53, server, () => tcp.listen(53, server, () => console.log(server)));
    }
  `]);
  const ready = [];
  for (const server of DNS_SERVERS) ready.push(await dns.next(`isolated DNS resolver (${server})`));
  assert.deepEqual(ready.sort(), [...DNS_SERVERS].sort());
}

function snapshot(keys) {
  return LINKS.map(name => egressPackets(name, keys));
}

function differences(before, keys) {
  return snapshot(keys).map((link, index) => Object.fromEntries(
    keys.map(key => [key, link[key] - before[index][key]])));
}

async function eventually(predicate, message) {
  const deadline = performance.now() + 3_000;
  while (!(await predicate())) {
    assert.ok(performance.now() < deadline, message);
    await delay(20);
  }
}

async function exerciseSwitch(t, url, session, relayPid, bootstrap, entrance, keys, dnsMode) {
  const secondaryDns = dnsMode === 'secondary';
  const origin = new URL(url).origin;
  const post = async (path, data, expectedStatuses = [200]) => {
    const response = await fetch(origin + path, {
      method: 'POST',
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(26_000),
    });
    const body = await response.json();
    assert.ok(expectedStatuses.includes(response.status),
      `${path}: ${response.status} ${JSON.stringify(body)}`);
    return body;
  };
  const discover = statuses => post('/api/discovery', {
    network_name: session.signed_gateway_record.network,
    peer: session.native_peer_id,
    lan: false,
  }, statuses);
  const senders = [];
  t.after(() => { for (const sender of senders) sender.close(); });
  const send = ({ sender, port }) => new Promise((resolve, reject) => {
    // Deliberately not WebRTC: this measures the companion UDP pump in
    // isolation. The later Chromium circuit checks authenticated data.
    sender.send('egress probe', port, '127.0.0.1', error => error ? reject(error) : resolve());
  });
  const upstreamPort = entrance.split('/')[4];
  const upstream = () => execFileSync('ss', ['-Huan', 'dst', `${REMOTE}:${upstreamPort}`],
    { encoding: 'utf8', timeout: 5_000 }).trim();

  let old;
  const ids = new Set();
  for (const [phase, active] of [['initial', 0], ['switch', 1], ['return', 0]]) {
    if (phase !== 'initial') {
      ip('route', phase === 'switch' ? 'add' : 'del', 'default',
        'via', ALT_REMOTE, 'dev', LINKS[1], 'metric', '10');
    }
    const [route] = JSON.parse(ip('-j', 'route', 'get', REMOTE));
    assert.equal(route.dev, LINKS[active]);
    for (const [index, link] of LINKS.entries()) {
      const [viaLink] = JSON.parse(ip('-j', 'route', 'get', REMOTE, 'oif', link));
      assert.equal(viaLink.dev, link);
      assert.equal(viaLink.gateway, index === 0 ? PRIMARY_GATEWAY : ALT_REMOTE);
    }
    if (old) {
      await eventually(() => udpPortAvailable(old.port), `${phase}: old gateway still bound`);
      assert.equal(upstream(), '', `${phase}: old companion upstream socket was not retired`);
      if (!dnsMode) {
        const before = snapshot(keys);
        await send(old);
        await delay(150);
        assert.deepEqual(differences(before, keys).map(link => link.relay), [0, 0],
          `${phase}: retired lease forwarded a datagram`);
      }
    }

    if (secondaryDns) {
      for (const server of DNS_SERVERS) {
        const [resolverRoute] = JSON.parse(ip('-j', 'route', 'get', server));
        assert.equal(resolverRoute.dev, LINKS[1]);
        assert.equal(resolverRoute.gateway, ALT_REMOTE);
        // Linux can synthesize an on-link route for a forced output device.
        // There is no resolver or proxy ARP responder on that primary link.
        const [forcedPrimary] = JSON.parse(ip('-j', 'route', 'get', server, 'oif', LINKS[0]));
        assert.equal(forcedPrimary.gateway, undefined);
      }
      if (active === 0) {
        const before = snapshot(keys);
        const failed = await discover([404, 504]);
        assert.ok(['no_candidates', 'discovery_timeout'].includes(failed.error));
        const delta = differences(before, keys);
        assert.ok(delta.every(link => Object.values(link).every(count => count === 0)),
          `${phase}: secondary-only resolver must not generate egress: ${JSON.stringify(delta)}`);
        t.diagnostic(`${phase} (secondary-only DNS, ${failed.error}): ${JSON.stringify(delta)}`);
        continue;
      }
    }

    const before = snapshot(keys);
    const reply = await discover().catch(error => {
      throw Error(`${phase}: ${error.message}; egress: ${JSON.stringify(differences(before, keys))}`,
        { cause: error });
    });
    assert.equal(reply.source, 'public_dht');
    assert.deepEqual(reply.addresses, []);
    assert.match(reply.relay_lease_id ?? '', /^[A-Za-z0-9_-]{32}$/);
    assert.ok(!ids.has(reply.relay_lease_id), `${phase}: reused an old lease ID`);
    ids.add(reply.relay_lease_id);
    const gateway = /^\/ip4\/127\.0\.0\.1\/udp\/(\d+)\//.exec(reply.relay_address);
    assert.ok(gateway, reply.relay_address);
    const port = Number(gateway[1]);
    assert.equal(await udpPortAvailable(port), false);
    const sender = createSocket('udp4');
    senders.push(sender);
    old = { sender, port };
    const socket = upstream();
    const expectedSource = active === 0 ? PRIMARY_LOCAL : ALT_LOCAL;
    assert.equal(socket.split('\n').length, 1, `${phase}: expected one companion upstream socket`);
    const [local, remote] = socket.split(/\s+/).slice(-2);
    assert.equal(remote, `${REMOTE}:${upstreamPort}`, `${phase}: unexpected relay destination`);
    assert.ok(local.startsWith(`${expectedSource}%${LINKS[active]}:`),
      `${phase}: upstream socket is not bound to the default interface: ${socket}`);
    for (let packet = 1; !dnsMode && packet <= 2; packet++) {
      await send(old);
      await eventually(() => differences(before, keys)[active].relay >= packet,
        `${phase}: default link did not forward datagram ${packet} through the same lease`);
      // Compare the endpoints, not the socket's asynchronous queue sizes.
      assert.deepEqual(upstream().split(/\s+/).slice(-2), socket.split(/\s+/).slice(-2),
        `${phase}: the lease replaced its connected upstream socket`);
    }
    const delta = differences(before, keys);
    for (const key of dnsMode ? ['dns', 'dnsTcp', 'bootstrap', 'identify']
      : ['dns', 'bootstrap', 'identify', 'relay']) {
      assert.ok(delta[active][key] > 0, `${phase}: no ${key} egress on the default link`);
    }
    assert.ok(Object.values(delta[1 - active]).every(count => count === 0),
      `${phase}: unexpected non-default egress: ${JSON.stringify(delta)}`);
    t.diagnostic(`${phase} (${LINKS[active]} default): ${JSON.stringify(delta)}`);
    if (phase === 'initial' && !dnsMode) {
      const block = ['dev', 'relay-peer', 'ingress', 'protocol', 'ip', 'pref', '1'];
      // Only the primary path fails. The same seed is reached without any
      // fixture change on the secondary once it becomes the default.
      namespaceTc(relayPid, 'filter', 'add', ...block,
        'flower', 'dst_ip', `${REMOTE}/32`, 'ip_proto', 'tcp',
        'dst_port', bootstrap.split('/')[4], 'action', 'drop');
      try {
        const blockedBefore = snapshot(keys);
        const failed = await discover([404, 504]);
        assert.ok(['no_candidates', 'discovery_timeout'].includes(failed.error));
        const [primary, secondary] = differences(blockedBefore, keys);
        assert.ok(primary.dns > 0 && primary.bootstrap > 0);
        assert.equal(primary.identify + primary.relay, 0);
        assert.ok(Object.values(secondary).every(count => count === 0),
          `failed default bootstrap retried the secondary: ${JSON.stringify(secondary)}`);
        assert.equal(await udpPortAvailable(port), false,
          'the original lease must still be live before the route changes');
        t.diagnostic(`blocked default bootstrap (${failed.error}): ${JSON.stringify([primary, secondary])}`);
      } finally {
        namespaceTc(relayPid, 'filter', 'del', ...block);
      }
    }
    if (phase === 'return' && !secondaryDns) {
      await post('/api/relay/release', { lease_id: reply.relay_lease_id });
      await eventually(() => udpPortAvailable(port), 'final probe lease remained bound');
    }
  }
}

async function exerciseSecondaryDirect(t, page, native, session, keys) {
  const before = snapshot(keys);
  const [wire, proof] = await Promise.all([
    native.next('secondary direct packet responses').then(JSON.parse),
    page.evaluate(async ({ config, dial_address }) => {
      const vpn = new window.BrowserVpn(JSON.stringify(config), dial_address);
      try {
        return JSON.parse(await vpn.test_drive_receiver());
      } finally {
        try { await vpn.close(); } finally { vpn.free(); }
      }
    }, session),
  ]);
  assert.equal(wire.packets.valid_ip, 'Accepted');
  assert.equal(proof.transport, 'webrtc-direct');
  assert.equal(proof.remote_peer_id, session.native_peer_id);
  assert.equal(proof.authorized, true);
  const [primary, secondary] = differences(before, keys);
  assert.equal(primary.direct, 0);
  assert.ok(secondary.direct > 0, 'browser-owned direct member socket did not use the secondary');
  assert.ok(keys.filter(key => key !== 'direct').every(key => secondary[key] === 0),
    `automatic companion infrastructure used the secondary: ${JSON.stringify(secondary)}`);
  t.diagnostic(`browser-owned direct member: primary=${primary.direct}, secondary=${secondary.direct}`);
}

test('Chromium falls back through a companion-issued relay lease and closes its UDP gateway', {
  timeout: 60_000,
}, t => exerciseGateway(t, false));

test('IPv4-only Chromium reaches an IPv6-only member through an automatically authenticated relay', {
  timeout: 60_000,
}, t => exerciseGateway(t, true));

test('companion DNS, bootstrap, Identify and relay egress follow the OS default on switch and return', {
  timeout: 60_000,
}, t => exerciseGateway(t, true, true));

test('companion DNS uses a secondary-only resolver route only while that link is the OS default', {
  timeout: 60_000,
}, t => exerciseGateway(t, true, true, { dnsMode: 'secondary' }));

test('companion DNS retries truncated UDP responses on TCP through the OS default on switch and return', {
  timeout: 60_000,
}, t => exerciseGateway(t, true, true, { dnsMode: 'tcp' }));

test('companion public discovery isolates its Identify probe from a live secondary connection to the same relay', {
  timeout: 60_000,
}, t => exerciseGateway(t, true, true, { mixedPurpose: true }));

async function exerciseMixedPurpose(t, page, relay, entrances, member, direct, directSession, keys) {
  const [, , , , port, , relayPeer] = entrances.identify.split('/');
  const sockets = () => execFileSync('ss', ['-Htn', 'state', 'established',
    'dst', `${REMOTE}:${port}`], { encoding: 'utf8', timeout: 5_000 }).trim()
    .split('\n').filter(Boolean).map(line => line.split(/\s+/).slice(-2));
  const established = sockets();
  assert.equal(established.length, 1);
  const [endpoints] = established;
  assert.ok(endpoints[0].startsWith(`${ALT_LOCAL}:`), endpoints.join(' -> '));
  assert.equal(endpoints[1], `${REMOTE}:${port}`);
  const reservation = `relay-hop ${member.native_peer_id} /ip4/${ALT_LOCAL}/tcp/${endpoints[0].split(':')[1]}`;
  assert.ok(relay.logs().includes(reservation), relay.logs());
  assert.match(relay.logs(), new RegExp(`ReservationReqAccepted.*${member.native_peer_id}`));

  await page.evaluate(async ({ config, dial_address }) => {
    const { default: init, BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
    await init();
    window.BrowserVpn = BrowserVpn;
    window.member = new BrowserVpn(JSON.stringify(config), dial_address);
  }, directSession);
  const probeLines = () => relay.logs().split('\n').filter(line =>
    line.includes(` /ip4/${PRIMARY_LOCAL}/tcp/`));
  assert.deepEqual(probeLines(), []);
  const before = snapshot(keys);
  const [reply, proof, wire] = await Promise.all([
    page.evaluate(async ({ config, native_peer_id }) => {
      const response = await fetch('/api/discovery', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: window.BrowserVpn.discovery_query(JSON.stringify(config), native_peer_id),
      });
      const result = await response.json();
      if (!response.ok) throw Error(`${response.status}: ${JSON.stringify(result)}`);
      return result;
    }, member),
    page.evaluate(async () => {
      const proof = JSON.parse(await window.member.connect());
      // Drive the ordinary inbound member keepalive while the lookup runs.
      const deadline = performance.now() + 2_000;
      while (performance.now() < deadline) await window.member.poll_foreground();
      return proof;
    }),
    direct.next('authorized direct member keepalive').then(JSON.parse),
  ]);
  assert.equal(reply.source, 'public_dht');
  assert.ok(reply.relay_address.endsWith(`/p2p/${relayPeer}/p2p-circuit/p2p/${member.native_peer_id}`));
  assert.match(reply.relay_lease_id, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(wire.keepalive, 'Accepted');
  assert.equal(proof.remote_peer_id, directSession.native_peer_id);
  assert.equal(proof.transport, 'webrtc-direct');
  assert.equal(proof.authorized, true);
  assert.deepEqual(sockets(), established,
    'the unscoped same-peer connection must survive the public operation');
  const [probe] = probeLines();
  assert.equal(probeLines().length, 1, relay.logs());
  assert.notEqual(probe.split(' ')[1], member.native_peer_id,
    'the scoped Identify probe must have its own swarm identity');
  const [primary, secondary] = differences(before, keys);
  for (const key of ['dns', 'bootstrap', 'identify']) assert.ok(primary[key] > 0, key);
  assert.equal(primary.direct, 0);
  assert.ok(secondary.direct > 0, 'the direct member did not use the secondary');
  assert.ok(keys.filter(key => key !== 'direct').every(key => secondary[key] === 0),
    `automatic companion traffic used the secondary: ${JSON.stringify(secondary)}`);
  t.diagnostic(`same relay ${relayPeer}: live reservation ${endpoints.join(' -> ')}; scoped ${probe}`);
  t.diagnostic(`mixed-purpose public_dht and accepted direct keepalive: ${JSON.stringify([primary, secondary])}`);
  await page.evaluate(async lease => {
    await window.member.close();
    window.member.free();
    const response = await fetch('/api/relay/release', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lease_id: lease }),
    });
    if (!response.ok || !(await response.json()).released) throw Error('lease not released');
  }, reply.relay_lease_id);
}

async function exerciseGateway(t, crossFamily, switchLinks = false, {
  dnsMode = null, mixedPurpose = false,
} = {}) {
  const secondaryDns = dnsMode === 'secondary';
  const env = process.env;
  assert.ok(env.P2P_VPN_BIN && env.P2P_VPN_RELAY_FIXTURE
    && env.P2P_VPN_RECEIVER_FIXTURE && env.P2P_VPN_RECEIVER_PKG);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/,
    'capture the parent network namespace before unshare');
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo'],
    'use a fresh namespace with no external interfaces');
  const secondaryResolvers = [];
  t.after(() => {
    if (mixedPurpose && namespaceAddresses(null, '-6').includes(MEMBER_V6)) {
      ip('-6', 'addr', 'del', `${MEMBER_V6}/128`, 'dev', 'lo');
    }
    for (const server of secondaryResolvers) {
      ip('rule', 'del', 'to', `${server}/32`, 'oif', LINKS[0], 'unreachable');
    }
    for (const { ifname } of JSON.parse(ip('-j', 'link', 'show'))) {
      if (LINKS.includes(ifname)) ip('link', 'del', ifname);
    }
  });

  const assetRoot = await assets(t, env.P2P_VPN_RECEIVER_PKG);
  ip('link', 'set', 'lo', 'up');
  const relay = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
    'printf "%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'ip link set relay-peer addrgenmode none',
    `ip addr add ${switchLinks ? PRIMARY_GATEWAY : REMOTE}/24 dev relay-peer`,
    'ip link set relay-peer up',
    ...(secondaryDns ? ['sysctl -qw net.ipv4.conf.relay-peer.arp_ignore=1'] : []),
    ...(switchLinks ? [
      `ip addr add ${REMOTE}/32 dev lo`,
      `ip addr add ${DIRECT_MEMBER}/32 dev lo`,
      ...DNS_SERVERS.map(server => `ip addr add ${server}/32 dev lo`),
    ] : []),
    ...(crossFamily ? [
      'ip link set alt-peer addrgenmode none',
      `ip addr add ${ALT_REMOTE}/24 dev alt-peer`,
      'ip link set alt-peer up',
      `ip -6 addr add ${RELAY_V6}/64 dev member-relay nodad`,
      'ip link set member-relay up',
    ] : []),
    'exec "$@"',
  ].join('\n'), 'relay-namespace', env.P2P_VPN_RELAY_FIXTURE, REMOTE,
  ...(crossFamily ? [RELAY_V6] : [])]);
  const pid = await relay.next('relay namespace');
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'gateway-peer', 'type', 'veth', 'peer', 'name', 'relay-peer', 'netns', pid);
  ip('link', 'set', 'gateway-peer', 'addrgenmode', 'none');
  ip('addr', 'add', `${switchLinks ? PRIMARY_LOCAL : LOCAL}/24`, 'dev', 'gateway-peer');
  ip('link', 'set', 'gateway-peer', 'up');
  ip('route', 'add', 'default', ...(switchLinks ? ['via', PRIMARY_GATEWAY] : []),
    'dev', 'gateway-peer', ...(switchLinks ? ['metric', '50'] : []));
  let memberPid = pid;
  let memberNamespace;
  if (crossFamily) {
    ip('link', 'add', 'gateway-alt', 'type', 'veth', 'peer', 'name', 'alt-peer', 'netns', pid);
    ip('link', 'set', 'gateway-alt', 'addrgenmode', 'none');
    ip('addr', 'add', `${ALT_LOCAL}/24`, 'dev', 'gateway-alt');
    ip('link', 'set', 'gateway-alt', 'up');
    ip('route', 'add', 'default', 'via', ALT_REMOTE, 'dev', 'gateway-alt', 'metric', '100');

    memberNamespace = fixture(t, 'unshare', ['--net', 'sh', '-ec', [
      'printf "%s\\n" "$$"',
      'read ready',
      'ip link set lo up',
      `ip -6 addr add ${MEMBER_V6}/64 dev member-peer nodad`,
      'ip link set member-peer up',
      'printf "ready\\n"',
      'exec "$@"',
    ].join('\n'), 'member-namespace', 'sleep', '90']);
    memberPid = await memberNamespace.next('IPv6-only member namespace');
    assert.match(memberPid, /^\d+$/);
    execFileSync('nsenter', ['--target', pid, '--net', '--', 'ip', 'link', 'add',
      'member-relay', 'type', 'veth', 'peer', 'name', 'member-peer', 'netns', memberPid]);
    memberNamespace.child.stdin.end('ready\n');
    assert.equal(await memberNamespace.next('IPv6 member link configured'), 'ready');
  }
  relay.child.stdin.end('ready\n');
  const listeners = await relay.next('relay listeners');
  const entrances = crossFamily ? JSON.parse(listeners) : { webrtc: listeners };
  const entrance = entrances.webrtc;
  assert.ok(entrance.startsWith(`/ip4/${REMOTE}/udp/`));
  if (crossFamily) {
    assert.deepEqual(namespaceAddresses(null, '-6'), [], 'browser namespace has no IPv6 underlay');
    assert.deepEqual(namespaceAddresses(memberPid, '-4'), [], 'member has no IPv4 underlay');
    assert.ok(namespaceAddresses(memberPid, '-6').includes(MEMBER_V6));
    assert.ok(entrances.identify.startsWith(`/ip4/${REMOTE}/tcp/`));
    assert.ok(entrances.reservation.startsWith(`/ip6/${RELAY_V6}/tcp/`));
    const [defaultRoute] = JSON.parse(ip('-j', 'route', 'get', '198.51.100.1'));
    const [alternate] = JSON.parse(ip('-j', 'route', 'get', REMOTE, 'oif', 'gateway-alt'));
    assert.equal(defaultRoute.dev, 'gateway-peer');
    assert.equal(alternate.dev, 'gateway-alt');
    assert.equal(alternate.gateway, ALT_REMOTE);
  }
  if (mixedPurpose) {
    // The reservation listener is never dialed in this case. Its unscoped
    // TCP relay connection originates in the companion's own namespace.
    ip('-6', 'addr', 'add', `${MEMBER_V6}/128`, 'dev', 'lo', 'nodad');
    ip('route', 'add', `${REMOTE}/32`, 'via', ALT_REMOTE, 'dev', LINKS[1]);
    assert.equal(JSON.parse(ip('-j', 'route', 'get', REMOTE))[0].dev, LINKS[1]);
    assert.equal(JSON.parse(ip('-j', 'route', 'get', REMOTE, 'oif', LINKS[0]))[0].dev, LINKS[0]);
  }
  const native = mixedPurpose
    ? fixture(t, env.P2P_VPN_RECEIVER_FIXTURE,
      ['relay-gateway-cross-family', entrances.identify, entrances.identify])
    : fixture(t, 'nsenter', ['--target', memberPid, '--net', '--',
      env.P2P_VPN_RECEIVER_FIXTURE, ...(crossFamily
        ? ['relay-gateway-cross-family', entrances.reservation, entrances.identify]
        : ['relay-gateway', entrance])]);
  const session = JSON.parse(await native.next('member reservation and signed DHT seed'));
  let seed;
  let bootstrap;
  let deadDirect;
  if (crossFamily) {
    const reservation = mixedPurpose ? entrances.identify : entrances.reservation;
    assert.equal(session.relay_address, `${reservation}/p2p-circuit/p2p/${session.native_peer_id}`);
    assert.ok(session.dial_address.startsWith(`/ip6/${MEMBER_V6}/udp/`));
    seed = fixture(t, 'nsenter', ['--target', pid, '--net', '--',
      env.P2P_VPN_RECEIVER_FIXTURE, 'relay-gateway-seed']);
    seed.child.stdin.end(JSON.stringify(session.signed_gateway_record));
    bootstrap = await seed.next('public-facing DHT seed for the signed member record');
    assert.ok(bootstrap.startsWith(`/ip4/${REMOTE}/tcp/`));
  } else {
    ({ bootstrap, unavailable_direct: deadDirect } = session.gateway_record);
  }
  const directMember = switchLinks ? fixture(t, 'nsenter', ['--target', pid, '--net', '--',
    env.P2P_VPN_RECEIVER_FIXTURE, mixedPurpose ? 'member-provider' : 'packets']) : null;
  const directSession = directMember ? JSON.parse(await directMember.next('secondary direct member')) : null;
  const flowKeys = switchLinks ? ['dns', 'dnsTcp', 'bootstrap', 'identify', 'relay', 'direct'] : ['tcp', 'udp'];
  if (crossFamily) {
    const port = address => Number(address.split('/')[4]);
    const flows = switchLinks ? [
      { destinations: DNS_SERVERS, protocol: 'udp', port: 53 },
      { destinations: DNS_SERVERS, protocol: 'tcp', port: 53 },
      { protocol: 'tcp', port: port(bootstrap) },
      { protocol: 'tcp', port: port(entrances.identify) },
      { protocol: 'udp', port: port(entrance) },
      { destinations: [mixedPurpose ? REMOTE : DIRECT_MEMBER],
        protocol: 'udp', port: port(directSession.dial_address) },
    ] : [{ protocol: 'tcp' }, { protocol: 'udp' }];
    for (const name of LINKS) countEgress(name, flows);
  }
  const hostArgs = ['browser-serve', '--assets', assetRoot, '--port', '0',
    '--kademlia-protocol', session.config.network.discovery.kademlia_protocol,
    '--bootstrap', switchLinks ? bootstrap.replace(`/ip4/${REMOTE}/`, `/dns4/${SEED_NAME}/`) : bootstrap,
    ...(crossFamily ? [] : ['--public-relay-entrance', entrance])];
  if (switchLinks) {
    ip('route', 'add', `${DIRECT_MEMBER}/32`, 'via', ALT_REMOTE, 'dev', 'gateway-alt');
    if (secondaryDns) {
      // A device-bound lookup must not fall through to the primary's default.
      for (const server of DNS_SERVERS) {
        ip('route', 'add', `${server}/32`, 'via', ALT_REMOTE, 'dev', LINKS[1]);
        ip('rule', 'add', 'to', `${server}/32`, 'oif', LINKS[0], 'unreachable');
        secondaryResolvers.push(server);
      }
    }
    namespaceTc(pid, 'qdisc', 'add', 'dev', 'relay-peer', 'clsact');
    await startDns(t, pid, Boolean(dnsMode));
  }
  const host = fixture(t, env.P2P_VPN_BIN, hostArgs);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/
    .exec(await host.next('companion listener'))?.[1];
  assert.ok(url);

  if (switchLinks && !mixedPurpose) {
    await exerciseSwitch(t, url, session, pid, bootstrap, entrance, flowKeys, dnsMode);
    if (dnsMode) return;
  }
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(url);

  try {
    if (mixedPurpose) {
      await exerciseMixedPurpose(t, page, relay, entrances, session, directMember, directSession, flowKeys);
      return;
    }
    const beforeCircuit = switchLinks ? snapshot(flowKeys) : null;
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
    assert.deepEqual(reply.addresses, crossFamily ? [] : [deadDirect]);
    if (!crossFamily) assert.notEqual(deadDirect, session.dial_address);
    assert.match(reply.relay_lease_id ?? '', /^[A-Za-z0-9_-]{32}$/);
    const loopback = /^\/ip4\/127\.0\.0\.1\/udp\/(\d+)(\/.*)$/.exec(reply.relay_address);
    assert.ok(loopback, reply.relay_address);
    const [, port, suffix] = loopback;
    const expectedCircuit = `${entrance}/p2p-circuit/p2p/${session.native_peer_id}`;
    assert.equal(suffix, expectedCircuit.replace(/^\/ip4\/[^/]+\/udp\/\d+/, ''));
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
      }, { direct: reply.addresses[0] ?? '', relay: reply.relay_address, lease: reply.relay_lease_id }),
    ]);
    if (!crossFamily) {
      assert.equal(wire.gateway_direct_attempted, true, 'the dead direct WebRTC endpoint saw a datagram');
    }
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
    if (crossFamily) {
      assert.ok(relay.logs().includes(
        `relay-hop ${session.config.network.local_peer} /ip4/${switchLinks ? PRIMARY_LOCAL : LOCAL}/udp/`), relay.logs());
      assert.ok(relay.logs().includes(
        `relay-hop ${session.native_peer_id} /ip6/${MEMBER_V6}/tcp/`), relay.logs());
      if (switchLinks) {
        const [primary, secondary] = differences(beforeCircuit, flowKeys);
        assert.ok(primary.relay > 0, 'companion did not forward authenticated relay traffic');
        for (const key of ['bootstrap', 'identify', 'relay']) assert.equal(secondary[key], 0, key);
        t.diagnostic(`authenticated circuit after return: primary relay=${primary.relay}, secondary relay=0`);
        await exerciseSecondaryDirect(t, page, directMember, directSession, flowKeys);
      } else {
        const [primary, secondary] = LINKS.map(name => egressPackets(name, flowKeys));
        assert.ok(primary.tcp > 0 && primary.udp > 0, 'default link carried DHT, Identify and relay traffic');
        assert.deepEqual(secondary, { tcp: 0, udp: 0 }, 'no DHT, Identify or relay traffic used the non-default link');
        t.diagnostic(`fixture IPv4 egress: default TCP=${primary.tcp} UDP=${primary.udp}; alternate TCP=0 UDP=0`);
      }
    }
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
    throw Error(`${error.message}\nCompanion: ${host.logs()}\nNative member: ${native.logs()}\nRelay: ${relay.logs()}\nSeed: ${seed?.logs() ?? ''}`,
      { cause: error });
  }
}
