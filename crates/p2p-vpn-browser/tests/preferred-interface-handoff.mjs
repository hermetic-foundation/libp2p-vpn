// Use production browser assets and the native webrtc binary from the same build.
// Set P2P_VPN_BIN, P2P_VPN_PAIRING_SEED, P2P_VPN_APP_ASSETS, and optionally P2P_VPN_CHROMIUM.
// Set P2P_VPN_LEGACY_APP_ASSETS to also exercise fallback with a pre-handoff browser build.
// Export P2P_VPN_TEST_NETNS=$(readlink /proc/self/ns/net) before running via:
// unshare --user --map-root-user --mount --net --pid --fork --kill-child=SIGKILL --mount-proc \
//   node --test crates/p2p-vpn-browser/tests/preferred-interface-handoff.mjs
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');
const LOCAL = '11.255.48.1';
const REMOTE = '11.255.48.2';
const INVITER_VPN = '100.64.48.2';
const UNDERLAYS = [
  { name: 'underlay1', source: '11.255.51.2', gateway: '11.255.51.1', table: '101' },
  { name: 'underlay2', source: '11.255.52.2', gateway: '11.255.52.1', table: '102' },
];
const HANDOFF_LIMIT = 30_000;
const OVERLAP = 31_000;

function processFixture(t, command, ...args) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(child, 'close');
  exited.catch(() => {});
  let logs = '';
  const records = [];
  for (const output of [child.stdout, child.stderr]) {
    let partial = '';
    output.setEncoding('utf8').on('data', text => {
      logs = (logs + text).slice(-65536);
      const lines = (partial + text).split('\n');
      partial = lines.pop();
      for (const line of lines) {
        records.push({ at: performance.now(), line,
          fields: Object.fromEntries([...line.matchAll(/\b(\w+)=(\S+)/g)]
            .map(([, key, value]) => [key, value])) });
      }
    });
  }
  t.after(async () => {
    child.kill();
    await exited.catch(() => {});
  });
  return {
    child, records,
    logs: () => logs,
    async expect(pattern, label) {
      const deadline = performance.now() + 20_000;
      do {
        const found = pattern.exec(logs);
        if (found) return found[1];
        if (child.exitCode !== null || child.signalCode !== null) break;
        await delay(50);
      } while (performance.now() < deadline);
      throw Error(`${label}: ${logs}`);
    },
  };
}

test('production Chromium moves payload to the preferred native interface without losing the old underlay', {
  timeout: 150_000,
}, t => exercise(t, false));

test('checkpoint-paired Chromium hands off without a static membership key under native traffic', {
  timeout: 150_000,
}, t => exercise(t, false, true));

test('legacy Chromium retains its working member circuit when preferred handoff is unsupported', {
  timeout: 150_000,
  skip: !process.env.P2P_VPN_LEGACY_APP_ASSETS && 'set P2P_VPN_LEGACY_APP_ASSETS to a pre-handoff browser build',
}, t => exercise(t, true));

async function exercise(t, legacy, checkpoint = false) {
  const env = process.env;
  const binary = env.P2P_VPN_BIN;
  const appAssets = legacy ? env.P2P_VPN_LEGACY_APP_ASSETS : env.P2P_VPN_APP_ASSETS;
  assert.ok(binary && env.P2P_VPN_PAIRING_SEED && appAssets);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  const cli = (...args) => execFileSync(binary, args, { encoding: 'utf8', timeout: 8000 });
  const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5000 });
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  const dir = await mkdtemp(join(tmpdir(), 'p2p-browser-preferred-interface-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const peer = path => /^local peer: (\S+)$/m.exec(cli('status', '-c', path))?.[1];
  async function config(name, address, configure) {
    const path = join(dir, `${name}.json`);
    cli('init-config', '--network', 'preferred-interface-handoff-test', '--interface', name,
      '--vpn-ip', address, '--output', path);
    const value = JSON.parse(await readFile(path, 'utf8'));
    value.network.discovery = {
      mdns: false, kademlia: false, kademlia_provider_advertisement: false,
      dcutr: false, autonat: false,
    };
    value.network.packet_plane = { listen: [], quic_listen: [] };
    configure(value.network);
    await writeFile(path, JSON.stringify(value), { mode: 0o600 });
    return path;
  }
  const remote = processFixture(t, 'unshare', '--net', 'sh', '-ec', [
    'printf "namespace:%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'ip link set relay-peer addrgenmode none',
    `ip addr add ${REMOTE}/24 dev relay-peer`,
    'ip link set relay-peer up',
    'printf "ready\\n"',
    'exec sleep 180',
  ].join('\n'));
  const pid = await remote.expect(/^namespace:(\d+)$/m, 'relay namespace');
  ip('link', 'set', 'lo', 'up');
  ip('link', 'add', 'gateway-peer', 'type', 'veth', 'peer', 'name', 'relay-peer', 'netns', pid);
  ip('link', 'set', 'gateway-peer', 'addrgenmode', 'none');
  ip('addr', 'add', `${LOCAL}/24`, 'dev', 'gateway-peer');
  ip('link', 'set', 'gateway-peer', 'up');
  ip('route', 'add', 'default', 'dev', 'gateway-peer');
  remote.child.stdin.end('ready\n');
  await remote.expect(/^ready$/m, 'relay veth');
  const nativeNs = processFixture(t, 'unshare', '--net', 'sh', '-ec',
    'printf "namespace:%s\\n" "$$"; exec sleep 180');
  const nid = await nativeNs.expect(/^namespace:(\d+)$/m, 'native namespace');
  const inNamespace = (id, command, ...args) => execFileSync('nsenter',
    ['--target', id, '--net', '--', command, ...args], { encoding: 'utf8', timeout: 5000 });
  const net = (id, ...args) => inNamespace(id, 'ip', ...args);
  const inRemote = (...args) => processFixture(t, 'nsenter', '--target', pid, '--net', '--', ...args);
  const inNative = (...args) => processFixture(t, 'nsenter', '--target', nid, '--net', '--', ...args);
  for (const id of [pid, nid]) {
    inNamespace(id, 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0',
      'net.ipv4.conf.default.rp_filter=0');
  }
  net(nid, 'link', 'set', 'lo', 'up');
  for (const [index, link] of UNDERLAYS.entries()) {
    const remoteName = `r${index + 1}`;
    net(pid, 'link', 'add', remoteName, 'type', 'veth', 'peer', 'name', link.name, 'netns', nid);
    net(pid, 'link', 'set', remoteName, 'addrgenmode', 'none');
    net(pid, 'address', 'add', `${link.gateway}/24`, 'dev', remoteName);
    net(pid, 'link', 'set', remoteName, 'up');
    net(nid, 'link', 'set', link.name, 'addrgenmode', 'none');
    net(nid, 'address', 'add', `${link.source}/24`, 'dev', link.name);
    net(nid, 'link', 'set', link.name, 'up');
    // Existing source-bound sockets must survive the change to the unbound default route.
    net(nid, 'route', 'add', 'table', link.table, `${link.gateway}/32`, 'dev', link.name);
    net(nid, 'route', 'add', 'table', link.table, 'default', 'via', link.gateway, 'dev', link.name);
    net(nid, 'rule', 'add', 'from', `${link.source}/32`, 'lookup', link.table);
  }
  net(nid, 'route', 'add', 'default', 'via', UNDERLAYS[0].gateway, 'dev', UNDERLAYS[0].name);
  const assertUnderlaysHealthy = () => {
    for (const link of UNDERLAYS) {
      const [device] = JSON.parse(net(nid, '-j', 'link', 'show', 'dev', link.name));
      assert.ok(device.flags.includes('UP') && device.flags.includes('LOWER_UP'), link.name);
      const [route] = JSON.parse(net(nid, '-j', 'route', 'get', REMOTE, 'from', link.source));
      assert.equal(route.dev, link.name);
      inNamespace(nid, 'ping', '-n', '-c', '1', '-W', '1', '-I', link.source, REMOTE);
    }
  };
  assertUnderlaysHealthy();
  const relayConfig = await config('pvrelay0', '100.64.48.3', network => {
    network.listen_addresses = [`/ip4/${REMOTE}/tcp/4001`, `/ip4/${REMOTE}/udp/0/webrtc-direct`];
    network.relay = { server: true, resources: {
      max_circuit_duration_secs: 180, max_circuit_bytes: 16_777_216,
    } };
  });
  const relaySocket = join(dir, 'relay.sock');
  const relay = inRemote(binary, 'up', '-c', relayConfig, '--control-socket', relaySocket);
  const entrance = await relay.expect(/event=webrtc_listener_ready[^\n]* address=(\S+)/,
    'relay WebRTC entrance');
  const relayPeer = peer(relayConfig);
  const nativeRelay = `/ip4/${REMOTE}/tcp/4001/p2p/${relayPeer}/p2p-circuit`;
  const inviterConfig = await config('pvinviter0', INVITER_VPN, network => {
    network.discovery.mdns = true;
    network.listen_addresses = [];
    network.relay = { reservations: [nativeRelay] };
  });
  const inviter = peer(inviterConfig);
  const socket = join(dir, 'inviter.sock');
  const daemon = inNative(binary, 'up', '-c', inviterConfig, '--control-socket', socket,
    '--pairing-state', join(dir, 'pairing'),
    ...(checkpoint ? ['--membership-state', join(dir, 'membership')] : []));
  const pair = (command, ...args) => JSON.parse(cli('pair', command, ...args,
    '--socket', socket, '--format', 'json'));
  const reservationDeadline = performance.now() + 15_000;
  while (!/^relay_server_reservations_accepted [1-9]/m.test(
    cli('daemon-status', '--socket', relaySocket, '--timeout-seconds', '1'),
  )) {
    assert.ok(performance.now() < reservationDeadline, daemon.logs());
    await delay(100);
  }
  const dataServer = inNative(process.execPath, '--input-type=module', '-e',
    `import { createServer } from 'node:http'; createServer((request, response) => {
      const nonce = new URL(request.url, 'http://vpn').searchParams.get('nonce');
      if (!nonce) { response.writeHead(400); response.end(); return; }
      const body = 'preferred-interface:' + nonce;
      response.writeHead(200, { 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
      response.end(body);
    }).listen(0, process.argv[1], function () { console.log(this.address().port); });`, INVITER_VPN);
  const dataPort = await dataServer.expect(/^(\d+)$/m, 'HTTP server on inviter VPN IP');
  const seed = checkpoint ? null
    : inRemote(env.P2P_VPN_PAIRING_SEED, '--ignored', '--exact', 'serve_pairing_seed', '--nocapture');
  const bootstrap = seed && await seed.expect(/^pairing-seed:(\S+)$/m, 'public DHT seed');
  const host = processFixture(t, binary, 'browser-serve', '--assets', appAssets,
    '--port', '0', '--relay-entrance', entrance, ...(bootstrap ? ['--bootstrap', bootstrap] : []));
  const url = await host.expect(/^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/m,
    'companion URL');
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const replies = [];
  page.on('response', response => {
    const path = new URL(response.url()).pathname;
    if (/^\/api\/(pairing|relay)\//.test(path)) {
      replies.push(response.json().catch(() => null).then(body => ({
        path, body, code: response.status(), request: response.request().postDataJSON(),
      })));
    }
  });
  const sendNonce = async (deadline, budget = 2500) => {
    const requestDeadline = Math.min(deadline, performance.now() + budget);
    const remaining = () => Math.max(1, requestDeadline - performance.now());
    const nonce = randomUUID();
    await page.locator('#path').fill(`/?nonce=${nonce}`, { timeout: remaining() });
    const sentAt = performance.now();
    await page.getByRole('button', { name: 'Send request', exact: true }).click({ timeout: remaining() });
    const response = page.locator('#response').filter({ hasText: `preferred-interface:${nonce}` });
    await response.waitFor({ timeout: remaining() });
    const text = await response.textContent({ timeout: remaining() });
    assert.match(text, /^HTTP\/1\.[01] 200\b/);
    assert.ok(text.endsWith(`preferred-interface:${nonce}`), text);
    return { sentAt, at: performance.now() };
  };
  let stopMonitoring = false;
  let monitoring;
  let healthFailure;
  try {
    await page.goto(url);
    await page.getByRole('status').filter({ hasText: /^Disconnected$/ }).waitFor();
    const opened = pair('open', '--expires-in-seconds', '75');
    let locator;
    if (checkpoint) {
      const value = JSON.parse(await readFile(inviterConfig, 'utf8'));
      assert.ok(!value.network.membership_key, 'checkpoint enrollment must not use a static key');
      const syncBy = performance.now() + 55_000;
      while (!/^checkpoint_sync_state participating$/m.test(cli('daemon-status', '--socket', socket))) {
        assert.ok(performance.now() < syncBy, 'checkpoint authority failed to become active');
        await delay(250);
      }
    } else {
      locator = await page.evaluate(async code => {
        const sdk = await import('/pkg/p2p_vpn_browser.js');
        await sdk.default();
        return sdk.pairing_code_v2_global_locator(code);
      }, opened.code);
      seed.child.stdin.write([locator, inviter, `${nativeRelay}/p2p/${inviter}`].join(' ') + '\n');
      await seed.expect(/^pairing-provider-ready$/m, 'locator record');
    }
    await page.getByRole('button', { name: 'Pair code', exact: true }).click();
    await page.getByLabel('Pairing code').fill(opened.code);
    await page.getByLabel('Hostname').fill('chromium-preferred-interface');
    assert.equal(await page.getByLabel('Inviter address').inputValue(), '');
    if (checkpoint) {
      const relayAddress = entrance.endsWith(`/p2p/${relayPeer}`) ? entrance : `${entrance}/p2p/${relayPeer}`;
      await page.getByLabel('Inviter address').fill(`${relayAddress}/p2p-circuit/p2p/${inviter}`);
    }
    await page.getByRole('button', { name: 'Join network' }).click();
    await page.getByRole('status').filter({ hasText: /^Waiting for approval$/ }).waitFor({ timeout: 25_000 });
    if (!checkpoint) {
      const located = (await Promise.all(replies)).find(reply => reply.path === '/api/pairing/locator');
      assert.equal(located?.code, 200);
      assert.deepEqual(located.request, { locator });
      assert.deepEqual(located.body.addresses, []);
      assert.equal(located.body.relay_source, 'approved');
    }
    const pending = pair('status', opened.operation_id);
    assert.equal(pending.phase, 'awaiting_approval');
    pair('approve', opened.operation_id, pending.candidate.approval_id);
    if (checkpoint) await page.locator('#continue-checkpoint').click({ timeout: 20_000 });
    await page.getByRole('status').filter({ hasText: /^Connected$/ }).waitFor({ timeout: 30_000 });
    assert.equal(await page.locator('#peer-id').textContent(), inviter);
    if (!checkpoint) {
      const paired = await Promise.all(replies);
      assert.equal(paired.find(reply => reply.path === '/api/relay/handoff')?.code, 200);
      assert.equal(paired.find(reply => reply.path === '/api/relay/activate')?.code, 200);
    }
    await page.locator('#ip').fill(INVITER_VPN);
    await page.locator('#port').fill(dataPort);
    await sendNonce(performance.now() + 15_000, 15_000);
    const original = daemon.records.findLast(record => record.fields.event === 'control_relay_circuit_owned');
    assert.ok(original, 'initial HTTP must have a native relay circuit owner');
    const old = original.fields;
    assert.match(old.connection_id, /^\d+$/);
    assert.match(old.outer, /^\d+$/);
    assert.equal(old.relay, relayPeer);
    assert.equal(old.physical_transport, 'tcp');
    assert.ok(old.source.startsWith(`${UNDERLAYS[0].source}:`), original.line);
    const sockets = () => inNamespace(nid, 'ss', '-H4tn', 'state', 'established',
      'dst', `${REMOTE}:4001`).trim().split('\n').filter(Boolean)
      .map(line => line.trim().split(/\s+/).slice(-2));
    const hasSocket = source => sockets().some(([local, remote]) => local === source && remote === `${REMOTE}:4001`);
    assert.ok(hasSocket(old.source), 'original TCP relay socket is established');
    assertUnderlaysHealthy();
    const firstRecord = daemon.records.length;
    const afterSwitch = event => daemon.records.slice(firstRecord)
      .filter(record => record.fields.event === event && record.fields.peer === old.peer);
    const payload = () => afterSwitch('preferred_handoff_payload_verified')[0];
    const committed = () => afterSwitch('preferred_handoff_committed')[0];
    const assertContinuity = () => {
      assert.equal(daemon.child.exitCode, null, daemon.logs());
      assert.equal(daemon.child.signalCode, null, daemon.logs());
      assert.equal(relay.child.exitCode, null, relay.logs());
      assert.equal(relay.child.signalCode, null, relay.logs());
      assert.doesNotMatch(relay.logs(), /relay server (?:circuit closed[^\n]*TimedOut|reservation timed out)/,
        'relay timeout must not be a prerequisite for migration');
      if (legacy) {
        assert.equal(payload(), undefined, 'legacy browser must not verify a preferred-handoff payload');
        assert.equal(committed(), undefined, 'legacy browser must not commit a preferred handoff');
      }
      const verified = payload();
      const prematureClose = daemon.records.slice(firstRecord).find(record =>
        record.fields.event === 'connection_closed'
        && [old.connection_id, old.outer].includes(record.fields.connection_id)
        && (!verified || daemon.records.indexOf(record) < daemon.records.indexOf(verified)));
      assert.equal(prematureClose, undefined, `fallback closed before candidate payload: ${prematureClose?.line}`);
      if (!verified) assert.ok(hasSocket(old.source), 'original TCP relay socket lost before candidate payload');
      if (committed()) assert.ok(verified, 'commit without a verified IP packet');
    };
    if (checkpoint) {
      const peers = JSON.parse(cli('peers', '--socket', socket, '--format', 'json')).peers;
      const target = peers.find(peer => peer.peer_id === old.peer)?.ipv4[0];
      assert.ok(target, 'checkpoint did not assign an overlay address to Chromium');
      inNative('ping', '-n', '-i', '0.1', '-w', '8', target);
    }
    net(nid, 'route', 'replace', 'default', 'via', UNDERLAYS[1].gateway, 'dev', UNDERLAYS[1].name);
    const [preferred] = JSON.parse(net(nid, '-j', 'route', 'get', REMOTE));
    assert.equal(preferred.dev, UNDERLAYS[1].name);
    assert.equal(preferred.prefsrc, UNDERLAYS[1].source);
    const usableAt = performance.now();
    const deadline = usableAt + HANDOFF_LIMIT;
    t.diagnostic(`preferred route usable: ${JSON.stringify(preferred)}`);
    // Check independently of HTTP waits, including the full healthy overlap after an early commit.
    monitoring = (async () => {
      let nextHealth = 0;
      while (!stopMonitoring) {
        assertContinuity();
        if (performance.now() >= nextHealth) {
          assertUnderlaysHealthy();
          nextHealth = performance.now() + 1000;
        }
        await delay(100);
      }
    })().catch(error => { healthFailure = error; });
    if (legacy) {
      while (performance.now() < usableAt + OVERLAP) {
        if (healthFailure) throw healthFailure;
        await sendNonce(performance.now() + 5000);
        await delay(200);
      }
      const finalReply = await sendNonce(performance.now() + 5000);
      assert.ok(finalReply.sentAt >= usableAt + OVERLAP,
        'legacy HTTP must still complete after more than 31s on the original member circuit');
      assertContinuity();
      assertUnderlaysHealthy();
      assert.ok(hasSocket(old.source), 'legacy member lost its original TCP relay socket');
      assert.equal(JSON.parse(net(nid, '-j', 'route', 'get', REMOTE))[0].dev, UNDERLAYS[1].name);
      assert.equal((await Promise.all(replies)).filter(reply => reply.path === '/api/pairing/locator').length, 1);
      for (const offered of afterSwitch('preferred_handoff_offer')) {
        assert.equal(offered.fields.fallback, old.connection_id);
      }
      if (healthFailure) throw healthFailure;
      t.diagnostic(`legacy HTTP and original circuit/socket survived ${Math.round(finalReply.at - usableAt)}ms; `
        + `offers=${afterSwitch('preferred_handoff_offer').length}, no payload verification or commit`);
      return;
    }
    let completed;
    let lastRequestError;
    while (!completed && performance.now() < deadline) {
      if (healthFailure) throw healthFailure;
      try {
        const reply = await sendNonce(deadline);
        if (committed() && reply.sentAt >= committed().at) completed = reply;
      } catch (error) {
        if (error.name !== 'TimeoutError') throw error;
        lastRequestError = error;
      }
      if (!completed) await delay(100);
    }
    if (healthFailure) throw healthFailure;
    assert.ok(completed && completed.at <= deadline,
      `no fresh HTTP nonce completed on the committed owner within 30s: ${lastRequestError?.message ?? daemon.logs()}`);
    const offered = afterSwitch('preferred_handoff_offer')[0];
    const verified = payload();
    const commit = committed();
    assert.ok(offered && verified && commit, 'missing offer, payload verification, or commit');
    const candidate = afterSwitch('control_relay_circuit_owned')
      .find(record => record.fields.connection_id === verified.fields.connection_id);
    assert.ok(candidate, 'verified payload has no native circuit ownership proof');
    const owner = candidate.fields;
    if (checkpoint && env.P2P_VPN_TEST_EARLY_HANDOFF_PROBE === '1') {
      const probe = daemon.records.find(record => record.at >= usableAt
        && record.line.includes(`early candidate probe binding=${owner.connection_id}`));
      assert.ok(probe, 'fault-injection peer did not send a premature probe on the candidate');
      const rejected = afterSwitch('packet_response_rejected').find(record =>
        record.at >= probe.at && record.at <= verified.at && record.fields.reason === 'unauthorized_peer');
      assert.ok(rejected, 'native peer did not receive an explicit early packet rejection');
      t.diagnostic(`candidate ${owner.connection_id} returned unauthorized_peer before authorized payload`);
    }
    assert.notEqual(owner.connection_id, old.connection_id);
    assert.notEqual(owner.outer, old.outer);
    assert.equal(owner.relay, old.relay);
    assert.equal(owner.physical_transport, 'tcp');
    assert.ok(owner.source.startsWith(`${UNDERLAYS[1].source}:`), candidate.line);
    const [newInterface] = JSON.parse(net(nid, '-j', 'link', 'show', 'dev', UNDERLAYS[1].name));
    assert.equal(owner.interface, String(newInterface.ifindex));
    assert.notEqual(owner.interface, old.interface);
    const outer = daemon.records.find(record => record.fields.event === 'control_tcp_route_owned'
      && record.fields.connection_id === owner.outer && record.fields.peer === relayPeer);
    assert.ok(outer, 'candidate outer connection has no physical TCP owner');
    for (const key of ['source', 'interface', 'generation']) assert.equal(owner[key], outer.fields[key]);
    assert.equal(offered.fields.fallback, old.connection_id);
    assert.equal(offered.fields.outer, owner.outer);
    assert.equal(verified.fields.outer, owner.outer);
    assert.equal(commit.fields.connection_id, owner.connection_id);
    assert.equal(commit.fields.fallback, old.connection_id);
    for (const [before, after] of [[outer, offered], [offered, candidate], [candidate, verified], [verified, commit]]) {
      assert.ok(daemon.records.indexOf(before) < daemon.records.indexOf(after),
        `incorrect native handoff order:\n${before.line}\n${after.line}`);
    }
    assert.ok(commit.at - usableAt <= HANDOFF_LIMIT);
    assert.ok(!daemon.records.some(record => record.fields.event === 'connection_closed'
      && record.fields.connection_id === owner.connection_id && record.at <= completed.at),
    'the verified candidate closed before the fresh HTTP response');
    assert.ok(hasSocket(owner.source), 'new payload owner TCP socket is not established');
    t.diagnostic(`HTTP nonce completed ${Math.round(completed.at - usableAt)}ms after usable route; ${candidate.line}`);
    while (performance.now() < usableAt + OVERLAP) {
      if (healthFailure) throw healthFailure;
      await sendNonce(performance.now() + 5000);
      await delay(200);
    }
    assertContinuity();
    assertUnderlaysHealthy();
    assert.ok(hasSocket(owner.source), 'preferred payload socket did not survive the healthy overlap');
    const retiredMember = afterSwitch('connection_closed')
      .find(record => record.fields.connection_id === old.connection_id);
    const retiredOuter = daemon.records.find(record => record.fields.event === 'connection_closed'
      && record.fields.peer === relayPeer && record.fields.connection_id === old.outer
      && record.at > usableAt);
    assert.ok(retiredMember && retiredOuter, 'old member and unneeded outer relay socket must retire');
    assert.ok(retiredMember.at >= commit.at && retiredOuter.at >= retiredMember.at,
      'old resources must retire only after payload-gated commit');
    assert.equal(hasSocket(old.source), false, 'old relay socket remained established after retirement');
    assert.equal(JSON.parse(net(nid, '-j', 'route', 'get', REMOTE))[0].dev, UNDERLAYS[1].name);
    assert.equal((await Promise.all(replies)).filter(reply => reply.path === '/api/pairing/locator').length,
      checkpoint ? 0 : 1);
    t.diagnostic('both original and preferred underlays stayed healthy for at least 31s without relay timeout');
    t.diagnostic(JSON.stringify({
      offerMs: Math.round(offered.at - usableAt),
      payloadMs: Math.round(verified.at - usableAt),
      commitMs: Math.round(commit.at - usableAt),
      oldCircuitClosedMs: Math.round(retiredMember.at - usableAt),
      oldSocketClosedMs: Math.round(retiredOuter.at - usableAt),
    }));
  } catch (error) {
    const visible = await page.locator('#error').textContent({ timeout: 1000 }).catch(() => '');
    throw Error(`${error.message}\napp error: ${visible}\nnative:\n${daemon.logs()}\nrelay:\n${relay.logs()}`,
      { cause: error });
  } finally {
    stopMonitoring = true;
    await monitoring;
  }
  if (healthFailure) throw healthFailure;
}
