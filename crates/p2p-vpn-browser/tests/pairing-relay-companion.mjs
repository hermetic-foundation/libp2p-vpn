// Use the built production app and native webrtc daemon from the same build.
// P2P_VPN_PAIRING_SEED: test binary from cargo test --test browser_public_pairing_seed --no-run.
// Set P2P_VPN_BIN, P2P_VPN_RELAY_FIXTURE, P2P_VPN_APP_ASSETS, and optionally P2P_VPN_CHROMIUM.
// Export P2P_VPN_TEST_NETNS=$(readlink /proc/self/ns/net) before running via:
// unshare --user --map-root-user --mount --net --pid --fork --kill-child=SIGKILL --mount-proc \
//   node --test crates/p2p-vpn-browser/tests/pairing-relay-companion.mjs
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createSocket } from 'node:dgram';
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
const PAYLOAD = 'actual companion pairing relay payload';

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

function processFixture(t, command, ...args) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(child, 'close');
  exited.catch(() => {});
  let logs = '';
  for (const output of [child.stdout, child.stderr]) {
    output.setEncoding('utf8').on('data', text => { logs = (logs + text).slice(-16384); });
  }
  t.after(async () => {
    child.kill();
    await exited.catch(() => {});
  });
  return {
    child,
    logs: () => logs,
    async expect(pattern, label) {
      const deadline = Date.now() + 20000;
      do {
        const found = pattern.exec(logs);
        if (found) return found[1];
        if (child.exitCode !== null || child.signalCode !== null) break;
        await delay(50);
      } while (Date.now() < deadline);
      throw Error(`${label}: ${logs}`);
    },
  };
}

test('real Chromium pairs through the companion and sends HTTP after relay handoff', {
  timeout: 95_000,
}, t => exercise(t, true));

test('real Chromium pairs through an independently verified public relay without a pin', {
  timeout: 95_000,
}, t => exercise(t, false));

async function exercise(t, pinned) {
  const env = process.env;
  const binary = env.P2P_VPN_BIN;
  assert.ok(binary && env.P2P_VPN_PAIRING_SEED && env.P2P_VPN_APP_ASSETS);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  const cli = (...args) => execFileSync(binary, args, { encoding: 'utf8', timeout: 8000 });
  const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5000 });
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  const dir = await mkdtemp(join(tmpdir(), 'p2p-browser-pairing-relay-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const peer = path => /^local peer: (\S+)$/m.exec(cli('status', '-c', path))?.[1];
  async function config(name, address, configure) {
    const path = join(dir, `${name}.json`);
    cli('init-config', '--network', 'pairing-relay-companion-test', '--interface', name,
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
    'exec sleep 120',
  ].join('\n'));
  const pid = await remote.expect(/^namespace:(\d+)$/m, 'remote namespace');
  ip('link', 'set', 'lo', 'up');
  ip('link', 'add', 'gateway-peer', 'type', 'veth', 'peer', 'name', 'relay-peer', 'netns', pid);
  ip('link', 'set', 'gateway-peer', 'addrgenmode', 'none');
  ip('addr', 'add', `${LOCAL}/24`, 'dev', 'gateway-peer');
  ip('link', 'set', 'gateway-peer', 'up');
  ip('route', 'add', 'default', 'dev', 'gateway-peer');
  remote.child.stdin.end('ready\n');
  await remote.expect(/^ready$/m, 'remote veth');
  const inRemote = (...args) => processFixture(t, 'nsenter', '--target', pid, '--net', '--', ...args);
  let relay, relaySocket, entrance, nativeContact;
  if (pinned) {
    const relayConfig = await config('pvrelay0', '100.64.48.3', network => {
      network.listen_addresses = [`/ip4/${REMOTE}/tcp/4001`, `/ip4/${REMOTE}/udp/0/webrtc-direct`];
      network.relay = { server: true };
    });
    relaySocket = join(dir, 'relay.sock');
    relay = inRemote(binary, 'up', '-c', relayConfig, '--control-socket', relaySocket);
    entrance = await relay.expect(/event=webrtc_listener_ready[^\n]* address=(\S+)/, 'relay WebRTC entrance');
    nativeContact = `/ip4/${REMOTE}/tcp/4001/p2p/${peer(relayConfig)}`;
  } else {
    assert.ok(env.P2P_VPN_RELAY_FIXTURE);
    relay = inRemote(env.P2P_VPN_RELAY_FIXTURE, '--auto-relay-dht', REMOTE, REMOTE);
    const fixture = JSON.parse(await relay.expect(/^(\{"bootstrap":.*\})$/m, 'DHT relay readiness'));
    entrance = fixture.webrtc;
    nativeContact = fixture.native;
  }
  const nativeRelay = `${nativeContact}/p2p-circuit`;
  const inviterConfig = await config('pvinviter0', INVITER_VPN, network => {
    network.listen_addresses = [];
    network.relay = { reservations: [nativeRelay] };
  });
  const inviter = peer(inviterConfig);
  const socket = join(dir, 'inviter.sock');
  const daemon = inRemote(binary, 'up', '-c', inviterConfig, '--control-socket', socket,
    '--pairing-state', join(dir, 'pairing'));
  const pair = (command, ...args) => JSON.parse(cli('pair', command, ...args, '--socket', socket, '--format', 'json'));
  if (pinned) {
    const until = Date.now() + 15000;
    for (;;) {
      if (/^relay_server_reservations_accepted [1-9]/m.test(
        cli('daemon-status', '--socket', relaySocket, '--timeout-seconds', '1'),
      )) break;
      assert.ok(Date.now() < until, daemon.logs());
      await delay(100);
    }
  } else {
    await relay.expect(/(ReservationReqAccepted)/, 'DHT relay accepted the inviter');
  }
  const dataServer = inRemote(process.execPath, '--input-type=module', '-e',
    `import { createServer } from 'node:http'; createServer((request, response) => {
      response.end(${JSON.stringify(PAYLOAD)});
    }).listen(0, process.argv[1], function () { console.log(this.address().port); });`,
    INVITER_VPN);
  const dataPort = await dataServer.expect(/^(\d+)$/m, 'HTTP server bound to inviter VPN IP');
  const seed = inRemote(env.P2P_VPN_PAIRING_SEED, '--ignored', '--exact', 'serve_pairing_seed', '--nocapture');
  const bootstrap = await seed.expect(/^pairing-seed:(\S+)$/m, 'public DHT seed');
  const host = processFixture(t, binary, 'browser-serve', '--assets', env.P2P_VPN_APP_ASSETS,
    '--port', '0', '--bootstrap', bootstrap, ...(pinned ? ['--relay-entrance', entrance] : []));
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
      replies.push(response.json().catch(() => null)
        .then(body => ({ path, body, code: response.status(), request: response.request().postDataJSON() })));
    }
  });
  try {
    await page.goto(url);
    await page.getByRole('status').filter({ hasText: /^Disconnected$/ }).waitFor();
    const opened = pair('open', '--expires-in-seconds', '75');
    const locator = await page.evaluate(async code => {
      const sdk = await import('/pkg/p2p_vpn_browser.js');
      await sdk.default();
      return sdk.pairing_code_v2_global_locator(code);
    }, opened.code);
    const relayHint = pinned ? nativeRelay : nativeRelay.replace(/\/tcp\/\d+\//, '/tcp/1111/');
    const record = [locator, inviter, `${relayHint}/p2p/${inviter}`];
    if (!pinned) {
      // The seed does not offer HOP despite this preferred WebRTC hint.
      const unusable = entrance.replace(/\/p2p\/[^/]+$/, `/p2p/${bootstrap.split('/').at(-1)}`);
      record.push(nativeContact, `${unusable}/p2p-circuit/p2p/${inviter}`);
    }
    seed.child.stdin.write(record.join(' ') + '\n');
    await seed.expect(/^pairing-provider-ready$/m, 'locator record');
    await page.getByRole('button', { name: 'Pair code', exact: true }).click();
    await page.getByLabel('Pairing code').fill(opened.code);
    await page.getByLabel('Hostname').fill('chromium-companion-relay');
    assert.equal(await page.getByLabel('Inviter address').inputValue(), '');
    await page.getByRole('button', { name: 'Join network' }).click();
    await page.getByRole('status').filter({ hasText: /^Waiting for approval$/ }).waitFor({ timeout: 25000 });
    const before = await Promise.all(replies);
    const located = before.find(reply => reply.path === '/api/pairing/locator');
    assert.ok(located);
    assert.equal(located.code, 200);
    assert.deepEqual(located.request, { locator });
    assert.deepEqual(located.body.addresses, []);
    assert.equal(located.body.relay_source, 'approved');
    assert.match(located.body.relay_address, /^\/ip4\/127\.0\.0\.1\/udp\//);
    assert.ok(!before.some(reply => reply.path === '/api/relay/handoff'));
    const pending = pair('status', opened.operation_id);
    assert.equal(pending.phase, 'awaiting_approval');
    pair('approve', opened.operation_id, pending.candidate.approval_id);
    await page.getByRole('status').filter({ hasText: /^Connected$/ }).waitFor({ timeout: 30000 });
    assert.equal(await page.locator('#peer-id').textContent(), inviter);
    const observed = await Promise.all(replies);
    const handoff = observed.find(reply => reply.path === '/api/relay/handoff');
    const active = observed.find(reply => reply.path === '/api/relay/activate');
    assert.equal(handoff?.code, 200);
    assert.equal(active?.code, 200);
    assert.deepEqual(handoff.request, {
      lease_id: located.body.relay_lease_id, relay_address: located.body.relay_address,
    });
    assert.notEqual(handoff.body.relay_address, located.body.relay_address);
    assert.notEqual(handoff.body.relay_lease_id, located.body.relay_lease_id);
    const [, , , , port, ...circuit] = handoff.body.relay_address.split('/');
    assert.deepEqual(circuit, located.body.relay_address.split('/').slice(5));
    assert.equal(circuit.at(-1), inviter);
    assert.deepEqual(active.request, {
      lease_id: handoff.body.relay_lease_id, relay_address: handoff.body.relay_address,
    });
    assert.equal(observed.filter(reply => reply.path === '/api/pairing/locator').length, 1);
    await page.locator('#ip').fill(INVITER_VPN);
    await page.locator('#port').fill(dataPort);
    await page.getByRole('button', { name: 'Send request' }).click();
    await page.locator('#response').filter({ hasText: PAYLOAD }).waitFor({ timeout: 15000 });
    assert.equal(await udpPortAvailable(Number(port)), false);
    const release = page.waitForResponse(response => response.url().endsWith('/api/relay/release')
      && response.request().postDataJSON().lease_id === handoff.body.relay_lease_id);
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    assert.equal((await release).status(), 200);
    const deadline = Date.now() + 2000;
    while (!await udpPortAvailable(Number(port))) {
      assert.ok(Date.now() < deadline, 'the replacement UDP port must close after disconnect');
      await delay(10);
    }
  } catch (error) {
    const visible = await page.locator('#error').textContent().catch(() => '');
    const statuses = (await Promise.all(replies)).map(({ path, code, body }) => ({
      path, code, error: body?.error, addresses: body?.addresses?.length,
    }));
    throw Error(`${error.message}\napp error: ${visible}\ncompanion: ${JSON.stringify(statuses)}\n${daemon.logs().slice(-4000)}`,
      { cause: error });
  }
}
