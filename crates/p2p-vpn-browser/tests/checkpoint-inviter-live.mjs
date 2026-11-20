import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

async function fixture(t, binary, ...args) {
  const child = spawn(binary, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const closed = once(child, 'close');
  // A failing test may stop a fixture while it is waiting for its next command.
  child.stdin.on('error', () => {});
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  const output = createInterface({ input: child.stdout });
  const lines = output[Symbol.asyncIterator]();
  t.after(async () => {
    output.close();
    child.kill();
    await closed;
  });
  return {
    async line() {
      const { value } = await lines.next();
      assert.ok(value, `Fixture ended without output: ${stderr}`);
      return value;
    },
    send(line) { child.stdin.write(`${line}\n`); },
    async waitForEvent(pattern, timeoutMs) {
      const deadline = Date.now() + timeoutMs;
      do {
        const match = stderr.match(pattern);
        if (match) return match[0];
        await delay(50);
      } while (Date.now() < deadline);
      assert.fail(`Relay did not report ${pattern}:\n${stderr}`);
    },
  };
}

async function recoveryRelay(t) {
  const binary = process.env.P2P_VPN_BIN;
  assert.ok(binary, 'set P2P_VPN_BIN to the native relay daemon');
  const directory = await mkdtemp(join(tmpdir(), 'p2p-vpn-checkpoint-recovery-'));
  const config = join(directory, 'relay.json');
  // This isolated namespace has no other TCP listener on this port. Keep the
  // address and certificate unchanged across both reservations.
  const tcpAddress = '/ip4/11.250.0.2/tcp/24081';
  execFileSync(binary, [
    'init-config', '--output', config, '--network', 'checkpoint-recovery-relay',
    '--listen-address', '/ip4/11.250.0.2/udp/0/webrtc-direct',
    '--listen-address', tcpAddress, '--external-address', tcpAddress,
    '--relay-server', '--relay-max-reservations', '1',
    '--relay-max-circuits', '2', '--relay-max-circuit-duration-secs', '30',
    '--relay-reservation-duration-secs', '35', '--ipfs-kademlia',
  ], { timeout: 5000 });
  const relay = await fixture(t, binary, 'up', '--config', config);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const webrtc = await relay.waitForEvent(
    /(?<=event=webrtc_listener_ready runtime_network=checkpoint-recovery-relay address=)\/ip4\/11\.250\.0\.2\/udp\/\d+\/webrtc-direct\/certhash\/[^/\s]+\/p2p\/[A-Za-z0-9]+/,
    10_000,
  );
  return { relay, webrtc, tcp: `${tcpAddress}/p2p/${webrtc.split('/').at(-1)}` };
}

test('Chromium checkpoint issuer serves a new native member on its reserved circuit',
  { timeout: 105_000 }, t => exercise(t, false));
test('the served app approves a reviewed checkpoint request over a live reservation',
  { timeout: 105_000 }, t => exercise(t, true));
test('the served app admits a code applicant only after durable approval and checkpoint sync',
  { timeout: 105_000 }, t => exercise(t, true, 'native'));
test('two served browser apps complete checkpoint enrollment by code',
  { timeout: 105_000 }, t => exercise(t, true, 'browser'));
test('Chromium recovers a lost committed Accepted after reopening the public reservation', {
  timeout: 105_000,
  skip: !process.env.P2P_VPN_CHECKPOINT_RETRY_PKG && 'requires checkpoint retry WASM test hooks',
}, t => exercise(t, false, 'restart'));
test('live checkpoint invitations publish successive locators through independent storage',
  { timeout: 105_000 }, exerciseScopedPublication);

async function exerciseScopedPublication(t) {
  const env = process.env;
  assert.ok(env.P2P_VPN_BIN && env.P2P_VPN_RELAY_FIXTURE && env.P2P_VPN_CHECKPOINT_INVITER_NATIVE
    && env.P2P_VPN_PAIRING_PKG);
  assert.match(env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), env.P2P_VPN_TEST_NETNS);
  const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5000 });
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up');
  const relay = await fixture(t, 'unshare', '--net', 'sh', '-ec', [
    'printf "%s\\n" "$$"',
    'read ready',
    'ip link set lo up',
    'ip addr add 11.250.0.2/24 dev fixture-peer',
    'ip addr add 11.250.0.3/24 dev fixture-peer',
    'ip addr add 11.250.0.4/24 dev fixture-peer',
    'ip link set fixture-peer up',
    'exec "$@"',
  ].join('\n'), 'checkpoint-topology', env.P2P_VPN_RELAY_FIXTURE,
  '--auto-relay-dht', '11.250.0.3', '11.250.0.2', '11.250.0.4');
  const pid = await relay.line();
  assert.match(pid, /^\d+$/);
  ip('link', 'add', 'physical', 'type', 'veth', 'peer', 'name', 'fixture-peer', 'netns', pid);
  ip('addr', 'add', '11.250.0.1/24', 'dev', 'physical');
  ip('link', 'set', 'physical', 'up');
  ip('route', 'add', 'default', 'dev', 'physical');
  ip('link', 'add', 'secondary', 'type', 'dummy');
  t.after(() => ip('link', 'del', 'secondary'));
  ip('addr', 'add', '11.251.0.1/24', 'dev', 'secondary');
  ip('link', 'set', 'secondary', 'up');
  relay.send('ready');
  const { webrtc, native: tcp, bootstrap, storage } = JSON.parse(await relay.line());
  assert.notEqual(bootstrap.split('/').at(-1), tcp.split('/').at(-1));
  assert.notEqual(storage.split('/').at(-1), tcp.split('/').at(-1));
  const native = await fixture(t, 'nsenter', '-t', pid, '-n', env.P2P_VPN_CHECKPOINT_INVITER_NATIVE,
    webrtc, '--scoped', tcp);
  const seed = JSON.parse(await native.line());
  const assets = await mkdtemp(join(tmpdir(), 'checkpoint-scoped-assets-'));
  t.after(() => rm(assets, { recursive: true, force: true }));
  await mkdir(join(assets, 'pkg'));
  for (const name of ['app.html', 'app.js', 'app.css', 'checkpoint-code.js', 'code-inviter.html', 'code-inviter.js']) {
    await copyFile(new URL(`../web/${name}`, import.meta.url), join(assets, name));
  }
  for (const name of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm', 'logo.svg']) {
    await copyFile(join(env.P2P_VPN_PAIRING_PKG, name), join(assets, 'pkg', name));
  }
  const companion = await fixture(t, env.P2P_VPN_BIN, 'browser-serve',
    '--assets', assets, '--port', '0', '--bootstrap', tcp,
    '--relay-entrance', webrtc, '--relay-native-alias', tcp);
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/.exec(await companion.line())?.[1];
  assert.ok(url);
  const browser = await chromium.launch(env.P2P_VPN_CHROMIUM
    ? { executablePath: env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const starts = [];
  page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/relay/inviter/locator') {
      starts.push(request.postDataJSON());
    }
  });
  await page.goto(url);
  const passphrase = 'checkpoint scoped invitation fixture';
  const reserved = await page.evaluate(async ({ bundle, passphrase }) => {
    const { default: init, BrowserVpn } = await import('/pkg/p2p_vpn_browser.js');
    await init();
    const response = await fetch('/api/relay/inviter/reservation', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"checkpoint":true}',
    });
    if (!response.ok) throw Error(`ingress preparation: ${response.status}`);
    const { relay_lease_id, relay_entrance, native_alias } = await response.json();
    window.vpn = await BrowserVpn.import_scoped_checkpoint_credentials(
      bundle, passphrase, relay_lease_id, relay_entrance, native_alias);
    return window.vpn.reserve_relay();
  }, { bundle: sealFixture(seed, passphrase), passphrase });
  assert.equal(reserved, seed.reservation);
  native.send(reserved);
  const ready = await page.evaluate(async () => JSON.parse(await window.vpn.accept_relay()));
  assert.equal(ready.ready, true);
  const publish = () => page.evaluate(async () => {
    const { pairing_code_v2_global_locator } = await import('/pkg/p2p_vpn_browser.js');
    const code = window.vpn.start_checkpoint_code();
    await window.vpn.publish_checkpoint_code_distributed();
    const repeat = await window.vpn.publish_checkpoint_code_distributed()
      .then(() => 'accepted', error => error.message);
    return { code, locator: pairing_code_v2_global_locator(code), repeat };
  });
  const lookup = (locator, seed = bootstrap) => JSON.parse(execFileSync('nsenter',
    ['-t', pid, '-n', env.P2P_VPN_RELAY_FIXTURE, '--lookup-locator', seed, locator],
    { encoding: 'utf8', timeout: 8000 }));
  const owner = reserved.split('/').at(-1);
  const provider = [{ peer: owner, addresses: [reserved] }];
  const first = await publish();
  assert.match(first.repeat, /already attempted/);
  assert.deepEqual(lookup(first.locator), provider);
  assert.deepEqual(lookup(first.locator, storage), provider);
  await page.evaluate(() => window.vpn.cancel_checkpoint_code());
  const second = await publish();
  assert.match(second.repeat, /already attempted/);
  assert.notEqual(second.locator, first.locator);
  assert.deepEqual(lookup(second.locator), provider);
  assert.deepEqual(lookup(second.locator, storage), provider);
  assert.deepEqual(lookup(first.locator, storage), provider, 'cancellation does not erase the cached hint');
  assert.equal(starts.length, 2);
  assert.equal(starts[0].lease_id, starts[1].lease_id);
  assert.equal(starts[0].relay_entrance, starts[1].relay_entrance);
  assert.notEqual(starts[0].child_id, starts[1].child_id);
  for (const [request, invite] of [[starts[0], first], [starts[1], second]]) {
    assert.deepEqual(Object.keys(request).sort(), ['child_id', 'lease_id', 'provider_key', 'relay_entrance']);
    assert.equal(request.provider_key, `/p2p-vpn/pairing-code/${invite.locator}/providers/2`);
  }
  const post = (path, body) => page.evaluate(async ({ path, body }) => {
    const reply = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { ok: reply.ok, data: await reply.json() };
  }, { path, body });
  const startEndpoint = '/api/relay/inviter/locator';
  const child = () => ({ ...starts[1], child_id: randomBytes(24).toString('base64url') });
  const delayedChild = child();
  const delayedUrl = new URL(startEndpoint, url).href;
  const intercepted = Promise.withResolvers();
  const unblock = Promise.withResolvers();
  const hold = async route => {
    intercepted.resolve();
    await unblock.promise;
    await route.continue();
  };
  await page.route(delayedUrl, hold);
  const late = post(startEndpoint, delayedChild);
  late.catch(() => {});
  await intercepted.promise;
  let release;
  try {
    release = await post(`${startEndpoint}/release`, {
      lease_id: delayedChild.lease_id, child_id: delayedChild.child_id,
    });
  } finally {
    unblock.resolve();
  }
  assert.deepEqual(release, { ok: true, data: { released: true } });
  assert.equal((await late).ok, false, 'a released child cannot start discovery');
  await page.unroute(delayedUrl, hold);
  assert.ok(relay.logs().includes(`storage-hop ${owner} /ip4/11.250.0.1/tcp/`));
  const drive = () => page.evaluate(() => {
    window.running = true;
    window.pump = (async () => {
      while (window.running) await window.vpn.receive_relay_packet(100);
    })().catch(error => { window.pumpError = error.message; });
  });
  const stop = () => page.evaluate(async () => {
    window.running = false;
    await window.pump;
  });
  await drive();
  native.send(first.code);
  assert.deepEqual(JSON.parse(await native.line()), { stale_code_denied: true });
  native.send(`code ${second.code}`);
  assert.deepEqual(JSON.parse(await native.line()), { provisional_denied: true });
  await stop();
  const readAuthority = () => page.evaluate(() => {
    const key = Object.keys(localStorage).find(key => key.startsWith('p2p-vpn:checkpoint-membership:1:'));
    return JSON.parse(localStorage.getItem(key)).payload.retained.snapshot.payload;
  });
  const before = await readAuthority();
  assert.equal(before.authority_revision, 0);
  const applicant = await page.evaluate(async () => {
    const review = JSON.parse(window.vpn.checkpoint_code_review());
    await window.vpn.approve_checkpoint_code(review.ticket);
    return review.peer;
  });
  const committed = await readAuthority();
  assert.equal(committed.authority_revision, 1);
  assert.ok(committed.members.some(member => member.subject.peer_id === applicant));
  await drive();
  const facts = {};
  while (!facts.packet_accepted) Object.assign(facts, JSON.parse(await native.line()));
  assert.equal(facts.incumbent_applied, 1);
  assert.equal(facts.activated_rank.authority_revision, 1);
  await stop();

  // Open an actual forwarded storage stream and leave it idle for its deadline.
  // The scoped ingress must still be live when the child dies.
  const expiringChild = child();
  const granted = await post(startEndpoint, expiringChild);
  assert.equal(granted.ok, true, 'a retired child did not occupy the publication slot');
  const index = granted.data.indexOf(storage.split('/').at(-1));
  assert.notEqual(index, -1);
  await page.evaluate(async ({ id, index }) => {
    const stream = new WebSocket(
      `ws://${location.host}/api/relay/inviter/locator/stream/${index}`, `p2p-vpn-locator.${id}`);
    window.expiringLocator = stream;
    await new Promise((resolve, reject) => {
      stream.onopen = resolve;
      stream.onerror = () => reject(Error('Publication stream failed to open'));
    });
  }, { id: expiringChild.child_id, index });
  const destination = `11.250.0.4:${storage.split('/')[4]}`;
  const socketDeadline = performance.now() + 3000;
  const connected = () => execFileSync('ss', ['-Htn', 'state', 'established'], { encoding: 'utf8', timeout: 3000 })
    .includes(destination);
  while (!connected() && performance.now() < socketDeadline) await delay(30);
  assert.ok(connected(), 'WebSocket did not open a scoped storage TCP stream');
  await page.waitForFunction(() => window.expiringLocator.readyState === WebSocket.CLOSED,
    undefined, { timeout: 17_000 });
  assert.equal(connected(), false, 'expired publication left its storage TCP stream open');
  await page.evaluate(() => window.vpn.check_checkpoint_ingress());
  assert.deepEqual(await readAuthority(), committed);
  ip('route', 'replace', 'default', 'dev', 'secondary');
  await page.evaluate(async () => {
    for (let i = 0; i < 30; i++) {
      try { await window.vpn.check_checkpoint_ingress(); }
      catch (e) {
        if (window.vpn.relay_reservation_address()) throw Error('Revoked ingress can still admit');
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw Error('Default-link change did not revoke checkpoint ingress');
  });
  ip('route', 'replace', 'default', 'dev', 'physical');
  await assert.rejects(page.evaluate(() => window.vpn.check_checkpoint_ingress()), /lease ended/);
  const denied = await page.evaluate(async start => {
    const response = await fetch('/api/relay/inviter/locator', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(start),
    });
    return !response.ok;
  }, { ...starts[1], child_id: randomBytes(24).toString('base64url') });
  assert.equal(denied, true, 'restoring reachability does not restore the lease');
  assert.deepEqual(lookup(second.locator, storage), provider, 'scope revocation does not erase cached hints');
}

async function exercise(t, app, code = false) {
  const {
    P2P_VPN_CHECKPOINT_INVITER_NATIVE: nativeBinary,
    P2P_VPN_RELAY_FIXTURE: relayBinary,
    P2P_VPN_PAIRING_PKG: productionPkg,
    P2P_VPN_TEST_NETNS: parentNamespace,
    P2P_VPN_CHROMIUM: executablePath,
  } = process.env;
  const restarting = code === 'restart';
  const pkg = restarting ? process.env.P2P_VPN_CHECKPOINT_RETRY_PKG : productionPkg;
  assert.ok(nativeBinary && relayBinary && pkg);
  assert.match(parentNamespace ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), parentNamespace);
  const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5000 });
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up');
  ip('link', 'add', 'checkpoint-lan', 'type', 'dummy');
  t.after(() => ip('link', 'delete', 'checkpoint-lan'));
  ip('addr', 'add', '11.250.0.2/24', 'dev', 'checkpoint-lan');
  ip('link', 'set', 'checkpoint-lan', 'up');
  const { relay, webrtc: entrance, tcp } = restarting ? await recoveryRelay(t) : await (async () => {
    const relay = await fixture(t, relayBinary, '11.250.0.2');
    return { relay, webrtc: await relay.line() };
  })();
  assert.match(entrance, /^\/ip4\/11\.250\.0\.2\/udp\/\d+\/webrtc-direct\/certhash\/[^/]+\/p2p\/[^/]+$/);
  const native = await fixture(t, nativeBinary, entrance, ...(restarting ? [tcp] : []));
  const seed = JSON.parse(await native.line());
  if (app) return exerciseApp(t, native, seed, executablePath, code);
  const files = new Map([['/', ['text/html', '<!doctype html><title>Checkpoint relay issuer test</title>']]]);
  for (const [file, mime] of [['p2p_vpn_browser.js', 'text/javascript'], ['p2p_vpn_browser_bg.wasm', 'application/wasm']]) {
    files.set(`/${file}`, [mime, await readFile(join(pkg, file))]);
  }
  const server = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);

  const reservation = await page.evaluate(async ({ config, first_route, bootstrap, secret }) => {
    const { default: init, BrowserVpn } = await import('/p2p_vpn_browser.js');
    await init();
    window.vpn = await BrowserVpn.open_checkpoint_with_relay(
      JSON.stringify(config), '', first_route, JSON.stringify(bootstrap), new Uint8Array(secret),
    );
    return window.vpn.reserve_relay();
  }, seed);
  assert.equal(reservation, seed.reservation);
  native.send(reservation);
  if (restarting) {
    const alias = `${tcp}/p2p-circuit/p2p/${reservation.split('/').at(-1)}`;
    return exerciseRecovery(t, page, native, relay, seed, alias);
  }
  const issuer = await page.evaluate(async () => {
    const primary = JSON.parse(await window.vpn.accept_relay());
    window.invitation = window.vpn.checkpoint_invitation();
    return { primary, offer: window.invitation.offer_json() };
  });
  assert.equal(issuer.primary.ready, true);
  assert.equal(issuer.primary.checkpoint.sync, 'participating');
  assert.equal(issuer.primary.checkpoint.boundary.authority_revision, 0);
  native.send(issuer.offer);
  const { request } = JSON.parse(await native.line());
  const approval = await page.evaluate(async requestJson => {
    const response = await window.vpn.approve_checkpoint_invitation(window.invitation, requestJson);
    const { payload } = JSON.parse(response);
    const key = `p2p-vpn:checkpoint-membership:1:${JSON.stringify([payload.network_name, payload.inviter_peer])}`;
    const { retained, enrollment_floor } = JSON.parse(localStorage.getItem(key)).payload;
    return {
      response,
      floor: payload.checkpoint.minimum,
      member: payload.checkpoint.joiner.subject.peer_id,
      revision: retained.snapshot.payload.authority_revision,
      savedMember: retained.snapshot.payload.members.some(member => member.subject.peer_id === payload.checkpoint.joiner.subject.peer_id),
      activatedFloor: enrollment_floor,
    };
  }, JSON.stringify(request));
  assert.equal(approval.revision, 1);
  assert.equal(approval.savedMember, true);
  assert.equal(approval.activatedFloor, null);
  native.send(approval.response);

  const [packet, result] = await Promise.all([
    page.evaluate(async () => {
      const deadline = performance.now() + 20_000;
      while (performance.now() < deadline) {
        const bytes = await window.vpn.receive_relay_packet(1000);
        if (bytes) {
          await window.vpn.poll_foreground();
          return Array.from(bytes);
        }
      }
      throw new Error('No authorized IP packet reached the browser');
    }),
    (async () => {
      const facts = {};
      while (!facts.packet_accepted) Object.assign(facts, JSON.parse(await native.line()));
      return facts;
    })(),
  ]);
  assert.equal(result.incumbent_applied, 1);
  assert.deepEqual(result.activated_rank, approval.floor);
  assert.equal(packet.length, 28);
  assert.equal(packet.slice(12, 16).join('.'), seed.joiner_ip);
}

async function exerciseRecovery(t, page, native, relay, seed, alias) {
  const owner = seed.reservation.split('/').at(-1);
  const accept = () => page.evaluate(async expectedAlias => {
    const session = JSON.parse(await window.vpn.accept_relay());
    for (let i = 0; i < 10 && window.vpn.checkpoint_code_public_alias() !== expectedAlias; i++) {
      await window.vpn.poll_foreground();
    }
    return { session, alias: window.vpn.checkpoint_code_public_alias() };
  }, alias);
  const first = await accept();
  assert.equal(first.session.ready, true);
  assert.equal(first.session.checkpoint.boundary.authority_revision, 0);
  assert.equal(first.alias, alias);

  const drive = packets => page.evaluate(packets => {
    window.running = true;
    window.pump = (async () => {
      while (window.running) {
        if (packets) {
          const packet = await window.vpn.receive_relay_packet(100);
          if (packet) window.received = Array.from(packet);
        } else {
          await window.vpn.poll_foreground();
        }
      }
    })().catch(error => { window.pumpError = error.message; });
  }, packets);
  const stop = () => page.evaluate(async () => {
    window.running = false;
    await window.pump;
    return window.pumpError;
  });
  const stored = () => page.evaluate(() => {
    const key = Object.keys(localStorage).find(key => key.startsWith('p2p-vpn:checkpoint-membership:1:'));
    const { retained, code_recovery } = JSON.parse(localStorage.getItem(key)).payload;
    return { snapshot: retained.snapshot, recovery: code_recovery };
  });
  const code = await page.evaluate(() => window.vpn.start_checkpoint_code());
  await page.evaluate(alias => window.vpn.publish_checkpoint_code(alias), alias);
  await drive(false);
  native.send(code);
  assert.deepEqual(JSON.parse(await native.line()), { provisional_denied: true });
  assert.equal(await stop(), undefined);

  await page.evaluate(async () => {
    const review = JSON.parse(window.vpn.checkpoint_code_review());
    await window.vpn.approve_checkpoint_code(review.ticket);
    window.vpn.test_drop_next_checkpoint_accepted();
  });
  const committed = await stored();
  assert.equal(committed.snapshot.payload.authority_revision, 1);
  assert.equal(committed.recovery.response.payload.checkpoint.capability_secret, '');
  await drive(false);
  native.send('poll after commit');
  const lost = {};
  while (!lost.accepted_lost) Object.assign(lost, JSON.parse(await native.line()));
  assert.equal(lost.incumbent_applied, 1);
  // Incumbent teardown may have reached the old connection's dispatcher.
  await stop();
  await page.evaluate(async () => {
    await window.vpn.close();
    window.vpn.free();
  });
  const closedAt = performance.now();
  const released = await relay.waitForEvent(
    new RegExp(`relay server reservation (?:closed|timed out) for ${owner}\\b`),
    40_000,
  );
  const remaining = committed.recovery.expires - Math.floor(Date.now() / 1000);
  assert.ok(remaining > 0, 'the route must return before the durable ticket expires');
  const releaseDelay = ((performance.now() - closedAt) / 1000).toFixed(1);
  t.diagnostic(`${released}; ${releaseDelay}s after owner close, ${remaining}s before ticket expiry`);
  await page.reload();
  const reopenedAddress = await page.evaluate(async ({ config, first_route, bootstrap, secret }) => {
    const { default: init, BrowserVpn } = await import('/p2p_vpn_browser.js');
    await init();
    window.vpn = await BrowserVpn.open_checkpoint_with_relay(
      JSON.stringify(config), '', first_route, JSON.stringify(bootstrap), new Uint8Array(secret),
    );
    return window.vpn.reserve_relay();
  }, seed);
  assert.equal(reopenedAddress, seed.reservation);
  native.send(reopenedAddress);
  const reopened = await accept();
  assert.equal(reopened.session.ready, true);
  assert.deepEqual(reopened.session.checkpoint.boundary, committed.recovery.boundary);
  assert.equal(reopened.alias, alias);
  assert.deepEqual((await stored()).snapshot, committed.snapshot);

  await drive(true);
  native.send('retry');
  const retry = JSON.parse(await native.line());
  assert.equal(retry.outsider_denied, true);
  assert.equal(retry.wrong_ticket_denied, true);
  assert.deepEqual(retry.recovered, committed.recovery.response);
  const activated = JSON.parse(await native.line());
  assert.equal(activated.packet_accepted, true);
  assert.deepEqual(activated.activated_rank, committed.recovery.response.payload.checkpoint.minimum);
  assert.equal(await stop(), undefined);
  const packet = await page.evaluate(() => window.received);
  assert.equal(packet.slice(12, 16).join('.'), seed.joiner_ip);
  const after = await stored();
  assert.deepEqual(after.snapshot, committed.snapshot);
  assert.equal(after.recovery, undefined);
}

function sealFixture(seed, passphrase) {
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const key = pbkdf2Sync(passphrase, salt, 600_000, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from('p2p-vpn browser checkpoint credential bundle v1'));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify({
    config: seed.config,
    bootstrap: { ...seed.bootstrap, enrollment_floor: seed.floor },
    capability_secret: seed.secret,
    direct_addresses: [],
    relay_address: seed.first_route,
  })), cipher.final(), cipher.getAuthTag()]);
  return JSON.stringify({ version: 1, salt: [...salt], nonce: [...nonce], ciphertext: [...ciphertext] });
}

async function exerciseApp(t, native, seed, executablePath, byCode) {
  const binary = process.env.P2P_VPN_BIN;
  assert.ok(binary, 'set P2P_VPN_BIN to the native browser companion');
  const assets = fileURLToPath(new URL('../web', import.meta.url));
  const host = await fixture(t, binary, 'browser-serve', '--assets', assets, '--port', '0');
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/.exec(await host.line())?.[1];
  assert.ok(url, 'native companion did not publish its app URL');
  const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  const writes = [];
  const downloads = [];
  page.on('request', request => {
    if (request.method() !== 'GET') writes.push(new URL(request.url()).pathname);
  });
  page.on('download', download => downloads.push(download.suggestedFilename()));
  await page.goto(url);
  await page.getByRole('button', { name: 'Credentials', exact: true }).click();
  const passphrase = 'isolated issuer fixture passphrase';
  await page.getByLabel('Encrypted credentials').setInputFiles({
    name: 'issuer.json', mimeType: 'application/json', buffer: Buffer.from(sealFixture(seed, passphrase)),
  });
  await page.getByLabel('Bundle passphrase').fill(passphrase);
  const invite = page.getByRole('button', { name: 'Download invitation', exact: true });
  await page.getByRole('button', { name: 'Listen on relay', exact: true }).click();
  await page.locator('#relay-address').filter({ hasText: seed.reservation }).waitFor();
  assert.equal(await invite.isVisible(), false);
  native.send(seed.reservation);
  await invite.waitFor({ timeout: 30_000 });
  if (byCode) {
    const start = page.getByRole('button', { name: 'Pair by code', exact: true });
    const approve = page.getByRole('button', { name: 'Approve code request' });
    const cancel = page.getByRole('button', { name: 'Cancel code invitation' });
    const value = page.locator('#checkpoint-code-value');
    await start.click();
    await value.filter({ hasText: /\S/ }).waitFor();
    const discarded = await value.textContent();
    assert.ok(discarded);
    await page.locator('#checkpoint-code-publication').filter({ hasText: /^Manual address only$/ }).waitFor();
    await cancel.click();
    await start.click();
    await value.filter({ hasText: /\S/ }).waitFor();
    const code = await value.textContent();
    assert.ok(code && code !== discarded);
    assert.equal(await approve.isDisabled(), true);
    const authority = () => page.evaluate(() => {
      const key = Object.keys(localStorage).find(key => key.startsWith('p2p-vpn:checkpoint-membership:1:'));
      const { retained } = JSON.parse(localStorage.getItem(key)).payload;
      return {
        revision: retained.snapshot.payload.authority_revision,
        members: retained.snapshot.payload.members.map(member => member.subject.peer_id),
      };
    });
    let joiner;
    if (byCode === 'browser') {
      joiner = await browser.newPage();
      await joiner.goto(url);
      await joiner.getByRole('button', { name: 'Pair code', exact: true }).click();
      await joiner.getByLabel('Pairing code', { exact: true }).fill(code);
      await joiner.locator('#pair-hostname').fill('checkpoint-applicant');
      await joiner.locator('#address').fill(seed.reservation);
      await joiner.locator('#connect').click();
      await joiner.locator('#state').filter({ hasText: 'Waiting for approval' }).waitFor();
    } else {
      native.send(`code ${code}`);
      assert.deepEqual(JSON.parse(await native.line()), { provisional_denied: true });
    }
    const requested = page.locator('#checkpoint-code-peer');
    await page.locator('#checkpoint-code-name').filter({ hasText: 'checkpoint-applicant' }).waitFor();
    const applicant = await requested.textContent();
    assert.ok(applicant);
    const before = await authority();
    assert.equal(before.revision, 0);
    assert.ok(!before.members.includes(applicant));
    assert.equal(await page.locator('#state').textContent(), 'Connected');
    assert.equal(await page.locator('#relay-address').textContent(), seed.reservation);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await approve.click();
    const result = {};
    if (joiner) {
      Object.assign(result, JSON.parse(await native.line()));
      await joiner.locator('#state').filter({ hasText: /^Connected$/ }).waitFor({ timeout: 25_000 })
        .catch(async cause => { throw new Error(`Applicant activation failed: ${await joiner.locator('#error').textContent()}`, { cause }); });
      const joined = await joiner.evaluate(() => {
        const key = Object.keys(localStorage).find(key => key.startsWith('p2p-vpn:checkpoint-membership:1:'));
        return JSON.parse(localStorage.getItem(key)).payload;
      });
      assert.equal(joined.enrollment_floor, null);
      assert.equal(joined.retained.snapshot.payload.authority_revision, 1);
    } else {
      while (!result.packet_accepted) Object.assign(result, JSON.parse(await native.line()));
    }
    assert.equal(result.incumbent_applied, 1);
    const committed = await authority();
    assert.equal(committed.revision, 1);
    assert.ok(committed.members.includes(applicant));
    await page.locator('#checkpoint-approved-peer').filter({ hasText: applicant }).waitFor();
    assert.equal(await page.locator('#relay-address').textContent(), seed.reservation);
    assert.deepEqual(downloads, []);
    assert.deepEqual(writes, [], 'manual code pairing does not upload enrollment artifacts');
    return;
  }
  const download = async (button, name) => {
    const pending = page.waitForEvent('download');
    await button.click();
    const artifact = await pending;
    assert.equal(artifact.suggestedFilename(), name);
    return readFile(await artifact.path(), 'utf8');
  };
  const offer = await download(invite, 'p2p-vpn-checkpoint-invitation.json');
  const { network_name: network, inviter_peer: issuer } = JSON.parse(offer).payload;
  const storageKey = `p2p-vpn:checkpoint-membership:1:${JSON.stringify([network, issuer])}`;
  const authority = () => page.evaluate(key => {
    const { retained } = JSON.parse(localStorage.getItem(key)).payload;
    return {
      revision: retained.snapshot.payload.authority_revision,
      members: retained.snapshot.payload.members.map(member => member.subject.peer_id),
    };
  }, storageKey);
  native.send(offer);
  const { request } = JSON.parse(await native.line());
  const approved = page.getByRole('button', { name: 'Approve and download response' });
  assert.equal(await approved.isDisabled(), true);
  const requestInput = page.getByLabel('Signed join request');
  await requestInput.setInputFiles({
    name: 'malformed.json', mimeType: 'application/json', buffer: Buffer.from('{'),
  });
  await page.getByText('The signed join request is not valid JSON.', { exact: true }).waitFor();
  assert.equal(await approved.isDisabled(), true);
  await requestInput.setInputFiles({
    name: 'join.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(request)),
  });
  const joiner = request.payload.joiner_peer;
  const requestedPeer = page.locator('#checkpoint-requested-peer');
  await requestedPeer.filter({ hasText: joiner }).waitFor();
  assert.equal(await requestedPeer.textContent(), joiner);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  assert.deepEqual(downloads, ['p2p-vpn-checkpoint-invitation.json']);
  const before = await authority();
  assert.equal(before.revision, 0);
  assert.ok(!before.members.includes(joiner));
  const response = await download(approved, 'p2p-vpn-checkpoint-response.json');
  const committed = await authority();
  assert.equal(committed.revision, 1);
  assert.ok(committed.members.includes(joiner));
  assert.equal(await page.locator('#checkpoint-approved-peer').textContent(), joiner);
  native.send(response);
  const result = {};
  while (!result.packet_accepted) Object.assign(result, JSON.parse(await native.line()));
  assert.equal(result.incumbent_applied, 1);
  assert.deepEqual(result.activated_rank, JSON.parse(response).payload.checkpoint.minimum);
  assert.deepEqual(writes, [], 'the app must not upload local enrollment artifacts');
}
