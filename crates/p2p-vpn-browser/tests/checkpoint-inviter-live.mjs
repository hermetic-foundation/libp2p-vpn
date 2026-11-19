import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFile, readlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
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
  };
}

test('Chromium checkpoint issuer serves a new native member on its reserved circuit',
  { timeout: 105_000 }, t => exercise(t, false));
test('the served app approves a reviewed checkpoint request over a live reservation',
  { timeout: 105_000 }, t => exercise(t, true));
test('the served app admits a code applicant only after durable approval and checkpoint sync',
  { timeout: 105_000 }, t => exercise(t, true, 'native'));
test('two served browser apps complete checkpoint enrollment by code',
  { timeout: 105_000 }, t => exercise(t, true, 'browser'));

async function exercise(t, app, code = false) {
  const {
    P2P_VPN_CHECKPOINT_INVITER_NATIVE: nativeBinary,
    P2P_VPN_RELAY_FIXTURE: relayBinary,
    P2P_VPN_PAIRING_PKG: pkg,
    P2P_VPN_TEST_NETNS: parentNamespace,
    P2P_VPN_CHROMIUM: executablePath,
  } = process.env;
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
  const publicLocator = code === 'browser';
  const relay = await fixture(t, relayBinary, '11.250.0.2', ...(publicLocator ? ['--locator-dht'] : []));
  const opening = await relay.line();
  const { webrtc: entrance, tcp } = publicLocator ? JSON.parse(opening) : { webrtc: opening };
  assert.match(entrance, /^\/ip4\/11\.250\.0\.2\/udp\/\d+\/webrtc-direct\/certhash\/[^/]+\/p2p\/[^/]+$/);
  const native = await fixture(t, nativeBinary, entrance);
  const seed = JSON.parse(await native.line());
  if (app) return exerciseApp(t, native, seed, executablePath, code, tcp && { relayBinary, tcp });
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

async function exerciseApp(t, native, seed, executablePath, byCode, discovery) {
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
    if (discovery) await page.locator('#checkpoint-code-publication').filter({ hasText: /^Announced$/ }).waitFor();
    await cancel.click();
    await start.click();
    await value.filter({ hasText: /\S/ }).waitFor();
    const code = await value.textContent();
    assert.ok(code && code !== discarded);
    assert.equal(await approve.isDisabled(), true);
    if (discovery) {
      await page.locator('#checkpoint-code-publication').filter({ hasText: /^Announced$/ }).waitFor();
      const locator = await page.evaluate(async code => {
        const { pairing_code_v2_global_locator } = await import('/pkg/p2p_vpn_browser.js');
        return pairing_code_v2_global_locator(code);
      }, code);
      const found = execFileSync(discovery.relayBinary, ['--lookup-locator', discovery.tcp, locator], {
        encoding: 'utf8', timeout: 8_000,
      });
      const owner = seed.reservation.split('/').at(-1);
      assert.deepEqual(JSON.parse(found), [{ peer: owner, addresses: [`${discovery.tcp}/p2p-circuit/p2p/${owner}`] }]);
    }
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
