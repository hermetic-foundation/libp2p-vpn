// Run in the Linux browser gate's isolated underlay. Requires the production
// WASM, native companion, and native one-reservation relay fixture.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readlink, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

function launch(t, binary, ...args) {
  const proc = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = once(proc, 'close');
  closed.catch(() => {});
  let logs = '';
  for (const stream of [proc.stdout, proc.stderr]) {
    stream.setEncoding('utf8').on('data', chunk => { logs = (logs + chunk).slice(-32_768); });
  }
  t.after(async () => {
    proc.kill();
    await closed.catch(() => {});
  });
  return {
    logs: () => logs,
    async ready(pattern) {
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline) {
        const match = pattern.exec(logs);
        if (match) return match[1];
        if (proc.exitCode !== null) break;
        await delay(25);
      }
      throw Error(`Missing start message from ${binary}: ${logs}`);
    },
  };
}

async function ready(page, text) {
  await page.getByRole('status').filter({ hasText: text }).waitFor();
}

async function serveInvitation(t) {
  const { P2P_VPN_BIN: companion, P2P_VPN_RELAY_FIXTURE: fixture, P2P_VPN_PAIRING_PKG: pkg,
    P2P_VPN_CHROMIUM: executablePath, P2P_VPN_TEST_NETNS: outer, P2P_VPN_CODE_UI_SCREENSHOTS: screenshots } = process.env;
  assert.ok(companion && fixture && pkg);
  assert.match(outer ?? '', /^net:\[\d+\]$/);
  assert.notEqual(await readlink('/proc/self/ns/net'), outer);

  const assets = await mkdtemp(join(tmpdir(), 'p2p-vpn-code-inviter-'));
  t.after(() => rm(assets, { recursive: true, force: true }));
  await mkdir(join(assets, 'pkg'));
  for (const name of ['app.html', 'app.js', 'app.css', 'code-inviter.html', 'code-inviter.js']) {
    await copyFile(new URL(`../web/${name}`, import.meta.url), join(assets, name));
  }
  for (const name of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm']) {
    await copyFile(join(pkg, name), join(assets, 'pkg', name));
  }
  await copyFile(new URL('../../../assets/p2p-vpn-logo.svg', import.meta.url), join(assets, 'pkg/logo.svg'));
  await writeFile(join(assets, 'code-inviter.js.bak'), 'not a served asset');

  const host = launch(t, companion, 'browser-serve', '--assets', assets, '--port', '0');
  const origin = await host.ready(/Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html/);
  const relay = launch(t, fixture, '192.0.2.1');
  const entrance = await relay.ready(/^(\/ip4\/192\.0\.2\.1\/udp\/\d+\/webrtc-direct\/certhash\/\S+)$/m);
  const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
  t.after(() => browser.close());
  return { browser, companion, entrance, origin, relay, screenshots };
}

function watchRequests(page, effects) {
  page.setDefaultTimeout(15_000);
  page.on('request', request => {
    const { pathname, search } = new URL(request.url());
    effects.push([request.method(), pathname, Boolean(search || request.postData())]);
  });
  page.on('pageerror', failure => effects.push(['pageerror', failure.name]));
}

function onlyStaticRequests(effects) {
  const allowed = new Set(['/app.html', '/app.js', '/app.css', '/code-inviter.html',
    '/code-inviter.js', '/pkg/logo.svg', '/pkg/p2p_vpn_browser.js', '/pkg/p2p_vpn_browser_bg.wasm']);
  assert.ok(effects.every(([method, pathname, hasPayload]) => method === 'GET'
    && allowed.has(pathname) && !hasPayload), JSON.stringify(effects));
}

test('the served code invitation previews approval and activates one reservation', { timeout: 60_000 }, async t => {
  const { browser, entrance, origin, relay, screenshots } = await serveInvitation(t);
  const inviter = await browser.newPage({ viewport: { width: 360, height: 800 } });
  const joiner = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  const effects = [];
  for (const page of [inviter, joiner]) watchRequests(page, effects);

  try {
    const pages = await Promise.all([
      inviter.goto(origin + '/app.html'),
      joiner.goto(origin + '/code-inviter.html#join'),
    ]);
    assert.deepEqual(pages.map(page => page.status()), [200, 200]);
    await inviter.getByRole('link', { name: 'Create or join an explicit code invitation' }).click();
    await Promise.all([ready(inviter, 'Ready'), ready(joiner, 'Ready')]);
    const backup = await inviter.request.get(origin + '/code-inviter.js.bak');
    assert.equal(backup.status(), 404);
    assert.equal(await inviter.locator('input[type=file]:visible').count(), 0);
    assert.equal(await joiner.locator('input[type=file]:visible').count(), 0);
    if (screenshots) await inviter.screenshot({ path: join(screenshots, 'code-inviter-360.png') });

    const pin = await joiner.locator('#local-joiner').textContent();
    assert.ok(pin?.length > 32);
    for (const [label, text] of [
      ['Network name', 'explicit-code-ui'], ['Joiner peer ID', pin],
      ['Inviter VPN address', '10.80.0.1'], ['Joiner VPN address', '10.80.0.2'],
      ['Pinned WebRTC Direct relay address', entrance],
    ]) await inviter.locator('#create-form').getByLabel(label, { exact: true }).fill(text);
    await inviter.getByRole('button', { name: 'Reserve relay' }).click();
    await ready(inviter, 'Waiting for joiner');
    const address = await inviter.locator('#invite-address').textContent();
    const peer = await inviter.locator('#inviter-peer').textContent();
    assert.equal(address, `${entrance}/p2p-circuit/p2p/${peer}`);
    await joiner.getByLabel('Private v2 code').fill(await inviter.locator('#invite-code').textContent());
    await joiner.getByLabel('Inviter peer ID').fill(pin);
    await joiner.getByLabel('Circuit address').fill(address);
    await joiner.getByRole('button', { name: 'Request approval' }).click();
    await joiner.getByRole('alert').filter({ hasText: 'must end in the inviter peer ID' }).waitFor();
    await joiner.getByLabel('Inviter peer ID').fill(peer);
    await joiner.getByLabel('Hostname (optional)').fill('reviewed-joiner');
    await joiner.getByRole('button', { name: 'Request approval' }).click();

    await Promise.all([ready(inviter, 'Approval required'), ready(joiner, 'Waiting for inviter approval')]);
    assert.equal(await inviter.locator('#candidate-peer').textContent(), pin);
    assert.equal(await inviter.locator('#candidate-name').textContent(), 'reviewed-joiner');
    assert.equal(await inviter.locator('#candidate-ip').textContent(), '10.80.0.2');
    assert.equal(await inviter.locator('#review-title').evaluate(el => document.activeElement === el), true);
    for (const page of [inviter, joiner]) assert.equal(await page.locator('#active').isVisible(), false);
    assert.equal([...relay.logs().matchAll(/CircuitReqAccepted/g)].length, 1);
    assert.ok(await inviter.evaluate(() => document.documentElement.scrollWidth <= innerWidth));

    await inviter.getByRole('button', { name: 'Approve peer' }).click();
    await Promise.all([ready(inviter, 'VPN connected'), ready(joiner, 'VPN connected')]);
    for (const [page, local, remote] of [[inviter, peer, pin], [joiner, pin, peer]]) {
      assert.equal(await page.locator('#active-local').textContent(), local);
      assert.equal(await page.locator('#active-remote').textContent(), remote);
      assert.equal(await page.locator('#active-address').textContent(), address);
      assert.equal(await page.locator('#active-transport').textContent(), 'Circuit Relay v2');
    }
    assert.equal(await inviter.locator('#invite-code').textContent(), '');
    assert.equal(await joiner.locator('#entered-code').inputValue(), '');
    assert.equal([...relay.logs().matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1);
    assert.ok([...relay.logs().matchAll(/CircuitReqAccepted/g)].length >= 2);
    assert.doesNotMatch(relay.logs(), /ReservationReqDenied/);
    onlyStaticRequests(effects);
    if (screenshots) await joiner.screenshot({ path: join(screenshots, 'code-inviter-active-1280.png') });

    await inviter.getByRole('button', { name: 'End session' }).click();
    await ready(inviter, 'Ready');
    assert.equal(await inviter.locator('#active').isVisible(), false);
  } catch (failure) {
    const statuses = await Promise.all([inviter, joiner].map(page => page.locator('#state').textContent()
      .catch(() => 'not loaded')));
    throw Error(`${failure.message}\nPage states: ${JSON.stringify(statuses)}\n${relay.logs()}`, { cause: failure });
  }
});

test('the served existing legacy invitation requires a rooted unlocked issuer and a successful save',
  { timeout: 60_000 }, async t => {
    const { browser, companion, entrance, origin, relay, screenshots } = await serveInvitation(t);
    const inviter = await browser.newPage({ viewport: { width: 360, height: 800 } });
    const joiner = await browser.newPage();
    const effects = [];
    for (const page of [inviter, joiner]) watchRequests(page, effects);
    const pages = await Promise.all([
      inviter.goto(origin + '/code-inviter.html'),
      joiner.goto(origin + '/code-inviter.html#join'),
    ]);
    assert.deepEqual(pages.map(page => page.status()), [200, 200]);
    await Promise.all([ready(inviter, 'Ready'), ready(joiner, 'Ready')]);
    await inviter.getByRole('button', { name: 'Invite to existing network' }).click();
    const issuerFile = inviter.getByLabel('Issuer legacy JSON config');
    const openIssuer = inviter.getByRole('button', { name: 'Open issuer and reserve relay' });
    assert.ok(await issuerFile.isVisible());
    if (screenshots) await inviter.screenshot({ path: join(screenshots, 'code-inviter-existing-360.png') });

    const keys = execFileSync(companion, ['keygen', '--output', '-'], { encoding: 'utf8' });
    const network = {
      name: 'existing-code-ui',
      local_peer: /^peer_id: (\S+)$/m.exec(keys)[1],
      private_key: /^private_key: (\S+)$/m.exec(keys)[1],
    };
    const seeded = await inviter.evaluate(async ({ network, entrance }) => {
      const { BrowserFileInviter, BrowserPairing } = await import('/pkg/p2p_vpn_browser.js');
      const circuit = peer => `${entrance}/p2p-circuit/p2p/${peer}`;
      const enroll = (issuer, guest, hostname) => {
        const enrollment = guest.begin_offline(issuer.create_offer(), hostname);
        issuer.review_request(enrollment.request_json());
        const response = issuer.approve(guest.peer_id());
        return JSON.parse(enrollment.accept_response(response, circuit(enrollment.inviter_peer()))).config;
      };
      network.external_addresses = [circuit(network.local_peer)];
      const founder = await BrowserFileInviter.open(JSON.stringify({ network }));
      const config = enroll(founder, new BrowserPairing(), 'delegated-issuer');
      await founder.close();
      config.network.external_addresses = [circuit(config.network.local_peer)];
      const delegated = await BrowserFileInviter.open(JSON.stringify(config));
      const oldMember = new BrowserPairing();
      enroll(delegated, oldMember, 'old-member');
      window.testIssuerLock = delegated;
      const key = 'p2p-vpn:legacy-membership:1:' + JSON.stringify([network.name, config.network.local_peer]);
      return { config, key, oldMember: oldMember.peer_id(), ledger: localStorage.getItem(key) };
    }, { network, entrance });
    const pin = await joiner.locator('#local-joiner').textContent();
    const selectConfig = config => issuerFile.setInputFiles({
      name: 'issuer.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(config)),
    });
    const form = inviter.locator('#existing-form');
    await form.getByLabel('Joiner peer ID', { exact: true }).fill(pin);
    await form.getByLabel('Pinned WebRTC Direct relay address', { exact: true }).fill(entrance);
    await selectConfig(seeded.config);
    await openIssuer.click();
    await inviter.getByRole('alert').filter({ hasText: 'issuer identity is in use' }).waitFor();
    await inviter.evaluate(() => window.testIssuerLock.close());
    await selectConfig({ ...seeded.config, network: { ...seeded.config.network, member_records: [] } });
    await openIssuer.click();
    await inviter.getByRole('alert').filter({ hasText: 'rooted legacy issuer config' }).waitFor();
    assert.doesNotMatch(relay.logs(), /ReservationReqAccepted/);

    await selectConfig(seeded.config);
    await openIssuer.click();
    await ready(inviter, 'Waiting for joiner');
    assert.equal(await issuerFile.inputValue(), '');
    const ownerPeer = seeded.config.network.local_peer;
    const address = await inviter.locator('#invite-address').textContent();
    assert.equal(address, `${entrance}/p2p-circuit/p2p/${ownerPeer}`);
    await joiner.getByLabel('Private v2 code').fill(await inviter.locator('#invite-code').textContent());
    await joiner.getByLabel('Inviter peer ID').fill(ownerPeer);
    await joiner.getByLabel('Circuit address').fill(address);
    await joiner.getByLabel('Hostname (optional)').fill('existing-review');
    await joiner.getByRole('button', { name: 'Request approval' }).click();
    await Promise.all([ready(inviter, 'Approval required'), ready(joiner, 'Waiting for inviter approval')]);
    assert.equal(await inviter.locator('#candidate-peer').textContent(), pin);
    assert.equal(await inviter.locator('#candidate-name').textContent(), 'existing-review');
    assert.match(await inviter.locator('#candidate-ip').textContent(), /^100\.64\.\d+\.\d+$/);

    await inviter.evaluate(key => {
      const setItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function (name, value) {
        if (name === key) {
          Storage.prototype.setItem = setItem;
          throw new DOMException('Test quota', 'QuotaExceededError');
        }
        return setItem.call(this, name, value);
      };
    }, seeded.key);
    const approve = inviter.getByRole('button', { name: 'Approve peer' });
    await approve.click();
    await inviter.getByRole('alert').filter({ hasText: 'Approval was not sent' }).waitFor();
    assert.equal(await inviter.evaluate(key => localStorage.getItem(key), seeded.key), seeded.ledger);
    assert.equal(await inviter.locator('#invite-address').textContent(), address);
    assert.equal(await joiner.locator('#active').isVisible(), false);
    assert.equal([...relay.logs().matchAll(/CircuitReqAccepted/g)].length, 1);
    await approve.click();
    await Promise.all([ready(inviter, 'VPN connected'), ready(joiner, 'VPN connected')]);
    assert.equal(await inviter.locator('#active-local').textContent(), ownerPeer);
    assert.equal(await inviter.locator('#active-remote').textContent(), pin);
    assert.equal(await inviter.locator('#active-address').textContent(), address);
    assert.equal(await joiner.locator('#active-remote').textContent(), ownerPeer);
    assert.equal(await inviter.getByRole('alert').isVisible(), false);
    const persisted = await inviter.evaluate(key => JSON.parse(localStorage.getItem(key)).records, seeded.key);
    const old = JSON.parse(seeded.ledger);
    assert.ok(old.some(record => record.payload.member_peer === seeded.oldMember));
    assert.equal(persisted.length, old.length + 1);
    assert.ok(old.every(record => persisted.some(entry => record.signature === entry.signature)));
    const grant = persisted.find(record => record.payload.member_peer === pin).payload;
    assert.equal(grant.issuer_peer, ownerPeer);
    assert.deepEqual(grant.roles, ['overlay_member']);
    assert.doesNotMatch(JSON.stringify(persisted), /"private_key"/);
    assert.equal(await inviter.evaluate(key => navigator.locks.request(key, { ifAvailable: true }, Boolean),
      seeded.key), false);
    assert.equal([...relay.logs().matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1, relay.logs());
    assert.doesNotMatch(relay.logs(), /ReservationReqDenied/);
    await inviter.getByRole('button', { name: 'End session' }).click();
    await ready(inviter, 'Ready');
    assert.equal(await inviter.evaluate(key => navigator.locks.request(key, { ifAvailable: true }, Boolean),
      seeded.key), true);
    assert.deepEqual(await inviter.evaluate(key => JSON.parse(localStorage.getItem(key)).records, seeded.key), persisted);
    onlyStaticRequests(effects);
  });
