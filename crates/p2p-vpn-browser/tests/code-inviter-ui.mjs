// Run in the Linux browser gate's isolated underlay. Requires the production
// WASM, native companion, and native one-reservation relay fixture.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
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

test('the served code invitation previews approval and activates one reservation', { timeout: 60_000 }, async t => {
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
  const inviter = await browser.newPage({ viewport: { width: 360, height: 800 } });
  const joiner = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  const effects = [];
  for (const page of [inviter, joiner]) {
    page.setDefaultTimeout(15_000);
    page.on('request', request => effects.push([request.method(), new URL(request.url()).pathname]));
    page.on('pageerror', failure => effects.push(['pageerror', failure.name]));
  }

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
    assert.equal(await inviter.locator('input[type=file]').count(), 0);
    assert.equal(await joiner.locator('input[type=file]').count(), 0);
    if (screenshots) await inviter.screenshot({ path: join(screenshots, 'code-inviter-360.png') });

    const pin = await joiner.locator('#local-joiner').textContent();
    assert.ok(pin?.length > 32);
    for (const [label, text] of [
      ['Network name', 'explicit-code-ui'], ['Joiner peer ID', pin],
      ['Inviter VPN address', '10.80.0.1'], ['Joiner VPN address', '10.80.0.2'],
      ['Pinned WebRTC Direct relay address', entrance],
    ]) await inviter.getByLabel(label, { exact: true }).fill(text);
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
    const allowed = new Set(['/app.html', '/app.js', '/app.css', '/code-inviter.html',
      '/code-inviter.js', '/pkg/logo.svg', '/pkg/p2p_vpn_browser.js', '/pkg/p2p_vpn_browser_bg.wasm']);
    assert.ok(effects.every(([method, pathname]) => method === 'GET' && allowed.has(pathname)),
      JSON.stringify(effects));
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
