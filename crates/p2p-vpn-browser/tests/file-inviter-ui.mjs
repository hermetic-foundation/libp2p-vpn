import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

test('detached inviter previews the signed request and downloads only after approval', {
  timeout: 30_000,
}, async t => {
  const { P2P_VPN_BIN, P2P_VPN_PAIRING_PKG } = process.env;
  assert.ok(P2P_VPN_BIN && P2P_VPN_PAIRING_PKG);
  const keys = execFileSync(P2P_VPN_BIN, ['keygen', '--output', '-'], { encoding: 'utf8' });
  const peer = /^peer_id: (\S+)$/m.exec(keys)[1];
  const address = '/ip4/192.0.2.1/udp/4433/webrtc-direct/'
    + 'certhash/uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w/p2p/' + peer;
  const config = JSON.stringify({ network: {
    name: 'inviter-page', local_peer: peer, private_key: /^private_key: (\S+)$/m.exec(keys)[1],
    external_addresses: [address],
  } });
  const files = new Map([['/joiner', ['text/html', '<!doctype html><title>Joiner fixture</title>']]]);
  for (const [name, type] of [
    ['file-inviter.html', 'text/html'], ['file-inviter.js', 'text/javascript'], ['app.css', 'text/css'],
  ]) {
    files.set('/' + name, [type, await readFile(new URL(`../web/${name}`, import.meta.url))]);
  }
  for (const [name, type] of [
    ['p2p_vpn_browser.js', 'text/javascript'], ['p2p_vpn_browser_bg.wasm', 'application/wasm'],
  ]) {
    files.set('/pkg/' + name, [type, await readFile(join(P2P_VPN_PAIRING_PKG, name))]);
  }
  files.set('/pkg/logo.svg', ['image/svg+xml', await readFile(
    new URL('../../../assets/p2p-vpn-logo.svg', import.meta.url),
  )]);
  const web = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  web.listen(0, '127.0.0.1');
  await once(web, 'listening');
  t.after(() => new Promise(resolve => web.close(resolve)));
  const origin = `http://127.0.0.1:${web.address().port}`;
  const browser = await chromium.launch(process.env.P2P_VPN_CHROMIUM
    ? { executablePath: process.env.P2P_VPN_CHROMIUM } : { channel: 'chrome' });
  t.after(() => browser.close());
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const unexpected = [];
  context.on('request', request => {
    const url = new URL(request.url());
    if (url.origin !== origin || !files.has(url.pathname)
      || request.method() !== 'GET' || request.postData() !== null) {
      unexpected.push('Non-asset browser request');
    }
  });
  const inviter = await context.newPage();
  const joiner = await context.newPage();
  await joiner.goto(origin + '/joiner');
  await inviter.goto(origin + '/file-inviter.html');
  await inviter.getByText(/Disconnect any VPN using this identity/).waitFor();
  await inviter.getByLabel('Founder config').setInputFiles({
    name: 'founder.json', mimeType: 'application/json', buffer: Buffer.from(config),
  });
  await inviter.getByRole('button', { name: 'Open session' }).click();
  await inviter.getByRole('button', { name: 'Create offer' }).click();
  const offerDownload = inviter.waitForEvent('download');
  await inviter.getByRole('button', { name: 'Download offer' }).click();
  const offerFile = await offerDownload;
  assert.equal(offerFile.suggestedFilename(), 'p2p-vpn-offer.pair');
  const offer = await readFile(await offerFile.path(), 'utf8');
  assert.match(offer, /^p2pvpn:/);
  const request = await joiner.evaluate(async uri => {
    const { default: init, BrowserPairing } = await import('/pkg/p2p_vpn_browser.js');
    await init();
    const pairing = new BrowserPairing();
    window.enrollment = pairing.begin_offline(uri, 'new-browser');
    pairing.free();
    return window.enrollment.request_json();
  }, offer);
  const signed = JSON.parse(request);
  const tampered = structuredClone(signed);
  tampered.payload.requested_hostname = 'changed-name';
  async function review(body) {
    await inviter.getByLabel('Signed request file').setInputFiles({
      name: 'request.json', mimeType: 'application/json', buffer: Buffer.from(body),
    });
    await inviter.getByRole('button', { name: 'Verify request' }).click();
  }
  await review(JSON.stringify(tampered));
  await inviter.getByRole('alert').filter({ hasText: 'invalid signed pairing request' }).waitFor();
  assert.equal(await inviter.getByRole('button', { name: 'Approve peer' }).isVisible(), false);
  await review(request);
  const preview = inviter.getByRole('heading', { name: 'Verified request' });
  await preview.waitFor();
  assert.ok(await preview.evaluate(heading => document.activeElement === heading));
  await inviter.getByText(signed.payload.joiner_peer, { exact: true }).waitFor();
  await inviter.getByText('new-browser', { exact: true }).waitFor();
  assert.equal(await inviter.getByRole('button', { name: 'Download response' }).isVisible(), false);
  const ledgerKey = `p2p-vpn:legacy-membership:1:${JSON.stringify(['inviter-page', peer])}`;
  assert.equal(await inviter.evaluate(key => localStorage.getItem(key), ledgerKey), null);
  assert.ok(await inviter.evaluate(() =>
    document.documentElement.scrollWidth === document.documentElement.clientWidth));
  if (process.env.P2P_VPN_INVITER_SCREENSHOT) {
    await inviter.screenshot({ path: process.env.P2P_VPN_INVITER_SCREENSHOT, fullPage: true });
  }
  await inviter.getByRole('button', { name: 'Approve peer' }).click();
  await inviter.getByRole('status').filter({ hasText: /^Approved$/ }).waitFor();
  const saved = JSON.parse(await inviter.evaluate(key => localStorage.getItem(key), ledgerKey));
  assert.ok(saved.some(record => record.payload.member_peer === signed.payload.joiner_peer));
  assert.ok(await inviter.getByRole('button', { name: 'Finish' }).isDisabled());
  const responseDownload = inviter.waitForEvent('download');
  await inviter.getByRole('button', { name: 'Download response' }).click();
  const responseFile = await responseDownload;
  assert.equal(responseFile.suggestedFilename(), 'p2p-vpn-response.json');
  const response = await readFile(await responseFile.path(), 'utf8');
  const accepted = await joiner.evaluate(({ response, address }) => {
    const result = JSON.parse(window.enrollment.accept_response(response, address));
    return { kind: result.kind, localPeer: result.config.network.local_peer };
  }, { response, address });
  assert.deepEqual(accepted, { kind: 'legacy', localPeer: signed.payload.joiner_peer });
  await inviter.getByRole('button', { name: 'Finish' }).click();
  await inviter.getByRole('button', { name: 'Close session' }).click();
  await inviter.getByRole('status').filter({ hasText: /^Closed$/ }).waitFor();
  assert.deepEqual(unexpected, []);
});
