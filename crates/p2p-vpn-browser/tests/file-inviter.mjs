import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

test('browser founder saves signed legacy membership before releasing the response', {
  timeout: 25_000,
}, async t => {
  const { P2P_VPN_BIN, P2P_VPN_PAIRING_PKG } = process.env;
  assert.ok(P2P_VPN_BIN && P2P_VPN_PAIRING_PKG);
  const keys = execFileSync(P2P_VPN_BIN, ['keygen', '--output', '-'], { encoding: 'utf8' });
  const config = { network: {
    name: 'file-inviter-test',
    local_peer: /^peer_id: (\S+)$/m.exec(keys)[1],
    private_key: /^private_key: (\S+)$/m.exec(keys)[1],
  } };
  const address = '/ip4/192.0.2.1/udp/4433/webrtc-direct/'
    + 'certhash/uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w/p2p/' + config.network.local_peer;
  config.network.external_addresses = [address];
  const files = new Map([
    ['/', ['text/html', '<!doctype html><title>File inviter fixture</title>']],
    ['/p2p_vpn_browser.js', ['text/javascript', await readFile(join(P2P_VPN_PAIRING_PKG, 'p2p_vpn_browser.js'))]],
    ['/p2p_vpn_browser_bg.wasm', ['application/wasm', await readFile(join(P2P_VPN_PAIRING_PKG, 'p2p_vpn_browser_bg.wasm'))]],
  ]);
  const server = createServer((req, res) => {
    const file = req.method === 'GET' && files.get(req.url);
    if (!file) return res.writeHead(404).end();
    res.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const browser = await chromium.launch(process.env.P2P_VPN_CHROMIUM
    ? { executablePath: process.env.P2P_VPN_CHROMIUM }
    : { channel: 'chrome' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const requests = [];
  page.on('request', request => {
    if (request.method() !== 'GET' || !files.has(new URL(request.url()).pathname)) {
      requests.push('Unexpected non-asset request');
    }
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const observed = await page.evaluate(async ({ configJson, address }) => {
    const { default: init, BrowserFileInviter, BrowserPairing } = await import('/p2p_vpn_browser.js');
    await init();
    const fail = async operation => {
      try { await operation(); return null; } catch (error) { return error.message; }
    };
    const inviter = await BrowserFileInviter.open(configJson);
    const overlap = await fail(() => BrowserFileInviter.open(configJson));
    const joiner = new BrowserPairing();
    const peer = joiner.peer_id();
    const enrollment = joiner.begin_offline(inviter.create_offer(), 'guest-node');
    const request = enrollment.request_json();
    const premature = await fail(() => inviter.approve(peer));
    const tampered = JSON.parse(request);
    tampered.payload.requested_hostname = 'altered-name';
    const wrongSignature = await fail(() => inviter.review_request(JSON.stringify(tampered)));
    const review = JSON.parse(inviter.review_request(request));
    const wrongApproval = await fail(() => inviter.approve('different-peer'));
    const key = 'p2p-vpn:legacy-membership:1:'
      + JSON.stringify(['file-inviter-test', enrollment.inviter_peer()]);
    const before = localStorage.getItem(key);
    const write = Storage.prototype.setItem;
    Storage.prototype.setItem = function (name, value) {
      if (name === key) throw new DOMException('Test quota', 'QuotaExceededError');
      return write.call(this, name, value);
    };
    let failedWrite;
    try { failedWrite = await fail(() => inviter.approve(review.joiner_peer)); }
    finally { Storage.prototype.setItem = write; }
    const failedLedger = localStorage.getItem(key);
    const response = inviter.approve(review.joiner_peer);
    const repeat = await fail(() => inviter.approve(review.joiner_peer));
    const saved = localStorage.getItem(key);
    const output = JSON.parse(enrollment.accept_response(response, address));
    await inviter.close();
    const reopened = await BrowserFileInviter.open(configJson);
    const staleOffer = await fail(() => reopened.review_request(request));
    const repeatJoiner = joiner.begin_offline(reopened.create_offer());
    const priorMember = await fail(() => reopened.review_request(repeatJoiner.request_json()));
    await reopened.close();
    return { overlap, premature, wrongSignature, review, wrongApproval, before, failedWrite,
      failedLedger, repeat, staleOffer, priorMember, peer,
      admitted: JSON.parse(saved).some(entry => entry.payload.member_peer === peer),
      responseMatchesLedger: JSON.parse(response).payload.member_records.every(record =>
        JSON.parse(saved).some(entry => entry.signature === record.signature)),
      leakedPrivateKey: saved.includes('private_key') || response.includes('private_key'),
      output: { kind: output.kind, peer: output.config.network.local_peer, dial: output.dial_address },
    };
  }, { configJson: JSON.stringify(config), address });
  assert.match(observed.overlap, /identity is in use/);
  assert.match(observed.premature, /No reviewed request/);
  assert.match(observed.wrongSignature, /invalid signed pairing request/);
  assert.equal(observed.review.joiner_peer, observed.peer);
  assert.equal(observed.review.requested_hostname, 'guest-node');
  assert.match(observed.wrongApproval, /did not name the reviewed joiner/);
  assert.equal(observed.before, null);
  assert.match(observed.failedWrite, /Could not save/);
  assert.equal(observed.failedLedger, null);
  assert.match(observed.repeat, /No active offer/);
  assert.match(observed.staleOffer, /No active offer/);
  assert.match(observed.priorMember, /no prior membership/);
  assert.equal(observed.admitted, true);
  assert.equal(observed.responseMatchesLedger, true);
  assert.equal(observed.leakedPrivateKey, false);
  assert.deepEqual(observed.output, { kind: 'legacy', peer: observed.peer, dial: address });
  assert.deepEqual(requests, []);
});
