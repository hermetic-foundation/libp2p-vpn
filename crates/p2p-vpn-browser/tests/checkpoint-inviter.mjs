import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';
import { chromium } from 'playwright';

test('Chromium commits checkpoint issuance but an undialed joiner stays gated', {
  timeout: 30_000,
}, async t => {
  const {
    P2P_VPN_CHECKPOINT_INVITER_PKG: fixturePkg,
    P2P_VPN_PAIRING_PKG: browserPkg,
    P2P_VPN_CHROMIUM: executablePath,
  } = process.env;
  assert.ok(fixturePkg && browserPkg, 'set both WASM package directories');
  const files = new Map([['/', ['text/html', '<!doctype html><title>Checkpoint issuer test</title>']]]);
  for (const [pkg, stem] of [[fixturePkg, 'checkpoint_inviter_fixture'], [browserPkg, 'p2p_vpn_browser']]) {
    files.set(`/${stem}.js`, ['text/javascript', await readFile(join(pkg, `${stem}.js`))]);
    files.set(`/${stem}_bg.wasm`, ['application/wasm', await readFile(join(pkg, `${stem}_bg.wasm`))]);
  }
  const server = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0], 'Cache-Control': 'no-store' }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  const origin = `http://127.0.0.1:${server.address().port}/`;
  const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const issuer = await context.newPage();
  const otherTab = await context.newPage();
  await Promise.all([issuer.goto(origin), otherTab.goto(origin)]);

  const issuerPeer = await issuer.evaluate(async () => {
    const fixture = await import('/checkpoint_inviter_fixture.js');
    await fixture.default();
    window.issuer = await fixture.CheckpointIssuerFixture.form();
    return JSON.parse(window.issuer.offer_json()).payload.inviter_peer;
  });
  const canLock = () => otherTab.evaluate(async peer => {
    const fixture = await import('/checkpoint_inviter_fixture.js');
    await fixture.default();
    return fixture.can_lock_issuer(peer);
  }, issuerPeer);
  assert.equal(await canLock(), false);

  const observed = await issuer.evaluate(async () => {
    const { default: init, BrowserPairing, BrowserVpn } = await import('/p2p_vpn_browser.js');
    await init();
    const passphrase = 'checkpoint fixture passphrase';
    const offer = window.issuer.offer_json();
    const { network_name: network, inviter_peer: inviter } = JSON.parse(offer).payload;
    const pairing = new BrowserPairing();
    const joiner = pairing.peer_id();
    const enrollment = pairing.begin_offline(offer, undefined);
    const request = enrollment.request_json();
    const issued = await window.issuer.approve(request);
    const { minimum } = JSON.parse(issued).payload.checkpoint;
    const artifacts = JSON.parse(enrollment.accept_response(issued, ''));
    const activation = enrollment.take_checkpoint_activation();
    const vpn = await BrowserVpn.open_checkpoint_activation(activation);
    try {
      const snapshot = JSON.parse(vpn.snapshot());
      const stored = peer => JSON.parse(localStorage.getItem(
        `p2p-vpn:checkpoint-membership:1:${JSON.stringify([network, peer])}`,
      )).payload;
      const retained = stored(inviter);
      const provisional = stored(joiner);
      const backup = JSON.parse(await window.issuer.encrypted_backup(passphrase));
      let exportDenied = false;
      try {
        await vpn.export_checkpoint_credentials(passphrase);
      } catch (error) {
        exportDenied = /connect an authorized checkpoint peer/i.test(error.message);
      }
      let secondApprovalDenied = false;
      try {
        await window.issuer.approve(request);
      } catch {
        secondApprovalDenied = true;
      }
      return {
        kind: artifacts.kind, joiner, minimum, snapshot, exportDenied, secondApprovalDenied,
        issuerRevision: retained.retained.snapshot.payload.authority_revision,
        issuerPeers: retained.retained.snapshot.payload.members.map(member => member.subject.peer_id),
        issuerFloor: retained.enrollment_floor,
        pendingFloor: provisional.enrollment_floor,
        pendingRevision: provisional.retained.snapshot.payload.authority_revision,
        backupFields: Object.keys(backup).sort(),
        rawSecretInStore: /private_key|capability_secret/.test(JSON.stringify([retained, provisional])),
      };
    } finally {
      await vpn.close();
      vpn.free();
      enrollment.free();
      pairing.free();
    }
  });
  assert.equal(observed.kind, 'checkpoint');
  assert.deepEqual(new Set(observed.issuerPeers), new Set([issuerPeer, observed.joiner]));
  assert.equal(observed.issuerRevision, 1);
  assert.equal(observed.minimum.authority_revision, 1);
  assert.equal(observed.issuerFloor, null);
  assert.deepEqual(observed.pendingFloor, observed.minimum);
  assert.equal(observed.pendingRevision, 0);
  assert.equal(observed.snapshot.remote_peer_id, issuerPeer);
  assert.equal(observed.snapshot.transport, 'circuit-relay');
  assert.equal(observed.snapshot.authorized, false);
  assert.equal(observed.snapshot.ready, false);
  assert.equal(observed.snapshot.checkpoint.sync, 'resync_required');
  assert.equal(observed.snapshot.counters.connections, 0);
  assert.equal(observed.exportDenied, true);
  assert.equal(observed.secondApprovalDenied, true);
  assert.deepEqual(observed.backupFields, ['ciphertext', 'nonce', 'salt', 'version']);
  assert.equal(observed.rawSecretInStore, false);
  assert.equal(await canLock(), false);
  await issuer.evaluate(async () => {
    await window.issuer.close();
    window.issuer.free();
  });
  assert.equal(await canLock(), true);
});
