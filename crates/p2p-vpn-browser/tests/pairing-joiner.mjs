// Build the native daemon with the webrtc feature and the production browser
// package with scripts/build-browser.sh (no test hooks).
// Set P2P_VPN_BIN and P2P_VPN_PAIRING_PKG to the daemon binary and <pkg>.
// Run with Playwright installed, Chromium, and TUN access:
// unshare --user --map-root-user --mount --net --pid --fork --kill-child=SIGKILL --mount-proc -- sh -ec '
//   ip link set lo up
//   ip link add pv-pairing type dummy
//   ip address add 192.0.2.1/24 dev pv-pairing
//   ip link set pv-pairing up
//   node --test crates/p2p-vpn-browser/tests/pairing-joiner.mjs
// '
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

test('production browser pairing activates the approved legacy config over WebRTC Direct', {
  timeout: 60_000,
}, () => exercisePairing('legacy'));

test('production browser pairing returns checkpoint credentials without a legacy config', {
  timeout: 60_000,
}, () => exercisePairing('checkpoint'));

test('browser app completes code-only enrollment after approval', {
  timeout: 60_000,
}, () => exercisePairing('legacy', true));

async function exercisePairing(kind, app = false) {
  const binary = process.env.P2P_VPN_BIN;
  const pkg = process.env.P2P_VPN_PAIRING_PKG;
  assert.ok(binary && pkg, 'set P2P_VPN_BIN and P2P_VPN_PAIRING_PKG');
  const files = new Map([['/', ['text/html', '<!doctype html><title>Pairing fixture</title>']]]);
  for (const [file, mime] of [
    ['p2p_vpn_browser.js', 'text/javascript'],
    ['p2p_vpn_browser_bg.wasm', 'application/wasm'],
  ]) {
    const bytes = await readFile(join(pkg, file));
    files.set(`/${file}`, [mime, bytes]);
    if (app) files.set(`/pkg/${file}`, [mime, bytes]);
  }
  if (app) {
    for (const [file, mime] of [
      ['app.html', 'text/html'], ['app.js', 'text/javascript'], ['app.css', 'text/css'],
    ]) {
      let bytes = await readFile(new URL(`../web/${file}`, import.meta.url));
      if (file === 'app.html') {
        bytes = bytes.toString().replace('</head>',
          '<meta name="p2p-vpn-pairing" content="/api/pairing/locator"></head>');
      }
      files.set(`/${file}`, [mime, bytes]);
    }
    files.set('/pkg/logo.svg', ['image/svg+xml', await readFile(join(pkg, 'logo.svg'))]);
  }
  const lookups = [];
  let inviterAddress;
  const web = createServer(async (req, res) => {
    if (app && req.method === 'POST' && req.url === '/api/pairing/locator') {
      try {
        let request = '';
        for await (const chunk of req) {
          request += chunk;
          if (request.length > 128) throw Error('unexpected pairing lookup body size');
        }
        lookups.push(JSON.parse(request));
        return res.writeHead(200, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ addresses: [inviterAddress] }));
      } catch {
        return res.writeHead(400).end();
      }
    }
    const file = req.method === 'GET' && files.get(req.url);
    if (!file) return res.writeHead(404).end();
    res.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  const directory = await mkdtemp(join(tmpdir(), 'p2p-vpn-pairing-joiner-'));
  const config = join(directory, 'native.json');
  const socket = join(directory, 'control.sock');
  const state = join(directory, 'pairing-state');
  const cli = (...args) => execFileSync(binary, args, { encoding: 'utf8', timeout: 5000 });
  const pair = (action, ...args) =>
    JSON.parse(cli('pair', action, ...args, '--socket', socket, '--format', 'json'));
  let daemon, exited, browser;
  let logs = '';
  async function waitFor(description, check, timeout = 12_000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline && daemon.exitCode === null && !daemon.signalCode) {
      const result = check();
      if (result) return result;
      await delay(100);
    }
    throw Error(`Did not see ${description}: ${logs.slice(-8000)}`);
  }
  try {
    cli('init-config', '--network', 'browser-pairing-test', '--interface', 'pvbrowser0', '--output', config);
    const native = JSON.parse(await readFile(config, 'utf8'));
    native.network.listen_addresses = ['/ip4/192.0.2.1/udp/0/webrtc-direct'];
    native.network.discovery = {
      mdns: false, kademlia: false, kademlia_provider_advertisement: false, dcutr: false, autonat: false,
    };
    native.network.packet_plane = { listen: [], quic_listen: [] };
    await writeFile(config, JSON.stringify(native), { mode: 0o600 });
    daemon = spawn(binary, [
      'up', '-c', config, '--control-socket', socket, '--pairing-state', state,
      ...(kind === 'checkpoint' ? ['--membership-state', join(directory, 'membership-state')] : []),
    ], { stdio: ['ignore', 'ignore', 'pipe'] });
    exited = once(daemon, 'close');
    daemon.stderr.setEncoding('utf8').on('data', chunk => {
      logs = (logs + chunk).slice(-16_384);
    });
    const address = await waitFor('the WebRTC listener', () =>
      /event=webrtc_listener_ready[^\n]* address=(\S+)/.exec(logs)?.[1],
    );
    const nativePeer = /\/p2p\/([^/]+)$/.exec(address)?.[1];
    assert.ok(nativePeer && address.includes('/webrtc-direct/certhash/'));
    inviterAddress = address;

    web.listen(0, '127.0.0.1');
    await once(web, 'listening');
    browser = await chromium.launch(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: 'chrome' });
    const page = await browser.newPage();
    const pageErrors = [];
    const unexpectedRequests = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('request', request => {
      const url = new URL(request.url());
      if (app && request.method() === 'POST'
          && url.host === `127.0.0.1:${web.address().port}`
          && url.pathname === '/api/pairing/locator') return;
      if (request.method() !== 'GET' || url.host !== `127.0.0.1:${web.address().port}`
          || !files.has(url.pathname)) {
        unexpectedRequests.push('Non-asset browser request');
      }
    });
    const origin = `http://127.0.0.1:${web.address().port}`;
    if (app) {
      await page.goto(origin + '/app.html');
      await page.getByRole('status').filter({ hasText: /^Disconnected$/ }).waitFor();
      await page.getByRole('button', { name: 'Pair code', exact: true }).click();
      const approval = pair('open', '--expires-in-seconds', '45');
      await page.getByLabel('Pairing code').fill(approval.code);
      await page.getByLabel('Hostname').fill('browser-app-pair');
      assert.equal(await page.getByLabel('Inviter address').inputValue(), '');
      await page.getByRole('button', { name: 'Join network' }).click();
      await page.locator('#state:visible, #error:visible').first().waitFor();
      await page.getByRole('status').filter({ hasText: /^Waiting for approval$/ }).waitFor();
      const pending = pair('status', approval.operation_id);
      assert.equal(pending.phase, 'awaiting_approval');
      assert.equal(pending.candidate.requested_hostname, 'browser-app-pair');
      assert.equal(await page.getByRole('button', { name: 'Send request' }).isDisabled(), true);
      pair('approve', approval.operation_id, pending.candidate.approval_id);
      await page.getByRole('status').filter({ hasText: /^Connected$/ }).waitFor();
      assert.equal(await page.locator('#peer-id').textContent(), nativePeer);
      const download = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download config' }).click();
      assert.equal((await download).suggestedFilename(), 'p2p-vpn-browser.json');
      assert.equal(lookups.length, 1);
      assert.deepEqual(Object.keys(lookups[0]), ['locator']);
      assert.match(lookups[0].locator, /^[A-Za-z0-9_-]{43}$/);
      assert.notEqual(lookups[0].locator, approval.code);
      assert.deepEqual(unexpectedRequests, []);
      assert.deepEqual(pageErrors, []);
      return;
    }
    await page.goto(origin + '/');
    const { browserPeer, wrongPeer } = await page.evaluate(async () => {
      const {
        default: init, BrowserPairing, BrowserVpn, pairing_code_v2_global_locator: locate,
      } = await import('/p2p_vpn_browser.js');
      await init();
      if (locate('0000-0000-0000-0000') !== 'QWdoARuxKdBvbMw6Jtg71lvSOyrmZ-cPv18Gi5MgV1M'
          || locate('0000000000000000') === locate('1000000000000000')) {
        throw Error('Unexpected v2 global locator');
      }
      let invalidCodeRejected = false;
      try {
        locate('invalid pairing code');
      } catch {
        invalidCodeRejected = true;
      }
      if (!invalidCodeRejected) throw Error('Invalid pairing code produced a locator');
      const peers = [new BrowserPairing(), new BrowserPairing()];
      let legacy;
      window.startJoin = (code, remote, address, joiner) => {
        window.pending = 0;
        window.outcome = null;
        legacy = undefined;
        const hostname = joiner === 0 ? ' Browser-Pairing ' : undefined;
        peers[joiner].join_v2(code, remote, address, 30_000, hostname, () => { ++window.pending; })
          .then(result => {
            const artifacts = JSON.parse(result);
            if (artifacts.kind === 'checkpoint') {
              const payload = artifacts.response.payload;
              const activation = peers[joiner].take_checkpoint_activation();
              if (!activation) throw Error('Approved checkpoint did not produce an activation handle');
              window.outcome = { checkpoint: {
                legacy_config: Object.hasOwn(artifacts, 'config'),
                offer_inviter: artifacts.offer.payload.inviter_peer,
                joiner: payload.checkpoint.joiner.subject.peer_id,
                transcript_sha256: artifacts.transcript_sha256,
                activation_peer: activation.peer_id(),
                sealed: !('config_json' in activation || 'capability_secret' in activation
                  || 'bootstrap_json' in activation || 'into_inputs' in activation),
                single_use: peers[joiner].take_checkpoint_activation() == null,
              } };
              activation.free();
              return;
            }
            if (artifacts.kind !== 'legacy') throw Error('Expected a legacy pairing result');
            legacy = artifacts;
            const { network, peers: configuredPeers } = artifacts.config;
            window.outcome = { enrollment: {
              network: network.name,
              inviter: configuredPeers[0].id,
              joiner: network.local_peer,
              member: network.member_records.some(({ payload }) =>
                payload.member_peer === network.local_peer && !payload.revoked),
              transcript_sha256: artifacts.transcript_sha256,
            } };
          })
          .catch(error => { window.outcome = { error: error.message }; });
      };
      window.activate = async () => {
        if (!legacy) throw Error('No approved legacy configuration');
        const vpn = window.vpn = new BrowserVpn(JSON.stringify(legacy.config), legacy.dial_address);
        return JSON.parse(await vpn.connect());
      };
      return { browserPeer: peers[0].peer_id(), wrongPeer: peers[1].peer_id() };
    });
    assert.notEqual(nativePeer, browserPeer);
    const start = (code, remote = nativePeer, dial = address, joiner = 0) =>
      page.evaluate(args => window.startJoin(...args), [code, remote, dial, joiner]);
    async function outcome(timeout) {
      await page.waitForFunction(() => window.outcome !== null, null, { timeout });
      return page.evaluate(() => window.outcome);
    }
    async function waitPending(timeout) {
      await page.waitForFunction(() => window.pending === 1 || window.outcome !== null, null, { timeout });
      const progress = await page.evaluate(() => ({ pending: window.pending, outcome: window.outcome }));
      assert.equal(progress.pending, 1, `Pairing stopped before approval: ${progress.outcome?.error}`);
    }
    const approval = pair('open', '--expires-in-seconds', '45');
    assert.equal(approval.local_peer, nativePeer);
    await start(approval.code, wrongPeer);
    assert.deepEqual(await outcome(2000), { error: 'WebRTC Direct address must pin the expected peer' });

    await start(approval.code);
    await waitPending(12_000);
    const status = pair('status', approval.operation_id);
    assert.equal(status.phase, 'awaiting_approval');
    assert.equal(status.artifacts_ready, false);
    assert.equal(status.candidate.peer_id, browserPeer);
    assert.equal(status.candidate.requested_hostname, 'browser-pairing');
    // Leave enough time for a poll against the unapproved native ticket.
    await delay(1250);
    assert.deepEqual(await page.evaluate(() => [window.pending, window.outcome]), [1, null]);

    if (kind === 'checkpoint') {
      await waitFor('native checkpoint participation', () =>
        /^checkpoint_sync_state participating$/m.test(cli('daemon-status', '--socket', socket)),
      20_000);
      pair('approve', approval.operation_id, status.candidate.approval_id);
      const result = await outcome(8000);
      assert.equal(result.error, undefined);
      assert.deepEqual(
        [result.checkpoint.legacy_config, result.checkpoint.offer_inviter, result.checkpoint.joiner],
        [false, nativePeer, browserPeer],
      );
      assert.match(result.checkpoint.transcript_sha256, /^[A-Za-z0-9_-]{43}$/);
      assert.equal(result.checkpoint.activation_peer, browserPeer);
      assert.equal(result.checkpoint.sealed, true);
      assert.equal(result.checkpoint.single_use, true);
      assert.deepEqual(unexpectedRequests, []);
      assert.deepEqual(pageErrors, []);
      return;
    }

    pair('approve', approval.operation_id, status.candidate.approval_id);
    const { enrollment, error } = await outcome(8000);
    assert.equal(error, undefined);
    assert.deepEqual(
      [enrollment.network, enrollment.inviter, enrollment.joiner, enrollment.member],
      [approval.network_name, nativePeer, browserPeer, true],
    );
    const receipt = spawnSync(binary, ['pair', 'artifacts', approval.operation_id, '--socket', socket], {
      stdio: ['ignore', 'ignore', 'pipe'], encoding: 'utf8', timeout: 5000,
    });
    assert.equal(receipt.status, 0, receipt.stderr);
    assert.match(enrollment.transcript_sha256, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(/^pairing receipt: (\S+)$/m.exec(receipt.stderr)?.[1], enrollment.transcript_sha256);
    const connected = await page.evaluate(() => window.activate());
    assert.equal(connected.authorized, true);
    assert.equal(connected.local_peer_id, browserPeer);
    assert.equal(connected.remote_peer_id, nativePeer);
    assert.equal(connected.transport, 'webrtc-direct');
    assert.ok(connected.stream_mtu > 0);

    const expires = pair('open', '--expires-in-seconds', '7');
    await start(expires.code, nativePeer, address, 1);
    await waitPending(6000);
    const candidate = pair('status', expires.operation_id).candidate;
    assert.equal(candidate.peer_id, wrongPeer);
    assert.equal(candidate.requested_hostname, undefined);
    const timedOut = await outcome(10_000);
    assert.match(timedOut.error, /^Pairing (expired|rejected: Expired)$/);
    assert.equal(timedOut.enrollment, undefined);
    assert.equal(pair('status', expires.operation_id).artifacts_ready, false);

    assert.deepEqual(unexpectedRequests, []);
    assert.deepEqual(pageErrors, []);
  } catch (error) {
    throw Error(`${error.message}\nNative daemon:\n${logs.slice(-8000)}`, { cause: error });
  } finally {
    await browser?.close();
    if (daemon && daemon.exitCode === null && !daemon.signalCode) {
      daemon.kill('SIGTERM');
      if (!(await Promise.race([exited, delay(3000, null, { ref: false })]))) {
        daemon.kill('SIGKILL');
        await exited;
      }
    }
    await new Promise(resolve => web.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}
