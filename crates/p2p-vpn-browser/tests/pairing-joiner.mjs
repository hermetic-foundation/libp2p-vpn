// Build with the webrtc feature for the native daemon and, for WASM:
// cargo build --locked -p p2p-vpn-browser --target wasm32-unknown-unknown --example pairing_joiner_fixture
// wasm-bindgen --target web --out-dir <pkg> target/wasm32-unknown-unknown/debug/examples/pairing_joiner_fixture.wasm
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

test('browser v2 enrollment requires native approval over explicitly addressed WebRTC Direct', {
  timeout: 60_000,
}, async () => {
  const binary = process.env.P2P_VPN_BIN;
  const pkg = process.env.P2P_VPN_PAIRING_PKG;
  assert.ok(binary && pkg, 'set P2P_VPN_BIN and P2P_VPN_PAIRING_PKG');
  const files = new Map([['/', ['text/html', '<!doctype html><title>Pairing fixture</title>']]]);
  for (const [file, mime] of [
    ['pairing_joiner_fixture.js', 'text/javascript'],
    ['pairing_joiner_fixture_bg.wasm', 'application/wasm'],
  ]) {
    files.set(`/${file}`, [mime, await readFile(join(pkg, file))]);
  }
  const web = createServer((req, res) => {
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
  async function waitFor(description, check) {
    const deadline = Date.now() + 12_000;
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

    web.listen(0, '127.0.0.1');
    await once(web, 'listening');
    browser = await chromium.launch(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: 'chrome' });
    const page = await browser.newPage();
    const pageErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.goto(`http://127.0.0.1:${web.address().port}/`);
    const { browserPeer, wrongPeer } = await page.evaluate(async () => {
      const { default: init, PairingJoinerFixture } = await import('/pairing_joiner_fixture.js');
      await init();
      const peers = [new PairingJoinerFixture(), new PairingJoinerFixture()];
      window.startJoin = (code, remote, address, joiner) => {
        window.pending = 0;
        window.outcome = null;
        const hostname = joiner === 0 ? 'browser-pairing' : 'browser-expiring';
        peers[joiner].join(code, remote, address, 30_000, hostname, () => { ++window.pending; })
          .then(result => { window.outcome = { enrollment: JSON.parse(result) }; })
          .catch(error => { window.outcome = { error: error.message }; });
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
    assert.deepEqual(await outcome(2000), { error: 'InvalidAddress' });

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

    const expires = pair('open', '--expires-in-seconds', '7');
    await start(expires.code, nativePeer, address, 1);
    await waitPending(6000);
    assert.equal(pair('status', expires.operation_id).candidate.peer_id, wrongPeer);
    const timedOut = await outcome(10_000);
    assert.match(timedOut.error, /^(Expired|Rejected\(Expired\))$/);
    assert.equal(timedOut.enrollment, undefined);
    assert.equal(pair('status', expires.operation_id).artifacts_ready, false);
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
});
