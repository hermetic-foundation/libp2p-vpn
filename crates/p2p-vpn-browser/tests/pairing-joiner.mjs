// Build the native daemon with the webrtc feature and the production browser
// package with scripts/build-browser.sh (no test hooks).
// Set P2P_VPN_BIN and P2P_VPN_PAIRING_PKG to the daemon binary and <pkg>.
// Run with Playwright installed, Chromium, and TUN access:
// unshare --user --map-root-user --mount --net --pid --fork --kill-child=SIGKILL --mount-proc -- sh -ec '
//   ip link set lo up
//   ip link add pv-pairing type dummy
//   ip address add 192.0.2.1/24 dev pv-pairing
//   ip link set pv-pairing up
//   ip route add default dev pv-pairing
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

test('production browser pairing synchronizes and reopens an encrypted checkpoint backup', {
  timeout: 95_000,
}, () => exercisePairing('checkpoint'));

test('browser app completes code-only enrollment after approval', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { app: true }));
test('browser app falls back to the locator when LAN discovery is unavailable', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { app: true, lanUnavailable: true }));
test('browser app hands off the code-pairing lease before activating VPN traffic', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { app: true, relayed: true, managedRelay: true }));

test('browser explicitly joins a native inviter using network-scoped code v1', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { scoped: true }));

test('browser v2 joins and connects over a real Circuit Relay v2 reservation', {
  timeout: 75_000,
}, () => exercisePairing('legacy', { relayed: true }));

test('browser v2 checkpoint enrollment activates over a real Circuit Relay v2 reservation', {
  timeout: 75_000,
}, () => exercisePairing('checkpoint', { relayed: true }));
test('browser file-bearer exchange uses the WebRTC address signed by native pair offer', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { fileBearer: true }));
test('browser file-bearer exchange uses an explicit Circuit Relay v2 route', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { fileBearer: true, relayed: true }));
test('browser app joins from a native signed invite without a locator request', {
  timeout: 60_000,
}, () => exercisePairing('legacy', { app: true, fileBearer: true }));

async function exercisePairing(kind, {
  app = false, scoped = false, relayed = false, fileBearer = false, lanUnavailable = false,
  managedRelay = false,
} = {}) {
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
        const lan = lanUnavailable
          ? '<meta name="p2p-vpn-pairing-lan" content="/api/pairing/lan">' : '';
        bytes = bytes.toString().replace('</head>',
          `<meta name="p2p-vpn-pairing" content="/api/pairing/locator">${lan}</head>`);
      }
      files.set(`/${file}`, [mime, bytes]);
    }
    files.set('/pkg/logo.svg', ['image/svg+xml', await readFile(join(pkg, 'logo.svg'))]);
  }
  const lookups = [];
  const lookupPaths = [];
  const relayCalls = [];
  const pendingLease = '1'.repeat(32);
  const activeLease = '2'.repeat(32);
  let inviterAddress;
  const web = createServer(async (req, res) => {
    if (lanUnavailable && req.method === 'POST' && req.url === '/api/pairing/lan') {
      lookupPaths.push(req.url);
      if (req.headers['content-length'] !== '2') return res.writeHead(400).end();
      return res.writeHead(503, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: 'lan_discovery_unavailable' }));
    }
    if (app && req.method === 'POST' && req.url === '/api/pairing/locator') {
      lookupPaths.push(req.url);
      try {
        let request = '';
        for await (const chunk of req) {
          request += chunk;
          if (request.length > 128) throw Error('unexpected pairing lookup body size');
        }
        lookups.push(JSON.parse(request));
        const hints = managedRelay
          ? { addresses: [], relay_address: inviterAddress, relay_lease_id: pendingLease }
          : { addresses: [inviterAddress] };
        return res.writeHead(200, { 'Content-Type': 'application/json' })
          .end(JSON.stringify(hints));
      } catch {
        return res.writeHead(400).end();
      }
    }
    if (managedRelay && req.method === 'POST'
        && ['/api/relay/handoff', '/api/relay/activate', '/api/relay/release'].includes(req.url)) {
      try {
        let bytes = '';
        for await (const chunk of req) {
          bytes += chunk;
          if (bytes.length > 512) throw Error('relay control body too large');
        }
        const action = req.url.split('/').at(-1);
        const token = JSON.parse(bytes);
        relayCalls.push([action, token]);
        const reply = action === 'handoff'
          ? { relay_address: inviterAddress, relay_lease_id: activeLease }
          : action === 'activate' ? { active: true } : { released: true };
        return res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(reply));
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
  const relaySocket = join(directory, 'relay.sock');
  const state = join(directory, 'pairing-state');
  const cli = (...args) => execFileSync(binary, args, { encoding: 'utf8', timeout: 5000 });
  const pair = (action, ...args) =>
    JSON.parse(cli('pair', action, ...args, '--socket', socket, '--format', 'json'));
  let daemon, exited, browser, relay, relayExited;
  let logs = '';
  let relayLogs = '';
  async function waitFor(description, check, timeout = 12_000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline && (!daemon || daemon.exitCode === null && !daemon.signalCode)) {
      const result = check();
      if (result) return result;
      await delay(100);
    }
    throw Error(`Did not see ${description}: ${logs.slice(-8000)}`);
  }
  try {
    const network = 'browser-pairing-test';
    cli('init-config', '--network', network, '--interface', 'pvbrowser0', '--output', config);
    const native = JSON.parse(await readFile(config, 'utf8'));
    native.network.listen_addresses = ['/ip4/192.0.2.1/udp/0/webrtc-direct'];
    native.network.discovery = {
      mdns: false, kademlia: false, kademlia_provider_advertisement: false, dcutr: false, autonat: false,
    };
    native.network.packet_plane = { listen: [], quic_listen: [] };
    if (relayed) {
      const relayConfig = join(directory, 'relay.json');
      cli('init-config', '--network', 'browser-pairing-relay', '--interface', 'pvrelay0', '--output', relayConfig);
      const relayNode = JSON.parse(await readFile(relayConfig, 'utf8'));
      relayNode.network.listen_addresses = [
        '/ip4/192.0.2.1/tcp/4001',
        '/ip4/192.0.2.1/udp/0/webrtc-direct',
      ];
      relayNode.network.discovery = native.network.discovery;
      relayNode.network.packet_plane = native.network.packet_plane;
      relayNode.network.relay = { server: true };
      await writeFile(relayConfig, JSON.stringify(relayNode), { mode: 0o600 });
      relay = spawn(binary, ['up', '-c', relayConfig, '--control-socket', relaySocket], {
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      relayExited = once(relay, 'close');
      relay.stderr.setEncoding('utf8').on('data', chunk => {
        relayLogs = (relayLogs + chunk).slice(-16_384);
      });
      const relayEntrance = await waitFor('the WebRTC relay listener', () =>
        /event=webrtc_listener_ready[^\n]* address=(\S+)/.exec(relayLogs)?.[1],
      );
      const relayPeer = /\/p2p\/([^/]+)$/.exec(relayEntrance)?.[1];
      assert.ok(relayPeer);
      native.network.listen_addresses = [];
      native.network.relay = {
        reservations: [`/ip4/192.0.2.1/tcp/4001/p2p/${relayPeer}/p2p-circuit`],
      };
      const nativePeer = /^local peer: (\S+)$/m.exec(cli('status', '-c', config))?.[1];
      assert.ok(nativePeer);
      inviterAddress = `${relayEntrance}/p2p-circuit/p2p/${nativePeer}`;
    }
    await writeFile(config, JSON.stringify(native), { mode: 0o600 });
    daemon = spawn(binary, [
      'up', '-c', config, '--control-socket', socket, '--pairing-state', state,
      ...(kind === 'checkpoint' ? ['--membership-state', join(directory, 'membership-state')] : []),
    ], { stdio: ['ignore', 'ignore', 'pipe'] });
    exited = once(daemon, 'close');
    daemon.stderr.setEncoding('utf8').on('data', chunk => {
      logs = (logs + chunk).slice(-16_384);
    });
    if (relayed) {
      await waitFor('the native relay reservation', () =>
        /^relay_server_reservations_accepted [1-9]\d*$/m.test(
          cli('daemon-status', '--socket', relaySocket, '--timeout-seconds', '1'),
        ),
      );
    }
    const address = inviterAddress ?? await waitFor('the WebRTC listener', () =>
      /event=webrtc_listener_ready[^\n]* address=(\S+)/.exec(logs)?.[1],
    );
    const nativePeer = /\/p2p\/([^/]+)$/.exec(address)?.[1];
    assert.ok(nativePeer && address.includes('/webrtc-direct/certhash/'));
    inviterAddress = address;

    let offerPath;
    if (fileBearer) {
      offerPath = join(directory, 'native.pair');
      // The listener's generated certhash is not available in the original config.
      const offerConfig = join(directory, 'native-offer.json');
      await writeFile(offerConfig, JSON.stringify({
        ...native, network: { ...native.network, external_addresses: [address] },
      }), { mode: 0o600 });
      cli('pair', 'offer', '--config', offerConfig, '--output', offerPath,
        ...(relayed ? ['--discovery-only'] : []));
    }

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
          && (url.pathname === '/api/pairing/locator'
            || (managedRelay && ['/api/relay/handoff', '/api/relay/activate', '/api/relay/release'].includes(url.pathname))
            || (lanUnavailable && url.pathname === '/api/pairing/lan'))) return;
      if (request.method() !== 'GET' || url.host !== `127.0.0.1:${web.address().port}`
          || !files.has(url.pathname)) {
        unexpectedRequests.push('Non-asset browser request');
      }
    });
    const origin = `http://127.0.0.1:${web.address().port}`;
    if (app) {
      await page.goto(origin + '/app.html');
      const status = page.getByRole('status');
      await status.filter({ hasText: /^Disconnected$/ }).waitFor();
      if (fileBearer) {
        await page.getByRole('button', { name: 'Invite file', exact: true }).click();
        await page.getByLabel('Offer file').setInputFiles(offerPath);
        await page.getByRole('button', { name: 'Continue', exact: true }).click();
        await status.filter({ hasText: /^Invite ready$/ }).waitFor();
        assert.equal(await page.getByRole('button', { name: 'Send request' }).isDisabled(), true);
        assert.equal(await page.getByLabel('Inviter address').inputValue(), '');
        await page.getByRole('button', { name: 'Join network' }).click();
        await status.filter({ hasText: /^Connected$/ }).waitFor();
        assert.equal(await page.locator('#peer-id').textContent(), nativePeer);
        assert.equal(await page.getByRole('button', { name: 'Send request' }).isEnabled(), true);
        assert.equal(lookups.length, 0);
        assert.deepEqual(unexpectedRequests, []);
        assert.deepEqual(pageErrors, []);
        return;
      }
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
      assert.deepEqual(relayCalls, []);
      pair('approve', approval.operation_id, pending.candidate.approval_id);
      await page.getByRole('status').filter({ hasText: /^Connected$/ }).waitFor();
      assert.equal(await page.locator('#peer-id').textContent(), nativePeer);
      const download = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download config' }).click();
      assert.equal((await download).suggestedFilename(), 'p2p-vpn-browser.json');
      assert.equal(lookups.length, 1);
      assert.deepEqual(lookupPaths, lanUnavailable
        ? ['/api/pairing/lan', '/api/pairing/locator'] : ['/api/pairing/locator']);
      assert.deepEqual(Object.keys(lookups[0]), ['locator']);
      assert.match(lookups[0].locator, /^[A-Za-z0-9_-]{43}$/);
      assert.notEqual(lookups[0].locator, approval.code);
      if (managedRelay) {
        await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
        await status.filter({ hasText: /^Disconnected$/ }).waitFor();
        assert.deepEqual(relayCalls, [
          ['handoff', { lease_id: pendingLease, relay_address: address }],
          ['release', { lease_id: pendingLease }],
          ['activate', { lease_id: activeLease, relay_address: address }],
          ['release', { lease_id: activeLease }],
        ]);
      }
      assert.deepEqual(unexpectedRequests, []);
      assert.deepEqual(pageErrors, []);
      return;
    }
    await page.goto(origin + '/');
    if (fileBearer) {
      const offer = await readFile(offerPath, 'utf8');
      const result = await page.evaluate(exerciseFileBearer, { offer, address, relayed });
      assert.notEqual(result.browserPeer, nativePeer);
      assert.equal(result.inviter, nativePeer);
      assert.equal(result.initiallySealed, false);
      assert.match(result.wrongPeer, /pinned to the inviter/);
      assert.match(result.completed, /already completed/);
      assert.equal(result.kind, 'legacy');
      assert.equal(result.dial, address);
      assert.equal(result.enrolled, true);
      assert.equal(result.signedRequestUsesBrowserIdentity, true);
      assert.equal(result.connected.local_peer_id, result.browserPeer);
      assert.equal(result.connected.remote_peer_id, nativePeer);
      assert.equal(result.connected.authorized, true);
      assert.equal(result.connected.transport, relayed ? 'circuit-relay' : 'webrtc-direct');
      await waitFor('native file-bearer admission', () =>
        logs.split('\n').some(line => line.includes('event=pairing_request_accepted ')
          && line.includes(`joiner=${result.browserPeer}`)));
      assert.equal(logs.match(/event=pairing_request_accepted /g)?.length, 1);
      assert.deepEqual(unexpectedRequests, []);
      assert.deepEqual(pageErrors, []);
      return;
    }
    const { browserPeer, wrongPeer, expiryPeer } = await page.evaluate(async ({ scoped, relayed }) => {
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
      const peers = [new BrowserPairing(), new BrowserPairing(), new BrowserPairing()];
      let legacy;
      let checkpointActivation;
      window.startJoin = (code, remote, address, joiner, scope, timeout, requestedHostname) => {
        window.pending = 0;
        window.outcome = null;
        legacy = undefined;
        checkpointActivation?.free();
        checkpointActivation = undefined;
        const hostname = requestedHostname ?? (joiner === 0 ? ' Browser-Pairing ' : undefined);
        const notify = () => { ++window.pending; };
        const pairing = peers[joiner];
        const operation = scoped
          ? pairing.join_v1(code, scope, remote, address, timeout, hostname, notify)
          : pairing.join_v2(code, remote, address, timeout, hostname, notify);
        operation
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
                minimum: payload.checkpoint.minimum,
                transcript_sha256: artifacts.transcript_sha256,
                activation_peer: activation.peer_id(),
                sealed: !('config_json' in activation || 'capability_secret' in activation
                  || 'bootstrap_json' in activation || 'into_inputs' in activation),
                single_use: peers[joiner].take_checkpoint_activation() == null,
              } };
              checkpointActivation = activation;
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
          .catch(error => {
            window.outcome = error.name === 'PairingCandidateMiss'
              ? { error: error.message, candidateMiss: error.reason }
              : { error: error.message };
          });
      };
      window.activate = async () => {
        if (!legacy) throw Error('No approved legacy configuration');
        const config = JSON.stringify(legacy.config);
        const vpn = window.vpn = relayed
          ? BrowserVpn.with_relay(config, '', legacy.dial_address)
          : new BrowserVpn(config, legacy.dial_address);
        return JSON.parse(await vpn.connect());
      };
      window.activateCheckpoint = async () => {
        if (!checkpointActivation) throw Error('No approved checkpoint activation');
        const activation = checkpointActivation;
        checkpointActivation = undefined;
        const vpn = window.vpn = await (relayed
          ? activation.open_relay()
          : BrowserVpn.open_checkpoint_activation(activation));
        const before = JSON.parse(vpn.snapshot());
        const passphrase = 'synthetic checkpoint backup passphrase';
        const rejection = async (operation) => {
          try {
            const unexpected = await operation();
            unexpected?.free?.();
            return null;
          } catch (error) {
            return error.message;
          }
        };
        const pendingExport = await rejection(() => vpn.export_checkpoint_credentials(passphrase));
        const after = JSON.parse(await vpn.connect());
        const bundle = await vpn.export_checkpoint_credentials(passphrase);
        const envelope = JSON.parse(bundle);
        const bundleFields = Object.keys(envelope).sort();
        const concurrentImport = await rejection(() => BrowserVpn.import_checkpoint_credentials(bundle, passphrase));
        const wrongPassphrase = await rejection(() =>
          BrowserVpn.import_checkpoint_credentials(bundle, 'another synthetic passphrase'));
        envelope.ciphertext[0] ^= 1;
        const tampered = await rejection(() =>
          BrowserVpn.import_checkpoint_credentials(JSON.stringify(envelope), passphrase));
        await vpn.close();
        const imported = window.vpn = await BrowserVpn.import_checkpoint_credentials(bundle, passphrase);
        const restored = JSON.parse(imported.snapshot());
        const key = Object.keys(localStorage).find(name => name.startsWith('p2p-vpn:checkpoint-membership:'));
        const stored = localStorage.getItem(key);
        const minRank = JSON.parse(stored).payload.enrollment_floor;
        const leakedCredentials = /capability_secret|private_key/.test(stored);
        const reconnected = JSON.parse(await imported.connect());
        await imported.close();
        return { before, after, restored, reconnected, bundleFields, pendingExport,
          concurrentImport, wrongPassphrase, tampered, minRank, leakedCredentials };
      };
      return { browserPeer: peers[0].peer_id(), wrongPeer: peers[1].peer_id(), expiryPeer: peers[2].peer_id() };
    }, { scoped, relayed });
    assert.notEqual(nativePeer, browserPeer);
    const start = (code, remote = nativePeer, dial = address, joiner = 0,
      scope = network, timeout = 30_000, hostname) =>
      page.evaluate(args => window.startJoin(...args), [code, remote, dial, joiner, scope, timeout, hostname]);
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
    assert.deepEqual(await outcome(2000), { error: 'Pairing address must pin the expected peer' });
    if (scoped) {
      const unreachable = address.replace(/\/udp\/\d+\//, '/udp/9/');
      await start(approval.code, nativePeer, unreachable, 1, network, 1000);
      assert.deepEqual(await outcome(4000), {
        error: 'Pairing candidate could not be reached', candidateMiss: 'transport',
      });
      await start(approval.code, nativePeer, address, 1, 'a-different-network');
      assert.deepEqual(await outcome(6000), {
        error: 'Pairing rejected: Unavailable', candidateMiss: 'unavailable',
      });
      assert.equal(await page.evaluate(() => window.pending), 0);
    }

    await start(approval.code);
    await waitPending(12_000);
    const status = pair('status', approval.operation_id);
    assert.equal(status.phase, 'awaiting_approval');
    assert.equal(status.artifacts_ready, false);
    assert.equal(status.candidate.peer_id, browserPeer);
    assert.equal(status.candidate.requested_hostname, 'browser-pairing');
    if (relayed) assert.equal(status.diagnostics.selected_transport, 'relay');
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
      const {
        before, after, restored, reconnected, bundleFields, pendingExport,
        concurrentImport, wrongPassphrase, tampered, minRank, leakedCredentials,
      } = await page.evaluate(() => window.activateCheckpoint());
      assert.equal(before.authorized, false);
      assert.equal(before.checkpoint.sync, 'resync_required');
      assert.equal(after.authorized, true);
      assert.equal(after.local_peer_id, browserPeer);
      assert.equal(after.remote_peer_id, nativePeer);
      assert.equal(after.transport, relayed ? 'circuit-relay' : 'webrtc-direct');
      assert.equal(after.membership_snapshot, null);
      assert.equal(after.checkpoint.sync, 'participating');
      const minimum = result.checkpoint.minimum;
      assert.deepEqual(after.checkpoint.boundary, {
        authority_revision: minimum.authority_revision, digest: minimum.digest,
      });
      assert.equal(after.checkpoint.active_member_count, minimum.active_member_count);
      assert.match(pendingExport, /Connect an authorized checkpoint peer/);
      assert.deepEqual(bundleFields, ['ciphertext', 'nonce', 'salt', 'version']);
      assert.match(concurrentImport, /identity is in use by another tab/);
      assert.match(wrongPassphrase, /bundle or passphrase is invalid/);
      assert.match(tampered, /bundle or passphrase is invalid/);
      assert.equal(restored.authorized, false);
      assert.equal(restored.checkpoint.sync, 'resync_required');
      assert.deepEqual(restored.checkpoint.boundary, after.checkpoint.boundary);
      assert.deepEqual(minRank, minimum);
      assert.equal(leakedCredentials, false);
      assert.equal(reconnected.authorized, true);
      assert.deepEqual(reconnected.checkpoint.boundary, after.checkpoint.boundary);
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
    assert.equal(connected.transport, relayed ? 'circuit-relay' : 'webrtc-direct');
    assert.ok(connected.stream_mtu > 0);

    if (relayed || scoped) {
      assert.deepEqual(unexpectedRequests, []);
      assert.deepEqual(pageErrors, []);
      return;
    }

    const rejected = pair('open', '--expires-in-seconds', '20');
    // An existing signed name allows Hello but rejects Submit before Pending.
    await start(rejected.code, nativePeer, address, 1, network, 10_000, 'browser-pairing');
    assert.deepEqual(await outcome(8000), { error: 'Pairing rejected: Unavailable' });
    assert.equal(await page.evaluate(() => window.pending), 0);
    const rejectedStatus = pair('status', rejected.operation_id);
    assert.ok(rejectedStatus.diagnostics.handshake_attempts > 0);
    assert.equal(rejectedStatus.artifacts_ready, false);
    pair('cancel', rejected.operation_id);

    const expires = pair('open', '--expires-in-seconds', '7');
    await start(expires.code, nativePeer, address, 2);
    await waitPending(6000);
    const candidate = pair('status', expires.operation_id).candidate;
    assert.equal(candidate.peer_id, expiryPeer);
    assert.equal(candidate.requested_hostname, undefined);
    const timedOut = await outcome(10_000);
    assert.match(timedOut.error, /^Pairing (expired|rejected: Expired)$/);
    assert.equal(timedOut.enrollment, undefined);
    assert.equal(pair('status', expires.operation_id).artifacts_ready, false);

    assert.deepEqual(unexpectedRequests, []);
    assert.deepEqual(pageErrors, []);
  } catch (error) {
    throw Error(`${error.message}\nNative daemon:\n${logs.slice(-8000)}\nRelay:\n${relayLogs.slice(-4000)}`, {
      cause: error,
    });
  } finally {
    await browser?.close();
    if (daemon && daemon.exitCode === null && !daemon.signalCode) {
      daemon.kill('SIGTERM');
      if (!(await Promise.race([exited, delay(3000, null, { ref: false })]))) {
        daemon.kill('SIGKILL');
        await exited;
      }
    }
    if (relay && relay.exitCode === null && !relay.signalCode) {
      relay.kill('SIGTERM');
      if (!(await Promise.race([relayExited, delay(3000, null, { ref: false })]))) {
        relay.kill('SIGKILL');
        await relayExited;
      }
    }
    await new Promise(resolve => web.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

async function exerciseFileBearer({ offer, address, relayed }) {
  const { default: init, BrowserPairing, BrowserVpn } = await import('/p2p_vpn_browser.js');
  await init();
  const pairing = new BrowserPairing();
  const session = pairing.begin_offline(offer, 'file-bearer-browser');
  const browserPeer = pairing.peer_id();
  const inviter = session.inviter_peer();
  const initiallySealed = session.take_checkpoint_activation() != null;
  const signedRequest = session.request_json();
  const request = JSON.parse(signedRequest);
  const signedRequestUsesBrowserIdentity = request.payload.joiner_peer === browserPeer
    && request.payload.requested_hostname === 'file-bearer-browser'
    && !('code_authentication' in request) && !signedRequest.includes('private_key');
  const rejection = async operation => {
    try {
      await operation();
      return null;
    } catch (error) {
      return error.message;
    }
  };
  const wrongPeer = await rejection(() =>
    session.exchange(address.replace(new RegExp(`${inviter}$`), browserPeer), 5000));
  const artifacts = JSON.parse(await session.exchange(relayed ? address : '', 15_000));
  const completed = await rejection(() => session.exchange(address));
  const { config, kind, dial_address: dial } = artifacts;
  if (kind !== 'legacy' || session.take_checkpoint_activation() != null) {
    throw Error('Expected only legacy approval from the native file-bearer daemon');
  }
  const enrolled = config.network.member_records.some(({ payload }) =>
    payload.member_peer === browserPeer && !payload.revoked);
  const vpn = relayed
    ? BrowserVpn.with_relay(JSON.stringify(config), '', dial)
    : new BrowserVpn(JSON.stringify(config), dial);
  const connected = JSON.parse(await vpn.connect());
  await vpn.close();
  session.free();
  pairing.free();
  return { browserPeer, inviter, initiallySealed, wrongPeer, completed, kind, dial,
    enrolled, signedRequestUsesBrowserIdentity, connected };
}
