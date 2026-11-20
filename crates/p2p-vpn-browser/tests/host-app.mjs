// Run with an isolated Linux user, mount, PID, and network namespace.
// P2P_VPN_BIN must point to the native daemon built with --features webrtc.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chromium } from 'playwright';

test('the Linux companion discovers a configured member on a separate LAN link', {
  timeout: 75_000,
}, () => exerciseHost('config'));

test('the Linux companion pairs by code over a separate LAN link without public lookup', {
  timeout: 75_000,
}, () => exerciseHost('legacy'));

test('the browser app applies live roster changes, withdraws revoked checkpoint authority, and rejects stale credentials', {
  timeout: 120_000,
}, () => exerciseHost('checkpoint'));

test('a failed live checkpoint save does not publish the candidate or acknowledge revocation', {
  timeout: 90_000,
}, () => exerciseHost('checkpoint', { terminalMutation: 'failed-save' }));

test('the browser acknowledges an excluded checkpoint issuer without retaining it as a member', {
  timeout: 90_000,
}, () => exerciseHost('checkpoint', { terminalMutation: 'issuer-resigns' }));

test('the served browser resumes an approved pending backup before sending overlay HTTP', {
  timeout: 105_000,
}, t => exerciseHost('checkpoint', { pendingRecovery: 'resume', t }));

test('the served browser learns ordinary exclusion on first sync from a pending backup', {
  timeout: 105_000,
}, t => exerciseHost('checkpoint', { pendingRecovery: 'exclude', t }));

test('the browser can continue without saving, then export and reopen active credentials', {
  timeout: 95_000,
}, () => exerciseHost('checkpoint', { activeBackupOnly: true }));

async function recordCheckpointTransport(page) {
  await page.addInitScript(() => {
    const events = window.checkpointTransportEvents = [];
    const note = (...event) => {
      if (events.length === 48) events.shift();
      events.push(event);
    };
    const protocols = ['/ipfs/id/', '/p2p-vpn/checkpoint-mutation/1'];
    const decoder = new TextDecoder();
    const replies = window.checkpointMutationReplies = [];
    const send = RTCDataChannel.prototype.send;
    RTCDataChannel.prototype.send = function (data) {
      if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
        const frame = decoder.decode(data);
        // The small JSON body is carried inside the WebRTC stream's binary envelope.
        const start = frame.indexOf('{"version":1,"mutation_digest":');
        if (start !== -1) {
          const reply = JSON.parse(frame.slice(start, frame.lastIndexOf('}') + 1));
          replies.push(reply);
          if (window.dropNextCheckpointAck && reply.outcome.applied) {
            window.dropNextCheckpointAck = false;
            return;
          }
        }
      }
      return send.call(this, data);
    };
    const NativePeerConnection = window.RTCPeerConnection;
    let nextConnection = 0;
    window.RTCPeerConnection = class extends NativePeerConnection {
      constructor(...args) {
        super(...args);
        const connection = ++nextConnection;
        this.addEventListener('connectionstatechange', () => note(connection, this.connectionState));
        this.addEventListener('datachannel', ({ channel }) => {
          note(connection, 'native channel', channel.id);
          channel.addEventListener('message', ({ data }) => {
            if (!(data instanceof ArrayBuffer) || data.byteLength > 512) return;
            const frame = decoder.decode(data);
            for (const protocol of protocols) {
              if (frame.includes(protocol)) note(connection, channel.id, protocol, !!channel.onmessage);
            }
          });
        });
      }
    };
  });
}

async function exerciseHost(mode, { terminalMutation, pendingRecovery, activeBackupOnly, t } = {}) {
  const pairing = mode !== 'config';
  const binary = process.env.P2P_VPN_BIN;
  assert.ok(binary, 'P2P_VPN_BIN must point to the native webrtc build');
  assert.match(process.env.P2P_VPN_TEST_NETNS ?? '', /^net:\[\d+\]$/,
    'set P2P_VPN_TEST_NETNS to the parent namespace link before unshare');
  assert.notEqual(await readlink('/proc/self/ns/net'), process.env.P2P_VPN_TEST_NETNS,
    'refusing to configure the parent network');

  const directory = await mkdtemp(join(tmpdir(), 'p2p-vpn-browser-host-'));
  const cli = (...args) => execFileSync(binary, args, { encoding: 'utf8', timeout: 10_000 });
  const ip = (...args) => execFileSync('ip', args, { encoding: 'utf8', timeout: 5_000 });
  const processes = [];
  let chromiumBrowser;
  function track(child) {
    const process = { child, stdout: '', stderr: '', exited: once(child, 'close') };
    child.stdout.setEncoding('utf8').on('data', text => {
      process.stdout = (process.stdout + text).slice(-16_384);
    });
    child.stderr.setEncoding('utf8').on('data', text => {
      process.stderr = (process.stderr + text).slice(-16_384);
    });
    processes.push(process);
    return process;
  }
  async function waitFor(process, expression, description, timeout = 15_000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const found = expression.exec(process.stdout + process.stderr);
      if (found) return found[1];
      if (process.child.exitCode !== null || process.child.signalCode) break;
      await delay(50);
    }
    throw Error(`Did not see ${description}: ${process.stderr.slice(-4000)}`);
  }

  try {
    const nativePath = join(directory, 'native.json');
    const browserPath = join(directory, 'browser.json');
    const socket = join(directory, 'control.sock');
    const pair = (action, ...args) =>
      JSON.parse(cli('pair', action, ...args, '--socket', socket, '--format', 'json'));
    for (const path of [nativePath, browserPath]) {
      cli('init-config', '--network', 'browser-host-test', '--interface', 'pvbrowser0', '--output', path);
    }
    const native = JSON.parse(await readFile(nativePath, 'utf8'));
    const browser = JSON.parse(await readFile(browserPath, 'utf8'));
    const peerId = path => /^local peer: (\S+)$/m.exec(cli('status', '-c', path))?.[1];
    const nativeId = peerId(nativePath);
    const browserId = peerId(browserPath);
    assert.ok(nativeId && browserId && nativeId !== browserId);
    native.network.listen_addresses = ['/ip4/192.168.42.2/udp/0/webrtc-direct'];
    native.network.discovery = {
      mdns: true, kademlia: false, kademlia_provider_advertisement: false,
      dcutr: false, autonat: false,
    };
    native.network.packet_plane = { listen: [], quic_listen: [] };
    native.peers = pairing ? [] : [{ id: browserId, addresses: ['/ip4/127.0.0.1/tcp/9'] }];
    browser.network.discovery = native.network.discovery;
    browser.peers = [{ id: nativeId }];
    await writeFile(nativePath, JSON.stringify(native), { mode: 0o600 });
    await writeFile(browserPath, JSON.stringify(browser), { mode: 0o600 });

    ip('link', 'set', 'lo', 'up');
    ip('link', 'add', 'browser-lan', 'type', 'veth', 'peer', 'name', 'native-lan');
    const daemon = track(spawn('unshare', ['--net', 'sh', '-ec', [
      'printf "native-namespace:%s\n" "$$"',
      'read ready',
      'ip link set lo up',
      'ip addr add 192.168.42.2/24 dev native-lan',
      'ip link set native-lan up',
      'ip route add 224.0.0.251/32 dev native-lan',
      'exec "$@"',
    ].join('\n'), 'native-namespace', binary, 'up', '-c', nativePath,
    '--control-socket', socket, '--pairing-state', join(directory, 'pairing'),
    ...(mode === 'checkpoint' ? ['--membership-state', join(directory, 'membership')] : [])],
    { stdio: ['pipe', 'pipe', 'pipe'] }));
    const pid = await waitFor(daemon, /^native-namespace:(\d+)$/m, 'native namespace process');
    ip('link', 'set', 'native-lan', 'netns', pid);
    ip('addr', 'add', '192.168.42.1/24', 'dev', 'browser-lan');
    ip('link', 'set', 'browser-lan', 'up');
    ip('route', 'add', '224.0.0.251/32', 'dev', 'browser-lan');
    daemon.child.stdin.end('ready\n');
    const dial = await waitFor(daemon, /event=webrtc_listener_ready[^\n]* address=(\S+)/,
      'native WebRTC listener');
    assert.ok(dial.startsWith('/ip4/192.168.42.2/udp/'));

    const assets = fileURLToPath(new URL('../web', import.meta.url));
    const host = track(spawn(binary, ['browser-serve', '--assets', assets, '--port', '0'],
      { stdio: ['ignore', 'pipe', 'pipe'] }));
    const url = await waitFor(host, /^Browser app: (http:\/\/127\.0\.0\.1:\d+\/app\.html)$/m,
      'browser companion listener');
    const chromiumOptions = process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: 'chrome' };
    const viewport = { width: 360, height: 740 };
    const openProfile = () => chromium.launchPersistentContext(join(directory, 'profile'),
      { ...chromiumOptions, viewport });
    let context;
    if (pendingRecovery) {
      chromiumBrowser = context = await openProfile();
    } else {
      chromiumBrowser = await chromium.launch(chromiumOptions);
      context = await chromiumBrowser.newContext({ viewport });
    }
    let page = context.pages()[0] ?? await context.newPage();
    if (mode === 'checkpoint' && !pendingRecovery && !activeBackupOnly) await recordCheckpointTransport(page);
    if (pendingRecovery) {
      await page.addInitScript(() => {
        window.transportsOpened = 0;
        window.RTCPeerConnection = class extends window.RTCPeerConnection {
          constructor(...args) {
            super(...args);
            window.transportsOpened++;
          }
        };
      });
    }
    const pairingRequests = [];
    const pairingResponses = [];
    const unexpectedRequests = [];
    const observeRequests = profile => profile.on('request', request => {
      const target = new URL(request.url());
      if (target.origin !== new URL(url).origin
          || (request.method() !== 'GET'
            && !(target.pathname === '/api/pairing/lan' && request.postData() === '{}'))) {
        unexpectedRequests.push([request.method(), target.pathname]);
      }
    });
    if (pendingRecovery) observeRequests(context);
    let checkpointIdentity;
    page.on('request', request => {
      const path = new URL(request.url()).pathname;
      if (path.startsWith('/api/pairing/')) {
        pairingRequests.push([path, request.postData()]);
      }
    });
    page.on('response', response => {
      const path = new URL(response.url()).pathname;
      if (path.startsWith('/api/pairing/')) {
        pairingResponses.push(response.json().catch(() => null)
          .then(body => [path, response.status(), body]));
      }
    });
    await page.goto(url);
    await page.getByRole('status').filter({ hasText: /^Disconnected$/ }).waitFor();
    if (pairing) {
      const approval = pair('open', '--expires-in-seconds', '45');
      await page.getByRole('button', { name: 'Pair code', exact: true }).click();
      await page.getByLabel('Pairing code').fill(approval.code);
      await page.getByLabel('Hostname').fill('browser-lan-joiner');
      assert.equal(await page.getByLabel('Inviter address').inputValue(), '');
      await page.getByRole('button', { name: 'Join network' }).click();
      try {
        await page.locator('#state:text-is("Waiting for approval"), #error:visible').first().waitFor({
          timeout: 20_000,
        });
      } catch {
        assert.fail(`No enrollment result: ${JSON.stringify(await Promise.all(pairingResponses))}`);
      }
      if (await page.locator('#error').isVisible()) {
        assert.fail(`${await page.locator('#error').textContent()} ${JSON.stringify(await Promise.all(pairingResponses))}`);
      }
      const pending = pair('status', approval.operation_id);
      assert.equal(pending.phase, 'awaiting_approval');
      assert.equal(pending.candidate.requested_hostname, 'browser-lan-joiner');
      assert.equal(await page.getByRole('button', { name: 'Send request' }).isDisabled(), true);
      assert.equal(await page.getByRole('button', { name: 'Download credentials' }).isVisible(), false);
      if (mode === 'checkpoint') {
        checkpointIdentity = {
          peer: pending.candidate.peer_id,
          key: `p2p-vpn:checkpoint-membership:1:${JSON.stringify([approval.network_name, pending.candidate.peer_id])}`,
        };
        const deadline = Date.now() + 20_000;
        for (;;) {
          const status = cli('daemon-status', '--socket', socket);
          if (/^checkpoint_sync_state participating$/m.test(status)) break;
          assert.ok(Date.now() < deadline, status);
          await delay(200);
        }
      }
      const pairingTransports = pendingRecovery && await page.evaluate(() => window.transportsOpened);
      pair('approve', approval.operation_id, pending.candidate.approval_id);
      if (mode === 'checkpoint') {
        await page.getByText('Approved, not connected', { exact: true }).waitFor();
        if (!pendingRecovery) {
          await page.getByRole('button', { name: 'Continue without saving' }).click();
        } else {
          const state = () => page.locator('#state');
          const send = () => page.getByRole('button', { name: 'Send request' });
          const readSaved = () => page.evaluate(key => localStorage.getItem(key), checkpointIdentity.key);
          const stored = await readSaved();
          assert.doesNotMatch(stored, /private_key|capability_secret/);
          const { retained, enrollment_floor: floor } = JSON.parse(stored).payload;
          assert.equal(floor.authority_revision, 1);
          assert.ok(retained.snapshot.payload.authority_revision < floor.authority_revision);
          assert.equal(await state().getAttribute('data-connected'), 'false');
          assert.equal(await send().isDisabled(), true);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
          if (pendingRecovery === 'resume' && process.env.P2P_VPN_PENDING_SCREENSHOT) {
            await page.screenshot({ path: process.env.P2P_VPN_PENDING_SCREENSHOT });
          }

          const passphrase = 'isolated pending checkpoint backup';
          await page.getByRole('button', { name: 'Download credentials' }).click();
          await page.getByLabel('New passphrase').fill(passphrase);
          const downloaded = page.waitForEvent('download');
          await page.getByRole('button', { name: 'Download', exact: true }).click();
          const file = await downloaded;
          assert.equal(file.suggestedFilename(), 'p2p-vpn-credentials.json');
          const buffer = await readFile(await file.path());
          assert.deepEqual(Object.keys(JSON.parse(buffer)).sort(), ['ciphertext', 'nonce', 'salt', 'version']);
          assert.equal(JSON.parse(buffer).version, 1);
          assert.equal(await readSaved(), stored, 'backup alone must not install checkpoint authority');
          assert.equal(await page.evaluate(() => window.transportsOpened), pairingTransports,
            'first member sync started before the user chose to connect');
          assert.equal(await send().isDisabled(), true);
          t.diagnostic('downloaded encrypted backup at pending floor revision 1; no member dial or packet authority');
          await page.getByRole('button', { name: 'Close enrollment' }).click();
          await page.getByText('Disconnected', { exact: true }).waitFor();
          await context.close();

          if (pendingRecovery === 'exclude') {
            const revoked = JSON.parse(cli('membership', 'revoke', checkpointIdentity.peer,
              '--socket', socket, '--format', 'json'));
            assert.equal(revoked.membership_epoch, floor.authority_revision + 1);
          }

          chromiumBrowser = context = await openProfile();
          observeRequests(context);
          page = context.pages()[0] ?? await context.newPage();
          await page.goto(url);
          await page.getByText('Disconnected', { exact: true }).waitFor();
          assert.equal(await readSaved(), stored);
          await page.evaluate(key => {
            window.authorizations = [];
            const status = document.querySelector('#state');
            new MutationObserver(() => {
              if (status.dataset.connected !== 'true') return;
              const { retained, enrollment_floor } = JSON.parse(localStorage.getItem(key)).payload;
              window.authorizations.push({ floor: enrollment_floor,
                revision: retained.snapshot.payload.authority_revision });
            }).observe(status, { attributes: true, attributeFilter: ['data-connected'] });
          }, checkpointIdentity.key);
          await page.getByRole('button', { name: 'Credentials', exact: true }).click();
          await page.getByLabel('Encrypted credentials').setInputFiles({
            name: 'p2p-vpn-credentials.json', mimeType: 'application/json', buffer,
          });
          await page.getByLabel('Bundle passphrase').fill(passphrase);
          assert.equal(await send().isDisabled(), true);
          await page.getByRole('button', { name: 'Connect', exact: true }).click();
          await page.locator('#state[data-connected="true"], #error:visible').first().waitFor({ timeout: 35_000 });
          const installed = JSON.parse(await readSaved()).payload;
          const authorizations = await page.evaluate(() => window.authorizations);
          if (pendingRecovery === 'exclude') {
            assert.match(await page.locator('#error').textContent(), /checkpoint.*(Excluded|revoked)/i);
            assert.equal(await send().isDisabled(), true);
            assert.equal(await page.getByRole('button', { name: 'Download credentials' }).isVisible(), false);
            assert.deepEqual(authorizations, []);
            assert.equal(installed.enrollment_floor, null);
            assert.equal(installed.retained.snapshot.payload.authority_revision, floor.authority_revision + 1);
            assert.deepEqual(installed.retained.snapshot.payload.members.map(member => member.subject.peer_id), [nativeId]);
            t.diagnostic('revision 2 exclusion persisted on import without enabling overlay reachability');
          } else {
            assert.equal(await page.locator('#error').isVisible(), false, await page.locator('#error').textContent());
            assert.ok(authorizations.length > 0);
            for (const authorization of authorizations) {
              assert.deepEqual(authorization, { floor: null, revision: floor.authority_revision });
            }
            assert.equal(installed.enrollment_floor, null);
            assert.ok(installed.retained.snapshot.payload.members.some(member =>
              member.subject.peer_id === checkpointIdentity.peer));
            assert.equal(await page.getByRole('button', { name: 'Download credentials' }).isVisible(), true);
            const nativeIp = /^local overlay ipv4: (\S+)/m.exec(cli('status', '-c', nativePath))?.[1];
            assert.ok(nativeIp);
            const service = track(spawn('nsenter', ['-t', pid, '-n', process.execPath, '-e', `
              const server = require('node:http').createServer((request, response) =>
                response.end('pending-resume overlay: ' + request.url));
              server.listen(0, process.argv[1], () => console.log('port:' + server.address().port));
            `, nativeIp], { stdio: ['ignore', 'pipe', 'pipe'] }));
            const port = await waitFor(service, /^port:(\d+)$/m, 'overlay-only HTTP listener');
            await page.getByLabel('Overlay address').fill(nativeIp);
            await page.getByLabel('Port').fill(port);
            await page.getByLabel('Path').fill('/resumed');
            await send().click();
            await page.locator('#response').filter({ hasText: 'pending-resume overlay: /resumed' }).waitFor();
            assert.match(await page.locator('#response').textContent(), /^HTTP\/1\.1 200 OK/);
            t.diagnostic('revision 1 installed on authenticated sync, then a native overlay-only HTTP request succeeded');
          }
          assert.deepEqual(unexpectedRequests, [], 'credentials and overlay HTTP must stay off the companion HTTP path');
          assert.deepEqual(pairingRequests, [['/api/pairing/lan', '{}']]);
          return;
        }
      }
    } else {
      await page.getByLabel('Peer config').setInputFiles(browserPath);
      assert.equal(await page.getByLabel('Peer ID or address').inputValue(), '');
      const lookup = page.waitForResponse(response => response.url().endsWith('/api/discovery'));
      await page.getByRole('button', { name: 'Connect', exact: true }).click();
      const response = await lookup;
      assert.equal(response.status(), 200);
      const hints = await response.json();
      assert.equal(hints.source, 'lan');
      assert.ok(hints.addresses.includes(dial));
      const query = response.request().postDataJSON();
      assert.equal(query.peer, nativeId);
      assert.equal(query.lan, true);
      assert.equal(query.kademlia, false);
      assert.ok(!Object.hasOwn(query, 'private_key') && !Object.hasOwn(query, 'config'));
    }
    await page.locator('#state[data-connected="true"], #error:visible').first().waitFor();
    assert.equal(await page.locator('#error').isVisible(), false, await page.locator('#error').textContent());
    assert.equal(await page.locator('#peer-id').textContent(), nativeId);
    if (terminalMutation) {
      const failSave = terminalMutation === 'failed-save';
      const saved = await page.evaluate(({ key, failSave }) => {
        if (!failSave) return localStorage.getItem(key);
        const original = Storage.prototype.setItem;
        window.checkpointSaveAttempts = 0;
        Storage.prototype.setItem = function (name, value) {
          if (this === localStorage && name === key) {
            window.checkpointSaveAttempts++;
            throw new DOMException('Injected checkpoint write failure', 'QuotaExceededError');
          }
          return original.call(this, name, value);
        };
        return localStorage.getItem(key);
      }, { key: checkpointIdentity.key, failSave });
      assert.ok(saved);
      const previous = JSON.parse(saved).payload.retained.snapshot.payload;
      assert.deepEqual(new Set(previous.members.map(member => member.subject.peer_id)),
        new Set([nativeId, checkpointIdentity.peer]));
      const send = page.getByRole('button', { name: 'Send request' });
      assert.equal(await send.isEnabled(), true);
      const command = failSave ? ['revoke', checkpointIdentity.peer] : ['resign'];
      const revoked = JSON.parse(cli('membership', ...command,
        '--socket', socket, '--format', 'json'));
      assert.equal(revoked.membership_epoch, previous.authority_revision + 1);
      await page.getByRole('status').filter({ hasText: /^Disconnected$/ }).waitFor();
      assert.equal(await send.isDisabled(), true);
      const [reply] = await page.evaluate(() => window.checkpointMutationReplies);
      const after = await page.evaluate(key => ({
        attempts: window.checkpointSaveAttempts, saved: localStorage.getItem(key),
      }), checkpointIdentity.key);
      if (failSave) {
        assert.match(await page.locator('#error').textContent(), /Could not save authenticated checkpoint state/);
        assert.deepEqual(reply?.outcome, { rejected: { reason: 'persistence_failed', current: null } });
        assert.deepEqual(after, { attempts: 1, saved });
      } else {
        assert.equal(revoked.resigned, true);
        assert.match(await page.locator('#error').textContent(), /Checkpoint no longer authorizes the connected peer/);
        assert.equal(reply?.outcome.applied?.authority_revision, revoked.membership_epoch);
        const retained = JSON.parse(after.saved).payload.retained.snapshot.payload;
        assert.equal(retained.authority_revision, revoked.membership_epoch);
        assert.deepEqual(retained.members.map(member => member.subject.peer_id), [checkpointIdentity.peer]);
      }
      const deadline = Date.now() + 20_000;
      for (;;) {
        const status = cli('daemon-status', '--socket', socket);
        if (failSave) assert.match(status, /^checkpoint_handoff_acknowledged 0$/m);
        if (/^checkpoint_handoff_active 0$/m.test(status)) {
          assert.match(status, /^checkpoint_handoff_recipients 1$/m);
          assert.match(status, failSave ? /^checkpoint_handoff_failed 1$/m : /^checkpoint_handoff_failed 0$/m);
          assert.match(status, failSave ? /^checkpoint_handoff_acknowledged 0$/m : /^checkpoint_handoff_acknowledged 1$/m);
          break;
        }
        assert.ok(Date.now() < deadline, status);
        await delay(100);
      }
      return;
    }
    if (mode === 'checkpoint') {
      const passphrase = 'isolated credential fixture';
      await page.getByRole('button', { name: 'Download credentials' }).click();
      await page.getByLabel('New passphrase').fill(passphrase);
      const downloaded = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download', exact: true }).click();
      const file = await downloaded;
      assert.equal(file.suggestedFilename(), 'p2p-vpn-credentials.json');
      const bytes = await readFile(await file.path());
      assert.doesNotMatch(bytes.toString(), /private_key|capability_secret|browser-lan-joiner/);
      const disconnected = page.getByRole('status').filter({ hasText: /^Disconnected$/ });
      const send = page.getByRole('button', { name: 'Send request' });
      const openOriginalFile = async (mustStayGated = false) => {
        await page.reload();
        await disconnected.waitFor({ timeout: 5000 });
        if (mustStayGated) {
          await page.evaluate(() => {
            const state = document.querySelector('#state');
            window.checkpointReauthorized = false;
            new MutationObserver(records => {
              if (state.dataset.connected === 'true' || records.some(record => record.oldValue === 'true')) {
                window.checkpointReauthorized = true;
              }
            }).observe(state, { attributes: true, attributeFilter: ['data-connected'], attributeOldValue: true });
          });
        }
        await page.getByRole('button', { name: 'Credentials', exact: true }).click();
        await page.getByLabel('Encrypted credentials').setInputFiles({
          name: 'p2p-vpn-credentials.json', mimeType: 'application/json', buffer: bytes,
        });
        await page.getByLabel('Bundle passphrase').fill(passphrase);
        await page.getByRole('button', { name: 'Connect', exact: true }).click();
        await page.locator('#state[data-connected="true"], #error:visible').first().waitFor({
          timeout: 30_000,
        });
      };
      const retainedCheckpoint = () => page.evaluate(key => {
        const { retained, enrollment_floor } = JSON.parse(localStorage.getItem(key)).payload;
        const { authority_revision, members } = retained.snapshot.payload;
        return { revision: authority_revision, peers: members.map(member => member.subject.peer_id),
          floor: enrollment_floor };
      }, checkpointIdentity.key);

      await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
      await disconnected.waitFor({ timeout: 5000 });
      await openOriginalFile();
      assert.equal(await page.locator('#error').isVisible(), false, await page.locator('#error').textContent());
      assert.equal(await page.locator('#peer-id').textContent(), nativeId);
      assert.equal(await send.isEnabled(), true);
      assert.equal(await page.evaluate(() => document.visibilityState), 'visible');
      const admitted = await retainedCheckpoint();
      assert.deepEqual(new Set(admitted.peers), new Set([nativeId, checkpointIdentity.peer]));
      assert.equal(admitted.floor, null);
      if (activeBackupOnly) {
        assert.deepEqual(pairingRequests, [['/api/pairing/lan', '{}']]);
        return;
      }

      const handoffStatus = () => cli('daemon-status', '--socket', socket)
        .split('\n').filter(line => line.startsWith('checkpoint_')).join('\n');
      async function waitForHandoff(recipients, timeout = 20_000) {
        const deadline = Date.now() + timeout;
        for (;;) {
          const status = handoffStatus();
          if (/^checkpoint_handoff_active 0$/m.test(status)
              && status.includes(`checkpoint_handoff_recipients ${recipients}\n`)
              && /^checkpoint_handoff_acknowledged [1-9]\d*$/m.test(status)) return status;
          assert.ok(Date.now() < deadline, `No durable handoff receipt.\n${status}`);
          await delay(100);
        }
      }

      const second = await chromiumBrowser.newPage();
      let secondPeer;
      try {
        const approval = pair('open', '--expires-in-seconds', '45');
        await second.goto(url);
        await second.getByRole('button', { name: 'Pair code', exact: true }).click();
        await second.getByLabel('Pairing code').fill(approval.code);
        await second.getByLabel('Hostname').fill('browser-lan-second');
        await second.getByRole('button', { name: 'Join network' }).click();
        await second.getByText('Waiting for approval', { exact: true }).waitFor({ timeout: 20_000 });
        const pending = pair('status', approval.operation_id);
        secondPeer = pending.candidate.peer_id;
        assert.notEqual(secondPeer, checkpointIdentity.peer);
        await page.bringToFront();
        await page.evaluate(() => { window.dropNextCheckpointAck = true; });
        pair('approve', approval.operation_id, pending.candidate.approval_id);
        await second.getByRole('button', { name: 'Continue without saving' }).click();
        const upsert = await waitForHandoff(1);
        assert.match(upsert, /^checkpoint_handoff_acknowledged 1$/m);
        assert.match(upsert, /^checkpoint_handoff_failed 0$/m);
        assert.match(upsert, /^checkpoint_handoff_attempts [23]$/m);
        const [lost, replay] = await page.evaluate(() => window.checkpointMutationReplies);
        assert.ok(lost?.outcome.applied);
        assert.deepEqual(replay?.mutation_digest, lost.mutation_digest);
        assert.deepEqual(replay.outcome, {
          rejected: { reason: 'stale_base', current: lost.outcome.applied },
        });
        const added = await retainedCheckpoint();
        assert.equal(added.revision, admitted.revision + 1);
        assert.deepEqual(new Set(added.peers), new Set([...admitted.peers, secondPeer]));
        assert.equal(added.floor, null);
        assert.equal(await send.isEnabled(), true);
        await second.locator('#state[data-connected="true"]').waitFor({ timeout: 25_000 });
        await second.getByRole('button', { name: 'Disconnect', exact: true }).click();
        await second.getByText('Disconnected', { exact: true }).waitFor({ timeout: 5000 });
      } finally {
        await second.close();
        await page.bringToFront();
      }

      const removedOther = JSON.parse(cli('membership', 'revoke', secondPeer,
        '--socket', socket, '--format', 'json'));
      assert.equal(removedOther.membership_epoch, admitted.revision + 2);
      await waitForHandoff(2);
      const beforeRevoke = await retainedCheckpoint();
      assert.equal(beforeRevoke.revision, removedOther.membership_epoch);
      assert.deepEqual(new Set(beforeRevoke.peers), new Set(admitted.peers));
      assert.equal(beforeRevoke.floor, null);
      assert.equal(await send.isEnabled(), true);

      const revoked = JSON.parse(cli('membership', 'revoke', checkpointIdentity.peer,
        '--socket', socket, '--format', 'json'));
      assert.equal(revoked.member_peer, checkpointIdentity.peer);
      assert.equal(revoked.membership_epoch, beforeRevoke.revision + 1);
      try {
        await disconnected.waitFor({ timeout: 30_000 });
      } catch (cause) {
        const peerEvents = daemon.stderr.split('\n')
          .filter(line => line.includes(checkpointIdentity.peer));
        const browserEvents = await page.evaluate(() => ({
          state: document.querySelector('#state').textContent,
          error: document.querySelector('#error').textContent,
          transport: window.checkpointTransportEvents,
        }));
        throw new Error([
          `Checkpoint peer ${checkpointIdentity.peer} did not disconnect after revocation.`,
          ...peerEvents,
          handoffStatus(),
          `Browser: ${JSON.stringify({ ...browserEvents, retained: await retainedCheckpoint() })}`,
        ].join('\n'), { cause });
      }
      assert.match(await page.locator('#error').textContent(), /checkpoint.*(Excluded|revoked)/i);
      assert.equal(await send.isDisabled(), true);
      assert.deepEqual(await retainedCheckpoint(), {
        revision: revoked.membership_epoch, peers: [nativeId], floor: null,
      });
      const receipt = await waitForHandoff(1, 5000);
      assert.match(receipt, /^checkpoint_handoff_acknowledged 1$/m);
      assert.match(receipt, /^checkpoint_handoff_failed 0$/m);
      const finalReply = await page.evaluate(() => window.checkpointMutationReplies.at(-1));
      assert.equal(finalReply?.outcome.applied?.authority_revision, revoked.membership_epoch);

      await openOriginalFile(true);
      assert.equal(await page.locator('#state').getAttribute('data-connected'), 'false');
      assert.equal(await page.evaluate(() => window.checkpointReauthorized), false);
      assert.match(await page.locator('#error').textContent(), /checkpoint.*(Excluded|revoked)/i);
      assert.equal(await send.isDisabled(), true);
      assert.deepEqual(await retainedCheckpoint(), {
        revision: revoked.membership_epoch, peers: [nativeId], floor: null,
      });
    }
    assert.deepEqual(pairingRequests, pairing ? [['/api/pairing/lan', '{}']] : []);
  } finally {
    await chromiumBrowser?.close();
    for (const process of processes.reverse()) {
      if (process.child.exitCode === null && process.child.signalCode === null) {
        process.child.kill('SIGTERM');
        if (!await Promise.race([process.exited, delay(3000, false, { ref: false })])) {
          process.child.kill('SIGKILL');
        }
      }
      await process.exited;
    }
    await rm(directory, { recursive: true, force: true });
  }
}
