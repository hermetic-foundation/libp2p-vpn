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

async function recordCheckpointTransport(page) {
  await page.addInitScript(() => {
    const events = window.checkpointTransportEvents = [];
    const note = (...event) => {
      if (events.length === 48) events.shift();
      events.push(event);
    };
    const protocols = ['/ipfs/id/', '/p2p-vpn/checkpoint-mutation/1'];
    const decoder = new TextDecoder();
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

async function exerciseHost(mode) {
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
    chromiumBrowser = await chromium.launch(process.env.P2P_VPN_CHROMIUM
      ? { executablePath: process.env.P2P_VPN_CHROMIUM }
      : { channel: 'chrome' });
    const page = await chromiumBrowser.newPage();
    if (mode === 'checkpoint') await recordCheckpointTransport(page);
    const pairingRequests = [];
    const pairingResponses = [];
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
      pair('approve', approval.operation_id, pending.candidate.approval_id);
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
        pair('approve', approval.operation_id, pending.candidate.approval_id);
        const upsert = await waitForHandoff(1);
        assert.match(upsert, /^checkpoint_handoff_acknowledged 1$/m);
        assert.match(upsert, /^checkpoint_handoff_failed 0$/m);
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
