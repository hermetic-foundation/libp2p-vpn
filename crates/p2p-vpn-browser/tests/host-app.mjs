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
}, async () => {
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
    native.peers = [{ id: browserId, addresses: ['/ip4/127.0.0.1/tcp/9'] }];
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
    '--control-socket', join(directory, 'control.sock')], { stdio: ['pipe', 'pipe', 'pipe'] }));
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
    await page.goto(url);
    await page.getByRole('status').filter({ hasText: /^Disconnected$/ }).waitFor();
    await page.getByLabel('Peer config').setInputFiles(browserPath);
    assert.equal(await page.getByLabel('Peer ID or address').inputValue(), '');
    const lookup = page.waitForResponse(response => response.url().endsWith('/api/discovery'));
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    const response = await lookup;
    assert.equal(response.status(), 200);
    assert.ok((await response.json()).addresses.includes(dial));
    const query = response.request().postDataJSON();
    assert.equal(query.peer, nativeId);
    assert.equal(query.lan, true);
    assert.equal(query.kademlia, false);
    assert.ok(!Object.hasOwn(query, 'private_key') && !Object.hasOwn(query, 'config'));
    await page.locator('#state[data-connected="true"], #error:visible').first().waitFor();
    assert.equal(await page.locator('#error').isVisible(), false, await page.locator('#error').textContent());
    assert.equal(await page.locator('#peer-id').textContent(), nativeId);
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
});
