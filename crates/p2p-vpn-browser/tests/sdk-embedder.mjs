import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { readFile, readlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const TUN = 'pvsdk0';
const NATIVE_UNDERLAY = '192.168.42.2';
const run = (command, ...args) => execFileSync(command, args, { encoding: 'utf8', timeout: 8000 });
const ip = (...args) => run('ip', ...args);

if (process.argv[2] === 'http') {
  const [address, expectedSource, nonce] = process.argv.slice(3);
  const service = createServer((req, res) => {
    const source = req.socket.remoteAddress;
    const accepted = source === expectedSource && req.method === 'GET' && req.url === `/?nonce=${nonce}`;
    console.log('request:' + JSON.stringify({ source, path: req.url, accepted }));
    const body = accepted ? `standalone-sdk:${nonce}` : 'Unexpected overlay request';
    res.writeHead(accepted ? 200 : 403, { 'Content-Length': Buffer.byteLength(body) }).end(body);
  });
  service.listen(0, address);
  await once(service, 'listening');
  console.log('port:' + service.address().port);
} else {
  test('a standalone Chromium embedder exchanges HTTP over the SDK and native TUN', verify);
}

function start(t, command, ...args) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = once(child, 'close');
  exited.catch(() => {});
  let logs = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8').on('data', chunk => { logs = (logs + chunk).slice(-32768); });
  }
  t.after(async () => {
    child.kill('SIGKILL');
    await exited.catch(() => {});
  });
  return {
    child,
    async expect(pattern) {
      const deadline = performance.now() + 12000;
      do {
        const match = pattern.exec(logs);
        if (match) return match[1];
        if (child.exitCode !== null || child.signalCode !== null) break;
        await delay(50);
      } while (performance.now() < deadline);
      throw new Error(`${command} never matched ${pattern}\n${logs}`);
    },
  };
}

async function verify(t) {
  const { P2P_VPN_BIN: binary, P2P_VPN_BROWSER_SDK_DIR: sdk, P2P_VPN_CHROMIUM: executablePath,
    P2P_VPN_TEST_NETNS: outer } = process.env;
  assert.ok(binary && sdk, 'run scripts/test-sdk-browser-embedder.sh CLI SDK_PKG');
  assert.match(outer ?? '', /^net:\[\d+\]$/);
  const browserNetns = await readlink('/proc/self/ns/net');
  assert.notEqual(browserNetns, outer);
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(link => link.ifname), ['lo']);
  const { chromium } = createRequire(import.meta.url)('playwright');

  const scratch = process.cwd();
  const network = `standalone-sdk-${randomUUID().slice(0, 8)}`;
  async function peer(name) {
    const path = join(scratch, `${name}.json`);
    run(binary, 'init-config', '--network', network, '--interface', TUN, '--output', path);
    const config = JSON.parse(await readFile(path, 'utf8'));
    Object.assign(config.network, {
      discovery: {
        mdns: false, kademlia: false, kademlia_provider_advertisement: false, dcutr: false, autonat: false,
      },
      dns: { enabled: false },
      packet_plane: { listen: [], quic_listen: [] },
      listen_addresses: [],
    });
    const status = run(binary, 'status', '-c', path);
    const id = /^local peer: (\S+)$/m.exec(status)?.[1];
    const address = /^local overlay ipv4: ((?:\d+\.){3}\d+)/m.exec(status)?.[1];
    assert.ok(id && address, status);
    return { path, config, id, address };
  }

  const native = await peer('native');
  const client = await peer('browser');
  assert.notEqual(native.id, client.id);
  assert.notEqual(native.address, client.address);
  native.config.network.listen_addresses = [`/ip4/${NATIVE_UNDERLAY}/udp/0/webrtc-direct`];
  native.config.peers = [{ id: client.id, addresses: ['/ip4/127.0.0.1/tcp/9'] }];
  client.config.peers = [{ id: native.id }];
  await writeFile(native.path, JSON.stringify(native.config), { mode: 0o600 });

  ip('link', 'set', 'lo', 'up');
  const daemon = start(t, 'unshare', '--net', 'sh', '-ec', [
    'printf "namespace:%s\\n" "$$"',
    'read -r ready',
    'ip link set lo up',
    `ip addr add ${NATIVE_UNDERLAY}/24 dev sdk-native`,
    'ip link set sdk-native up',
    'exec "$@"',
  ].join('\n'), 'native', binary, 'up', '-c', native.path,
  '--control-socket', join(scratch, 'peer.sock'), '--pairing-state', join(scratch, 'pairing'),
  '--membership-state', join(scratch, 'membership'));
  const pid = await daemon.expect(/^namespace:(\d+)$/m);
  const nativeNetns = await readlink(`/proc/${pid}/ns/net`);
  assert.notEqual(nativeNetns, browserNetns);
  assert.notEqual(nativeNetns, outer);
  ip('link', 'add', 'sdk-browser', 'type', 'veth', 'peer', 'name', 'sdk-native', 'netns', pid);
  ip('addr', 'add', '192.168.42.1/24', 'dev', 'sdk-browser');
  ip('link', 'set', 'sdk-browser', 'up');
  daemon.child.stdin.end('ready\n');
  const dial = await daemon.expect(/event=webrtc_listener_ready[^\n]* address=(\S+)/);
  assert.ok(dial.startsWith(`/ip4/${NATIVE_UNDERLAY}/udp/`) && dial.endsWith(`/p2p/${native.id}`), dial);
  const [tun] = JSON.parse(run('nsenter', '--target', pid, '--net', '--', 'ip', '-j', '-d', 'link', 'show', 'dev', TUN));
  assert.equal(tun.linkinfo.info_kind, 'tun');

  const nonce = randomUUID();
  const path = `/?nonce=${nonce}`;
  const service = start(t, 'nsenter', '--target', pid, '--net', '--',
    process.execPath, fileURLToPath(import.meta.url), 'http', native.address, client.address, nonce);
  const port = Number(await service.expect(/^port:(\d+)$/m));
  const files = new Map([
    ['/', ['text/html', '<!doctype html><meta charset="utf-8"><script type="module" src="/embedder.js"></script>']],
    ['/embedder.js', ['text/javascript', await readFile(new URL('./sdk-embedder.js', import.meta.url))]],
    ['/sdk/p2p_vpn_browser.js', ['text/javascript', await readFile(join(sdk, 'p2p_vpn_browser.js'))]],
    ['/sdk/p2p_vpn_browser_bg.wasm', ['application/wasm', await readFile(join(sdk, 'p2p_vpn_browser_bg.wasm'))]],
  ]);
  const origin = createServer((req, res) => {
    const asset = files.get(req.url);
    if (!asset) return res.writeHead(404).end();
    res.writeHead(200, { 'Content-Type': asset[0] }).end(asset[1]);
  });
  t.after(() => {
    origin.close();
    origin.closeAllConnections();
  });
  origin.listen(0, '127.0.0.1');
  await once(origin, 'listening');

  const browser = await chromium.launch({ ...(executablePath ? { executablePath } : { channel: 'chrome' }), timeout: 15000 });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  const loaded = new Set();
  page.on('response', res => {
    if (res.ok()) loaded.add(new URL(res.url()).pathname);
  });
  await page.goto(`http://127.0.0.1:${origin.address().port}`, { timeout: 10000 });
  await page.waitForFunction(() => typeof window.proof === 'function', null, { timeout: 5000 });
  const { connected, response, counters } = await Promise.race([
    page.evaluate(input => window.proof(input), { config: client.config, dial, address: native.address, port, path }),
    delay(25000, null, { ref: false }).then(() => { throw new Error('SDK connect/HTTP/close timed out'); }),
  ]);

  assert.equal(connected.authorized, true);
  assert.equal(connected.transport, 'webrtc-direct');
  assert.equal(connected.local_peer_id, client.id);
  assert.equal(connected.remote_peer_id, native.id);
  assert.match(response, /^HTTP\/1\.1 200 OK\r\n/);
  assert.equal(response.split('\r\n\r\n')[1], `standalone-sdk:${nonce}`);
  const request = JSON.parse(await service.expect(/^request:(.+)$/m));
  assert.deepEqual(request, { source: client.address, path, accepted: true });
  for (const key of ['outbound_ip_packets', 'inbound_ip_packets', 'accepted_outbound_packets']) {
    assert.ok(counters[key] > 0, key);
  }
  assert.deepEqual(loaded, new Set(files.keys()));
  assert.deepEqual(pageErrors, []);
  t.diagnostic(JSON.stringify({
    chromium: browser.version(), transport: connected.transport, browserNetns, nativeNetns,
    tun: tun.ifname, target: `${native.address}:${port}`, request, counters, assets: [...loaded],
  }));
}
