// Native fixture + Chromium test-hooks in an isolated netns with only lo and
// a dummy interface. Neither fixture address is used outside it.
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, readlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';

const { chromium } = createRequire(import.meta.url)('playwright');
const run = promisify(execFile);
const FIXTURE_IP = '11.255.48.1';
const SEED_IP = '11.255.48.2';

test('single-relay publication is found via its referral but missed on an independent DHT route',
  { timeout: 50_000 }, async t => {
    const { P2P_VPN_LOCATOR_PKG: pkg, P2P_VPN_RELAY_FIXTURE: fixture,
      P2P_VPN_CHROMIUM: executablePath, P2P_VPN_TEST_NETNS: outer } = process.env;
    assert.ok(pkg && fixture);
    assert.match(outer ?? '', /^net:\[\d+\]$/);
    assert.notEqual(await readlink('/proc/self/ns/net'), outer);
    const links = JSON.parse(execFileSync('ip', ['-j', '-d', 'address', 'show'], { encoding: 'utf8' }));
    const underlay = links.filter(link => link.ifname !== 'lo');
    assert.equal(underlay.length, 1);
    assert.equal(underlay[0].linkinfo.info_kind, 'dummy');
    assert.ok(underlay[0].addr_info.some(ip => ip.local === FIXTURE_IP));
    for (const family of ['-4', '-6']) {
      assert.deepEqual(JSON.parse(execFileSync('ip', [family, '-j', 'route', 'show', 'default'])), []);
    }
    for (const address of [SEED_IP, '11.255.48.3', '11.255.48.4']) {
      execFileSync('ip', ['address', 'add', `${address}/24`, 'dev', underlay[0].ifname]);
    }

    const files = new Map([
      ['/', ['text/html', '<!doctype html><title>Controlled locator fixture</title>']],
      ['/p2p_vpn_browser.js', ['text/javascript', await readFile(join(pkg, 'p2p_vpn_browser.js'))]],
      ['/p2p_vpn_browser_bg.wasm', ['application/wasm', await readFile(join(pkg, 'p2p_vpn_browser_bg.wasm'))]],
    ]);
    const server = createServer((req, res) => {
      const file = req.method === 'GET' && files.get(req.url);
      if (!file) return res.writeHead(404).end();
      res.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));

    async function route(seedIp, serverIp) {
      const child = spawn(fixture, ['--auto-relay-dht', seedIp, serverIp], { stdio: ['ignore', 'pipe', 'pipe'] });
      const closed = once(child, 'close');
      const lines = createInterface({ input: child.stdout });
      let log = '';
      child.stderr.setEncoding('utf8').on('data', chunk => { log = (log + chunk).slice(-32768); });
      t.after(async () => {
        lines.close();
        child.kill();
        await closed;
      });
      const [opening] = await once(lines, 'line');
      return { ...JSON.parse(opening), log: () => log };
    }
    const publishing = await route(SEED_IP, FIXTURE_IP);
    const { bootstrap, native: tcp, webrtc } = publishing;
    assert.match(webrtc, /^\/ip4\/11\.255\.48\.1\/udp\/\d+\/webrtc-direct\//);
    assert.match(tcp, /^\/ip4\/11\.255\.48\.1\/tcp\/\d+\/p2p\//);
    assert.match(bootstrap, /^\/ip4\/11\.255\.48\.2\/tcp\/\d+\/p2p\//);
    assert.notEqual(bootstrap.split('/').at(-1), tcp.split('/').at(-1));
    const lookup = async (locator, seed = bootstrap) => {
      const { stdout } = await run(fixture, ['--lookup-locator', seed, locator], { timeout: 8_000 });
      return JSON.parse(stdout);
    };

    const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage();
    const requests = [];
    page.on('request', request => requests.push([request.method(), new URL(request.url()).pathname]));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const scope = await page.evaluate(async ({ webrtc, tcp }) => {
      const { default: init, BrowserCodeInviter, BrowserPairing, pairing_code_v2_global_locator } =
        await import('/p2p_vpn_browser.js');
      await init();
      const joiner = new BrowserPairing();
      const inviter = new BrowserCodeInviter('controlled-code-locator', '10.80.0.1', '10.80.0.2',
        joiner.peer_id(), webrtc);
      const peer = inviter.peer_id();
      const alias = `${tcp}/p2p-circuit/p2p/${peer}`;
      try {
        await inviter.publish_locator_controlled(alias);
        throw Error('Publication unexpectedly accepted before reservation');
      } catch (error) {
        if (!/No confirmed invitation reservation/.test(error.message)) throw error;
      }
      const primary = await inviter.reserve();
      window.testInviter = inviter;
      return { peer, alias, primary, locator: pairing_code_v2_global_locator(inviter.code()) };
    }, { webrtc, tcp });
    assert.equal(scope.primary, `${webrtc}/p2p-circuit/p2p/${scope.peer}`);
    assert.deepEqual(await lookup(scope.locator), []);

    const published = await page.evaluate(async alias => {
      const inviter = window.testInviter;
      const fail = async address => {
        try { await inviter.publish_locator_controlled(address); return ''; }
        catch (error) { return error.message; }
      };
      const loopback = await fail(alias.replace('/ip4/11.255.48.1/', '/ip4/127.0.0.1/'));
      const unconfirmed = await fail(alias.replace(/\/tcp\/(\d+)\//, (_, port) =>
        `/tcp/${Number(port) === 65000 ? 65001 : 65000}/`));
      const deadline = performance.now() + 3000;
      for (;;) {
        const result = await fail(alias);
        if (!result) break;
        if (!/confirmed public TCP or QUIC/.test(result) || performance.now() >= deadline) throw Error(result);
        await inviter.drive(100);
      }
      const repeated = await fail(alias);
      return { loopback, unconfirmed, repeated, primary: await inviter.reserve() };
    }, scope.alias).catch(error => {
      throw Error(`${error.message}\n${publishing.log()}`, { cause: error });
    });
    assert.match(published.loopback, /confirmed public TCP or QUIC/);
    assert.match(published.unconfirmed, /confirmed public TCP or QUIC/);
    assert.match(published.repeated, /already attempted/);
    assert.equal(published.primary, scope.primary);
    const beforeLookup = publishing.log().length;
    assert.deepEqual(await lookup(scope.locator), [{ peer: scope.peer, addresses: [scope.alias] }], publishing.log());
    // The client followed the seed's ordinary Kademlia referral. The seed
    // had no provider itself, and was never given to the browser.
    const referral = /fixture seed GET_PROVIDERS closer=1 providers=0[\s\S]*fixture relay GET_PROVIDERS providers=1/;
    async function checkReferral(log, expected) {
      const deadline = performance.now() + 1000;
      while (!expected.test(log()) && performance.now() < deadline) await delay(10);
      assert.match(log(), expected);
    }
    await checkReferral(() => publishing.log().slice(beforeLookup), referral);
    const independent = await route('11.255.48.3', '11.255.48.4');
    assert.notEqual(independent.relay_peer, publishing.relay_peer);
    assert.notEqual(independent.bootstrap.split('/').at(-1), bootstrap.split('/').at(-1));
    const beforeIndependent = publishing.log().match(/GET_PROVIDERS/g)?.length;
    assert.deepEqual(await lookup(scope.locator, independent.bootstrap), []);
    await checkReferral(independent.log,
      /fixture seed GET_PROVIDERS closer=1 providers=0[\s\S]*fixture relay GET_PROVIDERS providers=0/);
    assert.equal(publishing.log().match(/GET_PROVIDERS/g)?.length, beforeIndependent);
    assert.deepEqual(await lookup(scope.locator.replace(/^./, char => char === 'A' ? 'B' : 'A')), []);
    assert.equal([...publishing.log().matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1, publishing.log());
    assert.equal(publishing.log().split('\n').filter(line => line.startsWith(`relay-hop ${scope.peer} `)).length, 1, publishing.log());
    assert.ok(requests.every(([method, path]) => method === 'GET' && files.has(path)), JSON.stringify(requests));
  });
