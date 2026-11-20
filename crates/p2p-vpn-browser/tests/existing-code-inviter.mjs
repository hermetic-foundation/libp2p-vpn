// Run beside code-inviter.mjs in the Linux browser gate's isolated underlay.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

async function scopedCompanion(t, binary, pkg, entrance, alias) {
  const assets = await mkdtemp(join(tmpdir(), 'existing-scoped-inviter-'));
  t.after(() => rm(assets, { recursive: true, force: true }));
  await mkdir(join(assets, 'pkg'));
  for (const name of ['app.html', 'app.js', 'app.css', 'code-inviter.html', 'code-inviter.js']) {
    await copyFile(new URL(`../web/${name}`, import.meta.url), join(assets, name));
  }
  for (const name of ['p2p_vpn_browser.js', 'p2p_vpn_browser_bg.wasm', 'logo.svg']) {
    await copyFile(join(pkg, name), join(assets, 'pkg', name));
  }
  const child = spawn(binary, ['browser-serve', '--assets', assets, '--port', '0',
    '--relay-entrance', entrance, '--relay-native-alias', alias],
  { stdio: ['ignore', 'pipe', 'inherit'] });
  const exited = once(child, 'close');
  const lines = createInterface({ input: child.stdout });
  t.after(async () => {
    lines.close();
    child.kill();
    await exited;
  });
  const [line] = await once(lines, 'line');
  const url = /^Browser app: (http:\/\/127\.0\.0\.1:\d+)\/app\.html$/.exec(line)?.[1];
  assert.ok(url, line);
  return url;
}

for (const role of ['founder', 'delegate', 'scoped delegate']) {
  test(`an existing legacy ${role} saves before code approval and activates the same reservation`,
    { timeout: 45_000 }, async t => {
      const { P2P_VPN_BIN: binary, P2P_VPN_PAIRING_PKG: pkg,
        P2P_VPN_RELAY_FIXTURE: fixture, P2P_VPN_CHROMIUM: executablePath } = process.env;
      assert.ok(binary && pkg && fixture);
      const scoped = role === 'scoped delegate';
      if (scoped) {
        const outer = process.env.P2P_VPN_TEST_NETNS;
        assert.match(outer ?? '', /^net:\[\d+\]$/);
        assert.notEqual(await readlink('/proc/self/ns/net'), outer);
      }
      const keys = execFileSync(binary, ['keygen', '--output', '-'], { encoding: 'utf8' });
      const network = {
        name: `existing-code-${role.replace(' ', '-')}`,
        local_peer: /^peer_id: (\S+)$/m.exec(keys)[1],
        private_key: /^private_key: (\S+)$/m.exec(keys)[1],
        vpn_ip: '10.80.0.1',
      };
      const files = new Map([
        ['/', ['text/html', '<!doctype html><title>Existing code inviter</title>']],
        ['/p2p_vpn_browser.js', ['text/javascript', await readFile(join(pkg, 'p2p_vpn_browser.js'))]],
        ['/p2p_vpn_browser_bg.wasm', ['application/wasm', await readFile(join(pkg, 'p2p_vpn_browser_bg.wasm'))]],
      ]);
      const server = createServer((request, response) => {
        const file = request.method === 'GET' && files.get(request.url);
        if (!file) return response.writeHead(404).end();
        response.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
      });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      t.after(() => new Promise(resolve => server.close(resolve)));

      const relayIp = '11.250.0.2';
      const relay = scoped ? spawn('unshare', ['--net', 'sh', '-ec', [
        'printf "%s\\n" "$$"',
        'read ready',
        'ip link set lo up',
        'ip link set legacy-relay addrgenmode none',
        `ip addr add ${relayIp}/24 dev legacy-relay`,
        'ip link set legacy-relay up',
        'exec "$@"',
      ].join('\n'), 'relay-namespace', fixture, relayIp, '--locator-dht'],
      { stdio: ['pipe', 'pipe', 'pipe'] }) :
        spawn(fixture, ['192.0.2.1'], { stdio: ['ignore', 'pipe', 'pipe'] });
      const exited = once(relay, 'close');
      const lines = createInterface({ input: relay.stdout });
      t.after(async () => {
        lines.close();
        relay.kill();
        await exited;
      });
      let log = '';
      relay.stderr.setEncoding('utf8').on('data', chunk => { log = (log + chunk).slice(-32_768); });
      const output = lines[Symbol.asyncIterator]();
      let entrance, alias;
      if (scoped) {
        const { value: pid } = await output.next();
        assert.match(pid, /^\d+$/);
        const ip = (...args) => execFileSync('ip', args, { timeout: 5000 });
        ip('link', 'add', 'legacy-egress', 'type', 'veth', 'peer', 'name', 'legacy-relay', 'netns', pid);
        ip('link', 'set', 'legacy-egress', 'addrgenmode', 'none');
        ip('addr', 'add', '11.250.0.1/24', 'dev', 'legacy-egress');
        ip('link', 'set', 'legacy-egress', 'up');
        ip('route', 'add', 'default', 'dev', 'legacy-egress');
        relay.stdin.end('ready\n');
        ({ webrtc: entrance, tcp: alias } = JSON.parse((await output.next()).value));
      } else {
        ({ value: entrance } = await output.next());
        assert.match(entrance, /^\/ip4\/192\.0\.2\.1\/udp\/\d+\/webrtc-direct\//);
      }

      const origin = scoped ? await scopedCompanion(t, binary, pkg, entrance, alias) :
        `http://127.0.0.1:${server.address().port}`;
      const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
      t.after(() => browser.close());
      const page = await browser.newPage();
      await page.goto(origin + '/');
      const result = await page.evaluate(async ({ network, entrance, role, scoped, alias }) => {
        const { default: init, BrowserFileInviter, BrowserCodeInviter, BrowserPairing, BrowserVpn } =
          await import(scoped ? '/pkg/p2p_vpn_browser.js' : '/p2p_vpn_browser.js');
        await init();
        const fail = async operation => {
          try { await operation(); return null; } catch (error) { return error.message; }
        };
        const circuit = peer => `${entrance}/p2p-circuit/p2p/${peer}`;
        const relayPeer = entrance.split('/').at(-1);
        let prepared;
        if (scoped) {
          const reply = await fetch('/api/relay/inviter/reservation', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ relay_peer: relayPeer }),
          });
          if (!reply.ok) throw Error(`Could not prepare scoped relay: ${await reply.text()}`);
          prepared = await reply.json();
          if (prepared.native_alias !== alias ||
              !prepared.relay_entrance.startsWith('/ip4/127.0.0.1/')) {
            throw Error('Companion did not return the scoped entrance and public alias');
          }
        }
        // The detached file path provisions real signed roots and delegated proofs.
        const seed = (inviter, guest, hostname) => {
          const enrollment = guest.begin_offline(inviter.create_offer(), hostname);
          const review = JSON.parse(inviter.review_request(enrollment.request_json()));
          const response = inviter.approve(guest.peer_id());
          return {
            ip: review.vpn_ipv4,
            config: JSON.parse(enrollment.accept_response(response, circuit(enrollment.inviter_peer()))).config,
          };
        };
        network.membership_key = btoa('k'.repeat(32));
        network.external_addresses = [circuit(network.local_peer)];
        let config = { network };
        let ownerIp = network.vpn_ip;
        const pinnedJoiner = scoped ? null : new BrowserPairing();
        const open = (json, pin = pinnedJoiner?.peer_id()) => scoped ?
          BrowserCodeInviter.open_existing_scoped(json, relayPeer, prepared.relay_entrance, prepared.native_alias) :
          BrowserCodeInviter.open_existing(json, pin, entrance);
        const unrooted = await fail(() => open(JSON.stringify(config)));
        let file = await BrowserFileInviter.open(JSON.stringify(config));
        const delegate = seed(file, new BrowserPairing(), 'delegate-peer');
        if (role !== 'founder') {
          await file.close();
          config = delegate.config;
          ownerIp = delegate.ip;
          config.network.external_addresses = [circuit(config.network.local_peer)];
          file = await BrowserFileInviter.open(JSON.stringify(config));
        }
        const older = new BrowserPairing();
        seed(file, older, 'older-peer');
        await file.close();
        config.peers = [...(config.peers ?? []), { id: older.peer_id() }];
        const configJson = JSON.stringify(config);
        const ownerPeer = config.network.local_peer;
        const key = 'p2p-vpn:legacy-membership:1:' + JSON.stringify([network.name, ownerPeer]);
        const original = localStorage.getItem(key);
        const prior = JSON.parse(original);
        const priorPeer = scoped ? null : await fail(() => open(configJson, older.peer_id()));
        const rootless = role !== 'founder' ? await fail(() => open(
          JSON.stringify({ ...config, network: { ...config.network, member_records: [] } }))) : null;
        const inviter = await open(configJson);
        const exclusive = await fail(() => BrowserFileInviter.open(configJson));
        const address = await inviter.reserve();
        const joiner = pinnedJoiner ?? new BrowserPairing();
        const pin = joiner.peer_id();
        const dialAddress = scoped ? circuit(ownerPeer) : address;
        let joined;
        let failure;
        let pending = false;
        const exchange = joiner.join_v2(inviter.code(), ownerPeer, dialAddress, 12_000, 'approved-peer',
          () => { pending = true; }).then(
          value => { joined = JSON.parse(value); }, error => { failure = error; });
        const until = async condition => {
          const deadline = performance.now() + 15_000;
          while (!condition()) {
            if (failure) throw failure;
            if (performance.now() >= deadline) throw Error('Pairing timed out');
            await inviter.drive(100);
          }
        };
        await until(() => pending && inviter.pending_candidate());
        const review = JSON.parse(inviter.pending_candidate());
        const wrongPeer = await fail(() => inviter.approve(older.peer_id()));
        const write = Storage.prototype.setItem;
        Storage.prototype.setItem = function (name, value) {
          if (name === key) throw new DOMException('Test quota', 'QuotaExceededError');
          return write.call(this, name, value);
        };
        let denied;
        try { denied = await fail(() => inviter.approve(pin)); }
        finally { Storage.prototype.setItem = write; }
        const waitForPoll = performance.now() + 1_300;
        await until(() => performance.now() >= waitForPoll);
        const stillPending = !joined && !inviter.delivered() && !!inviter.pending_candidate();
        const unchanged = localStorage.getItem(key) === original;
        inviter.approve(pin);
        const saved = JSON.parse(localStorage.getItem(key)).records;
        const savedBeforeDelivery = !inviter.delivered() && !joined;
        await until(() => !!joined && inviter.delivered());
        await exchange;
        const owner = await inviter.into_vpn();
        const lockTransferred = await fail(() => BrowserFileInviter.open(configJson));
        const member = BrowserVpn.with_relay(JSON.stringify(joined.config), '', dialAddress);
        let connected = 0;
        let failed = false;
        const establish = async (vpn, connect, label) => {
          try {
            const snapshot = JSON.parse(await connect());
            connected++;
            // An established peer must keep serving membership snapshots
            // while the other verifies the existing network's larger ledger.
            while (connected < 2 && !failed) await vpn.poll_foreground();
            return snapshot;
          } catch (error) {
            failed = true;
            throw Error(`${label}: ${error.message}`);
          }
        };
        const [incoming, outgoing] = await Promise.all([
          establish(owner, () => owner.accept_relay(), 'inviter authorization'),
          establish(member, () => member.connect(), 'joiner authorization'),
        ]);
        void member.fetch_http(ownerIp, 8080, '/').catch(() => {});
        const packet = await owner.receive_relay_packet(5000);
        const activeAddress = owner.relay_reservation_address();
        await owner.close().catch(error => { throw Error(`closing activated inviter: ${error.message}`); });
        const reopened = await BrowserFileInviter.open(configJson);
        await reopened.close();
        return {
          denied, stillPending, unchanged, savedBeforeDelivery, review, ownerPeer, ownerIp, pin,
          address, priorPeer, unrooted, rootless, exclusive, lockTransferred, activeAddress,
          wrongPeer, signedAddresses: joined.config.peers.find(peer => peer.id === ownerPeer).addresses,
          preserved: saved.length === prior.length + 1 && prior.every(record =>
            saved.some(candidate => candidate.signature === record.signature)),
          authorized: incoming.authorized && outgoing.authorized && incoming.ready && outgoing.ready,
          grant: saved.find(record => record.payload.member_peer === pin).payload,
          roots: joined.config.network.member_records
            .filter(record => record.payload.issuer_peer === record.payload.member_peer)
            .map(record => record.payload.issuer_peer),
          packet: packet && Array.from(packet),
        };
      }, { network, entrance, role, scoped, alias }).catch(error => {
        throw Error(`${error.message}\nRelay events:\n${log}`, { cause: error });
      });
      assert.match(result.denied, /Could not save/);
      assert.equal(result.stillPending && result.unchanged && result.savedBeforeDelivery, true);
      if (!scoped) assert.match(result.priorPeer, /no prior membership/);
      assert.match(result.wrongPeer, /No pending invitation/);
      assert.match(result.unrooted, /requires a rooted legacy ledger/);
      assert.match(result.exclusive, /identity is in use/);
      assert.match(result.lockTransferred, /identity is in use/);
      if (role !== 'founder') assert.match(result.rootless, /saved legacy issuer root/);
      assert.equal(result.review.peer_id, result.pin);
      assert.equal(result.review.requested_hostname, 'approved-peer');
      assert.equal(result.preserved, true);
      assert.equal(result.authorized, true);
      assert.equal(result.activeAddress, result.address);
      if (scoped) {
        assert.equal(result.address, `${alias}/p2p-circuit/p2p/${result.ownerPeer}`);
        assert.deepEqual(result.signedAddresses, [result.address]);
        assert.ok(log.includes(`ReservationReqAccepted { src_peer_id: PeerId("${result.ownerPeer}"), renewed: false }`), log);
      }
      assert.deepEqual(result.roots, [network.local_peer]);
      assert.equal(result.grant.issuer_peer, result.ownerPeer);
      assert.equal(result.grant.member_peer, result.pin);
      assert.deepEqual(result.grant.roles, ['overlay_member']);
      assert.deepEqual(result.grant.route_grants, []);
      assert.ok(result.packet?.length >= 40, log);
      assert.equal(result.packet[0] >> 4, 4);
      assert.equal(result.packet[9], 6);
      assert.deepEqual(result.packet.slice(12, 20),
        `${result.review.assigned_vpn_ip}.${result.ownerIp}`.split('.').map(Number));
      const tcp = (result.packet[0] & 0xf) * 4;
      assert.equal((result.packet[tcp + 2] << 8) | result.packet[tcp + 3], 8080);
      assert.equal(result.packet[tcp + 13] & 0x12, 0x02);
      assert.equal([...log.matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1, log);
      assert.doesNotMatch(log, /ReservationReqDenied/);
    });
}
