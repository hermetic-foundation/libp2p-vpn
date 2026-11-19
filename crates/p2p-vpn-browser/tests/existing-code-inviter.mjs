// Run beside code-inviter.mjs in the Linux browser gate's isolated underlay.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

for (const role of ['founder', 'delegate']) {
  test(`an existing legacy ${role} saves before code approval and activates the same reservation`,
    { timeout: 45_000 }, async t => {
      const { P2P_VPN_BIN: binary, P2P_VPN_PAIRING_PKG: pkg,
        P2P_VPN_RELAY_FIXTURE: fixture, P2P_VPN_CHROMIUM: executablePath } = process.env;
      assert.ok(binary && pkg && fixture);
      const keys = execFileSync(binary, ['keygen', '--output', '-'], { encoding: 'utf8' });
      const network = {
        name: `existing-code-${role}`,
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

      const relay = spawn(fixture, ['192.0.2.1'], { stdio: ['ignore', 'pipe', 'pipe'] });
      const exited = once(relay, 'close');
      const lines = createInterface({ input: relay.stdout });
      t.after(async () => {
        lines.close();
        relay.kill();
        await exited;
      });
      let log = '';
      relay.stderr.setEncoding('utf8').on('data', chunk => { log = (log + chunk).slice(-32_768); });
      const [entrance] = await once(lines, 'line');
      assert.match(entrance, /^\/ip4\/192\.0\.2\.1\/udp\/\d+\/webrtc-direct\//);

      const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
      t.after(() => browser.close());
      const page = await browser.newPage();
      await page.goto(`http://127.0.0.1:${server.address().port}/`);
      const result = await page.evaluate(async ({ network, entrance, role }) => {
        const { default: init, BrowserFileInviter, BrowserCodeInviter, BrowserPairing, BrowserVpn } =
          await import('/p2p_vpn_browser.js');
        await init();
        const fail = async operation => {
          try { await operation(); return null; } catch (error) { return error.message; }
        };
        const circuit = peer => `${entrance}/p2p-circuit/p2p/${peer}`;
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
        const joiner = new BrowserPairing();
        const pin = joiner.peer_id();
        const unrooted = await fail(() => BrowserCodeInviter.open_existing(JSON.stringify(config), pin, entrance));
        let file = await BrowserFileInviter.open(JSON.stringify(config));
        const delegate = seed(file, new BrowserPairing(), 'delegate-peer');
        if (role === 'delegate') {
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
        const priorPeer = await fail(() => BrowserCodeInviter.open_existing(configJson, older.peer_id(), entrance));
        const rootless = role === 'delegate' ? await fail(() => BrowserCodeInviter.open_existing(
          JSON.stringify({ ...config, network: { ...config.network, member_records: [] } }), pin, entrance)) : null;
        const inviter = await BrowserCodeInviter.open_existing(configJson, pin, entrance);
        const exclusive = await fail(() => BrowserFileInviter.open(configJson));
        const address = await inviter.reserve();
        let joined;
        let failure;
        let pending = false;
        const exchange = joiner.join_v2(inviter.code(), ownerPeer, address, 15_000, 'approved-peer',
          () => { pending = true; }).then(
          value => { joined = JSON.parse(value); }, error => { failure = error; });
        const until = async condition => {
          const deadline = performance.now() + 10_000;
          while (!condition()) {
            if (failure) throw failure;
            if (performance.now() >= deadline) throw Error('Pairing timed out');
            await inviter.drive(100);
          }
        };
        await until(() => pending && inviter.pending_candidate());
        const review = JSON.parse(inviter.pending_candidate());
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
        const saved = JSON.parse(localStorage.getItem(key));
        const savedBeforeDelivery = !inviter.delivered() && !joined;
        await until(() => !!joined && inviter.delivered());
        await exchange;
        const owner = await inviter.into_vpn();
        const lockTransferred = await fail(() => BrowserFileInviter.open(configJson));
        const member = BrowserVpn.with_relay(JSON.stringify(joined.config), '', address);
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
          preserved: saved.length === prior.length + 1 && prior.every(record =>
            saved.some(candidate => candidate.signature === record.signature)),
          authorized: incoming.authorized && outgoing.authorized && incoming.ready && outgoing.ready,
          grant: saved.find(record => record.payload.member_peer === pin).payload,
          roots: joined.config.network.member_records
            .filter(record => record.payload.issuer_peer === record.payload.member_peer)
            .map(record => record.payload.issuer_peer),
          packet: packet && Array.from(packet),
        };
      }, { network, entrance, role }).catch(error => {
        throw Error(`${error.message}\nRelay events:\n${log}`, { cause: error });
      });
      assert.match(result.denied, /Could not save/);
      assert.equal(result.stillPending && result.unchanged && result.savedBeforeDelivery, true);
      assert.match(result.priorPeer, /no prior membership/);
      assert.match(result.unrooted, /requires a rooted legacy ledger/);
      assert.match(result.exclusive, /identity is in use/);
      assert.match(result.lockTransferred, /identity is in use/);
      if (role === 'delegate') assert.match(result.rootless, /saved legacy issuer root/);
      assert.equal(result.review.peer_id, result.pin);
      assert.equal(result.review.requested_hostname, 'approved-peer');
      assert.equal(result.preserved, true);
      assert.equal(result.authorized, true);
      assert.equal(result.activeAddress, result.address);
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
