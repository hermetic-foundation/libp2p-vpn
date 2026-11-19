// Requires test-hooks and the native relay in the Linux gate's isolated underlay.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, readlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const { chromium } = createRequire(import.meta.url)('playwright');

for (const scenario of ['approval', 'cancelled', 'cancelled-after-save', 'expired', 'saturation']) {
  test(`unpinned v2: ${scenario} on a controlled reservation`, { timeout: 45_000 }, async t => {
    const { P2P_VPN_UNPINNED_PKG: pkg, P2P_VPN_RELAY_FIXTURE: fixture, P2P_VPN_BIN: binary,
      P2P_VPN_CHROMIUM: executablePath, P2P_VPN_TEST_NETNS: outer } = process.env;
    assert.ok(pkg && fixture && binary);
    assert.match(outer ?? '', /^net:\[\d+\]$/);
    assert.notEqual(await readlink('/proc/self/ns/net'), outer);
    const links = JSON.parse(execFileSync('ip', ['-j', 'address', 'show'], { encoding: 'utf8' }));
    assert.equal(links.filter(link => link.ifname !== 'lo').length, 1);

    const files = new Map([
      ['/', ['text/html', '<!doctype html><title>Unpinned invitation fixture</title>']],
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

    const relay = spawn(fixture, ['192.0.2.1'], { stdio: ['ignore', 'pipe', 'pipe'] });
    const exited = once(relay, 'close');
    const lines = createInterface({ input: relay.stdout });
    let log = '';
    relay.stderr.setEncoding('utf8').on('data', chunk => { log = (log + chunk).slice(-32_768); });
    t.after(async () => {
      lines.close();
      relay.kill();
      await exited;
    });
    const [entrance] = await once(lines, 'line');
    const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
    t.after(() => browser.close());
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const keys = execFileSync(binary, ['keygen', '--output', '-'], { encoding: 'utf8' });
    const attacker = {
      local_peer: /^peer_id: (\S+)$/m.exec(keys)[1],
      private_key: /^private_key: (\S+)$/m.exec(keys)[1],
    };
    const result = await page.evaluate(async ({ entrance, scenario, attacker }) => {
      const { default: init, BrowserCodeInviter, BrowserPairing, BrowserVpn } =
        await import('/p2p_vpn_browser.js');
      await init();
      const network = `unpinned-${scenario}`;
      const inviter = await BrowserCodeInviter.open_unpinned_controlled(network, '10.80.0.1', '10.80.0.2', entrance);
      const ownerPeer = inviter.peer_id();
      const address = await inviter.reserve();
      const code = inviter.code();
      const key = 'p2p-vpn:legacy-membership:1:' + JSON.stringify([network, ownerPeer]);
      const fail = async operation => {
        try { await operation(); return null; } catch (error) { return error.message; }
      };
      const driveUntil = async (predicate, label, ms = 12_000) => {
        const deadline = performance.now() + ms;
        while (!predicate()) {
          if (performance.now() >= deadline) throw Error(label);
          await inviter.drive(50);
        }
      };
      const settle = async (ms = 120) => {
        const until = performance.now() + ms;
        await driveUntil(() => performance.now() >= until, 'settle');
      };
      const alongside = async (promise, label) => {
        let outcome;
        const exchange = promise.then(value => { outcome = { value }; },
          error => { outcome = { error: error.message }; });
        await driveUntil(() => outcome, label);
        await exchange;
        await settle();
        return outcome;
      };
      const probe = () => alongside(BrowserCodeInviter.controlled_unsolicited_poll(ownerPeer, address), 'unsolicited poll');
      if (scenario === 'saturation') {
        const attempts = [];
        for (let i = 0; i < 8; i++) attempts.push((await probe()).value);
        const legitimate = new BrowserPairing();
        const exhausted = await alongside(legitimate.join_v2(code, ownerPeer, address, 3500), 'budget exhausted');
        return { attempts, exhausted: !!exhausted.error, candidate: inviter.pending_candidate(),
          ledger: localStorage.getItem(key) };
      }

      let unsolicited, wrongCode, unsolicitedData;
      if (scenario === 'approval') {
        unsolicited = (await probe()).value;
        const wrong = new BrowserPairing();
        const incorrect = (code[0] === '0' ? '1' : '0') + code.slice(1);
        wrongCode = !!(await alongside(wrong.join_v2(incorrect, ownerPeer, address, 3000), 'wrong code')).error;
        const alien = BrowserVpn.with_relay(JSON.stringify({
          network: { ...attacker, name: network, vpn_ip: '10.80.0.3' },
          peers: [{ id: ownerPeer, vpn_ip: '10.80.0.1' }],
        }), '', address);
        unsolicitedData = !!(await alongside(alien.connect(), 'unsolicited VPN')).error;
        if (inviter.pending_candidate() || localStorage.getItem(key)) throw Error('Unsolicited work was admitted');
      }

      const joiner = new BrowserPairing();
      const joinerPeer = joiner.peer_id();
      let joined, failure, pending;
      const exchange = joiner.join_v2(code, ownerPeer, address, 20_000, 'reviewed-joiner', () => { pending = true; })
        .then(value => { joined = JSON.parse(value); }, error => { failure = error; });
      await driveUntil(() => {
        if (failure) throw failure;
        return pending && inviter.pending_candidate();
      }, 'verified candidate');
      const candidate = JSON.parse(inviter.pending_candidate());
      if (scenario.startsWith('cancelled') || scenario === 'expired') {
        const now = Date.now;
        if (scenario === 'cancelled-after-save') inviter.approve(joinerPeer);
        if (scenario.startsWith('cancelled')) inviter.cancel();
        else Date.now = () => now() + 301_000;
        try {
          const denied = await fail(() => inviter.approve(joinerPeer));
          const notDriving = await fail(() => inviter.drive(50));
          return { denied, notDriving, candidate: inviter.pending_candidate(),
            ledger: localStorage.getItem(key), delivered: inviter.delivered(), joined: !!joined };
        } finally {
          Date.now = now;
        }
      }

      const other = new BrowserPairing();
      const second = await alongside(other.join_v2(code, ownerPeer, address, 2500), 'second valid code');
      const candidateStable = JSON.parse(inviter.pending_candidate()).peer_id === joinerPeer;
      const wrongPeer = await fail(() => inviter.approve(other.peer_id()));
      const write = Storage.prototype.setItem;
      Storage.prototype.setItem = function (name, value) {
        if (name === key) throw new DOMException('Test quota', 'QuotaExceededError');
        return write.call(this, name, value);
      };
      let failedSave;
      try { failedSave = await fail(() => inviter.approve(joinerPeer)); }
      finally { Storage.prototype.setItem = write; }
      await settle(1300);
      const stayedPending = !!inviter.pending_candidate() && !joined && !inviter.delivered()
        && localStorage.getItem(key) === null;
      inviter.approve(joinerPeer);
      const ledger = JSON.parse(localStorage.getItem(key));
      const savedFirst = !inviter.delivered() && !joined;
      const duplicate = await fail(() => inviter.approve(joinerPeer));
      await driveUntil(() => {
        if (failure) throw failure;
        return joined && inviter.delivered();
      }, 'approved response');
      await exchange;
      const owner = await inviter.into_vpn();
      const member = BrowserVpn.with_relay(JSON.stringify(joined.config), '', address);
      const [accepted, connected] = (await Promise.all([owner.accept_relay(), member.connect()])).map(JSON.parse);
      void member.fetch_http('10.80.0.1', 8080, '/').catch(() => {});
      const packet = await owner.receive_relay_packet(5000);
      return { unsolicited, wrongCode, unsolicitedData, ownerPeer, joinerPeer, candidate, candidateStable,
        wrongPeer, failedSave, duplicate, stayedPending, savedFirst, secondDenied: !!second.error,
        ledger: ledger.map(record => [record.payload.issuer_peer, record.payload.member_peer]),
        ready: accepted.authorized && connected.authorized && accepted.ready && connected.ready,
        address, active: owner.relay_reservation_address(), packet: packet && Array.from(packet) };
    }, { entrance, scenario, attacker }).catch(error => {
      throw Error(`${error.message}\nRelay events:\n${log}`, { cause: error });
    });
    assert.equal([...log.matchAll(/ReservationReqAccepted.*renewed: false/g)].length, 1, log);
    if (scenario === 'saturation') {
      assert.deepEqual(result.attempts, Array(8).fill(true));
      assert.equal(result.exhausted, true);
      assert.equal(result.candidate, undefined);
      assert.equal(result.ledger, null);
    } else if (scenario !== 'approval') {
      const label = scenario === 'expired' ? /expired/ : /cancelled/;
      assert.match(result.denied, label);
      assert.match(result.notDriving, label);
      assert.equal(result.candidate, undefined);
      if (scenario === 'cancelled-after-save') assert.equal(JSON.parse(result.ledger).length, 2);
      else assert.equal(result.ledger, null);
      assert.equal(result.delivered || result.joined, false);
    } else {
      assert.ok(result.unsolicited && result.unsolicitedData && result.wrongCode && result.secondDenied);
      assert.ok(result.candidateStable && result.stayedPending && result.savedFirst && result.ready);
      assert.match(result.wrongPeer, /No pending/);
      assert.match(result.failedSave, /Could not save/);
      assert.match(result.duplicate, /No pending/);
      assert.deepEqual(result.candidate, {
        peer_id: result.joinerPeer, requested_hostname: 'reviewed-joiner', assigned_vpn_ip: '10.80.0.2',
      });
      assert.deepEqual(result.ledger, [[result.ownerPeer, result.ownerPeer], [result.ownerPeer, result.joinerPeer]]);
      assert.equal(result.active, result.address);
      assert.ok(result.packet?.length >= 40, log);
      assert.equal(result.packet[9], 6);
      assert.deepEqual(result.packet.slice(12, 20), [10, 80, 0, 2, 10, 80, 0, 1]);
      const tcp = (result.packet[0] & 0xf) * 4;
      assert.equal((result.packet[tcp + 2] << 8) | result.packet[tcp + 3], 8080);
      assert.equal(result.packet[tcp + 13] & 0x12, 0x02);
    }
  });
}
