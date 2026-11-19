// Build with `cargo build --locked -p p2p-vpn-browser --bin browser-receiver-fixture`
// and `bash scripts/build-browser.sh --test-hooks` from the repository root.
// Set P2P_VPN_RECEIVER_FIXTURE to the native fixture binary, then run on Linux:
// unshare --user --map-root-user --net sh -ec '
//   ip link set lo up
//   ip link add pv-receiver type dummy
//   ip address add 192.0.2.1/24 dev pv-receiver
//   ip link set pv-receiver up
//   node --test crates/p2p-vpn-browser/tests/receiver.mjs
// '
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

const glue = 'p2p_vpn_browser.js';
const wasm = 'p2p_vpn_browser_bg.wasm';

async function withReceiver(scenario, check) {
  const fixture = process.env.P2P_VPN_RECEIVER_FIXTURE;
  assert.ok(fixture, 'P2P_VPN_RECEIVER_FIXTURE must point to the native receiver fixture');
  const pkg = process.env.P2P_VPN_RECEIVER_PKG;
  const files = new Map([['/', ['text/html', '<!doctype html><title>Receiver conformance</title>']]]);
  for (const [file, mime] of [[glue, 'text/javascript'], [wasm, 'application/wasm']]) {
    const path = pkg ? join(pkg, file) : new URL(`../web/pkg/${file}`, import.meta.url);
    files.set(`/${file}`, [mime, await readFile(path)]);
  }
  const server = createServer((request, response) => {
    const file = request.method === 'GET' && files.get(request.url);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { 'Content-Type': file[0], 'Cache-Control': 'no-store' }).end(file[1]);
  });
  let browser, child, exited, reader;
  let stderr = '';
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    browser = await chromium.launch({
      headless: true,
      ...(process.env.P2P_VPN_CHROMIUM
        ? { executablePath: process.env.P2P_VPN_CHROMIUM }
        : { channel: process.env.P2P_VPN_BROWSER_CHANNEL || 'chrome' }),
    });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.evaluate(async path => {
      const { default: init, BrowserVpn } = await import(path);
      await init();
      if (typeof BrowserVpn.prototype.test_drive_receiver !== 'function') {
        throw Error('WASM package is missing test_drive_receiver; build with --test-hooks');
      }
      window.BrowserVpn = BrowserVpn;
    }, `/${glue}`);

    child = spawn(fixture, [scenario], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.on('error', error => { stderr += error.message; });
    exited = new Promise(resolve => child.once('close', resolve));
    child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
    reader = createInterface({ input: child.stdout });
    const lines = reader[Symbol.asyncIterator]();
    async function next(description) {
      const { value, done } = await lines.next();
      if (done) {
        const code = await exited;
        throw Error(`Native fixture exited (${code}) before ${description}: ${stderr}`);
      }
      return JSON.parse(value);
    }
    const session = await next('printing the dial address');
    const timeout = new AbortController();
    try {
      const [wire, outcome] = await Promise.race([
        Promise.all([
          next('validating the on-wire responses'),
          page.evaluate(async ({ config, dial_address, scenario }) => {
            // Retain the peer until the native fixture has observed the reply.
            const vpn = window.vpn = new window.BrowserVpn(JSON.stringify(config), dial_address);
            try {
              const outcome = { snapshot: JSON.parse(await vpn.test_drive_receiver()) };
              if (scenario === 'membership') {
                const competing = new window.BrowserVpn(JSON.stringify(config), dial_address);
                try {
                  await competing.connect();
                } catch (competingError) {
                  outcome.concurrentError = competingError.message;
                  outcome.concurrentSnapshot = JSON.parse(competing.snapshot());
                } finally {
                  competing.free();
                }
              }
              return outcome;
            } catch (error) {
              const outcome = { error: { name: error.name, message: error.message } };
              if (scenario === 'revocation') {
                vpn.free();
                const reopened = new window.BrowserVpn(JSON.stringify(config), dial_address);
                try {
                  await reopened.connect();
                } catch (reopenedError) {
                  outcome.reopenedError = reopenedError.message;
                  outcome.reopenedSnapshot = JSON.parse(reopened.snapshot());
                } finally {
                  reopened.free();
                }
              }
              return outcome;
            }
          }, { ...session, scenario }),
        ]),
        delay(50_000, undefined, { signal: timeout.signal }).then(() => {
          throw Error(`Timed out waiting for receiver conformance: ${stderr}`);
        }),
      ]);
      check(wire, outcome, session);
    } finally {
      timeout.abort();
    }
  } finally {
    reader?.close();
    child?.kill();
    await Promise.all([exited, browser?.close(), new Promise(resolve => server.close(resolve))]);
  }
}

test('browser receives reliable IP and serves authorized status over WebRTC Direct', async () => {
  await withReceiver('packets', ({ packets, status, wrong_scope }, { snapshot, error }, session) => {
    assert.deepEqual(packets, {
      bad_source: 'Rejected(UnauthorizedSource)',
      wrong_destination: 'Rejected(UnauthorizedDestination)',
      valid_ip: 'Accepted',
      identical_ip: 'Accepted',
      nonempty_keepalive: 'Rejected(UnexpectedPayload)',
      keepalive: 'Accepted',
      identical_keepalive: 'Rejected(Replay)',
      too_large: 'Rejected(PacketTooLarge)',
      path_probe: 'Accepted',
    });
    assert.equal(status.Status.nonce, 42);
    assert.equal(status.Status.network_name, session.config.network.name);
    assert.equal(status.Status.effective_mtu, 1280);
    assert.equal(status.Status.selected_path, 'direct_webrtc_stream');
    assert.equal(status.Status.selected_path_mtu, 1200);
    assert.equal(status.Status.supports_quic_datagrams, false);
    assert.deepEqual(wrong_scope, { Rejected: 'MembershipMismatch' });
    assert.equal(error, undefined);
    assert.equal(snapshot.authorized, true);
    assert.equal(snapshot.stream_mtu, 1200);
    assert.equal(snapshot.transport, 'webrtc-direct');
    assert.equal(snapshot.local_peer_id, session.config.network.local_peer);
    assert.equal(snapshot.remote_peer_id, session.native_peer_id);
    assert.equal(snapshot.counters.connections, 1);
    assert.equal(snapshot.counters.inbound_ip_packets, 2);
    assert.equal(snapshot.counters.inbound_ip_bytes, 56);
    assert.equal(snapshot.counters.rejected_inbound_packets, 5);
  });
});

test('browser sends typed WrongNetwork rejection and surfaces a JS error', async () => {
  await withReceiver('wrong-network', ({ wrong_network }, outcome) => {
    assert.deepEqual(wrong_network, { CapabilitiesRejected: 'WrongNetwork' });
    assert.deepEqual(outcome, { error: { name: 'Error', message: 'WrongNetwork' } });
  });
});

test('browser converges a signed membership snapshot and serves it back to the native peer', async () => {
  await withReceiver('membership', (wire, { snapshot, error, concurrentError, concurrentSnapshot }) => {
    assert.equal(error, undefined);
    assert.equal(wire.total_records, 11);
    assert.equal(wire.pages_sent, 2);
    assert.equal(snapshot.membership_snapshot, wire.snapshot);
    assert.equal(snapshot.authorized, true);
    assert.match(concurrentError ?? '', /in use by another tab/);
    assert.equal(concurrentSnapshot.counters.connections, 0);
  });
});

test('browser keeps a verified revocation when opening the original config again', async () => {
  await withReceiver('revocation', (wire, outcome) => {
    assert.equal(wire.revocation_sent, true);
    assert.match(outcome.error?.message ?? '', /membership has expired or been revoked/);
    assert.match(outcome.reopenedError ?? '', /membership has expired or been revoked/);
    assert.equal(outcome.reopenedSnapshot.authorized, false);
    assert.equal(outcome.reopenedSnapshot.counters.connections, 0);
  });
});
