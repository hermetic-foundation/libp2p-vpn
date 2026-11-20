// Build with `cargo build --locked -p p2p-vpn-browser --bin browser-receiver-fixture`
// and `bash scripts/build-browser.sh --test-hooks` from the repository root.
// For circuit cases, build `--features test-hooks --bin browser-relay-fixture`
// for native and set P2P_VPN_RELAY_FIXTURE to that binary.
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
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
const { chromium } = createRequire(import.meta.url)('playwright');

const glue = 'p2p_vpn_browser.js';
const wasm = 'p2p_vpn_browser_bg.wasm';
const relayFixture = process.env.P2P_VPN_RELAY_FIXTURE;

async function withReceiver(scenario, check, route = 'direct-only') {
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
  let relay, relayExited, relayReader;
  let stderr = '';
  let relayStderr = '';
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

    const args = [scenario];
    const circuitExpected = route === 'relay-only' || route === 'fallback' || route === 'preferred-return';
    if (route !== 'direct-only') {
      relay = spawn(relayFixture, ['192.0.2.1'], { stdio: ['ignore', 'pipe', 'pipe'] });
      relayExited = new Promise(resolve => relay.once('close', resolve));
      relay.stderr.setEncoding('utf8').on('data', chunk => {
        relayStderr = (relayStderr + chunk).slice(-8192);
      });
      relayReader = createInterface({ input: relay.stdout });
      const { value: entrance } = await Promise.race([
        relayReader[Symbol.asyncIterator]().next(),
        once(relay, 'error').then(([error]) => { throw error; }),
      ]);
      assert.ok(entrance, `Relay did not advertise an address: ${relayStderr}`);
      args.push(entrance, circuitExpected ? 'relayed' : 'direct');
    }
    child = spawn(fixture, args, { stdio: ['ignore', 'pipe', 'pipe'] });
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
    const wireReport = next('validating the on-wire responses');
    let wireFinished = false;
    wireReport.then(() => { wireFinished = true; }, () => { wireFinished = true; });
    try {
      const [wire, outcome] = await Promise.race([
        Promise.all([
          wireReport,
          page.evaluate(async ({ config, dial_address, recovery_address, relay_address, scenario, route }) => {
            const configJson = JSON.stringify(config);
            const unavailable = dial_address.replace(/\/udp\/\d+\//, '/udp/1/');
            // Retain the peer until the native fixture has observed the reply.
            const vpn = window.vpn = route === 'direct-only'
              ? new window.BrowserVpn(configJson, dial_address)
              : window.BrowserVpn.with_relay(
                configJson,
                route === 'relay-only' || route === 'preferred-return' ? ''
                  : route === 'fallback' ? unavailable : dial_address,
                relay_address,
              );
            try {
              if (scenario === 'preferred-return') {
                const snapshot = () => JSON.parse(vpn.snapshot());
                async function waitFor(predicate) {
                  const deadline = Date.now() + 14_000;
                  while (!predicate()) {
                    if (Date.now() >= deadline) {
                      throw Error(`preferred return timed out: ${vpn.test_preferred_path_phase()} ${vpn.snapshot()}`);
                    }
                    await vpn.poll_foreground();
                  }
                }
                function queuePacket() {
                  vpn.test_queue_path_packet(Uint8Array.of(
                    0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 204, 0, 2,
                    10, 204, 0, 1, 0, 42, 0, 42, 0, 8, 0, 0,
                  ));
                }
                async function sendPacketAndWait(count) {
                  queuePacket();
                  await waitFor(() => snapshot().counters.accepted_outbound_packets === count);
                }
                const hints = JSON.stringify([dial_address]);
                const initial = JSON.parse(await vpn.connect());
                await sendPacketAndWait(1);
                const relayPathCount = vpn.test_established_path_count();

                // A pinned transport alone is insufficient: deny this candidate's capabilities.
                vpn.set_preferred_member_endpoints(1, hints);
                await waitFor(() => vpn.test_preferred_path_phase() === 'idle'
                  && vpn.test_established_path_count() === relayPathCount);
                const rejected = snapshot();
                await sendPacketAndWait(2);

                // Supersede a valid candidate while its exact packet probe is held.
                vpn.set_preferred_member_endpoints(2, hints);
                await waitFor(() => vpn.test_preferred_path_phase() === 'probing');
                const holdUntil = Date.now() + 250;
                while (Date.now() < holdUntil) await vpn.poll_foreground();
                vpn.set_preferred_member_endpoints(3, '[]');
                vpn.set_preferred_member_endpoints(2, hints);
                await waitFor(() => vpn.test_established_path_count() === relayPathCount);
                const stale = snapshot();
                await sendPacketAndWait(3);

                // Leave one packet's relay acknowledgment pending across promotion,
                // then queue a fresh packet which must use the probed direct connection.
                queuePacket();
                vpn.set_preferred_member_endpoints(4, hints);
                await waitFor(() => snapshot().transport === 'webrtc-direct');
                if (vpn.can_release_discovery_relay()) {
                  throw Error('relay became releasable while its old packet was still pending');
                }
                await sendPacketAndWait(5);
                await waitFor(() => vpn.can_release_discovery_relay());
                if (vpn.test_established_path_count() > relayPathCount) {
                  throw Error('relay became releasable before its old circuit closed');
                }
                return { initial, rejected, stale, promoted: snapshot() };
              }
              if (scenario === 'packets' && route === 'direct-only') {
                const mismatched = dial_address.replace(/\/p2p\/[^/]+$/, `/p2p/${config.network.local_peer}`);
                try {
                  vpn.set_member_endpoints(JSON.stringify([mismatched, dial_address]));
                  throw Error('accepted a different peer ID');
                } catch (error) {
                  if (!error.message.includes('does not match the pinned peer')) throw error;
                }
                vpn.set_member_endpoints(JSON.stringify([unavailable, dial_address]));
              }
              if (route === 'prefer-direct') {
                vpn.set_member_endpoints(JSON.stringify([unavailable, dial_address]));
              }
              const result = scenario === 'recovery'
                ? await vpn.test_drive_transport_probe()
                : await vpn.test_drive_receiver();
              const outcome = { snapshot: JSON.parse(result) };
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
              if (scenario === 'preferred-return') throw error;
              const outcome = {
                error: { name: error.name, message: error.message },
                snapshot: JSON.parse(vpn.snapshot()),
              };
              if (scenario === 'revocation') {
                await vpn.close();
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
              if (scenario === 'recovery') {
                outcome.disconnected = JSON.parse(vpn.snapshot());
                vpn.set_member_endpoints(JSON.stringify([recovery_address]));
                await vpn.reset_connection();
                outcome.reconnected = JSON.parse(await vpn.connect());
                const deadline = performance.now() + 2_000;
                while (performance.now() < deadline) await vpn.poll_foreground();
              }
              return outcome;
            }
          }, { ...session, scenario, route }).then(async outcome => {
            // connect() can return before the peer's reciprocal capabilities
            // request arrives. Keep driving the recovered session for the wire proof.
            if (scenario === 'recovery' && outcome.reconnected?.authorized) {
              while (!wireFinished) await page.evaluate(() => window.vpn.poll_foreground());
            }
            return outcome;
          }),
        ]),
        delay(50_000, undefined, { signal: timeout.signal }).then(() => {
          throw Error(`Timed out waiting for receiver conformance: ${stderr}`);
        }),
      ]);
      check(wire, outcome, session);
      if (relay) {
        const browserHop = `relay-hop ${session.config.network.local_peer}`;
        assert.equal(relayStderr.includes(browserHop), circuitExpected, relayStderr);
      }
    } finally {
      timeout.abort();
    }
  } finally {
    reader?.close();
    relayReader?.close();
    child?.kill();
    relay?.kill();
    await Promise.all([exited, relayExited, browser?.close(), new Promise(resolve => server.close(resolve))]);
  }
}

test('browser receives reliable IP and serves authorized status over WebRTC Direct', async () => {
  await withReceiver('packets', packetAssertions('webrtc-direct', 'direct_webrtc_stream'));
});

function packetAssertions(transport, wirePath) {
  return ({ packets, status, wrong_scope }, { snapshot, error }, session) => {
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
      malformed_ip: 'Rejected(MalformedPacket)',
      identical_path_probe: 'Rejected(Replay)',
    });
    assert.equal(status.Status.nonce, 42);
    assert.equal(status.Status.network_name, session.config.network.name);
    assert.equal(status.Status.effective_mtu, 1280);
    assert.equal(status.Status.selected_path, wirePath);
    assert.equal(status.Status.selected_path_mtu, 1200);
    assert.equal(status.Status.supports_quic_datagrams, false);
    assert.deepEqual(wrong_scope, { Rejected: 'MembershipMismatch' });
    assert.equal(error, undefined);
    assert.equal(snapshot.authorized, true);
    assert.equal(snapshot.stream_mtu, 1200);
    assert.equal(snapshot.transport, transport);
    assert.equal(snapshot.local_peer_id, session.config.network.local_peer);
    assert.equal(snapshot.remote_peer_id, session.native_peer_id);
    assert.equal(snapshot.counters.connections, 1);
    assert.equal(snapshot.counters.inbound_ip_packets, 2);
    assert.equal(snapshot.counters.inbound_ip_bytes, 56);
    assert.equal(snapshot.counters.rejected_inbound_packets, 7);
  };
}

const relayOptions = { skip: !relayFixture && 'set P2P_VPN_RELAY_FIXTURE to run circuit tests' };

test('BrowserVpn exchanges authorized control and IP packets over a relay-only route', relayOptions, async () => {
  await withReceiver('packets', packetAssertions('circuit-relay', 'circuit_relay'), 'relay-only');
});

test('BrowserVpn falls back to the explicit circuit when WebRTC Direct is unavailable', relayOptions, async () => {
  await withReceiver('packets', packetAssertions('circuit-relay', 'circuit_relay'), 'fallback');
});

test('BrowserVpn keeps a healthy alternate direct endpoint ahead of the circuit', relayOptions, async () => {
  await withReceiver('packets', packetAssertions('webrtc-direct', 'direct_webrtc_stream'), 'prefer-direct');
});

test('BrowserVpn validates preferred return on the exact direct path and drains a healthy circuit', relayOptions, async () => {
  await withReceiver('preferred-return', (wire, outcome, session) => {
    assert.equal(outcome.error, undefined);
    for (const phase of [outcome.initial, outcome.rejected, outcome.stale]) {
      assert.equal(phase.transport, 'circuit-relay');
      assert.equal(phase.authorized, true);
      assert.equal(phase.remote_peer_id, session.native_peer_id);
    }
    assert.equal(outcome.promoted.transport, 'webrtc-direct');
    assert.equal(outcome.promoted.authorized, true);
    assert.equal(outcome.promoted.remote_peer_id, session.native_peer_id);
    assert.equal(outcome.promoted.counters.connections, 2);
    assert.equal(outcome.promoted.counters.accepted_outbound_packets, 5);
    assert.deepEqual(wire, {
      obsolete_probe_held: true,
      relay_packets: 4,
      direct_packets: 1,
      relay_drained: true,
    });
  }, 'preferred-return');
});

test('BrowserVpn does not try the circuit after a direct capability rejection', relayOptions, async () => {
  await withReceiver('deny-capabilities', (wire, { error, snapshot }) => {
    assert.equal(wire.denied, 'WrongNetwork');
    assert.match(error?.message ?? '', /WrongNetwork/);
    assert.equal(snapshot.authorized, false);
    assert.equal(snapshot.path_recovery_needed, false);
    assert.equal(snapshot.counters.connections, 1);
  }, 'prefer-direct');
});

test('browser sends typed WrongNetwork rejection and surfaces a JS error', async () => {
  await withReceiver('wrong-network', ({ wrong_network }, { error, snapshot }) => {
    assert.deepEqual(wrong_network, { CapabilitiesRejected: 'WrongNetwork' });
    assert.deepEqual(error, { name: 'Error', message: 'WrongNetwork' });
    assert.equal(snapshot.authorized, false);
  });
});

for (const [scenario, reason] of [
  ['wrong-wire-version', 'UnsupportedWireVersion'],
  ['wrong-packet-protocol', 'UnsupportedPacketProtocol'],
  ['wrong-header-length', 'UnsupportedPacketHeaderLength'],
  ['zero-mtu', 'InvalidEffectiveMtu'],
  ['unknown-path', 'UnsupportedPreferredPath'],
  ['ungranted-route', 'UnauthorizedRouteAdvertisement'],
  ['local-route-collision', 'UnauthorizedRouteAdvertisement'],
  ['wrong-membership-tag', 'MembershipMismatch'],
  ['rotated-membership-tag', 'MembershipMismatch'],
]) {
  test(`browser rejects ${scenario} and clears session authority`, async () => {
    await withReceiver(scenario, ({ rejection, previous_tag_accepted }, { error, snapshot }) => {
      assert.deepEqual(rejection, { CapabilitiesRejected: reason });
      if (scenario === 'rotated-membership-tag') assert.equal(previous_tag_accepted, true);
      assert.deepEqual(error, { name: 'Error', message: reason });
      assert.equal(snapshot.authorized, false);
      assert.equal(snapshot.path_recovery_needed, false);
      assert.equal(snapshot.counters.connections, 1);
      assert.equal(snapshot.counters.inbound_ip_packets, 0);
    }, relayFixture ? 'prefer-direct' : 'direct-only');
  });
}

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

test('browser reauthenticates after a transport closes', async () => {
  await withReceiver('recovery', (wire, outcome) => {
    assert.equal(wire.reauthenticated, true);
    assert.equal(outcome.disconnected.authorized, false);
    assert.equal(outcome.disconnected.path_recovery_needed, true);
    assert.equal(outcome.reconnected.authorized, true);
    assert.equal(outcome.reconnected.path_recovery_needed, false);
    assert.equal(outcome.reconnected.remote_peer_id, outcome.disconnected.remote_peer_id);
  });
});
