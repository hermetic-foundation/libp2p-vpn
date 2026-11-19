const byId = id => document.getElementById(id);
const config = byId('config');
const address = byId('address');
const state = byId('state');
const error = byId('error');
const response = byId('response');
const connect = byId('connect');
const disconnect = byId('disconnect');
const send = byId('send');
const pairCode = byId('pair-code');
const pairVersion = byId('pair-version');
const pairNetwork = byId('pair-network');
const useConfig = byId('use-config');
const useCredentials = byId('use-credentials');
const useCode = byId('use-code');
const useOffer = byId('use-offer');
const offlineOffer = byId('offline-offer');
const offlineUri = byId('offline-uri');
const offlineResponse = byId('offline-response');
const download = byId('export-config');
const credentialPassphrase = byId('credential-passphrase');
const exportDialog = byId('export-dialog');
const exportPassphrase = byId('export-passphrase');
const exportError = byId('export-error');
let vpn;
let BrowserVpn;
let BrowserPairing;
let pairingLocator;
let pairingScopedLocator;
let discoveryPlan;
let exportedConfig;
let exportCheckpoint = false;
let offlineSession;
let enrollmentMode = 'config';
let loaded = false;
let busy = false;
let foregroundPoll;
let foregroundTimer;
let nextLanRefresh = 0;
let lanRefresh;
let preferredGeneration = 0;
let preferredResult;
const relayLeases = new WeakMap();

const discoveryMarker = document.querySelector('meta[name="p2p-vpn-discovery"]');
const discoveryEndpoint = discoveryMarker?.content === '/api/discovery' ? discoveryMarker.content : null;
const pairingMarker = document.querySelector('meta[name="p2p-vpn-pairing"]');
const pairingEndpoint = pairingMarker?.content === '/api/pairing/locator' ? pairingMarker.content : null;
const pairingLanMarker = document.querySelector('meta[name="p2p-vpn-pairing-lan"]');
const pairingLanEndpoint = pairingLanMarker?.content === '/api/pairing/lan'
  ? pairingLanMarker.content : null;

async function lookupEndpoints(plan, endpoint = discoveryEndpoint, allowEmpty = false) {
  const result = await fetch(endpoint, {
    method: 'POST',
    mode: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: plan,
    signal: AbortSignal.timeout(30_000),
  });
  if (!result.ok) throw Error(`Local discovery failed (HTTP ${result.status}).`);
  const { addresses, source, relay_address: relay, relay_lease_id: lease } = await result.json();
  if (!Array.isArray(addresses) || addresses.some(address => typeof address !== 'string')
      || (relay != null && typeof relay !== 'string')
      || (lease != null && (typeof lease !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(lease)))) {
    throw Error('Local discovery returned invalid endpoints.');
  }
  if (!allowEmpty && !addresses.length && !relay) {
    throw Error('No reachable endpoint found for the authorized peer.');
  }
  return { endpoints: addresses.slice(0, 8), relay, lease, source };
}

async function releaseLease(lease) {
  if (!lease) return;
  try {
    await fetch('/api/relay/release', {
      method: 'POST', mode: 'same-origin', redirect: 'error', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lease_id: lease }),
      signal: AbortSignal.timeout(2_000), keepalive: true,
    });
  } catch {
    // The companion also expires leases after an idle timeout or route change.
  }
}

async function rememberLease(peer, lease) {
  const previous = relayLeases.get(peer);
  if (lease) relayLeases.set(peer, lease);
  else relayLeases.delete(peer);
  if (previous !== lease) await releaseLease(previous);
}

window.addEventListener('pagehide', () => {
  if (vpn) void releaseLease(relayLeases.get(vpn));
});

async function replaceDiscoveredPaths(peer, { endpoints, relay, lease }) {
  try {
    await peer.replace_discovered_paths(JSON.stringify(endpoints), relay ?? undefined);
  } catch (error) {
    await releaseLease(lease);
    throw error;
  }
  await rememberLease(peer, lease);
}

async function connectWithLease(peer) {
  const session = await peer.connect();
  if (JSON.parse(session).transport !== 'circuit-relay') await rememberLease(peer);
  return session;
}

function newBrowserPeer(configJson, endpoints, relay) {
  const peer = relay
    ? BrowserVpn.with_relay(configJson, endpoints[0] ?? '', relay)
    : new BrowserVpn(configJson, endpoints[0]);
  try {
    if (endpoints.length > 1) peer.set_member_endpoints(JSON.stringify(endpoints));
    return peer;
  } catch (e) {
    peer.free();
    throw e;
  }
}

function explicitBrowserPeer(configJson, address) {
  return address.includes('/p2p-circuit/')
    ? newBrowserPeer(configJson, [], address)
    : newBrowserPeer(configJson, [address]);
}

async function* pairingCandidates(selected, locator, scoped) {
  if (selected) {
    yield selected;
    return;
  }
  const attempted = new Set();
  const channels = [
    [pairingLanEndpoint, '{}'],
    [pairingEndpoint && (scoped ? `${pairingEndpoint}/scoped` : pairingEndpoint), JSON.stringify({ locator })],
  ];
  for (const [endpoint, request] of channels) {
    if (!endpoint) continue;
    const { endpoints, relay } = await lookupEndpoints(request, endpoint, true);
    const candidates = endpoints.slice(0, 3);
    if (relay) candidates.push(relay);
    for (const candidate of [...new Set(candidates)].filter(address => !attempted.has(address))) {
      attempted.add(candidate);
      yield candidate;
    }
  }
}

async function approvePairing() {
  const code = pairCode.value.trim();
  const hostname = byId('pair-hostname').value.trim() || undefined;
  const selected = address.value.trim();
  const scoped = pairVersion.value === '1';
  const network = scoped ? pairNetwork.value.trim() : undefined;
  const locator = scoped ? pairingScopedLocator(code, network) : pairingLocator(code);
  const pairing = new BrowserPairing();
  let lastError;
  try {
    for await (const endpoint of pairingCandidates(selected, locator, scoped)) {
      const peerId = /\/p2p\/([^/]+)$/.exec(endpoint)?.[1];
      if (!peerId) throw Error('Pairing requires a WebRTC address with a pinned peer ID.');
      let artifacts;
      try {
        const pending = () => render('Waiting for approval');
        artifacts = JSON.parse(await (scoped
          ? pairing.join_v1(code, network, peerId, endpoint, 300_000, hostname, pending)
          : pairing.join_v2(code, peerId, endpoint, 300_000, hostname, pending)));
      } catch (error) {
        if (selected || error.name !== 'PairingCandidateMiss') throw error;
        lastError = error;
        continue;
      }
      pairCode.value = '';
      return await openApprovedPeer(artifacts, pairing);
    }
    throw lastError ?? Error('No reachable inviter found.');
  } finally {
    pairing.free();
  }
}

async function openApprovedPeer(artifacts, enrollment) {
  if (artifacts.kind === 'legacy') {
    const configJson = JSON.stringify(artifacts.config);
    return { candidate: explicitBrowserPeer(configJson, artifacts.dial_address), configJson };
  }
  if (artifacts.kind === 'checkpoint') {
    const activation = enrollment.take_checkpoint_activation();
    if (!activation) throw Error('Approved pairing did not provide checkpoint activation.');
    return { candidate: await BrowserVpn.open_checkpoint_activation(activation) };
  }
  throw Error('Unknown pairing artifact.');
}

async function readEnrollmentFile(input, label) {
  const file = input.files[0];
  if (!file || file.size > 32 * 1024) throw Error(`Select a ${label} no larger than 32 KiB.`);
  return file.text();
}

async function createOfflineRequest() {
  const offer = offlineUri.value.trim() || await readEnrollmentFile(offlineOffer, 'signed offer');
  const pairing = new BrowserPairing();
  try {
    offlineSession = pairing.begin_offline(offer);
    downloadJson(offlineSession.request_json(), 'p2p-vpn-pairing-request.json');
    offlineUri.value = '';
    offlineOffer.value = '';
  } finally {
    pairing.free();
  }
}

async function approveOfflineResponse() {
  const response = await readEnrollmentFile(offlineResponse, 'signed response');
  const artifacts = JSON.parse(offlineSession.accept_response(response, address.value.trim()));
  try {
    return await openApprovedPeer(artifacts, offlineSession);
  } finally {
    offlineSession.free();
    offlineSession = undefined;
    offlineResponse.value = '';
  }
}

async function connectDiscoveredPeer(peer, plan, source) {
  try {
    return await connectWithLease(peer);
  } catch (error) {
    const request = JSON.parse(plan);
    if (source !== 'lan' || !request.kademlia || !JSON.parse(peer.snapshot()).path_recovery_needed) {
      throw error;
    }
    await replaceDiscoveredPaths(peer, await lookupEndpoints(JSON.stringify({ ...request, lan: false })));
    return connectWithLease(peer);
  }
}

async function recoverPeer(peer, plan = discoveryPlan) {
  if (plan) {
    await rememberLease(peer);
    const hints = await lookupEndpoints(plan);
    await replaceDiscoveredPaths(peer, hints);
    return connectDiscoveredPeer(peer, plan, hints.source);
  }
  await peer.reset_connection();
  return peer.connect();
}

function refreshPreferredLan(peer) {
  if (!discoveryPlan || lanRefresh || performance.now() < nextLanRefresh
      || typeof peer.set_preferred_member_endpoints !== 'function') return;
  const plan = JSON.parse(discoveryPlan);
  nextLanRefresh = performance.now() + 30_000;
  if (!plan.lan || JSON.parse(peer.snapshot()).transport !== 'circuit-relay') return;
  const generation = ++preferredGeneration;
  lanRefresh = lookupEndpoints(JSON.stringify({ ...plan, kademlia: false }), discoveryEndpoint, true)
    .then(result => result.source === 'lan' ? result.endpoints : [])
    .catch(() => [])
    .then(endpoints => {
      if (peer === vpn && generation === preferredGeneration) {
        preferredResult = { peer, generation, endpoints, expires: performance.now() + 5_000 };
      }
    }).finally(() => { lanRefresh = undefined; });
}

async function driveForeground(peer) {
  if (preferredResult?.peer === peer) {
    const { generation, endpoints, expires } = preferredResult;
    preferredResult = undefined;
    peer.set_preferred_member_endpoints?.(generation,
      JSON.stringify(performance.now() < expires ? endpoints : []));
  }
  refreshPreferredLan(peer);
  await peer.poll_foreground();
  if (relayLeases.has(peer) && peer.can_release_discovery_relay?.()) {
    void rememberLease(peer);
  }
}

function scheduleForegroundPoll() {
  clearTimeout(foregroundTimer);
  if (!vpn || busy || foregroundPoll || document.visibilityState !== 'visible') return;
  foregroundTimer = setTimeout(() => {
    if (!vpn || busy || document.visibilityState !== 'visible') return;
    const peer = vpn;
    foregroundPoll = driveForeground(peer).catch(async e => {
      if (busy || peer !== vpn) return;
      const session = JSON.parse(peer.snapshot());
      // Admission errors are not path failures and must not start discovery.
      if (!session.path_recovery_needed && session.authorized) return;
      busy = true;
      try {
        if (session.path_recovery_needed) {
          render('Reconnecting');
          await recoverPeer(peer);
        } else {
          render('Disconnecting');
          setError(e.message);
          await closePeer();
        }
      } catch (reconnectError) {
        setError(reconnectError.message);
        await closePeer();
      } finally {
        busy = false;
        render(vpn ? 'Connected' : 'Disconnected');
      }
    }).finally(() => {
      foregroundPoll = undefined;
      scheduleForegroundPoll();
    });
  }, 0);
}

document.addEventListener('visibilitychange', scheduleForegroundPoll);
window.addEventListener('online', () => {
  nextLanRefresh = 0;
  if (vpn) {
    preferredResult = { peer: vpn, generation: ++preferredGeneration, endpoints: [], expires: 0 };
  }
  scheduleForegroundPoll();
});
pairVersion.addEventListener('change', () => render(state.textContent));

function render(status) {
  const pairing = enrollmentMode === 'code';
  const credentials = enrollmentMode === 'credentials';
  const offline = enrollmentMode === 'offline';
  const wantsAddress = !credentials && (!offline || !!offlineSession);
  connect.disabled = !loaded || busy;
  connect.textContent = offline && !offlineSession ? 'Create request'
    : pairing || offline ? 'Join network' : 'Connect';
  connect.hidden = !!vpn;
  disconnect.hidden = !vpn;
  disconnect.disabled = busy;
  config.disabled = pairing || offline || busy || !!vpn;
  config.required = !pairing && !offline;
  document.querySelector('label[for="config"]').textContent = credentials
    ? 'Encrypted credentials' : 'Peer config';
  credentialPassphrase.disabled = !credentials || busy || !!vpn;
  credentialPassphrase.required = credentials;
  byId('credential-input').hidden = !credentials;
  pairCode.disabled = !pairing || busy || !!vpn;
  pairCode.required = pairing;
  byId('pair-hostname').disabled = !pairing || busy || !!vpn;
  pairVersion.disabled = !pairing || busy || !!vpn;
  const scoped = pairing && pairVersion.value === '1';
  byId('pair-network-input').hidden = !scoped;
  pairNetwork.disabled = !scoped || busy || !!vpn;
  pairNetwork.required = scoped;
  byId('pair-inputs').hidden = !pairing;
  byId('config-import').hidden = pairing || offline;
  byId('offline-offer-fields').hidden = !offline || !!offlineSession;
  byId('offline-response-fields').hidden = !offline || !offlineSession;
  offlineOffer.disabled = offlineUri.disabled = !offline || busy || !!vpn || !!offlineSession;
  offlineResponse.disabled = !offline || busy || !!vpn || !offlineSession;
  offlineResponse.required = offline && !!offlineSession;
  useConfig.disabled = useCredentials.disabled = useCode.disabled = useOffer.disabled = busy;
  useConfig.setAttribute('aria-pressed', String(!pairing && !credentials && !offline));
  useCredentials.setAttribute('aria-pressed', String(credentials));
  useCode.setAttribute('aria-pressed', String(pairing));
  useOffer.setAttribute('aria-pressed', String(offline));
  address.disabled = !wantsAddress || busy || !!vpn;
  address.hidden = !wantsAddress;
  address.required = wantsAddress && !offline && (pairing ? !pairingEndpoint : !discoveryEndpoint);
  const addressLabel = document.querySelector('label[for="address"]');
  addressLabel.hidden = !wantsAddress;
  addressLabel.textContent = pairing || offline
    ? 'Inviter address'
    : discoveryEndpoint ? 'Peer ID or address' : 'Native peer address';
  byId('config-fields').hidden = !!vpn;
  send.disabled = !vpn || busy;
  state.textContent = status;
  state.dataset.connected = String(!!vpn);
  byId('identity').hidden = !vpn;
  download.hidden = !exportedConfig && !exportCheckpoint;
  download.textContent = exportCheckpoint ? 'Download credentials' : 'Download config';
  download.disabled = busy;
  scheduleForegroundPoll();
}

function setError(message = '') {
  error.textContent = message;
  error.hidden = !message;
}

function discardPeer() {
  vpn?.free();
  vpn = undefined;
  discoveryPlan = undefined;
  preferredResult = undefined;
  nextLanRefresh = 0;
  exportedConfig = undefined;
  exportCheckpoint = false;
  byId('peer-id').textContent = '';
}

async function closePeer() {
  const peer = vpn;
  try {
    await peer?.close();
  } catch (e) {
    if (error.hidden) setError(e.message);
  } finally {
    if (peer) await rememberLease(peer);
    discardPeer();
  }
}

for (const [button, mode] of [
  [useConfig, 'config'], [useCredentials, 'credentials'], [useCode, 'code'], [useOffer, 'offline'],
]) {
  button.addEventListener('click', () => {
    if (busy || vpn) return;
    if (enrollmentMode !== mode) {
      config.value = '';
      pairCode.value = '';
      credentialPassphrase.value = '';
      offlineOffer.value = offlineUri.value = offlineResponse.value = '';
      offlineSession?.free();
      offlineSession = undefined;
    }
    enrollmentMode = mode;
    setError();
    render(loaded ? 'Disconnected' : 'Loading');
  });
}

function downloadJson(data, filename) {
  const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

download.addEventListener('click', () => {
  if (exportCheckpoint) {
    exportError.hidden = true;
    exportDialog.showModal();
  } else if (exportedConfig) {
    downloadJson(exportedConfig, 'p2p-vpn-browser.json');
  }
});

byId('cancel-export').addEventListener('click', () => exportDialog.close());
exportDialog.addEventListener('cancel', event => {
  if (busy) event.preventDefault();
});
exportDialog.addEventListener('close', () => { exportPassphrase.value = ''; });
byId('export-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!vpn || busy || !exportCheckpoint) return;
  busy = true;
  render('Connected');
  exportError.hidden = true;
  byId('save-export').disabled = byId('cancel-export').disabled = true;
  const passphrase = exportPassphrase.value;
  exportPassphrase.value = '';
  try {
    await foregroundPoll;
    const encrypted = await vpn.export_checkpoint_credentials(passphrase);
    downloadJson(encrypted, 'p2p-vpn-credentials.json');
    exportDialog.close();
  } catch (e) {
    exportError.textContent = e.message;
    exportError.hidden = false;
  } finally {
    busy = false;
    byId('save-export').disabled = byId('cancel-export').disabled = false;
    render(vpn ? 'Connected' : 'Disconnected');
  }
});

byId('connect-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!loaded || busy || vpn) return;
  let candidate;
  busy = true;
  setError();
  render('Connecting');
  try {
    let plan;
    let source;
    let pairedConfig;
    if (enrollmentMode === 'code') {
      const approved = await approvePairing();
      candidate = approved.candidate;
      pairedConfig = approved.configJson;
    } else if (enrollmentMode === 'offline') {
      if (!offlineSession) {
        await createOfflineRequest();
        return;
      }
      const approved = await approveOfflineResponse();
      candidate = approved.candidate;
      pairedConfig = approved.configJson;
    } else if (enrollmentMode === 'credentials') {
      const file = config.files[0];
      if (!file || file.size > 18 * 1024 * 1024) {
        throw Error('Select an encrypted credentials file no larger than 18 MiB.');
      }
      const passphrase = credentialPassphrase.value;
      credentialPassphrase.value = '';
      candidate = await BrowserVpn.import_checkpoint_credentials(await file.text(), passphrase);
    } else {
      const file = config.files[0];
      if (!file || file.size > 4 * 1024 * 1024) {
        throw Error('Select a peer config no larger than 4 MiB.');
      }
      const configJson = await file.text();
      const target = address.value.trim();
      if (discoveryEndpoint && !target.startsWith('/')) {
        plan = BrowserVpn.discovery_query(configJson, target);
        const resolution = await lookupEndpoints(plan);
        const { endpoints, relay, lease } = resolution;
        source = resolution.source;
        try {
          candidate = newBrowserPeer(configJson, endpoints, relay);
        } catch (error) {
          await releaseLease(lease);
          throw error;
        }
        await rememberLease(candidate, lease);
        if (JSON.parse(candidate.snapshot()).remote_peer_id !== JSON.parse(plan).peer) {
          throw Error('Local discovery returned the wrong peer.');
        }
      } else {
        candidate = explicitBrowserPeer(configJson, target);
      }
    }
    const managedPlan = !plan && discoveryEndpoint && enrollmentMode !== 'config'
      ? candidate.member_discovery_query?.() : undefined;
    let result;
    try {
      result = await (plan
        ? connectDiscoveredPeer(candidate, plan, source)
        : connectWithLease(candidate));
    } catch (error) {
      if (!managedPlan || !JSON.parse(candidate.snapshot()).path_recovery_needed) throw error;
      result = await recoverPeer(candidate, managedPlan);
    }
    const session = JSON.parse(result);
    byId('peer-id').textContent = session.remote_peer_id;
    vpn = candidate;
    discoveryPlan = plan ?? managedPlan;
    exportedConfig = pairedConfig;
    exportCheckpoint = !!session.checkpoint;
    candidate = undefined;
    config.value = '';
  } catch (e) {
    setError(e.message);
  } finally {
    if (candidate) {
      try {
        await candidate.close();
      } catch (e) {
        if (error.hidden) setError(e.message);
      } finally {
        await rememberLease(candidate);
        candidate.free();
      }
    }
    busy = false;
    render(vpn ? 'Connected' : offlineSession ? 'Awaiting response' : 'Disconnected');
  }
});

disconnect.addEventListener('click', async () => {
  if (busy) return;
  busy = true;
  setError();
  render('Disconnecting');
  try {
    await foregroundPoll;
    await closePeer();
  } catch (e) {
    setError(e.message);
  } finally {
    response.hidden = true;
    response.textContent = '';
    busy = false;
    render('Disconnected');
  }
});

byId('request-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!vpn || busy) return;
  busy = true;
  setError();
  response.hidden = true;
  response.textContent = '';
  render('Requesting');
  try {
    await foregroundPoll;
    response.textContent = await vpn.fetch_http(
      byId('ip').value.trim(), byId('port').valueAsNumber, byId('path').value,
    );
    response.hidden = false;
  } catch (e) {
    setError(e.message);
    const session = JSON.parse(vpn.snapshot());
    if (session.path_recovery_needed) {
      try {
        render('Reconnecting');
        await recoverPeer(vpn);
        setError('Connection restored. Send the request again.');
      } catch (reconnectError) {
        setError(reconnectError.message);
        await closePeer();
      }
    } else if (!session.authorized) {
      await closePeer();
    }
  } finally {
    busy = false;
    render(vpn ? 'Connected' : 'Disconnected');
  }
});

try {
  if (!window.isSecureContext) throw Error('Open this page over HTTPS or loopback.');
  const {
    default: init, BrowserVpn: peer, BrowserPairing: enroll,
    pairing_code_v1_scoped_locator: locateScoped, pairing_code_v2_global_locator: locate,
  } = await import('./pkg/p2p_vpn_browser.js');
  await init();
  BrowserVpn = peer;
  BrowserPairing = enroll;
  pairingLocator = locate;
  pairingScopedLocator = locateScoped;
  loaded = true;
  render('Disconnected');
} catch (e) {
  setError(e.message);
  render('Unavailable');
}
