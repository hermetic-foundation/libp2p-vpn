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
const useConfig = byId('use-config');
const useCode = byId('use-code');
const download = byId('export-config');
let vpn;
let BrowserVpn;
let BrowserPairing;
let pairingLocator;
let discoveryPlan;
let exportedConfig;
let enrollmentMode = 'config';
let loaded = false;
let busy = false;

const discoveryMarker = document.querySelector('meta[name="p2p-vpn-discovery"]');
const discoveryEndpoint = discoveryMarker?.content === '/api/discovery' ? discoveryMarker.content : null;
const pairingMarker = document.querySelector('meta[name="p2p-vpn-pairing"]');
const pairingEndpoint = pairingMarker?.content === '/api/pairing/locator' ? pairingMarker.content : null;

async function lookupEndpoints(plan, endpoint = discoveryEndpoint) {
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
  const { addresses, source } = await result.json();
  if (!Array.isArray(addresses) || addresses.some(address => typeof address !== 'string')) {
    throw Error('Local discovery returned invalid endpoints.');
  }
  if (!addresses.length) throw Error('No reachable endpoint found for the authorized peer.');
  return { endpoints: addresses.slice(0, 8), source };
}

async function approvePairing() {
  const code = pairCode.value.trim();
  const hostname = byId('pair-hostname').value.trim() || undefined;
  const selected = address.value.trim();
  const endpoints = selected
    ? [selected]
    : (await lookupEndpoints(JSON.stringify({ locator: pairingLocator(code) }), pairingEndpoint)).endpoints;
  const pairing = new BrowserPairing();
  let lastError;
  try {
    for (const endpoint of endpoints.slice(0, 3)) {
      const peerId = /\/p2p\/([^/]+)$/.exec(endpoint)?.[1];
      if (!peerId) throw Error('Pairing requires a WebRTC address with a pinned peer ID.');
      let pending = false;
      let artifacts;
      try {
        artifacts = JSON.parse(await pairing.join_v2(code, peerId, endpoint, 300_000,
          hostname, () => {
            pending = true;
            render('Waiting for approval');
          }));
      } catch (error) {
        if (selected || pending || ![
          'WebRTC Direct dial failed', 'Pairing transport failed',
          'Pairing request timed out', 'Pairing code authentication failed',
        ].includes(error.message)) throw error;
        lastError = error;
        continue;
      }
      pairCode.value = '';
      if (artifacts.kind === 'legacy') {
        const configJson = JSON.stringify(artifacts.config);
        return { candidate: new BrowserVpn(configJson, artifacts.dial_address), configJson };
      }
      if (artifacts.kind === 'checkpoint') {
        const activation = pairing.take_checkpoint_activation();
        if (!activation) throw Error('Approved pairing did not provide checkpoint activation.');
        return { candidate: await BrowserVpn.open_checkpoint_activation(activation) };
      }
      throw Error('Unknown pairing artifact.');
    }
    throw lastError ?? Error('No reachable inviter found.');
  } finally {
    pairing.free();
  }
}

async function connectDiscoveredPeer(peer, plan, source) {
  try {
    return await peer.connect();
  } catch (error) {
    const request = JSON.parse(plan);
    if (source !== 'lan' || !request.kademlia || !JSON.parse(peer.snapshot()).path_recovery_needed) {
      throw error;
    }
    const { endpoints } = await lookupEndpoints(JSON.stringify({ ...request, lan: false }));
    peer.set_member_endpoints(JSON.stringify(endpoints));
    await peer.reset_connection();
    return await peer.connect();
  }
}

function render(status) {
  const pairing = enrollmentMode === 'code';
  connect.disabled = !loaded || busy;
  connect.textContent = pairing ? 'Join network' : 'Connect';
  connect.hidden = !!vpn;
  disconnect.hidden = !vpn;
  disconnect.disabled = busy;
  config.disabled = pairing || busy || !!vpn;
  config.required = !pairing;
  pairCode.disabled = !pairing || busy || !!vpn;
  pairCode.required = pairing;
  byId('pair-hostname').disabled = !pairing || busy || !!vpn;
  byId('pair-inputs').hidden = !pairing;
  byId('config-import').hidden = pairing;
  useConfig.disabled = useCode.disabled = busy;
  useConfig.setAttribute('aria-pressed', String(!pairing));
  useCode.setAttribute('aria-pressed', String(pairing));
  address.disabled = busy || !!vpn;
  address.required = pairing ? !pairingEndpoint : !discoveryEndpoint;
  document.querySelector('label[for="address"]').textContent = pairing
    ? 'Inviter address'
    : discoveryEndpoint ? 'Peer ID or address' : 'Native peer address';
  byId('config-fields').hidden = !!vpn;
  send.disabled = !vpn || busy;
  state.textContent = status;
  state.dataset.connected = String(!!vpn);
  byId('identity').hidden = !vpn;
  download.hidden = !exportedConfig;
  download.disabled = busy;
}

function setError(message = '') {
  error.textContent = message;
  error.hidden = !message;
}

function discardPeer() {
  vpn?.free();
  vpn = undefined;
  discoveryPlan = undefined;
  exportedConfig = undefined;
  byId('peer-id').textContent = '';
}

for (const [button, mode] of [[useConfig, 'config'], [useCode, 'code']]) {
  button.addEventListener('click', () => {
    if (busy || vpn) return;
    enrollmentMode = mode;
    setError();
    render(loaded ? 'Disconnected' : 'Loading');
  });
}

download.addEventListener('click', () => {
  if (!exportedConfig) return;
  const url = URL.createObjectURL(new Blob([exportedConfig], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'p2p-vpn-browser.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
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
        const { endpoints } = resolution;
        source = resolution.source;
        candidate = new BrowserVpn(configJson, endpoints[0]);
        if (JSON.parse(candidate.snapshot()).remote_peer_id !== JSON.parse(plan).peer) {
          throw Error('Local discovery returned the wrong peer.');
        }
        candidate.set_member_endpoints(JSON.stringify(endpoints));
      } else {
        candidate = new BrowserVpn(configJson, target);
      }
    }
    const session = JSON.parse(await (plan
      ? connectDiscoveredPeer(candidate, plan, source)
      : candidate.connect()));
    byId('peer-id').textContent = session.remote_peer_id;
    vpn = candidate;
    discoveryPlan = plan;
    exportedConfig = pairedConfig;
    candidate = undefined;
    config.value = '';
  } catch (e) {
    setError(e.message);
  } finally {
    candidate?.free();
    busy = false;
    render(vpn ? 'Connected' : 'Disconnected');
  }
});

disconnect.addEventListener('click', async () => {
  if (busy) return;
  busy = true;
  setError();
  render('Disconnecting');
  try {
    await vpn?.close();
  } catch (e) {
    setError(e.message);
  } finally {
    discardPeer();
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
        if (discoveryPlan) {
          const { endpoints, source } = await lookupEndpoints(discoveryPlan);
          vpn.set_member_endpoints(JSON.stringify(endpoints));
          await vpn.reset_connection();
          await connectDiscoveredPeer(vpn, discoveryPlan, source);
        } else {
          await vpn.reset_connection();
          await vpn.connect();
        }
        setError('Connection restored. Send the request again.');
      } catch (reconnectError) {
        setError(reconnectError.message);
        discardPeer();
      }
    } else if (!session.authorized) {
      discardPeer();
    }
  } finally {
    busy = false;
    render(vpn ? 'Connected' : 'Disconnected');
  }
});

try {
  if (!window.isSecureContext) throw Error('Open this page over HTTPS or loopback.');
  const { default: init, BrowserVpn: peer, BrowserPairing: enroll, pairing_code_v2_global_locator: locate }
    = await import('./pkg/p2p_vpn_browser.js');
  await init();
  BrowserVpn = peer;
  BrowserPairing = enroll;
  pairingLocator = locate;
  loaded = true;
  render('Disconnected');
} catch (e) {
  setError(e.message);
  render('Unavailable');
}
