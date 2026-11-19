const byId = id => document.getElementById(id);
const config = byId('config');
const address = byId('address');
const state = byId('state');
const error = byId('error');
const response = byId('response');
const connect = byId('connect');
const disconnect = byId('disconnect');
const send = byId('send');
let vpn;
let BrowserVpn;
let discoveryPlan;
let loaded = false;
let busy = false;

const discoveryMarker = document.querySelector('meta[name="p2p-vpn-discovery"]');
const discoveryEndpoint = discoveryMarker?.content === '/api/discovery' ? discoveryMarker.content : null;
if (discoveryEndpoint) {
  address.required = false;
  address.placeholder = '';
  document.querySelector('label[for="address"]').textContent = 'Peer ID or address';
}

async function lookupEndpoints(plan) {
  const result = await fetch(discoveryEndpoint, {
    method: 'POST',
    mode: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: plan,
    signal: AbortSignal.timeout(30_000),
  });
  if (!result.ok) throw Error(`Local discovery failed (HTTP ${result.status}).`);
  const { addresses } = await result.json();
  if (!Array.isArray(addresses) || addresses.some(address => typeof address !== 'string')) {
    throw Error('Local discovery returned invalid endpoints.');
  }
  if (!addresses.length) throw Error('No reachable endpoint found for the authorized peer.');
  return addresses.slice(0, 8);
}

function render(status) {
  connect.disabled = !loaded || busy;
  connect.hidden = !!vpn;
  disconnect.hidden = !vpn;
  disconnect.disabled = busy;
  config.disabled = busy || !!vpn;
  address.disabled = busy || !!vpn;
  byId('config-fields').hidden = !!vpn;
  send.disabled = !vpn || busy;
  state.textContent = status;
  state.dataset.connected = String(!!vpn);
  byId('identity').hidden = !vpn;
}

function setError(message = '') {
  error.textContent = message;
  error.hidden = !message;
}

function discardPeer() {
  vpn?.free();
  vpn = undefined;
  discoveryPlan = undefined;
  byId('peer-id').textContent = '';
}

byId('connect-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!loaded || busy || vpn) return;
  let candidate;
  busy = true;
  setError();
  render('Connecting');
  try {
    const file = config.files[0];
    if (!file || file.size > 4 * 1024 * 1024) {
      throw Error('Select a peer config no larger than 4 MiB.');
    }
    const configJson = await file.text();
    const target = address.value.trim();
    let plan;
    if (discoveryEndpoint && !target.startsWith('/')) {
      plan = BrowserVpn.discovery_query(configJson, target);
      const endpoints = await lookupEndpoints(plan);
      candidate = new BrowserVpn(configJson, endpoints[0]);
      if (JSON.parse(candidate.snapshot()).remote_peer_id !== JSON.parse(plan).peer) {
        throw Error('Local discovery returned the wrong peer.');
      }
      candidate.set_member_endpoints(JSON.stringify(endpoints));
    } else {
      candidate = new BrowserVpn(configJson, target);
    }
    const session = JSON.parse(await candidate.connect());
    byId('peer-id').textContent = session.remote_peer_id;
    vpn = candidate;
    discoveryPlan = plan;
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

disconnect.addEventListener('click', () => {
  if (busy) return;
  discardPeer();
  response.hidden = true;
  response.textContent = '';
  setError();
  render('Disconnected');
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
          vpn.set_member_endpoints(JSON.stringify(await lookupEndpoints(discoveryPlan)));
        }
        await vpn.reset_connection();
        await vpn.connect();
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
  const { default: init, BrowserVpn: peer } = await import('./pkg/p2p_vpn_browser.js');
  await init();
  BrowserVpn = peer;
  loaded = true;
  render('Disconnected');
} catch (e) {
  setError(e.message);
  render('Unavailable');
}
