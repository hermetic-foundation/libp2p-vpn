const el = id => document.getElementById(id);
const value = id => el(id).value.trim();
const show = (id, visible) => { el(id).hidden = !visible; };
const write = (id, text) => { el(id).textContent = text; };
const modes = { create: 'invite-mode', scoped: 'scoped-mode', existing: 'existing-mode', join: 'join-mode' };
const MAX_CONFIG_BYTES = 1024 * 1024;
// Allow the companion's 15-second discovery budget plus HTTP overhead.
const SCOPED_RESERVATION_TIMEOUT_MS = 18_000;
let BrowserCodeInviter, BrowserPairing, BrowserVpn;
let joiner;
let decision;
let scopedLease;

const onCompanion = location.protocol === 'http:' && location.hostname === '127.0.0.1';

function companionPost(path, fields, options = {}) {
  return fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    mode: 'same-origin', redirect: 'error', credentials: 'omit',
    body: JSON.stringify(fields), ...options,
  });
}

async function releaseScopedRelay(options = { signal: AbortSignal.timeout(3000) }) {
  if (!scopedLease) return;
  const lease = scopedLease;
  scopedLease = null;
  await companionPost('/api/relay/release', { lease_id: lease }, options).catch(() => {});
}

async function prepareScopedRelay(relay) {
  const response = await companionPost('/api/relay/inviter/reservation', relay ? { relay_peer: relay } : {},
    { signal: AbortSignal.timeout(SCOPED_RESERVATION_TIMEOUT_MS) });
  if (!response.ok) throw Error('Scoped relay unavailable');
  const prepared = await response.json();
  if (typeof prepared.relay_lease_id !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(prepared.relay_lease_id)) {
    throw Error('Invalid scoped relay reply');
  }
  scopedLease = prepared.relay_lease_id;
  return prepared;
}

function state(label, connected = false) {
  write('state', label);
  el('state').dataset.connected = String(connected);
}

function error(message) {
  write('error', message);
  show('error', Boolean(message));
}

function role(mode) {
  error('');
  const joining = mode === 'join';
  if (joining && !joiner) joiner = new BrowserPairing();
  write('local-joiner', joining ? joiner.peer_id() : '');
  if (mode !== 'existing') el('issuer-config').value = '';
  for (const [section, id] of Object.entries(modes)) {
    el(id).setAttribute('aria-pressed', String(mode === section));
    show(section, mode === section);
  }
  history.replaceState(null, '', mode === 'create' ? location.pathname : `#${mode}`);
}

function lock(label) {
  error('');
  show('modes', false);
  show('reset', true);
  state(label);
  el('state').focus();
}

function clearInvitation() {
  show('invitation', false);
  show('review', false);
  el('approve').disabled = true;
  el('deny').disabled = true;
  show('deny', false);
  for (const id of ['invite-code', 'inviter-peer', 'invite-address', 'candidate-peer', 'candidate-name', 'candidate-ip']) {
    write(id, '');
  }
}

async function active(vpn, address, incoming) {
  try {
    state('Authorizing VPN');
    const connection = JSON.parse(await (incoming ? vpn.accept_relay() : vpn.connect()));
    if (!connection.ready || !connection.authorized || connection.transport !== 'circuit-relay'
        || (incoming && vpn.relay_reservation_address() !== address)) {
      throw Error('The relay did not authorize this VPN session');
    }
    write('active-local', connection.local_peer_id);
    write('active-remote', connection.remote_peer_id);
    write('active-address', address);
    show('active', true);
    state('VPN connected', true);
    el('active-title').focus();
    for (;;) await vpn.poll_foreground();
  } finally {
    show('active', false);
    try { await vpn.close(); } catch { /* Drop the swarm even if close failed. */ }
    vpn.free();
  }
}

for (const [mode, id] of Object.entries(modes)) el(id).addEventListener('click', () => role(mode));
el('reset').addEventListener('click', async () => {
  el('reset').disabled = true;
  await releaseScopedRelay();
  location.reload();
});
window.addEventListener('pagehide', () => { void releaseScopedRelay({ keepalive: true }); });
for (const action of ['approve', 'deny']) {
  el(action).addEventListener('click', () => {
    // The bounded foreground drive owns the WASM handle until it returns.
    decision = action;
    el('approve').disabled = true;
    el('deny').disabled = true;
  });
}

function openIssuerError(failure) {
  switch (failure?.message) {
    case 'This browser identity is in use by another tab':
      return 'This issuer identity is in use. Close its other VPN or invitation session and try again.';
    case 'Browser membership storage or locking is unavailable':
      return 'Browser membership storage or identity locking is unavailable.';
    case 'This browser identity requires explicit checkpoint bootstrap':
      return 'Checkpoint identities cannot issue this legacy invitation.';
    case 'This profile only admits a new peer with no prior membership':
      return 'Choose a new peer with no prior membership in this network.';
    case 'An existing invitation requires a rooted legacy ledger':
    case 'Open a rooted config matching the saved legacy issuer root':
    case 'The config cannot replace the saved legacy issuer root':
    case 'The legacy ledger has no explicit issuer root':
    case 'The inviter has no active rooted legacy membership proof':
      return 'An active, rooted legacy issuer config matching the saved ledger is required.';
    default:
      return 'Could not open the issuer. Check the legacy JSON config and invitation route.';
  }
}

function approvalError(failure) {
  switch (failure?.message) {
    case 'Could not save the signed membership ledger':
      return 'Could not save the membership ledger. Approval was not sent.';
    case 'Membership ledger exceeds its storage limit':
      return 'The membership ledger exceeds its storage limit. Approval was not sent.';
    case 'The requested hostname is already in use':
      return 'The requested hostname is already in use. Approval was not sent.';
    default:
      return 'This join request could not be approved.';
  }
}

async function runInvitation(inviter, { durable = false, scoped = false, allowDenial = false, recoverOpening = false } = {}) {
  decision = null;
  let finalState = 'Session ended';
  let published = false;
  lock('Reserving relay');
  try {
    const address = await inviter.reserve();
    if (scoped) {
      state('Publishing locator');
      await inviter.publish_locator_scoped();
    }
    write('invite-code', inviter.code());
    write('inviter-peer', inviter.peer_id());
    write('invite-address', address);
    show('invitation', true);
    published = true;
    state('Waiting for joiner');
    el('invitation-title').focus();

    let candidate;
    while (!inviter.delivered()) {
      await inviter.drive(150);
      if (!candidate) {
        const pending = inviter.pending_candidate();
        if (pending) {
          candidate = JSON.parse(pending);
          write('candidate-peer', candidate.peer_id);
          write('candidate-name', candidate.requested_hostname || 'Not provided');
          write('candidate-ip', candidate.assigned_vpn_ip);
          show('review', true);
          show('deny', allowDenial);
          el('deny').disabled = !allowDenial;
          el('approve').disabled = false;
          state('Approval required');
          el('review-title').focus();
        }
      }
      if (decision === 'deny') {
        inviter.cancel();
        finalState = 'Request denied';
        error('');
        return;
      }
      if (decision === 'approve') {
        decision = null;
        try {
          inviter.approve(candidate.peer_id);
        } catch (failure) {
          if (!durable || !inviter.pending_candidate()) throw failure;
          error(approvalError(failure));
          el('approve').disabled = false;
          el('deny').disabled = !allowDenial;
          el('approve').focus();
          continue;
        }
        error('');
        clearInvitation();
        state('Delivering approval');
      }
    }
    const activation = inviter.into_vpn();
    inviter = null;
    await active(await activation, address, true);
  } catch {
    if (recoverOpening && !published) return false;
    error(inviter ? (scoped ? 'The scoped relay or locator publication failed.' : 'The relay reservation or invitation ended.')
      : 'The authorized relay session ended or could not activate.');
  } finally {
    inviter?.free();
    clearInvitation();
    state(finalState);
  }
}

el('scoped-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!onCompanion) {
    error('Open the local Linux companion to publish a native invitation.');
    return;
  }
  const relay = value('scoped-relay');
  const network = value('scoped-network');
  const ownerIp = value('scoped-owner-ip');
  const joinerIp = value('scoped-joiner-ip');
  show('scoped', false);
  lock('Preparing scoped relay');
  try {
    const prepared = await prepareScopedRelay(relay);
    const inviter = await BrowserCodeInviter.open_unpinned_scoped(network, ownerIp, joinerIp,
      relay, prepared.relay_entrance, prepared.native_alias);
    await runInvitation(inviter, { durable: true, scoped: true });
  } catch {
    show('scoped', true);
    show('modes', true);
    show('reset', false);
    state('Not opened');
    error('No scoped reservation. Check the companion relay settings and VPN addresses.');
  } finally {
    await releaseScopedRelay();
  }
});

el('create-form').addEventListener('submit', async event => {
  event.preventDefault();
  let inviter;
  try {
    inviter = new BrowserCodeInviter(value('network'), value('owner-ip'), value('joiner-ip'),
      value('joiner-pin'), value('relay'));
  } catch {
    error('Enter distinct VPN addresses of the same family, a valid joiner peer ID, and a pinned WebRTC Direct relay address.');
    return;
  }
  show('create', false);
  await runInvitation(inviter);
});

// Existing legacy issuer: route selection and local config stay in this section.
function syncExistingRoute() {
  const scoped = value('existing-route') === 'scoped';
  show('existing-pinned-fields', !scoped);
  show('existing-scoped-fields', scoped);
  el('existing-pin').disabled = scoped;
  el('existing-relay').disabled = scoped;
  el('existing-scoped-relay').disabled = !scoped;
}

el('existing-route').addEventListener('change', syncExistingRoute);
el('existing-form').addEventListener('submit', async event => {
  event.preventDefault();
  const input = el('issuer-config');
  const file = input.files[0];
  if (!file || file.size > MAX_CONFIG_BYTES) {
    error('Select a legacy JSON config no larger than 1 MiB.');
    return;
  }
  const scoped = value('existing-route') === 'scoped';
  input.value = '';
  show('existing', false);
  lock(scoped ? 'Preparing scoped relay' : 'Opening issuer');
  const reopen = async message => {
    await releaseScopedRelay();
    show('existing', true);
    show('modes', true);
    show('reset', false);
    state('Not opened');
    error(message);
    input.focus();
  };
  try {
    let prepared;
    const relay = value('existing-scoped-relay');
    if (scoped) {
      if (el('existing-scoped-option').disabled) throw Error('Scoped relay unavailable');
      prepared = await prepareScopedRelay(relay);
      state('Opening issuer');
    }
    const config = await file.text();
    const inviter = scoped
      ? await BrowserCodeInviter.open_existing_scoped(config, relay, prepared.relay_entrance, prepared.native_alias)
      : await BrowserCodeInviter.open_existing(config, value('existing-pin'), value('existing-relay'));
    if (await runInvitation(inviter, { durable: true, scoped, allowDenial: scoped, recoverOpening: scoped }) === false) {
      await reopen('Could not reserve the relay or publish the code. Retry later or choose another configured relay.');
    }
  } catch (failure) {
    await reopen(failure.message === 'Scoped relay unavailable' || failure.name === 'TimeoutError'
      ? 'No scoped reservation. Check the companion relay settings.' : openIssuerError(failure));
  } finally {
    await releaseScopedRelay();
  }
});

el('join-form').addEventListener('submit', async event => {
  event.preventDefault();
  const address = value('entered-address');
  const peer = value('expected-peer');
  if (!address.endsWith(`/p2p-circuit/p2p/${peer}`)) {
    error('The circuit address must end in the inviter peer ID.');
    return;
  }
  const code = value('entered-code');
  const hostname = value('hostname');
  el('entered-code').value = '';
  show('join-form', false);
  lock('Requesting approval');
  try {
    let vpn;
    {
      const result = JSON.parse(await joiner.join_v2(code, peer, address, 300_000,
        hostname || undefined, () => state('Waiting for inviter approval')));
      joiner.free();
      joiner = null;
      if (result.kind !== 'legacy') throw Error('Not a legacy network');
      vpn = BrowserVpn.with_relay(JSON.stringify(result.config), '', address);
    }
    show('join', false);
    await active(vpn, address, false);
  } catch {
    if (joiner) {
      error('The invitation did not approve this peer. Check the code, peer ID and relay address.');
      show('join-form', true);
      state('Not enrolled');
      el('entered-code').focus();
      return;
    }
    error('The authorized relay session ended or could not activate.');
    state('Session ended');
  }
});

try {
  if (!window.isSecureContext) throw Error('Open this page over HTTPS or loopback.');
  const bindings = await import('./pkg/p2p_vpn_browser.js');
  ({ BrowserCodeInviter, BrowserPairing, BrowserVpn } = bindings);
  if (typeof BrowserCodeInviter !== 'function') throw Error('Code invitations unavailable in this build.');
  await bindings.default();
  const mode = location.hash.slice(1);
  role(Object.hasOwn(modes, mode) ? mode : 'create');
  for (const id of [...Object.values(modes), 'reserve', 'join-request']) el(id).disabled = false;
  if (typeof BrowserCodeInviter.open_existing === 'function') {
    el('existing-reserve').disabled = false;
    el('existing-scoped-option').disabled = !onCompanion || typeof BrowserCodeInviter.open_existing_scoped !== 'function';
    if (el('existing-scoped-option').disabled) el('existing-route').value = 'pinned';
    syncExistingRoute();
  } else {
    el('existing-mode').disabled = true;
    if (location.hash === '#existing') error('This browser package does not support existing code invitations.');
  }
  if (typeof BrowserCodeInviter.open_unpinned_scoped === 'function') {
    el('scoped-reserve').disabled = false;
  } else {
    el('scoped-mode').disabled = true;
    if (location.hash === '#scoped') error('This browser package does not support scoped invitations.');
  }
  state('Ready');
} catch {
  state('Unavailable');
  error('Code pairing requires HTTPS or loopback and a current relay-enabled browser package.');
}
