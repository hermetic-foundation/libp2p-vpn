const el = id => document.getElementById(id);
const value = id => el(id).value.trim();
const show = (id, visible) => { el(id).hidden = !visible; };
const write = (id, text) => { el(id).textContent = text; };
const modes = { create: 'invite-mode', existing: 'existing-mode', join: 'join-mode' };
const MAX_CONFIG_BYTES = 1024 * 1024;
let BrowserCodeInviter, BrowserPairing, BrowserVpn;
let joiner;
let approvalRequested = false;

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
el('reset').addEventListener('click', () => location.reload());
el('approve').addEventListener('click', () => {
  // The bounded foreground drive owns the WASM handle until it returns.
  approvalRequested = true;
  el('approve').disabled = true;
});

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
      return 'Could not open the issuer. Check the legacy JSON config, joiner peer ID, and pinned relay address.';
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

async function runInvitation(inviter, existing = false) {
  lock('Reserving relay');
  try {
    const address = await inviter.reserve();
    write('invite-code', inviter.code());
    write('inviter-peer', inviter.peer_id());
    write('invite-address', address);
    show('invitation', true);
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
          el('approve').disabled = false;
          state('Approval required');
          el('review-title').focus();
        }
      }
      if (approvalRequested) {
        approvalRequested = false;
        try {
          inviter.approve(candidate.peer_id);
        } catch (failure) {
          if (!existing || !inviter.pending_candidate()) throw failure;
          error(approvalError(failure));
          el('approve').disabled = false;
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
    error(inviter ? 'The relay reservation or invitation ended.' : 'The authorized relay session ended or could not activate.');
  } finally {
    inviter?.free();
    clearInvitation();
    state('Session ended');
  }
}

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

el('existing-form').addEventListener('submit', async event => {
  event.preventDefault();
  let inviter;
  {
    const input = el('issuer-config');
    const file = input.files[0];
    if (!file || file.size > MAX_CONFIG_BYTES) {
      error('Select a legacy JSON config no larger than 1 MiB.');
      return;
    }
    const peer = value('existing-pin');
    const relay = value('existing-relay');
    input.value = '';
    show('existing', false);
    lock('Opening issuer');
    try {
      inviter = await BrowserCodeInviter.open_existing(await file.text(), peer, relay);
    } catch (failure) {
      show('existing', true);
      show('modes', true);
      show('reset', false);
      state('Not opened');
      error(openIssuerError(failure));
      input.focus();
      return;
    }
  }
  await runInvitation(inviter, true);
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
  role(location.hash === '#join' ? 'join' : location.hash === '#existing' ? 'existing' : 'create');
  for (const id of [...Object.values(modes), 'reserve', 'join-request']) el(id).disabled = false;
  if (typeof BrowserCodeInviter.open_existing === 'function') {
    el('existing-reserve').disabled = false;
  } else {
    el('existing-mode').disabled = true;
    if (location.hash === '#existing') error('This browser package does not support existing code invitations.');
  }
  state('Ready');
} catch {
  state('Unavailable');
  error('Code pairing requires HTTPS or loopback and a current relay-enabled browser package.');
}
