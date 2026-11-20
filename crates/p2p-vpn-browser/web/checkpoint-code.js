export function bindCheckpointCode(byId, run, issued, deliveryFailed) {
  const start = byId('checkpoint-code-start');
  const panel = byId('checkpoint-code');
  const approve = byId('checkpoint-code-approve');
  const cancel = byId('checkpoint-code-cancel');
  const show = (id, text) => {
    const element = byId(`checkpoint-code-${id}`);
    if (element.textContent !== text) element.textContent = text;
  };
  let active;
  let review;
  let approvedPeer;
  let automatic;

  function clear() {
    active = review = approvedPeer = automatic = undefined;
    for (const id of ['value', 'address', 'publication', 'peer', 'name']) show(id, '');
    panel.hidden = true;
  }

  start.onclick = () => run(async (vpn, address) => {
    const code = vpn.start_checkpoint_code();
    active = vpn;
    show('value', code);
    show('address', address);
    automatic = vpn.checkpoint_code_is_scoped();
    if (automatic) {
      try {
        await vpn.publish_checkpoint_code_distributed();
      } catch (error) {
        await vpn.cancel_checkpoint_code();
        throw error;
      }
    }
  });
  approve.onclick = () => {
    const selected = review;
    if (!selected) return;
    return run(async vpn => {
      if (vpn !== active) return;
      await vpn.approve_checkpoint_code(selected.ticket);
      approvedPeer = selected.peer;
      show('value', '');
    });
  };
  cancel.onclick = () => run(async vpn => {
    if (vpn === active) {
      await vpn.cancel_checkpoint_code();
      clear();
    }
  });

  return {
    render(vpn, canStart, busy) {
      if (active && active !== vpn) clear();
      const supported = typeof vpn?.start_checkpoint_code === 'function';
      start.hidden = !supported || !canStart || !!active;
      start.disabled = busy;
      panel.hidden = !active;
      approve.disabled = busy || !review || !!approvedPeer;
      cancel.disabled = busy;
    },
    update(vpn) {
      if (vpn !== active) return false;
      if (!vpn.checkpoint_code_pending()) {
        if (approvedPeer) {
          if (vpn.checkpoint_code_delivered()) issued(approvedPeer);
          else deliveryFailed();
        }
        clear();
        return true;
      }
      const previous = review?.ticket;
      review = JSON.parse(vpn.checkpoint_code_review() ?? 'null');
      show('peer', review?.peer ?? approvedPeer ?? '');
      show('name', review?.hostname ?? '');
      const publication = vpn.checkpoint_code_publication();
      show('publication', publication === true ? 'Announced'
        : publication === false ? 'Announcement failed'
        : automatic ? 'Announcing' : 'Manual address only');
      return previous !== review?.ticket;
    },
    active: () => !!active,
  };
}

export async function prepareCheckpointIngress() {
  const response = await fetch('/api/relay/inviter/reservation', {
    method: 'POST', mode: 'same-origin', redirect: 'error', credentials: 'omit', cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: '{"checkpoint":true}', signal: AbortSignal.timeout(18_000),
  });
  if (!response.ok) throw Error('Scoped checkpoint relay unavailable.');
  const prepared = await response.json();
  if (!/^[A-Za-z0-9_-]{32}$/.test(prepared.relay_lease_id ?? '')) {
    throw Error('Invalid scoped checkpoint relay lease.');
  }
  return prepared;
}
