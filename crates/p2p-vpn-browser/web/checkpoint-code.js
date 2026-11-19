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
    const alias = vpn.checkpoint_code_public_alias();
    automatic = !!alias;
    if (alias) vpn.publish_checkpoint_code(alias);
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
    if (vpn === active && !approvedPeer) vpn.cancel_checkpoint_code();
  });

  return {
    render(vpn, canStart, busy) {
      if (active && active !== vpn) clear();
      const supported = typeof vpn?.start_checkpoint_code === 'function';
      start.hidden = !supported || !canStart || !!active;
      start.disabled = busy;
      panel.hidden = !active;
      approve.disabled = busy || !review || !!approvedPeer;
      cancel.disabled = busy || !!approvedPeer;
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
