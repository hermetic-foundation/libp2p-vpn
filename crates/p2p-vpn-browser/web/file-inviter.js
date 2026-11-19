import init, { BrowserFileInviter } from './pkg/p2p_vpn_browser.js';

const el = id => document.getElementById(id);
const controls = [...document.querySelectorAll('button, input')];
const MAX_CONFIG = 1024 * 1024;
const MAX_REQUEST = 64 * 1024;
let inviter;
let offer;
let review;
let response;
let downloaded = false;
let ready = false;
let busy = false;

async function readFile(id, max) {
  const file = el(id).files[0];
  if (!file) throw Error('Choose a file first.');
  if (file.size > max) throw Error('The selected file is too large.');
  return file.text();
}

function render() {
  el('state').textContent = busy ? 'Working' : !ready ? 'Unavailable'
    : response ? 'Approved' : review ? 'Review required' : offer ? 'Offer ready'
    : inviter ? 'Session open' : 'Closed';
  el('open-form').hidden = Boolean(inviter);
  el('close').hidden = !inviter;
  el('offer').hidden = !inviter || Boolean(response);
  el('offer-form').hidden = Boolean(offer);
  el('offer-actions').hidden = !offer;
  el('request').hidden = !offer || Boolean(response);
  el('review-form').hidden = Boolean(review);
  el('review').hidden = !review;
  el('response').hidden = !response;
  for (const input of controls) input.disabled = busy || !ready;
  el('close').disabled = busy || Boolean(response);
  el('finish').disabled = busy || !downloaded;
}

function report(error) {
  el('error').textContent = error?.message || 'The file invitation could not be completed.';
  el('error').hidden = false;
}

async function run(action) {
  if (busy || !ready) return;
  el('error').hidden = true;
  busy = true;
  render();
  let focus;
  try {
    focus = await action();
  } catch (error) {
    report(error);
  } finally {
    busy = false;
    render();
    if (focus) el(focus).focus();
  }
}

function submit(id, action) {
  el(id).addEventListener('submit', event => {
    event.preventDefault();
    void run(action);
  });
}

function download(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

subscribe();
try {
  await init();
  ready = true;
} catch {
  report(Error('Could not load the local pairing engine.'));
}
render();

function subscribe() {
  submit('open-form', async () => {
    inviter = await BrowserFileInviter.open(await readFile('founder-config', MAX_CONFIG));
    el('founder-config').value = '';
    return 'offer-title';
  });
  submit('offer-form', () => {
    offer = inviter.create_offer(el('lifetime').valueAsNumber * 60);
    return 'download-offer';
  });
  el('download-offer').addEventListener('click', () =>
    download(offer + '\n', 'p2p-vpn-offer.pair', 'text/plain'));
  submit('review-form', async () => {
    review = JSON.parse(inviter.review_request(await readFile('request-file', MAX_REQUEST)));
    el('request-file').value = '';
    el('joiner').textContent = review.joiner_peer;
    el('hostname').textContent = review.requested_hostname ?? 'None';
    el('vpn-ip').textContent = review.vpn_ipv4;
    return 'review-title';
  });
  el('approve').addEventListener('click', () => void run(() => {
    response = inviter.approve(review.joiner_peer);
    offer = review = undefined;
    return 'response-title';
  }));
  el('download-response').addEventListener('click', () => {
    download(response + '\n', 'p2p-vpn-response.json', 'application/json');
    downloaded = true;
    render();
  });
  el('finish').addEventListener('click', () => void run(() => {
    response = undefined;
    downloaded = false;
    return 'offer-title';
  }));
  el('cancel').addEventListener('click', () => void run(() => {
    inviter.cancel_offer();
    offer = review = undefined;
    el('request-file').value = '';
    return 'offer-title';
  }));
  el('close').addEventListener('click', () => void run(async () => {
    try {
      await inviter.close();
    } finally {
      inviter.free();
      inviter = offer = review = undefined;
      el('request-file').value = '';
    }
    return 'founder-config';
  }));
}
