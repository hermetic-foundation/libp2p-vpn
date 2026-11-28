import init, { BrowserVpn } from '/sdk/p2p_vpn_browser.js';

window.proof = async ({ config, dial, address, port, path }) => {
  await init();
  const vpn = new BrowserVpn(JSON.stringify(config), dial);
  try {
    const connected = JSON.parse(await vpn.connect());
    if (!connected.authorized) throw new Error('VPN session was not authorized');
    const response = await vpn.fetch_http(address, port, path);
    return { connected, response, counters: JSON.parse(vpn.snapshot()).counters };
  } finally {
    await vpn.close();
  }
};
