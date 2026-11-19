// Runs from an exported bundle. No Rust, native VPN, elevation, or LAN HTTP server.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { hostname, networkInterfaces } from 'node:os';
import { createHash } from 'node:crypto';

const root = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const unknown = args.filter(a => !['--test', '--local-smoke'].includes(a));
if (unknown.length) throw Error(`Unknown arguments: ${unknown.join(' ')}`);
if (args.includes('--local-smoke') && !args.includes('--test')) throw Error('--local-smoke requires --test');
const session = JSON.parse(await readFile(resolve(root, 'session.json'), 'utf8'));
if (session.qualification_mode !== 'split-lan' || session.shutdown_token) throw Error('Invalid split-client session');
if (Date.now() / 1000 >= session.expires_at) throw Error('Test credentials expired; export a fresh session');
const addresses = Object.values(networkInterfaces()).flat().filter(i => i.family === 'IPv4').map(i => i.address);
const sameHost = hostname().toLowerCase() === session.native_host || addresses.includes(session.webrtc_ip);
if (sameHost && !args.includes('--local-smoke')) throw Error('Copy the bundle to a second device. Use --test --local-smoke only for a clearly labeled same-host smoke run.');
if (!sameHost && args.includes('--local-smoke')) throw Error('Local smoke mode must run on the native host');
const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/session.json', ['session.json', 'application/json']],
  ['/pkg/p2p_vpn_browser.js', ['pkg/p2p_vpn_browser.js', 'text/javascript']],
  ['/pkg/p2p_vpn_browser_bg.wasm', ['pkg/p2p_vpn_browser_bg.wasm', 'application/wasm']],
]);
const server = createServer(async (req, res) => {
  const host = `127.0.0.1:${server.address().port}`;
  const file = files.get(req.url);
  if (req.headers.host !== host || req.method !== 'GET' || !file) {
    res.writeHead(403, { 'Cache-Control': 'no-store' }).end('Not allowed');
    return;
  }
  try {
    const bytes = await readFile(resolve(root, file[0]));
    res.writeHead(200, { 'Content-Type': file[1], 'Content-Length': bytes.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(bytes);
  } catch {
    res.writeHead(500).end('Client bundle file unavailable');
  }
});
server.requestTimeout = 10000;
server.headersTimeout = 10000;
server.maxConnections = 16;
await new Promise((ok, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ok); });
const url = `http://127.0.0.1:${server.address().port}`;
console.log(`Browser client: ${url}\nNative WebRTC: ${session.webrtc_ip}:${session.webrtc_port}\nSession: ${session.session_id}`);
if (args.includes('--test')) {
  process.env.P2P_VPN_BROWSER_URL = url;
  process.env.P2P_VPN_BROWSER_REPORT = resolve(root, 'client-report.json');
  process.env.P2P_VPN_BROWSER_SCREENSHOT = resolve(root, 'client.png');
  process.env.P2P_VPN_BROWSER_KEEP_FIXTURE = '1';
  process.env.P2P_VPN_BROWSER_LOCAL_SMOKE = args.includes('--local-smoke') ? '1' : '0';
  process.env.P2P_VPN_BROWSER_WASM_SHA256 = createHash('sha256').update(await readFile(resolve(root, 'pkg/p2p_vpn_browser_bg.wasm'))).digest('hex');
  try { await import('./tests/e2e.mjs'); }
  finally { server.closeAllConnections(); await new Promise(ok => server.close(ok)); }
} else {
  console.log('Inspect the page manually; use node client.mjs --test for saved qualification evidence. Ctrl+C stops this server.');
}
