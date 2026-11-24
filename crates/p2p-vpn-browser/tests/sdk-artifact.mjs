import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';
import { chromium } from 'playwright';

test('a standalone page loads the SDK and matches the pairing protocol vector', async () => {
  const artifactDir = process.env.P2P_VPN_BROWSER_SDK_DIR;
  assert.ok(artifactDir, 'set P2P_VPN_BROWSER_SDK_DIR to the generated SDK directory');
  const vector = JSON.parse(await readFile(
    new URL('../../../docs/developer/protocol/vectors.json', import.meta.url), 'utf8',
  ));
  const files = new Map([
    ['/', ['text/html', '<!doctype html><title>Browser SDK smoke</title>']],
    ['/p2p_vpn_browser.js', ['text/javascript', await readFile(join(artifactDir, 'p2p_vpn_browser.js'))]],
    ['/p2p_vpn_browser_bg.wasm', ['application/wasm', await readFile(join(artifactDir, 'p2p_vpn_browser_bg.wasm'))]],
  ]);
  const server = createServer((request, response) => {
    const file = files.get(request.url);
    if (!file) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { 'Content-Type': file[0] }).end(file[1]);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  try {
    const executablePath = process.env.P2P_VPN_CHROMIUM;
    const browser = await chromium.launch(executablePath ? { executablePath } : { channel: 'chrome' });
    try {
      const page = await browser.newPage();
      await page.goto(`http://127.0.0.1:${server.address().port}/`);
      const result = await page.evaluate(async (code) => {
        const sdk = await import('/p2p_vpn_browser.js');
        await sdk.default();
        return {
          peerConstructor: typeof sdk.BrowserVpn,
          locator: sdk.pairing_code_v2_global_locator(code),
        };
      }, vector.pairing_test_code);
      assert.deepEqual(result, { peerConstructor: 'function', locator: vector.locator_v2 });
    } finally {
      await browser.close();
    }
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
