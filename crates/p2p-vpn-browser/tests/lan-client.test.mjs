import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { get } from 'node:http';

test('portable server binds loopback and refuses unexpected hosts, methods and files', async t => {
  const source = dirname(fileURLToPath(import.meta.url));
  const parent = resolve(source, '../../../target');
  await mkdir(parent, { recursive: true });
  // Preserve synthetic test files under target for inspection. No real keys.
  const root = await mkdtemp(resolve(parent, 'browser-client-server-test-'));
  await mkdir(resolve(root, 'pkg'));
  await copyFile(resolve(source, 'lan-client.mjs'), resolve(root, 'client.mjs'));
  await writeFile(resolve(root, 'index.html'), 'synthetic page');
  await writeFile(resolve(root, 'session.json'), JSON.stringify({ qualification_mode: 'split-lan',
    expires_at: Date.now() / 1000 + 300, native_host: 'synthetic-remote-host', webrtc_ip: '192.0.2.9', webrtc_port: 12345, session_id: 'synthetic-session' }));
  const child = spawn(process.execPath, ['client.mjs'], { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = new Promise(ok => child.once('exit', ok));
  t.after(async () => { child.kill(); await exited; });
  const url = await new Promise((ok, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(Error('Client server startup timed out')), 10000);
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = /Browser client: (http:\/\/127\.0\.0\.1:\d+)/.exec(output);
      if (match) { clearTimeout(timer); ok(match[1]); }
    });
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('exit', () => { clearTimeout(timer); reject(Error(`Client exited before readiness: ${output}`)); });
  });
  const page = await fetch(url);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('cache-control'), 'no-store');
  assert.equal(await page.text(), 'synthetic page');
  assert.equal((await fetch(`${url}/session.json`)).status, 200);
  assert.equal((await fetch(`${url}/package-lock.json`)).status, 403);
  assert.equal((await fetch(`${url}/%2e%2e/client.mjs`)).status, 403);
  assert.equal((await fetch(`${url}/session.json`, { method: 'POST' })).status, 403);
  const status = await new Promise((ok, reject) => get(url, { headers: { Host: 'unexpected.example' } }, res => {
    res.resume(); ok(res.statusCode);
  }).on('error', reject));
  assert.equal(status, 403);
});
