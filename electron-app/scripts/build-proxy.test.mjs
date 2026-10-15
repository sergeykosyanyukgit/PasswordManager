import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { createRequire } from 'node:module';
import { after, before, test } from 'node:test';

// Exercise electron-builder's actual downloader and its overridden proxy dependency.
// All traffic terminates at loopback synthetic servers; no external request is made.
const require = createRequire(import.meta.url);
const requireFromBuilder = createRequire(require.resolve('app-builder-lib'));
const sockets = new Set();
const proxyRequests = [];
const tunnelRequests = [];
const proxy = http.createServer((request, response) => {
  proxyRequests.push(request.url);
  response.end('SYNTHETIC-PROXY-ONLY');
});
const origin = http.createServer((_request, response) => response.end('SYNTHETIC-DIRECT-ONLY'));
proxy.on('connect', (request, socket) => {
  tunnelRequests.push(request.url);
  socket.end('HTTP/1.1 502 Synthetic Test Rejection\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
});
for (const server of [proxy, origin]) server.on('connection', (socket) => {
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
});

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const get = (url, client = http) => new Promise((resolve, reject) => {
  const request = client.get(url, (response) => {
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => { text += chunk; });
    response.on('end', () => resolve(text));
    response.on('error', reject);
  });
  request.setTimeout(3_000, () => request.destroy(new Error('Synthetic test timeout')));
  request.on('error', reject);
});

before(async () => {
  await Promise.all([listen(proxy), listen(origin)]);
  // These process-local values replace any inherited proxy configuration without logging it.
  process.env.GLOBAL_AGENT_ENVIRONMENT_VARIABLE_NAMESPACE = 'GLOBAL_AGENT_';
  process.env.GLOBAL_AGENT_HTTP_PROXY = `http://127.0.0.1:${proxy.address().port}`;
  process.env.GLOBAL_AGENT_HTTPS_PROXY = process.env.GLOBAL_AGENT_HTTP_PROXY;
  process.env.GLOBAL_AGENT_NO_PROXY = '127.0.0.1';
  process.env.GLOBAL_AGENT_FORCE_GLOBAL_AGENT = 'true';
  delete process.env.ELECTRON_GET_USE_PROXY;
  delete process.env.DEBUG;
  const downloader = requireFromBuilder('@electron/get');
  downloader.initializeProxy();
  assert.ok(globalThis.GLOBAL_AGENT, 'Downloader must successfully initialize the overridden proxy API');
});

after(async () => {
  for (const socket of sockets) socket.destroy();
  await Promise.all([proxy, origin].map((server) => new Promise((resolve) => server.close(resolve))));
});

test('Electron downloader routes HTTP through the overridden proxy API', async () => {
  assert.equal(await get('http://synthetic-proxy.invalid/test-only'), 'SYNTHETIC-PROXY-ONLY');
  assert.deepEqual(proxyRequests, ['http://synthetic-proxy.invalid/test-only']);
});

test('Electron downloader preserves NO_PROXY bypass behavior', async () => {
  assert.equal(await get(`http://127.0.0.1:${origin.address().port}/test-only`), 'SYNTHETIC-DIRECT-ONLY');
  assert.equal(proxyRequests.length, 1);
});

test('Electron downloader uses CONNECT for HTTPS and rejects a failed tunnel', async () => {
  await assert.rejects(get('https://synthetic-proxy.invalid/test-only', https));
  assert.deepEqual(tunnelRequests, ['synthetic-proxy.invalid:443']);
});
