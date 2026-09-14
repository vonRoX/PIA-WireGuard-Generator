/**
 * The API-key console client against a fake console on 127.0.0.1, presenting
 * a self-signed CA:FALSE leaf the way a UCG Ultra does.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { X509Certificate } from 'node:crypto';

import { createConsoleClient, KEY_REJECTED_HINT } from '../scripts/engine/console.mjs';
import { startTlsServer, mintSelfSignedLeaf, hasOpenssl } from './helpers.js';

const skip = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';
const GOOD_KEY = 'local-integration-key-0001';

const rows = [
  { _id: 'aaa111', name: 'Default', purpose: 'corporate' },
  { _id: 'bbb222', name: 'PIA Czech', purpose: 'vpn-client', vpn_type: 'wireguard-client', wireguard_client_mode: 'file' },
  { _id: 'ccc333', name: 'PIA US', purpose: 'vpn-client', vpn_type: 'wireguard-client', wireguard_client_mode: 'manual' },
];

function handler(req) {
  if (req.headers['x-api-key'] !== GOOD_KEY) {
    return { status: 401, body: JSON.stringify({ error: { code: 401, message: 'Unauthorized' } }) };
  }
  switch (req.url) {
    case '/proxy/network/integration/v1/info':
      return { status: 200, body: JSON.stringify({ applicationVersion: '10.0.162' }) };
    case '/proxy/network/api/s/default/rest/networkconf':
      return { status: 200, body: JSON.stringify({ meta: { rc: 'ok' }, data: rows }) };
    case '/proxy/network/v2/api/site/default/vpn/connections':
      return { status: 200, body: JSON.stringify({ connections: [{ network_id: 'bbb222', status: 'CONNECTED', type: 'wireguard' }] }) };
    case '/proxy/network/not-json':
      return { status: 200, body: '<html>hello</html>', headers: { 'content-type': 'text/html' } };
    default:
      return { status: 404, body: JSON.stringify({ meta: { rc: 'error', msg: 'api.err.NotFound' } }) };
  }
}

describe('console client', { skip }, () => {
  let leaf;
  let otherLeaf;
  let server;
  let impostor;

  before(async () => {
    leaf = mintSelfSignedLeaf('unifi.local');
    otherLeaf = mintSelfSignedLeaf('unifi.local');
    server = await startTlsServer(leaf, handler);
    impostor = await startTlsServer(otherLeaf, handler);
  });

  after(async () => {
    if (server) await server.close();
    if (impostor) await impostor.close();
    leaf?.cleanUp();
    otherLeaf?.cleanUp();
  });

  const client = (overrides = {}) => createConsoleClient({
    url: `https://127.0.0.1:${server.port}`,
    pem: leaf.cert,
    fingerprint256: new X509Certificate(leaf.cert).fingerprint256,
    apiKey: GOOD_KEY,
    timeoutMs: 5000,
    ...overrides,
  });

  test('info, rows and status over the pinned certificate, with the key and no cookie', async () => {
    const unifi = client();
    assert.deepEqual(await unifi.info(), { applicationVersion: '10.0.162' });

    const vpn = await unifi.listVpnClients('default');
    assert.deepEqual(vpn.map((row) => row._id), ['bbb222', 'ccc333']);

    const connections = await unifi.vpnStatus('default');
    assert.equal(connections[0].status, 'CONNECTED');

    for (const request of server.requests) {
      assert.equal(request.method, 'GET');
      assert.equal(request.headers['x-api-key'], GOOD_KEY);
      assert.equal(request.headers.cookie, undefined, 'no cookie handling');
      assert.equal(request.headers['x-csrf-token'], undefined, 'no CSRF handling');
    }
  });

  test('get returns status and raw text, including non-2xx', async () => {
    const unifi = client();
    const missing = await unifi.get('/proxy/network/nope');
    assert.equal(missing.status, 404);
    assert.match(missing.text, /NotFound/);
    const html = await unifi.get('/proxy/network/not-json');
    assert.equal(html.text, '<html>hello</html>');
  });

  test('a 401 is UNIFI_KEY_REJECTED with the Site Manager hint, and the key is in no part of the error', async () => {
    const siteManagerKey = 'site-manager-key-from-unifi-ui-com';
    const unifi = client({ apiKey: siteManagerKey });
    for (const call of [() => unifi.info(), () => unifi.get('/proxy/network/integration/v1/info'), () => unifi.listVpnClients('default')]) {
      await assert.rejects(call(), (err) => {
        assert.equal(err.code, 'UNIFI_KEY_REJECTED');
        assert.equal(err.hint, KEY_REJECTED_HINT);
        assert.match(err.hint, /Settings → Control Plane → Integrations/);
        assert.match(err.hint, /Site Manager key from unifi\.ui\.com does not work here/);
        assert.ok(![err.message, err.hint, err.detail].join(' ').includes(siteManagerKey));
        return true;
      });
    }
  });

  test('a different certificate is CERT_CHANGED, and nothing reaches the impostor', async () => {
    const unifi = client({ url: `https://127.0.0.1:${impostor.port}` });
    await assert.rejects(unifi.info(), (err) => {
      assert.equal(err.code, 'CERT_CHANGED');
      assert.ok(err.hint);
      assert.ok(!JSON.stringify([err.message, err.hint, err.detail]).includes(GOOD_KEY));
      return true;
    });
    assert.equal(impostor.requests.length, 0);
  });

  test('a TLS failure while the same certificate is still presented stays a TLS error', async () => {
    // The impostor fails the pinned handshake, but the re-read is told it saw
    // the trusted certificate — so this is not a certificate change.
    const trustedRaw = new X509Certificate(leaf.cert).raw;
    const connect = (_options, onSecure) => {
      const socket = new EventEmitter();
      socket.setTimeout = () => {};
      socket.destroy = () => {};
      socket.getPeerCertificate = () => ({ raw: trustedRaw });
      setImmediate(onSecure);
      return socket;
    };
    const unifi = client({ url: `https://127.0.0.1:${impostor.port}`, connect });
    await assert.rejects(unifi.info(), (err) => err.code === 'TLS');
  });

  test('site names are identifiers', async () => {
    await assert.rejects(client().listVpnClients('../x'), (err) => err.code === 'INVALID_INPUT');
    await assert.rejects(client().vpnStatus('a/b'), (err) => err.code === 'INVALID_INPUT');
  });
});
