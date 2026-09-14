/**
 * The engine end to end: a temp store directory, in-memory secrets, and a fake
 * console on 127.0.0.1. Nothing here touches %LOCALAPPDATA% or the LAN.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';

import { createEngine, validateExplorePath, toTunnel } from '../scripts/engine/engine.mjs';
import { KEY_REJECTED_HINT } from '../scripts/engine/console.mjs';
import { startTlsServer, mintSelfSignedLeaf, hasOpenssl } from './helpers.js';

const skip = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';

const GOOD_KEY = 'local-integration-key-0001';
const BAD_KEY = 'site-manager-key-from-unifi-ui-com';
const PIA_PASSWORD = 'pia-password-never-shown';
const PRIVATE_KEY = 'cmVhbC1sb29raW5nLXByaXZhdGUta2V5LWZvci10ZXN0cw==';
const NOW = new Date('2026-09-14T12:00:00Z');

const vpnRows = [
  { _id: 'aaa111', name: 'Default', purpose: 'corporate' },
  {
    _id: 'bbb222', name: 'PIA Czech', purpose: 'vpn-client', vpn_type: 'wireguard-client', enabled: true,
    wireguard_client_mode: 'file',
    wireguard_client_configuration_file: `[Interface]\nPrivateKey = ${PRIVATE_KEY}\nAddress = 10.7.0.2/32\n`,
    x_wireguard_private_key: PRIVATE_KEY,
  },
  { _id: 'ccc333', name: 'PIA US', purpose: 'vpn-client', vpn_type: 'wireguard-client', wireguard_client_mode: 'manual', enabled: false },
  { _id: 'ddd444', name: 'Odd', purpose: 'vpn-client', vpn_type: 'openvpn-client' },
];

function consoleHandler(req) {
  if (req.headers['x-api-key'] !== GOOD_KEY) {
    return { status: 401, body: JSON.stringify({ error: { code: 401, message: 'Unauthorized' } }) };
  }
  switch (req.url) {
    case '/proxy/network/integration/v1/info':
      return { status: 200, body: JSON.stringify({ applicationVersion: '10.0.162' }) };
    case '/proxy/network/api/s/default/rest/networkconf':
      return { status: 200, body: JSON.stringify({ meta: { rc: 'ok' }, data: vpnRows }) };
    case '/proxy/network/v2/api/site/default/vpn/connections':
      return {
        status: 200,
        body: JSON.stringify({
          connections: [
            { network_id: 'bbb222', status: 'CONNECTING', type: 'wireguard', notes: ['CONNECTING_LONGER_THAN_USUAL'] },
            { network_id: 'zzz999', status: 'CONNECTED', type: 'wireguard' },
          ],
        }),
      };
    default:
      return { status: 404, body: JSON.stringify({ meta: { rc: 'error', msg: 'api.err.NotFound' } }) };
  }
}

/** Stands in for the DPAPI store; records what was written. */
function memorySecrets() {
  const values = { piaUsername: '', piaPassword: '', unifiApiKey: '' };
  const writes = [];
  return {
    values,
    writes,
    protected: 0,
    async read() { return { ...values }; },
    async write(partial) {
      writes.push(Object.keys(partial));
      for (const [key, value] of Object.entries(partial)) if (value) values[key] = value;
      return { piaUsername: Boolean(values.piaUsername), piaPassword: Boolean(values.piaPassword), unifiApiKey: Boolean(values.unifiApiKey) };
    },
    async clear() { for (const key of Object.keys(values)) values[key] = ''; },
    async status() {
      return { piaUsername: Boolean(values.piaUsername), piaPassword: Boolean(values.piaPassword), unifiApiKey: Boolean(values.unifiApiKey), version: null };
    },
    async protectDirectory() { this.protected += 1; },
  };
}

const errors = [];
/** Capture every rejection so the last test can check none carried a secret. */
async function rejects(promise, code) {
  await assert.rejects(promise, (err) => {
    errors.push(err);
    assert.equal(err.code, code, `${err.code}: ${err.message}`);
    return true;
  });
}

test('explore path validation', () => {
  const ok = ['/proxy/network/integration/v1/info', '/proxy/network/api/s/default/rest/networkconf', '/proxy/network/v2/api/site/default/vpn/connections?limit=5'];
  for (const path of ok) assert.equal(validateExplorePath(path), path);

  const bad = [
    '/proxy/network/../x', '/proxy/network/api/..', '/api/..', '//evil', 'https://x', 'https://x/proxy/network/',
    '/proxy/network//evil.example/x', '/proxy/networkx/', '/proxy/network', '/api/s/default/rest/networkconf',
    '/proxy/network/%2e%2e/x', '/proxy/network/a%2Fb', '/proxy/network/a\\b', '/proxy/network/a b', '/proxy/network/a\r\nHost: x',
    '/proxy/network/#x', '', null, 5, `/proxy/network/${'a'.repeat(3000)}`,
  ];
  for (const path of bad) {
    assert.throws(() => validateExplorePath(path), (err) => err.code === 'INVALID_INPUT', JSON.stringify(path));
  }
});

test('toTunnel maps a row and its connection', () => {
  const statuses = new Map([['x1', { network_id: 'x1', status: 'CONNECTED', notes: ['A', 5] }]]);
  assert.deepEqual(toTunnel({ _id: 'x1', name: 'T', wireguard_client_mode: 'file' }, statuses),
    { id: 'x1', name: 'T', mode: 'file', enabled: true, status: 'CONNECTED', notes: ['A'] });
  assert.deepEqual(toTunnel({ _id: 'x2', enabled: false }, statuses),
    { id: 'x2', name: '', mode: 'unknown', enabled: false, status: null, notes: [] });
});

describe('engine against a fake console', { skip }, () => {
  let leaf;
  let otherLeaf;
  let server;
  let impostor;
  let root;
  let storeDir;
  let secrets;
  let engine;
  let url;
  let fingerprint;

  before(async () => {
    leaf = mintSelfSignedLeaf('unifi.local');
    otherLeaf = mintSelfSignedLeaf('unifi.local');
    server = await startTlsServer(leaf, consoleHandler);
    impostor = await startTlsServer(otherLeaf, consoleHandler);
    root = mkdtempSync(join(tmpdir(), 'engine-core-'));
    storeDir = join(root, 'pia-unifi-sync');
    secrets = memorySecrets();
    engine = createEngine({ storeDir, secrets, now: () => NOW, timeoutMs: 5000 });
    url = `https://127.0.0.1:${server.port}`;
    fingerprint = new X509Certificate(leaf.cert).fingerprint256;
  });

  after(async () => {
    if (server) await server.close();
    if (impostor) await impostor.close();
    leaf?.cleanUp();
    otherLeaf?.cleanUp();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  test('starts unconfigured, and says so', async () => {
    assert.deepEqual(await engine.getState(), { console: null, unifiKey: { stored: false }, pia: { stored: false } });
    await rejects(engine.setUnifiKey(GOOD_KEY), 'NOT_CONFIGURED');
    await rejects(engine.explore('/proxy/network/integration/v1/info'), 'NOT_CONFIGURED');
    await rejects(engine.listTunnels(), 'NOT_CONFIGURED');
    assert.equal(server.requests.length, 0);
    assert.equal(secrets.writes.length, 0);
  });

  test('inspectConsole describes the certificate and stores nothing', async () => {
    const result = await engine.inspectConsole(`127.0.0.1:${server.port}`);
    assert.equal(result.url, url);
    assert.equal(result.certificate.fingerprint256, fingerprint);
    assert.equal(result.certificate.connectName, 'unifi.local');
    assert.equal(existsSync(join(storeDir, 'console.json')), false);
    assert.equal(server.requests.length, 0);
    await rejects(engine.inspectConsole('http://127.0.0.1'), 'INVALID_INPUT');
  });

  test('trustConsole refuses a fingerprint the console no longer presents', async () => {
    const stale = new X509Certificate(otherLeaf.cert).fingerprint256;
    await rejects(engine.trustConsole(url, stale), 'CERT_CHANGED');
    await rejects(engine.trustConsole(url, 'not-a-fingerprint'), 'INVALID_INPUT');
    assert.equal(existsSync(join(storeDir, 'console.json')), false);
  });

  test('trustConsole stores the pin and reports it', async () => {
    const state = await engine.trustConsole(url, fingerprint.replace(/:/g, '').toLowerCase());
    assert.deepEqual(state.console, { url, site: 'default', fingerprint256: fingerprint, connectName: 'unifi.local', trusted: true });
    assert.equal(secrets.protected, 1, 'a folder the engine creates gets the launcher ACL');

    const saved = JSON.parse(readFileSync(join(storeDir, 'console.json'), 'utf8'));
    assert.equal(saved.url, url);
    assert.equal(saved.site, 'default');
    assert.equal(saved.fingerprint256, fingerprint);
    assert.equal(saved.connectName, 'unifi.local');
    assert.equal(new X509Certificate(saved.pem).fingerprint256, fingerprint);
    assert.equal(saved.trustedAt, NOW.toISOString());
    assert.equal(server.requests.length, 0, 'trusting sends nothing');
  });

  test('a rejected key is explained and not stored', async () => {
    await assert.rejects(engine.setUnifiKey(BAD_KEY), (err) => {
      errors.push(err);
      assert.equal(err.code, 'UNIFI_KEY_REJECTED');
      assert.equal(err.hint, KEY_REJECTED_HINT);
      return true;
    });
    assert.equal(secrets.writes.length, 0);
    assert.deepEqual((await engine.getState()).unifiKey, { stored: false });
    await rejects(engine.setUnifiKey('has space'), 'INVALID_INPUT');
    await rejects(engine.setUnifiKey(''), 'INVALID_INPUT');
    await rejects(engine.explore('/proxy/network/integration/v1/info'), 'NOT_CONFIGURED');
  });

  test('a good key is verified, then stored', async () => {
    const before = server.requests.length;
    assert.deepEqual(await engine.setUnifiKey(`  ${GOOD_KEY}\n`), { verified: true, applicationVersion: '10.0.162' });
    assert.equal(server.requests[before].url, '/proxy/network/integration/v1/info');
    assert.deepEqual(secrets.writes, [['unifiApiKey']]);
    assert.equal(secrets.values.unifiApiKey, GOOD_KEY);
    assert.deepEqual((await engine.getState()).unifiKey, { stored: true });
  });

  test('explore validates, sends only valid GETs, and redacts', async () => {
    const before = server.requests.length;
    for (const path of ['/proxy/network/../x', '//evil', 'https://x', '/api/..']) {
      await rejects(engine.explore(path), 'INVALID_INPUT');
    }
    assert.equal(server.requests.length, before, 'an invalid path sends nothing');

    const result = await engine.explore('/proxy/network/api/s/default/rest/networkconf');
    assert.equal(result.status, 200);
    const json = JSON.stringify(result);
    assert.ok(!json.includes(PRIVATE_KEY), 'the private key never leaves the engine');
    assert.equal(result.body.data[1].x_wireguard_private_key, '<redacted>');
    assert.match(result.body.data[1].wireguard_client_configuration_file, /PrivateKey = <redacted>/);

    const missing = await engine.explore('/proxy/network/nothing-here');
    assert.equal(missing.status, 404);
    assert.equal(missing.body.meta.msg, 'api.err.NotFound');

    for (const request of server.requests) {
      assert.equal(request.method, 'GET');
      assert.equal(request.headers.cookie, undefined);
    }
  });

  test('listTunnels merges rows with their status by _id', async () => {
    assert.deepEqual(await engine.listTunnels(), {
      tunnels: [
        { id: 'bbb222', name: 'PIA Czech', mode: 'file', enabled: true, status: 'CONNECTING', notes: ['CONNECTING_LONGER_THAN_USUAL'] },
        { id: 'ccc333', name: 'PIA US', mode: 'manual', enabled: false, status: null, notes: [] },
        { id: 'ddd444', name: 'Odd', mode: 'unknown', enabled: true, status: null, notes: [] },
      ],
    });
  });

  test('PIA credentials are stored and forgotten', async () => {
    await rejects(engine.setPiaCredentials('', PIA_PASSWORD), 'INVALID_INPUT');
    await rejects(engine.setPiaCredentials('p1234567', ''), 'INVALID_INPUT');
    await rejects(engine.setPiaCredentials('p1234567', `${PIA_PASSWORD}\n`), 'INVALID_INPUT');

    const state = await engine.setPiaCredentials(' p1234567 ', PIA_PASSWORD);
    assert.deepEqual(state.pia, { stored: true });
    assert.equal(secrets.values.piaUsername, 'p1234567');

    const forgotten = await engine.forgetCredentials();
    assert.deepEqual(forgotten.unifiKey, { stored: false });
    assert.deepEqual(forgotten.pia, { stored: false });
    assert.equal(forgotten.console.trusted, true, 'forgetting credentials keeps the console pin');
    await rejects(engine.listTunnels(), 'NOT_CONFIGURED');
  });

  test('a console that changed its certificate is CERT_CHANGED on every call, and hears nothing', async () => {
    const dir = join(root, 'moved');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'console.json'), JSON.stringify({
      url: `https://127.0.0.1:${impostor.port}`, site: 'default', fingerprint256: fingerprint, pem: leaf.cert, connectName: 'unifi.local',
    }));
    const moved = memorySecrets();
    moved.values.unifiApiKey = GOOD_KEY;
    const other = createEngine({ storeDir: dir, secrets: moved, timeoutMs: 5000 });

    await rejects(other.listTunnels(), 'CERT_CHANGED');
    await rejects(other.explore('/proxy/network/integration/v1/info'), 'CERT_CHANGED');
    await rejects(other.setUnifiKey(GOOD_KEY), 'CERT_CHANGED');
    assert.equal(impostor.requests.length, 0);
    assert.deepEqual(moved.writes, []);
  });

  test('no error carried a secret', () => {
    assert.ok(errors.length > 10);
    for (const err of errors) {
      const text = JSON.stringify({ message: err.message, hint: err.hint, detail: err.detail });
      for (const secret of [GOOD_KEY, BAD_KEY, PIA_PASSWORD, PRIVATE_KEY]) {
        assert.ok(!text.includes(secret), `${err.code} leaked a secret`);
      }
    }
  });
});
