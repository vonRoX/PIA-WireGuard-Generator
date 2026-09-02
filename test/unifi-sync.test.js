/**
 * The UniFi automation, exercised offline.
 *
 * The UniFi side is a fake console over a real TLS connection: a self-signed
 * certificate that names a host the test never connects by, which is exactly
 * the situation a factory-fresh gateway puts you in. Pinning that certificate
 * must work, and a different self-signed certificate must be refused — the
 * point of not reaching for `rejectUnauthorized: false`.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpsServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { isBase64Key } from '../resources/js/core/wireguard.js';
import { curlExec } from '../scripts/unifi-sync/exec.mjs';
import { nodeCrypto } from '../scripts/unifi-sync/crypto.mjs';
import { UnifiClient, trustFromPem, csrfTokenFromJwt, parseSetCookie } from '../scripts/unifi-sync/unifi.mjs';
import {
  loadSyncConfig, readCredentials, findWireGuardClient, patchWireGuardClient, describeChanges, syncTunnels,
} from '../scripts/unifi-sync/sync.mjs';
import { hasOpenssl, mintCertificate, mintSelfSignedCertificate, nodeScalarMultBase } from './helpers.js';

const skip = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';

const KEYS = {
  privateKey: 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=',
  publicKey: 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=',
};
const PEER = { peerIp: '10.13.14.15', serverKey: 'sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=', serverIp: '193.176.86.1', serverPort: 1337 };

/** A VPN Client row as a UCG returns it, trimmed to the fields that matter. */
function vpnClientRow(overrides = {}) {
  return {
    _id: '66f1a2b3c4d5e6f7a8b9c0d1',
    site_id: '5f0a0b0c0d0e0f1011121314',
    name: 'WireGuard PIA CZ',
    purpose: 'vpn-client',
    vpn_type: 'wireguard-client',
    enabled: true,
    ip_subnet: '10.20.30.40/32',
    x_wireguard_private_key: 'oldoldoldoldoldoldoldoldoldoldoldoldoldoldA=',
    wireguard_public_key: 'oldpublicoldpublicoldpublicoldpublicoldpuA=',
    wireguard_client_peer_public_key: 'oldserveroldserveroldserveroldserveroldseA=',
    wireguard_client_peer_ip: '203.0.113.9',
    wireguard_client_peer_port: 1337,
    wireguard_client_preshared_key_enabled: false,
    wireguard_client_mode: 'manual',
    vpn_client_default_route: false,
    vpn_client_pull_dns: true,
    route_distance: 30,
    ...overrides,
  };
}

describe('configuration file', () => {
  const good = {
    unifi: { url: 'https://192.168.1.1', certificate: 'console.pem' },
    tunnels: [{ network: 'WireGuard PIA CZ', region: 'czech' }, { network: 'WireGuard US East', region: 'us_east', dns: '1.1.1.1, 9.9.9.9' }],
  };

  test('accepts a minimal file and fills the defaults', () => {
    const config = loadSyncConfig(good, (p) => `/etc/${p}`);

    assert.equal(config.unifi.site, 'default');
    assert.equal(config.unifi.selfHosted, false);
    assert.equal(config.unifi.certificate, '/etc/console.pem');
    assert.equal(config.tunnels[0].dns, '10.0.0.243');
    assert.equal(config.tunnels[1].dns, '1.1.1.1, 9.9.9.9');
  });

  test('refuses a console address that is not https', () => {
    assert.throws(() => loadSyncConfig({ ...good, unifi: { url: 'http://192.168.1.1' } }), /https:\/\//);
  });

  test('refuses an empty tunnel list, a tunnel without a region, and a duplicate name', () => {
    assert.throws(() => loadSyncConfig({ ...good, tunnels: [] }), /non-empty "tunnels"/);
    assert.throws(() => loadSyncConfig({ ...good, tunnels: [{ network: 'x' }] }), /Tunnel #1/);
    assert.throws(() => loadSyncConfig({ ...good, tunnels: [good.tunnels[0], good.tunnels[0]] }), /listed twice/);
  });

  test('validates DNS the same way the app does', () => {
    assert.throws(() => loadSyncConfig({ ...good, dns: 'not-an-ip' }), /not a valid IPv4 address/);
  });
});

describe('credentials', () => {
  test('come from the environment, or from files it names', () => {
    const files = { '/run/secrets/pia': 'hunter2\n' };
    const credentials = readCredentials({
      PIA_USERNAME: 'p1234567', PIA_PASSWORD_FILE: '/run/secrets/pia', UNIFI_API_KEY: 'key',
    }, (path) => {
      if (!(path in files)) throw new Error('ENOENT');
      return files[path];
    });

    assert.equal(credentials.piaPassword, 'hunter2', 'the trailing newline every secrets file has must not become part of the password');
    assert.equal(credentials.unifiApiKey, 'key');
  });

  test('insist on a PIA login and some way into UniFi', () => {
    assert.throws(() => readCredentials({ PIA_USERNAME: 'p' }, () => ''), /PIA_PASSWORD/);
    assert.throws(() => readCredentials({ PIA_USERNAME: 'p', PIA_PASSWORD: 'x' }, () => ''), /UNIFI_API_KEY/);
    assert.throws(() => readCredentials({ PIA_USERNAME: 'p', PIA_PASSWORD: 'x', UNIFI_USERNAME: 'u' }, () => ''), /UNIFI_API_KEY/);
  });

  test('a missing credentials file is reported by name', () => {
    assert.throws(
      () => readCredentials({ PIA_USERNAME_FILE: '/nope' }, () => { throw new Error('ENOENT'); }),
      (err) => err instanceof AppError && err.code === ErrorCode.FILESYSTEM && /PIA_USERNAME_FILE/.test(err.message),
    );
  });
});

describe('finding the VPN Client row', () => {
  const rows = [
    { _id: '1', name: 'Default', purpose: 'corporate' },
    { _id: '2', name: 'PIA CZ', purpose: 'vpn-client', vpn_type: 'openvpn-client' },
    vpnClientRow({ _id: '3', name: 'WireGuard PIA CZ' }),
    vpnClientRow({ _id: '4', name: 'WireGuard US East' }),
  ];

  test('matches by the name shown in the console', () => {
    assert.equal(findWireGuardClient(rows, 'WireGuard US East')._id, '4');
  });

  test('explains what exists when the name is unknown', () => {
    assert.throws(() => findWireGuardClient(rows, 'WireGuard PIA UK'),
      /"WireGuard PIA CZ", "WireGuard US East"/);
  });

  test('refuses to touch a row that is not a WireGuard client', () => {
    assert.throws(() => findWireGuardClient(rows, 'PIA CZ'), /openvpn-client VPN client/);
    assert.throws(() => findWireGuardClient(rows, 'Default'), /"corporate" network/);
  });
});

describe('patching the row', () => {
  test('replaces exactly the registration fields and nothing else', () => {
    const before = vpnClientRow();
    const after = patchWireGuardClient(before, { keys: KEYS, peer: PEER, config: '[Interface]…', regionId: 'czech' });

    assert.equal(after.x_wireguard_private_key, KEYS.privateKey);
    assert.equal(after.wireguard_public_key, KEYS.publicKey);
    assert.equal(after.wireguard_client_peer_public_key, PEER.serverKey);
    assert.equal(after.wireguard_client_peer_ip, PEER.serverIp);
    assert.equal(after.wireguard_client_peer_port, PEER.serverPort);
    assert.equal(after.ip_subnet, '10.13.14.15/32');

    for (const key of ['_id', 'site_id', 'name', 'enabled', 'vpn_client_default_route', 'vpn_client_pull_dns', 'route_distance', 'wireguard_client_preshared_key_enabled']) {
      assert.deepEqual(after[key], before[key], `${key} must survive untouched`);
    }
    assert.ok(!('wireguard_client_configuration_file' in after), 'a manual row must not grow a file');
    assert.deepEqual(before, vpnClientRow(), 'the input row must not be mutated');
  });

  test('a row created from an uploaded file gets the new file too', () => {
    const before = vpnClientRow({
      wireguard_client_mode: 'file',
      wireguard_client_configuration_file: '[Interface]\nPrivateKey = old\n',
      wireguard_client_configuration_filename: 'PIA-czech.conf',
    });
    const after = patchWireGuardClient(before, { keys: KEYS, peer: PEER, config: '[Interface]\nPrivateKey = new\n', regionId: 'czech' });

    assert.equal(after.wireguard_client_configuration_file, '[Interface]\nPrivateKey = new\n');
    assert.equal(after.wireguard_client_configuration_filename, 'PIA-czech.conf');
  });

  test('a row missing the WireGuard fields is left alone, with the schema reported', () => {
    const stranger = { _id: 'abc', name: 'x', purpose: 'vpn-client', vpn_type: 'wireguard-client', ip_subnet: '1.2.3.4/32' };

    assert.throws(() => patchWireGuardClient(stranger, { keys: KEYS, peer: PEER, config: '', regionId: 'czech' }),
      (err) => err instanceof AppError && err.code === ErrorCode.PROTOCOL &&
        /missing: wireguard_client_peer_public_key, wireguard_client_peer_ip, wireguard_client_peer_port/.test(err.detail));
  });

  test('the change report names secrets without printing them', () => {
    const before = vpnClientRow();
    const after = patchWireGuardClient(before, { keys: KEYS, peer: PEER, config: '', regionId: 'czech' });
    const report = describeChanges(before, after).join('\n');

    assert.match(report, /x_wireguard_private_key \(redacted\)/);
    assert.doesNotMatch(report, new RegExp(KEYS.privateKey.replace(/\+/g, '\\+')));
    assert.match(report, /wireguard_client_peer_ip: "203\.0\.113\.9" → "193\.176\.86\.1"/);
  });
});

describe('the Node crypto provider', () => {
  test('derives the same public key as the app would', () => {
    const secret = nodeCrypto.randomBytes(32);
    assert.equal(secret.length, 32);
    assert.deepEqual(nodeCrypto.scalarMultBase(secret), nodeScalarMultBase(secret));
  });
});

describe('the curl runner', () => {
  test('runs only the two commands the network layer issues', async () => {
    await assert.rejects(curlExec('curl -q --config - --insecure'), /unexpected command/);
    await assert.rejects(curlExec('rm -rf /'), /unexpected command/);
  });

  test('reports the curl version without a shell', async () => {
    const result = await curlExec('curl --version');
    assert.equal(result.exitCode, 0);
    assert.match(result.stdOut, /^curl \d+\.\d+/);
  });
});

describe('UniFi OS session plumbing', () => {
  test('reads the CSRF token out of the session JWT', () => {
    const payload = Buffer.from(JSON.stringify({ userId: 'u', csrfToken: 'csrf-123' })).toString('base64url');
    assert.equal(csrfTokenFromJwt(`eyJhbGciOiJIUzI1NiJ9.${payload}.sig`), 'csrf-123');
    assert.equal(csrfTokenFromJwt('not-a-jwt'), '');
    assert.equal(csrfTokenFromJwt('a.bm90IGpzb24.c'), '');
  });

  test('keeps only the name=value part of each cookie', () => {
    const cookies = parseSetCookie(['TOKEN=abc.def.ghi; path=/; HttpOnly; Secure', 'other=1']);
    assert.equal(cookies.get('TOKEN'), 'abc.def.ghi');
    assert.equal(cookies.get('other'), '1');
  });

  test('a certificate file with no PEM in it is rejected', () => {
    assert.throws(() => trustFromPem('nothing here'), /no PEM certificate/);
  });

  test('the console address must be https', () => {
    assert.throws(() => new UnifiClient({ url: 'http://192.168.1.1' }), /https:\/\//);
  });
});

describe('against a fake console over TLS', { skip }, () => {
  let cert;
  let rogueCert;
  let server;
  let rogue;
  let trust;
  let state;

  const CSRF = 'csrf-from-jwt';
  const JWT = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ csrfToken: CSRF })).toString('base64url')}.sig`;

  /** Something like what a UCG Ultra does. */
  function consoleHandler(req, res) {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      state.requests.push({ method: req.method, url: req.url, headers: req.headers, body });

      const json = (status, payload, headers = {}) => {
        res.writeHead(status, { 'content-type': 'application/json', ...headers });
        res.end(JSON.stringify(payload));
      };

      if (req.method === 'POST' && req.url === '/api/auth/login') {
        const { username, password } = JSON.parse(body);
        if (username === 'mfa') return json(499, { code: 'MFA_AUTH_REQUIRED' });
        if (username !== 'sync' || password !== 'secret') return json(401, { code: 'AUTHENTICATION_FAILED' });
        return json(200, { unique_id: 'u1' }, { 'set-cookie': [`TOKEN=${JWT}; path=/; HttpOnly; Secure`] });
      }

      const authed = (req.headers.cookie || '').includes(`TOKEN=${JWT}`) || req.headers['x-api-key'] === 'api-key-1';
      if (!authed) return json(401, { meta: { rc: 'error', msg: 'api.err.LoginRequired' }, data: [] });

      if (req.method === 'GET' && req.url === '/proxy/network/api/s/default/rest/networkconf') {
        return json(200, { meta: { rc: 'ok' }, data: state.rows });
      }

      const put = /^\/proxy\/network\/api\/s\/default\/rest\/networkconf\/([A-Za-z0-9]+)$/.exec(req.url);
      if (req.method === 'PUT' && put) {
        if (!req.headers['x-api-key'] && req.headers['x-csrf-token'] !== CSRF) {
          return json(401, { meta: { rc: 'error', msg: 'api.err.CsrfTokenInvalid' }, data: [] });
        }
        const index = state.rows.findIndex((row) => row._id === put[1]);
        if (index === -1) return json(400, { meta: { rc: 'error', msg: 'api.err.IdInvalid' }, data: [] });
        state.rows[index] = JSON.parse(body);
        return json(200, { meta: { rc: 'ok' }, data: [state.rows[index]] });
      }

      json(404, { meta: { rc: 'error', msg: 'api.err.NotFound' }, data: [] });
    });
  }

  before(async () => {
    // Self-signed, with a name the test never connects by — just like the
    // factory certificate on a console you reach as 192.168.1.1.
    cert = mintSelfSignedCertificate('ucg-ultra.local');
    rogueCert = mintSelfSignedCertificate('ucg-ultra.local');

    server = createHttpsServer({ key: cert.key, cert: cert.cert }, consoleHandler);
    rogue = createHttpsServer({ key: rogueCert.key, cert: rogueCert.cert }, consoleHandler);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    await new Promise((resolve) => rogue.listen(0, '127.0.0.1', resolve));

    // What a user exports from the browser: the console's own (self-signed) certificate.
    trust = trustFromPem(cert.cert);
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await new Promise((resolve) => rogue.close(resolve));
    cert?.cleanUp();
    rogueCert?.cleanUp();
  });

  function freshState() {
    state = { requests: [], rows: [{ _id: 'aaa111', name: 'Default', purpose: 'corporate' }, vpnClientRow({ _id: 'bbb222' }), vpnClientRow({ _id: 'ccc333', name: 'WireGuard US East' })] };
  }

  function client(extra = {}) {
    return new UnifiClient({ url: `https://127.0.0.1:${server.address().port}`, trust, ...extra });
  }

  test('signs in, harvests the session and CSRF token, reads and writes a row', async () => {
    freshState();
    const unifi = client();
    await unifi.login('sync', 'secret');

    assert.equal(unifi.csrfToken, CSRF, 'the CSRF token must be recovered from the JWT when no header carries it');

    const rows = await unifi.listNetworks();
    assert.equal(rows.length, 3);

    const updated = await unifi.updateNetwork('bbb222', { ...rows[1], wireguard_client_peer_ip: '198.51.100.7' });
    assert.equal(updated.wireguard_client_peer_ip, '198.51.100.7');
    assert.equal(state.rows[1].wireguard_client_peer_ip, '198.51.100.7');

    const put = state.requests.find((r) => r.method === 'PUT');
    assert.match(put.headers.cookie, /TOKEN=/);
    assert.equal(put.headers['x-csrf-token'], CSRF);
  });

  test('an API key replaces the sign-in entirely', async () => {
    freshState();
    const unifi = client({ apiKey: 'api-key-1' });

    const rows = await unifi.listNetworks();
    assert.equal(rows.length, 3);
    assert.equal(state.requests[0].headers['x-api-key'], 'api-key-1');
    assert.ok(!state.requests.some((r) => r.url === '/api/auth/login'));
  });

  test('bad credentials and MFA-protected accounts are explained, not retried', async () => {
    freshState();
    await assert.rejects(client().login('sync', 'wrong'), (err) => err.code === ErrorCode.AUTH && /rejected those credentials/.test(err.message));
    await assert.rejects(client().login('mfa', 'secret'), (err) => err.code === ErrorCode.AUTH && /multi-factor/.test(err.message));
  });

  test('a rejected write surfaces the console\'s own message', async () => {
    freshState();
    const unifi = client({ apiKey: 'api-key-1' });
    await assert.rejects(unifi.updateNetwork('zzz999', {}), /api\.err\.IdInvalid/);
  });

  test('the pinned certificate is trusted whatever name it carries — and only that certificate', async () => {
    freshState();
    // Same host name, same address family, different self-signed certificate: refused.
    const impostor = new UnifiClient({ url: `https://127.0.0.1:${rogue.address().port}`, trust, apiKey: 'api-key-1' });
    await assert.rejects(impostor.listNetworks(), (err) => err instanceof AppError && err.code === ErrorCode.TLS);
    assert.equal(state.requests.length, 0, 'nothing may reach an unverified server');

    // No trust file at all: the system store does not know a self-signed console either.
    const unpinned = new UnifiClient({ url: `https://127.0.0.1:${server.address().port}`, apiKey: 'api-key-1' });
    await assert.rejects(unpinned.listNetworks(), (err) => err instanceof AppError && err.code === ErrorCode.TLS);
  });

  test('a certificate from a private CA works when the file carries the issuer too', async () => {
    freshState();
    const issued = mintCertificate('ucg-ultra.local');
    const issuedServer = createHttpsServer({ key: issued.key, cert: issued.cert }, consoleHandler);
    await new Promise((resolve) => issuedServer.listen(0, '127.0.0.1', resolve));

    try {
      const url = `https://127.0.0.1:${issuedServer.address().port}`;

      // Leaf alone: the chain cannot be built, so it is refused.
      const leafOnly = new UnifiClient({ url, trust: trustFromPem(issued.cert), apiKey: 'api-key-1' });
      await assert.rejects(leafOnly.listNetworks(), (err) => err instanceof AppError && err.code === ErrorCode.TLS);

      // Leaf plus issuer: verified, and the name mismatch is forgiven for that exact leaf.
      const chain = new UnifiClient({ url, trust: trustFromPem(issued.cert + readFileSync(issued.caPath, 'utf8')), apiKey: 'api-key-1' });
      assert.equal((await chain.listNetworks()).length, 3);
    } finally {
      await new Promise((resolve) => issuedServer.close(resolve));
      issued.cleanUp();
    }
  });

  test('the whole sync, end to end, writes both tunnels and reports what changed', async () => {
    freshState();
    const unifi = client({ apiKey: 'api-key-1' });

    const addKeyCalls = [];
    const pia = {
      async login(username, password) {
        assert.equal(username, 'p1234567');
        assert.equal(password, 'pw');
        return 'tok';
      },
      async fetchRegions() {
        return [
          { id: 'czech', name: 'Czech Republic', country: 'CZ', portForward: true, geo: false, servers: [{ ip: '185.216.35.1', cn: 'prague401' }] },
          { id: 'us_east', name: 'US East', country: 'US', portForward: false, geo: false, servers: [{ ip: '84.239.14.1', cn: 'newyork402' }] },
        ];
      },
      async addKey({ token, publicKey, server }) {
        assert.equal(token, 'tok');
        assert.ok(isBase64Key(publicKey));
        addKeyCalls.push(server.cn);
        return { peerIp: `10.${addKeyCalls.length}.0.2`, serverKey: PEER.serverKey, serverIp: server.ip, serverPort: 1337 };
      },
    };

    const config = loadSyncConfig({
      unifi: { url: `https://127.0.0.1:${server.address().port}` },
      tunnels: [
        { network: 'WireGuard PIA CZ', region: 'czech' },
        { network: 'WireGuard US East', region: 'us_east' },
        { network: 'WireGuard PIA UK', region: 'uk_london' },
      ],
    });

    const lines = [];
    const results = await syncTunnels({
      pia, unifi, crypto: nodeCrypto, config, log: (l) => lines.push(l),
      credentials: { piaUsername: 'p1234567', piaPassword: 'pw' },
    });

    assert.deepEqual(results.map((r) => r.ok), [true, true, false]);
    assert.deepEqual(addKeyCalls, ['prague401', 'newyork402']);
    assert.match(results[2].error.message, /No WireGuard VPN Client named "WireGuard PIA UK"/);

    const cz = state.rows.find((r) => r._id === 'bbb222');
    assert.equal(cz.wireguard_client_peer_ip, '185.216.35.1');
    assert.equal(cz.ip_subnet, '10.1.0.2/32');
    assert.ok(isBase64Key(cz.x_wireguard_private_key));
    assert.notEqual(cz.x_wireguard_private_key, vpnClientRow().x_wireguard_private_key);
    assert.equal(cz.route_distance, 30, 'unrelated settings must survive');

    const us = state.rows.find((r) => r._id === 'ccc333');
    assert.equal(us.wireguard_client_peer_ip, '84.239.14.1');

    const joined = lines.join('\n');
    assert.doesNotMatch(joined, /tok|pw|api-key-1/, 'the log must not carry credentials');
  });

  test('a dry run registers with PIA but writes nothing', async () => {
    freshState();
    const unifi = client({ apiKey: 'api-key-1' });
    const pia = {
      async login() { return 'tok'; },
      async fetchRegions() {
        return [{ id: 'czech', name: 'Czech Republic', country: 'CZ', portForward: true, geo: false, servers: [{ ip: '185.216.35.1', cn: 'prague401' }] }];
      },
      async addKey() { return { ...PEER }; },
    };
    const config = loadSyncConfig({ unifi: { url: 'https://unused.invalid' }, tunnels: [{ network: 'WireGuard PIA CZ', region: 'czech' }] });

    const results = await syncTunnels({ pia, unifi, crypto: nodeCrypto, config, dryRun: true, credentials: { piaUsername: 'p', piaPassword: 'p' } });

    assert.equal(results[0].ok, true);
    assert.ok(results[0].changes.some((c) => c.startsWith('x_wireguard_private_key (redacted)')));
    assert.ok(!state.requests.some((r) => r.method === 'PUT'), 'no PUT on a dry run');
  });
});

describe('the CLI', () => {
  const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

  test('prints usage and exits 2 without --config', () => {
    const result = spawnCli([]);
    assert.equal(result.status, 2);
    assert.match(result.stdout, /Usage:/);
  });

  test('rejects an unknown flag before touching the network', () => {
    const result = spawnCli(['--config', 'x.json', '--bogus']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Unknown argument: --bogus/);
  });

  test('the example configuration is valid', () => {
    const example = JSON.parse(readFileSync(join(ROOT, 'examples', 'pia-unifi-sync.example.json'), 'utf8'));
    const config = loadSyncConfig(example);
    assert.equal(config.tunnels.length, 2);
  });

  function spawnCli(args) {
    try {
      const stdout = execFileSync(process.execPath, [join(ROOT, 'scripts', 'pia-unifi-sync.mjs'), ...args], {
        encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PIA_USERNAME: '', PIA_PASSWORD: '' },
      });
      return { status: 0, stdout, stderr: '' };
    } catch (err) {
      return { status: err.status, stdout: err.stdout || '', stderr: err.stderr || '' };
    }
  }
});
