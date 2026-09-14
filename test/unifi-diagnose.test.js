import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { probeRead, probeWrite, formatDiagnosis, describeRowFields } from '../scripts/unifi-sync/diagnose.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * A stand-in for UnifiClient. `probeRead` touches only `send`, `networkBase`,
 * `cookies` and `csrfToken`, so nothing here needs a socket.
 */
function fakeClient({
  headers = {}, body = '{"meta":{"rc":"ok"},"data":[]}', status = 200,
  cookies = [], csrfToken = '', derivesCsrf = '',
} = {}) {
  return {
    networkBase: '/proxy/network/api',
    cookies: new Map(cookies),
    csrfToken,
    sent: [],
    async send(request) {
      this.sent.push(request);
      // The real client harvests cookies and the CSRF token inside `send`, so
      // anything it learns from this response appears only after the call.
      if (derivesCsrf) this.csrfToken = derivesCsrf;
      return { status, headers, body };
    },
    async updateNetwork(id, entry) {
      this.updated = { id, entry };
      return entry;
    },
  };
}

describe('the console diagnosis', () => {
  describe('reading', () => {
    it('asks for the site the configuration names, url-encoded', async () => {
      const unifi = fakeClient();
      await probeRead(unifi, 'my site');

      assert.equal(unifi.sent.length, 1);
      assert.equal(unifi.sent[0].method, 'GET');
      assert.equal(unifi.sent[0].path, '/proxy/network/api/s/my%20site/rest/networkconf');
      assert.equal(unifi.sent[0].authenticated, true);
    });

    it('reports a cookie the app would not be able to see', async () => {
      const unifi = fakeClient({
        headers: { 'set-cookie': ['TOKEN=abc; Path=/; HttpOnly'], 'content-type': 'application/json' },
      });
      unifi.cookies.set('TOKEN', 'abc');

      const read = await probeRead(unifi, 'default');

      assert.equal(read.setCookie, true);
      assert.deepEqual(read.cookiesHeld, ['TOKEN']);
      assert.deepEqual(read.headerNames, ['content-type', 'set-cookie']);
    });

    it('distinguishes a rotated token from one derived out of the session cookie', async () => {
      const rotated = fakeClient({ headers: { 'x-updated-csrf-token': 'fresh' }, derivesCsrf: 'fresh' });
      assert.equal((await probeRead(rotated, 'default')).csrfToken, 'from header');

      // No header carried one, but the client dug it out of the session cookie.
      const derived = fakeClient({ headers: {}, derivesCsrf: 'out-of-the-jwt' });
      assert.equal((await probeRead(derived, 'default')).csrfToken, 'derived');

      // Held from an earlier request and unchanged by this one.
      const held = fakeClient({ headers: {}, csrfToken: 'from-before' });
      assert.equal((await probeRead(held, 'default')).csrfToken, 'already held');

      const none = fakeClient({ headers: {} });
      assert.equal((await probeRead(none, 'default')).csrfToken, 'none');
    });

    it('survives a body that is not JSON', async () => {
      const unifi = fakeClient({ status: 502, body: '<html>gateway</html>' });
      const read = await probeRead(unifi, 'default');

      assert.equal(read.status, 502);
      assert.deepEqual(read.rows, []);
    });

    it('counts only VPN Client rows', async () => {
      const unifi = fakeClient({
        body: JSON.stringify({
          meta: { rc: 'ok' },
          data: [
            { _id: 'a', purpose: 'vpn-client', name: 'CZ' },
            { _id: 'b', purpose: 'corporate', name: 'LAN' },
          ],
        }),
      });

      const read = await probeRead(unifi, 'default');
      assert.equal(read.rows.length, 2);
      assert.match(formatDiagnosis({ read }).join('\n'), /vpn-client rows\s+1/);
    });
  });

  describe('the write probe', () => {
    it('sends the row back exactly as it arrived', async () => {
      const unifi = fakeClient();
      const row = { _id: 'abc123', name: 'WireGuard PIA CZ', x_wireguard_private_key: 'secret' };

      const result = await probeWrite(unifi, row);

      assert.deepEqual(result, { ok: true });
      assert.equal(unifi.updated.id, 'abc123');
      assert.deepEqual(unifi.updated.entry, row, 'the probe must not alter the row it writes back');
    });

    it('refuses to write a row whose secret came back masked', async () => {
      const unifi = fakeClient();
      const result = await probeWrite(unifi, { _id: 'abc', wireguard_client_preshared_key: '*'.repeat(44) });

      assert.equal(result.ok, false);
      assert.match(result.error.message, /would replace the real value with the mask/);
      assert.equal(unifi.updated, undefined, 'and nothing may be sent — that is the point');
    });

    it('reports a refusal instead of throwing, so one row does not end the run', async () => {
      const unifi = fakeClient();
      unifi.updateNetwork = async () => {
        throw new AppError(ErrorCode.AUTH, 'The UniFi console refused the request.');
      };

      const result = await probeWrite(unifi, { _id: 'abc123' });

      assert.equal(result.ok, false);
      assert.equal(result.error.code, ErrorCode.AUTH);
    });

    it('wraps a non-AppError so the report always has a message', async () => {
      const unifi = fakeClient();
      unifi.updateNetwork = async () => { throw new TypeError('socket hang up'); };

      const result = await probeWrite(unifi, { _id: 'abc123' });

      assert.equal(result.ok, false);
      assert.ok(result.error instanceof AppError);
      assert.match(result.error.message, /write probe failed/i);
    });
  });

  describe('describing a row', () => {
    const row = {
      _id: 'abc', name: 'WireGuard PIA CZ', purpose: 'vpn-client', vpn_type: 'wireguard-client',
      enabled: true, ip_subnet: '10.1.2.3/32', wireguard_client_mode: 'manual',
      wireguard_client_peer_public_key: 'k', wireguard_client_peer_ip: '1.2.3.4',
      wireguard_client_peer_port: 1337, wireguard_client_preshared_key_enabled: false,
      x_wireguard_private_key: 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=',
    };

    it('lists field names, because nobody publishes a schema for this', () => {
      const described = describeRowFields(row);

      assert.ok(described.fields.includes('wireguard_client_peer_port'));
      assert.deepEqual(described.fields, [...described.fields].sort(), 'sorted, so two consoles can be compared');
      assert.equal(described.missingRequired.length, 0);
    });

    it('reveals the flags that decide how a row must be written, and no more', () => {
      const revealed = Object.fromEntries(describeRowFields(row).revealed);

      assert.equal(revealed.wireguard_client_mode, '"manual"');
      assert.equal(revealed.wireguard_client_preshared_key_enabled, 'false');
      assert.ok(!('ip_subnet' in revealed), 'an address is not a flag');
    });

    it('reports a secret as present without ever carrying its value', () => {
      const secrets = Object.fromEntries(describeRowFields(row).secrets);

      assert.equal(secrets.x_wireguard_private_key, 'present');
      assert.doesNotMatch(JSON.stringify(describeRowFields(row)), /yAnz5TF/, 'the key must not appear anywhere');
    });

    it('tells a mask apart from a key, which is the whole point', () => {
      const cases = [
        ['*'.repeat(44), 'looks redacted'],
        ['••••••••', 'looks redacted'],
        ['', 'absent'],
        [undefined, 'absent'],
        ['yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=', 'present'],
      ];

      for (const [value, expected] of cases) {
        const secrets = Object.fromEntries(describeRowFields({ ...row, x_wireguard_private_key: value }).secrets);
        assert.equal(secrets.x_wireguard_private_key, expected, `${JSON.stringify(value)} should read as ${expected}`);
      }
    });

    it('names the fields the sync needs but the row does not have', () => {
      const without = { ...row };
      delete without.wireguard_client_peer_port;

      assert.deepEqual(describeRowFields(without).missingRequired, ['wireguard_client_peer_port']);
    });
  });

  describe('the report', () => {
    const cleanRead = {
      status: 200, headerNames: ['content-type'], setCookie: false,
      cookiesHeld: [], csrfToken: 'none', rows: [],
    };

    it('says plainly when nothing blocks the port', () => {
      const report = formatDiagnosis({
        certificate: { subject: 'CN=unifi', issuer: 'CN=ui-ca', selfSigned: false, ca: true, names: 'DNS:unifi.local', fingerprint: 'AA:BB' },
        read: cleanRead,
      }).join('\n');

      assert.match(report, /Nothing here blocks the port/);
    });

    it('names a session cookie as a blocker', () => {
      const report = formatDiagnosis({
        read: { ...cleanRead, setCookie: true, cookiesHeld: ['TOKEN'] },
      }).join('\n');

      assert.match(report, /the console sets a cookie/);
      assert.doesNotMatch(report, /Nothing here blocks/);
    });

    it('names a refused write as a blocker', () => {
      const report = formatDiagnosis({
        read: cleanRead,
        writes: [{ name: 'WireGuard PIA CZ', result: { ok: false, error: new AppError(ErrorCode.AUTH, 'refused') } }],
      }).join('\n');

      assert.match(report, /REFUSED/);
      assert.match(report, /does not authorise a write/);
    });

    it('flags a self-signed leaf, which is the certificate Windows may refuse', () => {
      const report = formatDiagnosis({
        certificate: { subject: 'CN=ucg', issuer: 'CN=ucg', selfSigned: true, ca: false, names: 'DNS:ucg', fingerprint: 'AA' },
        read: cleanRead,
      }).join('\n');

      assert.match(report, /CA:TRUE\s+no/);
      assert.match(report, /self-signed leaf/);
    });

    it('does not flag a self-signed certificate that is a usable anchor', () => {
      const report = formatDiagnosis({
        certificate: { subject: 'CN=ucg', issuer: 'CN=ucg', selfSigned: true, ca: true, names: 'DNS:ucg', fingerprint: 'AA' },
        read: cleanRead,
      }).join('\n');

      assert.doesNotMatch(report, /self-signed leaf/);
    });

    it('reports a certificate that could not be read without losing the rest', () => {
      const report = formatDiagnosis({
        certificateError: new AppError(ErrorCode.NETWORK, 'Could not reach the console.'),
        read: cleanRead,
      }).join('\n');

      assert.match(report, /could not be read: Could not reach the console/);
      assert.match(report, /Read \(GET rest\/networkconf\)/);
    });

    it('describes each configured row, and says which are missing', () => {
      const report = formatDiagnosis({
        read: {
          ...cleanRead,
          rows: [{ _id: 'a', name: 'WireGuard PIA CZ', purpose: 'vpn-client', wireguard_client_mode: 'file' }],
        },
        tunnels: ['WireGuard PIA CZ', 'WireGuard US East'],
      }).join('\n');

      assert.match(report, /Row "WireGuard PIA CZ"/);
      assert.match(report, /wireguard_client_mode\s+"file"/);
      assert.match(report, /Row "WireGuard US East"\n\s+the console returned no row with this name/);
      assert.match(report, /missing fields this tool needs:/, 'that row carries none of them');
    });

    it('a masked preshared key is a blocker; a masked private key is not', () => {
      const base = { _id: 'a', name: 'CZ', purpose: 'vpn-client' };

      const privateOnly = formatDiagnosis({
        read: { ...cleanRead, rows: [{ ...base, x_wireguard_private_key: '****' }] },
        tunnels: ['CZ'],
      }).join('\n');
      assert.match(privateOnly, /a real refresh replaces this field/);

      const preshared = formatDiagnosis({
        read: { ...cleanRead, rows: [{ ...base, wireguard_client_preshared_key: '****' }] },
        tunnels: ['CZ'],
      }).join('\n');
      assert.match(preshared, /a refresh would erase it/);
      assert.match(preshared, /masks wireguard_client_preshared_key on read/);
    });

    it('lists header names but never header values', () => {
      const report = formatDiagnosis({
        read: {
          ...cleanRead,
          headerNames: ['content-type', 'set-cookie', 'x-csrf-token'],
          setCookie: true,
          cookiesHeld: ['TOKEN'],
        },
      }).join('\n');

      assert.match(report, /set-cookie/, 'the name is what makes the report useful');
      assert.doesNotMatch(report, /TOKEN=/, 'a cookie value must never be printed');
      assert.doesNotMatch(report, /eyJ/, 'nor any part of a JWT');
    });
  });
});

describe('the Windows launcher', () => {
  const launcher = readFileSync(join(ROOT, 'scripts', 'pia-unifi-sync.cmd'), 'utf8');

  /**
   * Batch comments explain the rules below, so they mention the very strings
   * those rules forbid. Strip them first, exactly as `guards.test.js` does for
   * JavaScript.
   */
  const code = launcher
    .split(/\r?\n/)
    .filter((line) => !/^\s*(?:rem\b|::)/i.test(line))
    .join('\n');

  it('does not enable delayed expansion, which would eat a "!" in a password', () => {
    assert.doesNotMatch(code, /enabledelayedexpansion/i);
  });

  it('never echoes a credential', () => {
    assert.match(launcher, /^@echo off/m, 'without @echo off every `set` prints its value');
    for (const name of ['PIA_PASSWORD', 'UNIFI_API_KEY', 'UNIFI_PASSWORD']) {
      assert.doesNotMatch(code, new RegExp(`echo[^\\r\\n]*%${name}%`, 'i'), `${name} must not be echoed`);
    }
  });

  it('passes no credential on the command line', () => {
    const nodeInvocation = /node\s+"%ENTRY%"[^\r\n]*/.exec(code);
    assert.ok(nodeInvocation, 'the launcher must invoke the entry point');
    assert.doesNotMatch(nodeInvocation[0], /PIA_|UNIFI_/, 'credentials travel in the environment, not argv');
  });

  it('resolves its paths from its own location, not the working directory', () => {
    assert.match(code, /set "SCRIPT_DIR=%~dp0"/);
    assert.doesNotMatch(code, /set "REPO_ROOT=\.\./, 'a relative root breaks when launched from elsewhere');
  });

  it('defaults to a dry run and only writes when asked', () => {
    assert.match(code, /set "ARGS=--dry-run"/);
    assert.match(code, /"%~1"=="--apply"/i);
  });
});
