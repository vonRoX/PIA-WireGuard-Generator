import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import {
  probeRead, probeWrite, probeWriteAccess, resolveTunnelRow, formatDiagnosis, describeRowFields,
} from '../scripts/unifi-sync/diagnose.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * A stand-in for UnifiClient. `probeRead` touches only `send`, `networkBase`,
 * `cookies` and `csrfToken`, so nothing here needs a socket.
 */
function fakeClient({
  headers = {}, body = '{"meta":{"rc":"ok"},"data":[]}', status = 200,
  cookies = [], csrfToken = '', derivesCsrf = '', writeError = null,
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
      if (writeError) throw writeError;
      this.updated = { id, entry };
      return entry;
    },
  };
}

/** A WireGuard VPN Client row that is safe to write back unchanged. */
function wireguardRow(overrides = {}) {
  return {
    _id: 'abc123', name: 'WireGuard PIA CZ', purpose: 'vpn-client', vpn_type: 'wireguard-client',
    enabled: true, ip_subnet: '10.1.2.3/32', wireguard_client_mode: 'manual',
    wireguard_client_peer_public_key: 'aZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
    wireguard_client_peer_ip: '1.2.3.4', wireguard_client_peer_port: 1337,
    wireguard_client_preshared_key_enabled: false,
    x_wireguard_private_key: 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=',
    ...overrides,
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
      const row = wireguardRow();

      const result = await probeWrite(unifi, row);

      assert.deepEqual(result, { ok: true, attempted: true });
      assert.equal(unifi.updated.id, 'abc123');
      assert.deepEqual(unifi.updated.entry, row, 'the probe must not alter the row it writes back');
    });

    it('refuses to write a row whose secret came back masked', async () => {
      const unifi = fakeClient();
      const result = await probeWrite(unifi, wireguardRow({ wireguard_client_preshared_key: '*'.repeat(44) }));

      assert.equal(result.ok, false);
      assert.equal(result.attempted, false);
      assert.match(result.error.message, /replace a real value with a mask or a blank/);
      assert.equal(unifi.updated, undefined, 'and nothing may be sent — that is the point');
    });

    it('refuses a secret hidden by any means, not only a run of asterisks', async () => {
      const cases = [
        ['x_wireguard_private_key', ''],
        ['x_wireguard_private_key', 'xxxx'],
        ['x_wireguard_private_key', 'REDACTED'],
        ['x_wireguard_private_key', `${'A'.repeat(43)}=`],
        ['x_wireguard_private_key', {}],
        ['x_wireguard_private_key', undefined],
        ['x_pppoe_password', ''],
        ['x_pppoe_password', '********'],
      ];

      for (const [field, value] of cases) {
        const row = wireguardRow({ [field]: value });
        if (value === undefined) delete row[field];
        const unifi = fakeClient();

        const result = await probeWrite(unifi, row);

        assert.equal(result.ok, false, `${field}=${JSON.stringify(value)} must be refused`);
        assert.match(result.error.message, new RegExp(field));
        assert.equal(unifi.updated, undefined);
      }
    });

    it('refuses a row that says it uses a preshared key but does not carry a real one', async () => {
      for (const value of [undefined, '', 'xxxx']) {
        const row = wireguardRow({ wireguard_client_preshared_key_enabled: true, wireguard_client_preshared_key: value });
        if (value === undefined) delete row.wireguard_client_preshared_key;

        const result = await probeWrite(fakeClient(), row);
        assert.equal(result.ok, false, `${JSON.stringify(value)} with a preshared key in use must be refused`);
      }

      const unused = await probeWrite(fakeClient(), wireguardRow({ wireguard_client_preshared_key: '' }));
      assert.equal(unused.ok, true, 'a blank preshared key on a tunnel that does not use one is nothing to protect');
    });

    it('refuses a row missing the fields the sync needs, rather than guessing at the schema', async () => {
      const row = wireguardRow();
      delete row.ip_subnet;

      const unifi = fakeClient();
      const result = await probeWrite(unifi, row);

      assert.equal(result.ok, false);
      assert.match(result.error.message, /lacks ip_subnet/);
      assert.equal(unifi.updated, undefined);
    });

    it('never puts a secret value into a refusal', async () => {
      const result = await probeWrite(fakeClient(), wireguardRow({ wireguard_client_preshared_key: 'not-a-key-but-still-secret' }));

      assert.equal(result.ok, false);
      assert.doesNotMatch(result.error.message, /not-a-key-but-still-secret/);
    });

    it('reports a refusal instead of throwing, so one row does not end the run', async () => {
      const unifi = fakeClient({ writeError: new AppError(ErrorCode.AUTH, 'The UniFi console refused the request.') });

      const result = await probeWrite(unifi, wireguardRow());

      assert.equal(result.ok, false);
      assert.equal(result.attempted, true);
      assert.equal(result.error.code, ErrorCode.AUTH);
    });

    it('wraps a non-AppError so the report always has a message', async () => {
      const unifi = fakeClient({ writeError: new TypeError('socket hang up') });

      const result = await probeWrite(unifi, wireguardRow());

      assert.equal(result.ok, false);
      assert.ok(result.error instanceof AppError);
      assert.match(result.error.message, /write probe failed/i);
    });
  });

  describe('a VPN Client created by uploading a .conf', () => {
    const conf = (privateKey) => [
      '[Interface]', `PrivateKey = ${privateKey}`, 'Address = 10.1.2.3/32', 'DNS = 10.0.0.243', '',
      '[Peer]', 'PublicKey = aZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=', 'Endpoint = 1.2.3.4:1337',
      'AllowedIPs = 0.0.0.0/0', 'PersistentKeepalive = 25', '',
    ].join('\n');

    /** The shape a UCG Ultra actually returns for a file-mode tunnel. */
    const fileRow = (overrides = {}) => ({
      _id: 'abc123', name: 'WireGuard PIA CZ', purpose: 'vpn-client', vpn_type: 'wireguard-client',
      enabled: true, external_id: 'e', interface_mtu: 1420, interface_mtu_enabled: false, ip_subnet: '10.1.2.3/32',
      mss_clamp: 'auto', mss_clamp_ipv6: 'auto', mss_clamp_mss: 1380, site_id: 's', wireguard_id: 1,
      wireguard_client_mode: 'file',
      wireguard_client_configuration_file: conf('yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk='),
      wireguard_client_configuration_filename: 'PIA-czech.conf',
      ...overrides,
    });

    it('is written back when the file holds a real key, although the row has no key or peer fields', async () => {
      const unifi = fakeClient();
      const result = await probeWrite(unifi, fileRow());

      assert.equal(result.ok, true, result.error && result.error.message);
      assert.deepEqual(unifi.updated.entry, fileRow());
    });

    it('is refused when the key inside the file is masked or not a key', async () => {
      for (const hidden of ['*'.repeat(44), 'xxxx', '']) {
        const unifi = fakeClient();
        const result = await probeWrite(unifi, fileRow({ wireguard_client_configuration_file: conf(hidden) }));

        assert.equal(result.ok, false, `PrivateKey = ${JSON.stringify(hidden)} must be refused`);
        assert.match(result.error.message, /wireguard_client_configuration_file/);
        assert.equal(unifi.updated, undefined);
      }
    });

    it('is refused when the file is missing or blank', async () => {
      for (const file of [undefined, '']) {
        const row = fileRow({ wireguard_client_configuration_file: file });
        if (file === undefined) delete row.wireguard_client_configuration_file;
        assert.equal((await probeWrite(fakeClient(), row)).ok, false);
      }
    });

    it('is never described as missing manual-mode fields, and does not block the port', () => {
      const report = formatDiagnosis({
        read: { status: 200, headerNames: [], setCookie: false, cookiesHeld: [], csrfToken: 'none', rows: [fileRow()] },
        tunnels: ['WireGuard PIA CZ'],
      }).join('\n');

      assert.doesNotMatch(report, /missing fields this tool needs/);
      assert.doesNotMatch(report, /x_wireguard_private_key\s+absent\s+<-/);
      assert.match(report, /wireguard_client_configuration_file\s+present/);
      assert.match(report, /Nothing here blocks the port/);
      assert.doesNotMatch(report, /yAnz5TF/, 'the key inside the file must never be printed');
    });
  });

  describe('finding the row to write', () => {
    const rows = [
      { _id: 'lan1', name: 'Default', purpose: 'corporate', x_secret: 'hunter2' },
      wireguardRow({ _id: 'wg1', name: 'CZ' }),
    ];

    it('resolves a WireGuard VPN Client by name', () => {
      assert.equal(resolveTunnelRow(rows, 'CZ').row._id, 'wg1');
    });

    it('will not hand back a network that is not a WireGuard VPN Client', () => {
      const { row, error } = resolveTunnelRow(rows, 'Default');

      assert.equal(row, null);
      assert.match(error.message, /not a WireGuard VPN Client/);
    });

    it('says which clients exist when the name matches nothing', () => {
      assert.match(resolveTunnelRow(rows, 'US East').error.message, /No WireGuard VPN Client named "US East".*"CZ"/);
    });
  });

  describe('whether a write needs the session', () => {
    it('writes first from a client that has sent nothing, and stops there if that works', async () => {
      const session = fakeClient({ cookies: [['TOKEN', 'abc']], csrfToken: 'csrf' });
      const bare = fakeClient();

      const result = await probeWriteAccess({ session, fresh: () => bare, row: wireguardRow() });

      assert.equal(result.withoutSession.ok, true);
      assert.equal(bare.updated.id, 'abc123');
      assert.equal(session.updated, undefined, 'a second write would drop the tunnel again for no new answer');
      assert.equal(result.withSession.skipped, 'not needed');
    });

    it('tries the session only when the bare write was refused and the session holds something', async () => {
      const session = fakeClient({ cookies: [['TOKEN', 'abc']] });
      const bare = fakeClient({ writeError: new AppError(ErrorCode.AUTH, 'refused') });

      const result = await probeWriteAccess({ session, fresh: () => bare, row: wireguardRow() });

      assert.equal(result.withoutSession.ok, false);
      assert.equal(result.withSession.ok, true);
      assert.equal(session.updated.id, 'abc123');
    });

    it('does not repeat an identical request when the read left no session behind', async () => {
      const session = fakeClient();
      const bare = fakeClient({ writeError: new AppError(ErrorCode.AUTH, 'refused') });

      const result = await probeWriteAccess({ session, fresh: () => bare, row: wireguardRow() });

      assert.equal(session.updated, undefined);
      assert.match(result.withSession.skipped, /no cookie or token/);
    });

    it('does not retry a failure a cookie could not have caused', async () => {
      const session = fakeClient({ cookies: [['TOKEN', 'abc']] });
      const bare = fakeClient({ writeError: new AppError(ErrorCode.NETWORK, 'timed out') });

      const result = await probeWriteAccess({ session, fresh: () => bare, row: wireguardRow() });

      assert.equal(session.updated, undefined, 'a timeout may itself have been the tunnel dropping');
      assert.match(result.withSession.skipped, /cookie would not change/);
    });

    it('writes nothing at all when the row is unsafe to round-trip', async () => {
      const session = fakeClient({ cookies: [['TOKEN', 'abc']] });
      const bare = fakeClient();

      const result = await probeWriteAccess({
        session, fresh: () => bare, row: wireguardRow({ x_wireguard_private_key: '****' }),
      });

      assert.ok(result.refused);
      assert.equal(bare.updated, undefined);
      assert.equal(session.updated, undefined);
    });

    it('uses the session directly when there is no credential a bare client could use', async () => {
      const session = fakeClient();
      const result = await probeWriteAccess({ session, fresh: null, row: wireguardRow() });

      assert.equal(result.withoutSession, null);
      assert.equal(result.withSession.ok, true);
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
        ['', 'blank'],
        ['xxxx', 'not a key'],
        [`${'A'.repeat(43)}=`, 'not a key'],
        [42, 'not a key'],
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

    const accepted = { ok: true, attempted: true };
    const refusedAuth = { ok: false, attempted: true, error: new AppError(ErrorCode.AUTH, 'refused') };

    it('names a refused write as a blocker', () => {
      const report = formatDiagnosis({
        read: cleanRead,
        writes: [{
          name: 'WireGuard PIA CZ',
          result: { refused: null, withoutSession: refusedAuth, withSession: { ok: false, attempted: false, skipped: 'no cookie' } },
        }],
      }).join('\n');

      assert.match(report, /without session cookie\s+REFUSED/);
      assert.match(report, /does not authorise a write/);
    });

    it('does not block on a cookie the console sets but a write does not need', () => {
      const report = formatDiagnosis({
        read: { ...cleanRead, setCookie: true, cookiesHeld: ['TOKEN'] },
        writes: [{
          name: 'CZ',
          result: { refused: null, withoutSession: accepted, withSession: { ok: false, attempted: false, skipped: 'not needed' } },
        }],
      }).join('\n');

      assert.match(report, /sets a cookie, but the write succeeded without it/);
      assert.match(report, /Nothing here blocks the port/);
    });

    it('blocks when a write is accepted only with the session cookie', () => {
      const report = formatDiagnosis({
        read: { ...cleanRead, setCookie: true, cookiesHeld: ['TOKEN'] },
        writes: [{ name: 'CZ', result: { refused: null, withoutSession: refusedAuth, withSession: accepted } }],
      }).join('\n');

      assert.match(report, /accepted the write only with the session cookie/);
      assert.doesNotMatch(report, /Nothing here blocks/);
    });

    it('leaves the cookie question open when a password sign-in made a bare write impossible', () => {
      const report = formatDiagnosis({
        read: { ...cleanRead, setCookie: true, cookiesHeld: ['TOKEN'] },
        writes: [{ name: 'CZ', result: { refused: null, withoutSession: null, withSession: accepted } }],
      }).join('\n');

      assert.match(report, /a password sign-in is itself a session/);
      assert.match(report, /still unknown/);
    });

    it('reports a row that was not written, and why, as a blocker', () => {
      const report = formatDiagnosis({
        read: cleanRead,
        writes: [{
          name: 'Default',
          result: { refused: new AppError(ErrorCode.INVALID_INPUT, '"Default" exists in UniFi but is not a WireGuard VPN Client'), withoutSession: null, withSession: null },
        }],
      }).join('\n');

      assert.match(report, /not written\s+"Default" exists/);
      assert.match(report, /"Default": not probed/);
    });

    it('reports a self-signed leaf without calling it a problem', () => {
      const report = formatDiagnosis({
        certificate: { subject: 'CN=ucg', issuer: 'CN=ucg', selfSigned: true, ca: false, names: 'DNS:ucg', fingerprint: 'AA' },
        read: cleanRead,
      }).join('\n');

      assert.match(report, /CA:TRUE\s+no/);
      assert.match(report, /normal for a factory console/);

      // The shape a UCG Ultra presents. Windows CI settled that Schannel pins
      // it happily (test/unifi-pinning.test.js), so a report that stopped the
      // port over it would be stopping over nothing.
      assert.match(report, /Nothing here blocks the port/);
    });

    it('does not flag a self-signed certificate that is its own authority', () => {
      const report = formatDiagnosis({
        certificate: { subject: 'CN=ucg', issuer: 'CN=ucg', selfSigned: true, ca: true, names: 'DNS:ucg', fingerprint: 'AA' },
        read: cleanRead,
      }).join('\n');

      assert.match(report, /CA:TRUE\s+yes/);
      assert.match(report, /Nothing here blocks the port/);
    });

    it('still blocks on a leaf when something else is actually wrong', () => {
      const report = formatDiagnosis({
        certificate: { subject: 'CN=ucg', issuer: 'CN=ucg', selfSigned: true, ca: false, names: 'DNS:ucg', fingerprint: 'AA' },
        read: { ...cleanRead, setCookie: true },
      }).join('\n');

      assert.match(report, /the console sets a cookie/);
      assert.doesNotMatch(report, /Nothing here blocks the port/);
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
          rows: [
            { _id: 'a', name: 'WireGuard PIA CZ', purpose: 'vpn-client', vpn_type: 'wireguard-client', wireguard_client_mode: 'manual' },
            { _id: 'b', name: 'Default', purpose: 'corporate' },
          ],
        },
        tunnels: ['WireGuard PIA CZ', 'WireGuard US East', 'Default'],
      }).join('\n');

      assert.match(report, /Row "WireGuard PIA CZ"/);
      assert.match(report, /wireguard_client_mode\s+"manual"/);
      assert.match(report, /Row "WireGuard US East"\n\s+not described: No WireGuard VPN Client named "WireGuard US East"/);
      assert.match(report, /Row "Default"\n\s+not described: .*not a WireGuard VPN Client/, 'a LAN is never described as a tunnel');
      assert.match(report, /missing fields this tool needs:/, 'that row carries none of them');
    });

    it('a masked preshared key is a blocker; a masked private key is not', () => {
      const base = { _id: 'a', name: 'CZ', purpose: 'vpn-client', vpn_type: 'wireguard-client' };

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
      assert.match(preshared, /returns wireguard_client_preshared_key looks redacted/);
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

describe('the DPAPI launcher', () => {
  const launcher = readFileSync(join(ROOT, 'scripts', 'pia-unifi-sync.ps1'), 'utf8');

  /** Without comments, which name the very things the rules below forbid. */
  const code = launcher
    .replace(/<#[\s\S]*?#>/g, '')
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');

  it('prompts for secrets without echoing them', () => {
    assert.match(code, /Read-Secret 'PIA password'/);
    assert.match(code, /Read-Secret 'UniFi API key/);
    assert.match(code, /function Read-Secret[\s\S]*?-AsSecureString/);
  });

  it('stores them encrypted, outside the repository', () => {
    assert.match(code, /Export-Clixml/, 'Export-Clixml is what applies DPAPI to a SecureString');
    assert.match(code, /\$env:LOCALAPPDATA/);
    assert.doesNotMatch(code, /Set-Content|Out-File|Add-Content/, 'nothing may write a credential as text');
    assert.match(code, /-not \$IsWindows/, 'off Windows the same call is not encryption, so it must refuse');
  });

  it('never prints a credential', () => {
    for (const line of code.split('\n').filter((l) => /Write-(Host|Output)|^\s*"/.test(l))) {
      assert.doesNotMatch(line, /\$values|\$piaPassword|\$unifiApiKey|\$stored|\$previous/, `prints a secret: ${line.trim()}`);
    }
  });

  it('passes no credential on the command line', () => {
    const nodeInvocation = /& node [^\r\n]*/.exec(code);
    assert.ok(nodeInvocation, 'the launcher must invoke node');
    assert.doesNotMatch(nodeInvocation[0], /PIA_|UNIFI_|\$values/, 'credentials travel in the environment, not argv');
  });

  it('takes the credentials back out of the environment when the run ends', () => {
    assert.match(code, /finally\s*\{[\s\S]*SetEnvironmentVariable\(\$name, \$previous\[\$name\], 'Process'\)/);
  });

  it('defaults to a dry run and only writes when asked', () => {
    assert.match(code, /\$nodeArguments = @\('--dry-run'\) \+ \$given/, 'a narrowed refresh (--only) is still a dry run');
    assert.match(code, /-contains '--apply'/);
  });
});
