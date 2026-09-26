import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { X509Certificate } from 'node:crypto';

import {
  inspectCertificate, normalizeConsoleUrl, normalizeFingerprint, pinnedTrust, splitNames,
} from '../scripts/engine/trust.mjs';
import { startTlsServer, mintSelfSignedLeaf, hasOpenssl } from './helpers.js';

const skipTls = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';

describe('normalizeConsoleUrl', () => {
  test('bare hosts get https, origins are kept', () => {
    assert.equal(normalizeConsoleUrl('192.168.1.1'), 'https://192.168.1.1');
    assert.equal(normalizeConsoleUrl(' https://unifi.local:8443/ '), 'https://unifi.local:8443');
    assert.equal(normalizeConsoleUrl('https://[fe80::1]'), 'https://[fe80::1]');
  });

  for (const bad of ['', '   ', 'http://192.168.1.1', 'ftp://x', 'https://u:p@192.168.1.1', 'https://192.168.1.1/network',
    'https://192.168.1.1?x=1', 'https://192.168.1.1#frag', 'https://a b', 'javascript:alert(1)', 42, null]) {
    test(`refuses ${JSON.stringify(bad)}`, () => {
      assert.throws(() => normalizeConsoleUrl(bad), (err) => err.code === 'INVALID_INPUT');
    });
  }
});

describe('normalizeFingerprint', () => {
  test('accepts any spelling of the same fingerprint', () => {
    const hex = 'ab'.repeat(32);
    const canonical = Array(32).fill('AB').join(':');
    assert.equal(normalizeFingerprint(hex), canonical);
    assert.equal(normalizeFingerprint(canonical.toLowerCase()), canonical);
  });

  test('refuses anything else', () => {
    for (const bad of ['', 'AB:CD', 'zz'.repeat(32), undefined, 'ab'.repeat(33)]) {
      assert.throws(() => normalizeFingerprint(bad), (err) => err.code === 'INVALID_INPUT');
    }
  });
});

test('splitNames turns subjectAltName into a list', () => {
  assert.deepEqual(splitNames('DNS:unifi.local, IP Address:192.168.1.1'), ['DNS:unifi.local', 'IP Address:192.168.1.1']);
  assert.deepEqual(splitNames(undefined), []);
});

describe('inspectCertificate against a self-signed leaf', { skip: skipTls }, () => {
  let leaf;
  let server;

  before(async () => {
    leaf = mintSelfSignedLeaf('unifi.local');
    server = await startTlsServer(leaf, () => ({ status: 200, body: '{}' }));
  });

  after(async () => {
    if (server) await server.close();
    if (leaf) leaf.cleanUp();
  });

  test('describes the certificate and sends no request', async () => {
    const certificate = await inspectCertificate(`https://127.0.0.1:${server.port}`);
    const expected = new X509Certificate(leaf.cert);

    assert.equal(certificate.fingerprint256, expected.fingerprint256);
    assert.equal(certificate.selfSigned, true);
    assert.equal(certificate.ca, false);
    assert.deepEqual(certificate.names, ['DNS:unifi.local']);
    assert.equal(certificate.connectName, 'unifi.local');
    assert.match(certificate.subject, /CN=unifi\.local/);
    assert.ok(certificate.validFrom && certificate.validTo);
    assert.equal(new X509Certificate(certificate.pem).fingerprint256, expected.fingerprint256, 'pem is the same certificate');
    assert.equal(server.requests.length, 0, 'reading the certificate must not send a request');

    const trust = pinnedTrust(certificate.pem);
    assert.ok(trust.fingerprints.has(expected.fingerprint256));
  });
});

describe('inspectCertificate with an injected connect', () => {
  /** A socket stand-in that fails or presents a given certificate. */
  function fakeConnect(behaviour) {
    const calls = [];
    const connect = (options, onSecure) => {
      calls.push(options);
      const socket = new EventEmitter();
      socket.destroyed = false;
      socket.setTimeout = () => {};
      socket.destroy = () => { socket.destroyed = true; };
      socket.getPeerCertificate = () => behaviour.peer || {};
      setImmediate(() => (behaviour.error ? socket.emit('error', behaviour.error) : onSecure()));
      return socket;
    };
    connect.calls = calls;
    return connect;
  }

  test('an unreachable console is a NETWORK error with a hint', async () => {
    const connect = fakeConnect({ error: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) });
    await assert.rejects(inspectCertificate('192.0.2.1', { connect }), (err) => err.code === 'NETWORK' && Boolean(err.hint));
    assert.equal(connect.calls[0].rejectUnauthorized, false);
    assert.equal(connect.calls[0].servername, undefined, 'no SNI for an IP address');
  });

  test('a handshake without a certificate is a TLS error', async () => {
    const connect = fakeConnect({ peer: {} });
    await assert.rejects(inspectCertificate('https://unifi.test', { connect }), (err) => err.code === 'TLS');
    assert.equal(connect.calls[0].servername, 'unifi.test');
  });
});
