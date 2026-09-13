/**
 * Can a self-signed *leaf* certificate be pinned with real curl?
 *
 * A UniFi console presents a self-signed end-entity certificate — `CA:FALSE` —
 * that names something you do not reach it by. The desktop app talks to the
 * network only through curl, and curl has no equivalent of Node's
 * `checkServerIdentity`: it cannot verify a chain while waiving the name check.
 * The only honest substitute is to make the exported certificate the entire
 * trust store (`cacert`) and move the name check onto a name the certificate
 * does carry (`connect-to`) — the same recipe `PiaClient.addKey` already uses
 * for pinning.
 *
 * Whether that works is backend-dependent. OpenSSL has a special case for "the
 * leaf is itself in the trust store"; Windows Schannel applies chain-building
 * rules to trust anchors and may reject `CA:FALSE` outright (curl#7384 reports
 * `SEC_E_UNTRUSTED_ROOT` for exactly this). Since CI already runs a Windows leg,
 * that question is answerable here rather than on the user's hardware — and the
 * answer decides whether the UniFi client can be ported into the app at all.
 *
 * The existing pinning tests cannot answer it: `mintSelfSignedCertificate` uses
 * `openssl req -x509`, which defaults to `basicConstraints = critical, CA:TRUE`,
 * so they pin a self-signed *authority* and prove the easy case.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildCurlConfig, CURL_COMMAND } from '../resources/js/core/curl.js';
import { shellExec, startTlsServer, mintSelfSignedLeaf, hasOpenssl, curlTlsBackend } from './helpers.js';

const CONSOLE_NAME = 'ucg-ultra.test.example';
const skip = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';

describe('pinning a self-signed leaf, the way a UniFi console presents one', { skip }, () => {
  let leaf;
  let server;
  let pemDir;
  let pemPath;

  before(async () => {
    leaf = mintSelfSignedLeaf(CONSOLE_NAME);
    server = await startTlsServer(leaf, () => ({
      status: 200,
      body: JSON.stringify({ meta: { rc: 'ok' }, data: [] }),
    }));

    // `cacert` takes a path, so the exported certificate has to reach the disk —
    // the same thing `CaCertFile` does for PIA's CA inside the app.
    pemDir = mkdtempSync(join(tmpdir(), 'unifi-pin-'));
    pemPath = join(pemDir, 'console.pem');
    writeFileSync(pemPath, leaf.cert, { mode: 0o600 });
  });

  after(async () => {
    if (server) await server.close();
    if (leaf) leaf.cleanUp();
    if (pemDir) rmSync(pemDir, { recursive: true, force: true });
  });

  /** The request the app would make, rendered as a curl config document. */
  const pinnedRequest = (port) => ({
    url: `https://${CONSOLE_NAME}:${port}/proxy/network/api/s/default/rest/networkconf`,
    caCertPath: pemPath,
    connectTo: { host: CONSOLE_NAME, port, toHost: '127.0.0.1', toPort: port },
    connectTimeoutSeconds: 5,
    maxTimeSeconds: 15,
    // Schannel treats "revocation status cannot be determined" as failure, and a
    // throwaway certificate publishes no CRL — exactly as PIA's own root does not.
    tolerateUnknownRevocation: process.platform === 'win32',
  });

  test('the certificate is a leaf, not an authority — otherwise this proves nothing', async () => {
    const { X509Certificate } = await import('node:crypto');
    const certificate = new X509Certificate(leaf.cert);

    assert.equal(certificate.ca, false, 'the fixture must not be a CA, or it is the easy case again');
    assert.equal(certificate.subject, certificate.issuer, 'and it must be self-signed');
  });

  test('curl accepts it as its own trust anchor', async (t) => {
    const backend = curlTlsBackend();
    t.diagnostic(`curl TLS backend: ${backend}`);

    const result = await shellExec(CURL_COMMAND, { stdIn: buildCurlConfig(pinnedRequest(server.port)) });

    if (result.exitCode !== 0) {
      // This is the finding, not a flake. Say what it means for the port.
      assert.fail(
        `curl (${backend}) refused a self-signed leaf supplied via --cacert: exit ${result.exitCode}.\n` +
        `  ${(result.stdErr || '').trim()}\n` +
        '  The app cannot pin a factory console certificate on this platform. The honest options are\n' +
        '  to import the certificate into the system store, put a real certificate on the console, or\n' +
        '  keep using the Node CLI, which pins by fingerprint through node:tls instead.',
      );
    }

    assert.match(result.stdOut, /"rc":"ok"/, 'the pinned request should have reached the server');
    assert.equal(server.requests.length, 1);
  });

  test('a different self-signed leaf is refused, and nothing reaches the server', async () => {
    const before = server.requests.length;
    const impostor = mintSelfSignedLeaf(CONSOLE_NAME);
    const impostorDir = mkdtempSync(join(tmpdir(), 'unifi-pin-rogue-'));
    const impostorPath = join(impostorDir, 'rogue.pem');
    writeFileSync(impostorPath, impostor.cert, { mode: 0o600 });

    try {
      const result = await shellExec(CURL_COMMAND, {
        stdIn: buildCurlConfig({ ...pinnedRequest(server.port), caCertPath: impostorPath }),
      });

      assert.notEqual(result.exitCode, 0, 'a certificate that is not the pinned one must not verify');
      assert.equal(server.requests.length, before, 'and the request must fail closed, before any data is sent');
    } finally {
      impostor.cleanUp();
      rmSync(impostorDir, { recursive: true, force: true });
    }
  });

  test('without the pin, the name mismatch alone is enough to refuse it', async () => {
    const before = server.requests.length;

    const result = await shellExec(CURL_COMMAND, {
      stdIn: buildCurlConfig({
        url: `https://127.0.0.1:${server.port}/proxy/network/api/s/default/rest/networkconf`,
        caCertPath: pemPath,
        connectTimeoutSeconds: 5,
        maxTimeSeconds: 15,
        tolerateUnknownRevocation: process.platform === 'win32',
      }),
    });

    assert.notEqual(result.exitCode, 0, 'the certificate names a host, and 127.0.0.1 is not it');
    assert.equal(server.requests.length, before);
  });
});
