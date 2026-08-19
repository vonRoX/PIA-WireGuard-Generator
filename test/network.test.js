/**
 * End-to-end tests over a real TLS connection made by a real curl process.
 *
 * The `addKey` request is the one that both carries the account token and
 * returns the server key written into the tunnel config, and v1 made it with
 * `curl -k`. These tests prove the replacement actually verifies: a certificate
 * from the wrong authority must fail, and must fail *closed*, with no data
 * reaching the caller.
 *
 * Certificates are minted per run rather than committed — a private key in a
 * repository is a liability even when it only ever protects 127.0.0.1.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { HttpClient } from '../resources/js/core/http.js';
import { PiaClient } from '../resources/js/core/pia.js';
import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { shellExec, startTlsServer, mintCertificate, hasOpenssl } from './helpers.js';

const COMMON_NAME = 'berlin401.test-pia.example';

/**
 * Windows curl uses Schannel, which rejects a certificate authority publishing no
 * revocation endpoint — true of the throwaway CA minted here, and true of PIA's
 * real root, which is why the application sets the same flag on Windows.
 */
const SCHANNEL = { tolerateUnknownRevocation: process.platform === 'win32' };
const skip = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';

const ADD_KEY_RESPONSE = {
  status: 'OK',
  server_key: 'sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
  server_port: 1337,
  server_ip: '193.176.86.1',
  server_vip: '10.4.0.1',
  peer_ip: '10.13.14.15',
  peer_pubkey: 'client',
  dns_servers: ['10.0.0.243'],
};

describe('addKey over TLS', { skip }, () => {
  let good;
  let evil;
  let server;
  let rogue;
  let bodies;

  before(async () => {
    good = mintCertificate(COMMON_NAME);
    evil = mintCertificate(COMMON_NAME); // same name, different authority
    bodies = [];

    const handler = (req) => {
      bodies.push(req.url);
      return { status: 200, body: JSON.stringify(ADD_KEY_RESPONSE) };
    };

    server = await startTlsServer(good, handler);
    rogue = await startTlsServer(evil, () => ({
      status: 200,
      body: JSON.stringify({ ...ADD_KEY_RESPONSE, server_ip: '203.0.113.66', server_key: 'attacker' }),
    }));
  });

  after(async () => {
    await server?.close();
    await rogue?.close();
    good?.cleanUp();
    evil?.cleanUp();
  });

  /** @param {{port: number, caPath: string}} target */
  function clientFor(target) {
    const client = new PiaClient(new HttpClient(shellExec, SCHANNEL), () => target.caPath);
    client.wireguardPort = target.port;
    return client;
  }

  test('succeeds against a certificate signed by the pinned authority', async () => {
    const client = clientFor({ port: server.port, caPath: good.caPath });

    const peer = await client.addKey({
      token: 'a-token-with $(spaces) & metacharacters',
      publicKey: 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=',
      server: { cn: COMMON_NAME, ip: '127.0.0.1' },
    });

    assert.deepEqual(peer, {
      peerIp: '10.13.14.15',
      serverKey: ADD_KEY_RESPONSE.server_key,
      serverIp: '193.176.86.1',
      serverPort: 1337,
    });
  });

  test('URL-encodes the token rather than letting it break the query string', async () => {
    bodies.length = 0;
    const client = clientFor({ port: server.port, caPath: good.caPath });

    await client.addKey({
      token: 'tok en&pubkey=injected',
      publicKey: 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=',
      server: { cn: COMMON_NAME, ip: '127.0.0.1' },
    });

    const url = bodies.at(-1);
    const params = new URLSearchParams(url.slice(url.indexOf('?') + 1));

    assert.equal(params.get('pt'), 'tok en&pubkey=injected');
    assert.equal(params.get('pubkey'), 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=');
    assert.equal(params.getAll('pubkey').length, 1, 'the token must not be able to add a second parameter');
  });

  test('fails closed against a certificate from another authority', async () => {
    const client = clientFor({ port: rogue.port, caPath: good.caPath });

    await assert.rejects(
      () => client.addKey({
        token: 'a-token',
        publicKey: 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=',
        server: { cn: COMMON_NAME, ip: '127.0.0.1' },
      }),
      (err) => {
        assert.ok(err instanceof AppError, `expected AppError, got ${err}`);
        assert.equal(err.code, ErrorCode.TLS);
        assert.match(err.message, /certificate could not be verified/i);
        assert.match(err.message, /No key was registered/i);
        return true;
      },
    );
  });

  test('the interception a user would have suffered under `curl -k` is what we now reject', async () => {
    // Same rogue server, verification switched off the way v1 did it: the
    // attacker's endpoint and public key come back looking perfectly valid.
    const insecure = await shellExec(
      `curl -s -k --connect-to "${COMMON_NAME}:${rogue.port}:127.0.0.1:${rogue.port}" "https://${COMMON_NAME}:${rogue.port}/addKey"`,
    );

    assert.equal(insecure.exitCode, 0, 'with -k the forged certificate is accepted');
    assert.match(insecure.stdOut, /203\.0\.113\.66/, 'and the attacker chooses the tunnel endpoint');
  });

  test('a server that answers with something other than JSON is reported, not parsed', async () => {
    const html = await startTlsServer(good, () => ({ status: 200, body: '<!doctype html><html>nope</html>' }));

    try {
      const client = clientFor({ port: html.port, caPath: good.caPath });
      await assert.rejects(
        () => client.addKey({
          token: 't',
          publicKey: 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=',
          server: { cn: COMMON_NAME, ip: '127.0.0.1' },
        }),
        (err) => {
          assert.equal(err.code, ErrorCode.PARSE);
          assert.match(err.message, /web page/i);
          return true;
        },
      );
    } finally {
      await html.close();
    }
  });

  test('an HTTP error status is surfaced as a status, not as a parse failure', async () => {
    const failing = await startTlsServer(good, () => ({ status: 503, body: 'upstream unavailable' }));

    try {
      const client = clientFor({ port: failing.port, caPath: good.caPath });
      await assert.rejects(
        () => client.addKey({
          token: 't',
          publicKey: 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=',
          server: { cn: COMMON_NAME, ip: '127.0.0.1' },
        }),
        (err) => {
          assert.equal(err.code, ErrorCode.HTTP);
          assert.match(err.message, /server error \(HTTP 503\)/);
          return true;
        },
      );
    } finally {
      await failing.close();
    }
  });

  test('an expired session comes back as an auth error the UI can act on', async () => {
    const unauthorised = await startTlsServer(good, () => ({ status: 401, body: '{"message":"invalid token"}' }));

    try {
      const client = clientFor({ port: unauthorised.port, caPath: good.caPath });
      await assert.rejects(
        () => client.addKey({
          token: 'stale',
          publicKey: 'GkTh8s5Yy1M+lTbAy6XkK0YhVfBd6DmRVy3nLbYQGXY=',
          server: { cn: COMMON_NAME, ip: '127.0.0.1' },
        }),
        (err) => {
          assert.equal(err.code, ErrorCode.AUTH);
          return true;
        },
      );
    } finally {
      await unauthorised.close();
    }
  });
});

describe('bodies survive the trip through curl unchanged', { skip }, () => {
  let credentials;
  let server;
  let received;

  before(async () => {
    credentials = mintCertificate('login.test-pia.example');
    received = [];

    server = await startTlsServerCollecting(credentials, received);
  });

  after(async () => {
    await server?.close();
    credentials?.cleanUp();
  });

  const PAYLOADS = [
    'a`id`b',
    'a$(id)b',
    'pa"ss',
    'back\\slash',
    '$HOME and %USERPROFILE%',
    'a && echo pwned | tee /tmp/x',
    'ünïcödé — ✓ 日本語',
    'tab\there',
    "single'quote",
  ];

  test('every hostile password arrives byte-for-byte', async () => {
    const http = new HttpClient(shellExec, SCHANNEL);

    for (const password of PAYLOADS) {
      received.length = 0;
      const body = JSON.stringify({ username: 'p1234567', password });

      await http.send({
        url: `https://login.test-pia.example:${server.port}/api/client/v2/token`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        caCertPath: credentials.caPath,
        connectTo: {
          host: 'login.test-pia.example', port: server.port, toHost: '127.0.0.1', toPort: server.port,
        },
      });

      assert.equal(received[0].body, body, `payload ${JSON.stringify(password)} was altered in transit`);
      assert.equal(JSON.parse(received[0].body).password, password);
      assert.equal(received[0].headers['content-type'], 'application/json');
    }
  });
});

/** A TLS server that records full request bodies. */
async function startTlsServerCollecting(credentials, sink) {
  const { createServer } = await import('node:https');

  const server = createServer({ key: credentials.key, cert: credentials.cert }, (req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      sink.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"token":"ok"}');
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  return {
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
