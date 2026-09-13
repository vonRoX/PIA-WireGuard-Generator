/**
 * The write path, carried by a real curl process to a real TLS server.
 *
 * Everything the desktop app will send to a UniFi console goes out as a curl
 * config document on stdin, and nothing in the unit tests proves that document
 * produces the request it describes. `neutralino-stub.js` answers anything with
 * a canned success and matches on substrings, so a config with two `request =`
 * lines, a misspelled `noproxy`, or a body mangled in transit passes it green.
 *
 * A write is the one request where that matters most: a GET that quietly goes
 * wrong returns nothing, while a PUT that quietly goes wrong writes the wrong
 * thing into a gateway and leaves it there. So this file asserts on what
 * actually arrived on the wire.
 *
 * The certificate is a self-signed leaf — `CA:FALSE` — because that is what a
 * factory console presents, and it is pinned by `cacert` with the name check
 * moved onto a name it carries by `connect-to`, which is the recipe the app
 * will use. `test/unifi-pinning.test.js` proves that recipe holds on Schannel;
 * this file assumes it and goes on to the request itself.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { HttpClient } from '../resources/js/core/http.js';
import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { shellExec, startTlsServer, mintSelfSignedLeaf, hasOpenssl } from './helpers.js';

const CONSOLE_NAME = 'ucg-ultra.test.example';
const API_KEY = 'a-local-api-key-1234';
const skip = hasOpenssl() ? false : 'openssl is not on PATH, so no test certificate can be minted';

/**
 * A VPN Client row, with the things that break naive escaping in it: an em dash
 * the user typed into the description, a quote, a backslash, and enough bulk to
 * push the body past the 1KB mark where curl would otherwise announce
 * `Expect: 100-continue`.
 */
const ROW = {
  _id: '66f1a2b3c4d5e6f7a8b9c0d1',
  name: 'WireGuard PIA CZ — Praha',
  purpose: 'vpn-client',
  vpn_type: 'wireguard-client',
  x_wireguard_private_key: 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=',
  wireguard_client_peer_public_key: 'sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
  wireguard_client_peer_ip: '185.216.35.1',
  wireguard_client_peer_port: 1337,
  ip_subnet: '10.13.14.15/32',
  note: 'quote " backslash \\ tab\tnewline\nhere',
  padding: 'x'.repeat(1400),
};

describe('a UniFi write, as curl actually sends it', { skip }, () => {
  let leaf;
  let server;
  let pemDir;
  let pemPath;

  before(async () => {
    leaf = mintSelfSignedLeaf(CONSOLE_NAME);
    server = await startTlsServer(leaf, (req) => {
      if (req.method !== 'PUT') {
        return { status: 405, body: JSON.stringify({ meta: { rc: 'error', msg: 'api.err.MethodNotAllowed' } }) };
      }
      if (req.headers['x-api-key'] !== API_KEY) {
        return { status: 401, body: JSON.stringify({ meta: { rc: 'error', msg: 'api.err.LoginRequired' } }) };
      }
      return { status: 200, body: JSON.stringify({ meta: { rc: 'ok' }, data: [ROW] }) };
    });

    pemDir = mkdtempSync(join(tmpdir(), 'unifi-write-'));
    pemPath = join(pemDir, 'console.pem');
    writeFileSync(pemPath, leaf.cert, { mode: 0o600 });
  });

  after(async () => {
    if (server) await server.close();
    if (leaf) leaf.cleanUp();
    if (pemDir) rmSync(pemDir, { recursive: true, force: true });
  });

  /** The request the app will make, pinned exactly as it will pin it. */
  const writeRequest = (overrides = {}) => ({
    url: `https://${CONSOLE_NAME}:${server.port}/proxy/network/api/s/default/rest/networkconf/${ROW._id}`,
    method: 'PUT',
    headers: { 'x-api-key': API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify(ROW),
    caCertPath: pemPath,
    connectTo: { host: CONSOLE_NAME, port: server.port, toHost: '127.0.0.1', toPort: server.port },
    connectTimeoutSeconds: 5,
    maxTimeSeconds: 15,
    ...overrides,
  });

  const client = () => new HttpClient(shellExec, { tolerateUnknownRevocation: process.platform === 'win32' });

  test('arrives as a PUT, authenticated, and is accepted', async () => {
    const before = server.requests.length;
    const { status, body } = await client().send(writeRequest());

    assert.equal(status, 200);
    assert.match(body, /"rc":"ok"/);

    const sent = server.requests[before];
    assert.equal(sent.method, 'PUT', 'a config that failed to set the method would arrive as a GET');
    assert.equal(sent.headers['x-api-key'], API_KEY);
    assert.equal(sent.headers['content-type'], 'application/json');
    assert.equal(server.requests.length, before + 1, 'exactly one request, not a retry');
  });

  test('the body arrives byte-identical, em dash, quote, backslash and all', async () => {
    const before = server.requests.length;
    await client().send(writeRequest());

    const sent = server.requests[before];
    assert.equal(sent.body, JSON.stringify(ROW),
      'anything less than byte-identical means the gateway is written a row nobody composed');
    assert.deepEqual(JSON.parse(sent.body), ROW, 'and it must still parse back to the row it started as');
  });

  test('no Expect header is announced, even though the body is over 1KB', async () => {
    const before = server.requests.length;
    assert.ok(JSON.stringify(ROW).length > 1024, 'the fixture must be large enough for curl to want to announce it');

    await client().send(writeRequest());

    assert.equal(server.requests[before].headers.expect, undefined,
      'a 100-continue announcement is a stall waiting for a middlebox that never answers');
  });

  test('a console that refuses the key is reported as a refusal, not a parse error', async () => {
    await assert.rejects(
      client().send(writeRequest({ headers: { 'x-api-key': 'wrong', 'content-type': 'application/json' } })),
      (err) => err instanceof AppError && err.code === ErrorCode.AUTH,
    );
  });

  test('the same refusal can be read rather than thrown, which is why the method exists', async () => {
    const response = await client().sendExpectingAnyStatus(
      writeRequest({ headers: { 'x-api-key': 'wrong', 'content-type': 'application/json' } }),
    );

    assert.equal(response.status, 401);
    assert.match(response.body, /api\.err\.LoginRequired/,
      "the console's own message is the only useful thing in a 401, and send() would have discarded it");
  });

  test('the key never reaches a command line — only the document on stdin', async () => {
    const seen = [];
    const recording = async (command, options) => {
      seen.push({ command, stdIn: options?.stdIn || '' });
      return shellExec(command, options);
    };

    await new HttpClient(recording, { tolerateUnknownRevocation: process.platform === 'win32' })
      .send(writeRequest());

    assert.equal(seen.length, 1);
    assert.equal(seen[0].command, 'curl -q --config -', 'the command is constant, or v1 happens again');
    assert.doesNotMatch(seen[0].command, /a-local-api-key/);
    assert.match(seen[0].stdIn, /x-api-key/, 'the key travels in the config document instead');
  });

  test('a pinned write to the wrong certificate fails closed, before the body is sent', async () => {
    const impostor = mintSelfSignedLeaf(CONSOLE_NAME);
    const impostorDir = mkdtempSync(join(tmpdir(), 'unifi-write-rogue-'));
    const impostorPath = join(impostorDir, 'rogue.pem');
    writeFileSync(impostorPath, impostor.cert, { mode: 0o600 });
    const before = server.requests.length;

    try {
      await assert.rejects(
        client().send(writeRequest({ caCertPath: impostorPath })),
        (err) => err instanceof AppError && err.code === ErrorCode.TLS,
      );
      assert.equal(server.requests.length, before, 'an API key must not reach an unverified server');
    } finally {
      impostor.cleanUp();
      rmSync(impostorDir, { recursive: true, force: true });
    }
  });
});

/**
 * Whether `noproxy` actually works, rather than whether the line is emitted.
 *
 * `test/helpers.js` strips proxy variables out of the environment for every
 * other test, precisely so an ambient proxy on a CI runner cannot interfere.
 * Here the point is the opposite: put a proxy in the environment that cannot
 * work, and show the request reaches the console anyway — and that without
 * `noProxy` it does not, so the test has teeth.
 *
 * The certificate names `localhost` so the URL can name it too: curl decides
 * whether to use a proxy from the URL's hostname, never from `--connect-to`,
 * and `isPrivateHost` gates the option on that same hostname.
 */
describe('a console on the LAN is reached past a proxy that cannot reach it', { skip }, () => {
  let leaf;
  let server;
  let pemDir;
  let pemPath;

  /** A proxy address with nothing listening on it. */
  const DEAD_PROXY = 'http://127.0.0.1:9';

  /** Like `shellExec`, but with a proxy in the environment instead of scrubbed out of it. */
  function execBehindProxy(command, options = {}) {
    return new Promise((resolve) => {
      const env = { ...process.env, http_proxy: DEAD_PROXY, https_proxy: DEAD_PROXY };
      delete env.NO_PROXY;
      delete env.no_proxy;

      const child = spawn(command, { shell: true, env });
      let stdOut = '';
      let stdErr = '';
      child.stdout.on('data', (chunk) => { stdOut += chunk; });
      child.stderr.on('data', (chunk) => { stdErr += chunk; });
      child.on('error', (err) => resolve({ exitCode: 127, stdOut: '', stdErr: String(err) }));
      child.on('close', (code) => resolve({ exitCode: code === null ? -1 : code, stdOut, stdErr }));

      if (typeof options.stdIn === 'string') child.stdin.write(options.stdIn);
      child.stdin.end();
    });
  }

  before(async () => {
    leaf = mintSelfSignedLeaf('localhost');
    server = await startTlsServer(leaf, () => ({ status: 200, body: JSON.stringify({ meta: { rc: 'ok' }, data: [] }) }));

    pemDir = mkdtempSync(join(tmpdir(), 'unifi-proxy-'));
    pemPath = join(pemDir, 'console.pem');
    writeFileSync(pemPath, leaf.cert, { mode: 0o600 });
  });

  after(async () => {
    if (server) await server.close();
    if (leaf) leaf.cleanUp();
    if (pemDir) rmSync(pemDir, { recursive: true, force: true });
  });

  const request = (extra) => ({
    url: `https://localhost:${server.port}/proxy/network/api/s/default/rest/networkconf`,
    caCertPath: pemPath,
    connectTimeoutSeconds: 5,
    maxTimeSeconds: 15,
    ...extra,
  });

  const client = () => new HttpClient(execBehindProxy, { tolerateUnknownRevocation: process.platform === 'win32' });

  test('without noProxy the request goes to the proxy, and dies there', async () => {
    await assert.rejects(
      client().send(request()),
      (err) => err instanceof AppError,
      'if this passes, the environment has no effect and the next test proves nothing',
    );
  });

  test('with noProxy it reaches the console directly', async () => {
    const before = server.requests.length;
    const { status } = await client().send(request({ noProxy: true }));

    assert.equal(status, 200);
    assert.equal(server.requests.length, before + 1, 'the request must have arrived at the console itself');
  });
});
