/**
 * Test scaffolding.
 *
 * `shellExec` deliberately goes through a real shell, the same way Neutralino's
 * `os.execCommand` does (`/bin/sh -c` on Unix, `cmd.exe /d /s /c` on Windows).
 * Anything the app can be made to execute, these tests can execute too — which
 * is the point: the injection tests are only meaningful if the shell is real.
 */

import { spawn, execFileSync } from 'node:child_process';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInThisContext } from 'node:vm';
import { createPrivateKey, createPublicKey } from 'node:crypto';

/**
 * @param {string} command
 * @param {{stdIn?: string}} [options]
 * @returns {Promise<{exitCode: number, stdOut: string, stdErr: string}>}
 */
export function shellExec(command, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, { shell: true, env: envWithoutProxy() });

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

/**
 * curl reads `HTTPS_PROXY` and friends from the environment, and decides whether
 * to use a proxy from the URL's hostname — not from `--connect-to`. A CI runner
 * or sandbox with an ambient proxy would therefore send these tests' requests to
 * that proxy instead of to the local server they are pointed at. Production
 * deliberately still honours the user's proxy settings; only the harness opts out.
 *
 * @returns {NodeJS.ProcessEnv}
 */
function envWithoutProxy() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(https?|all|no)_proxy$/i.test(key)) delete env[key];
  }
  env.NO_PROXY = '*';
  return env;
}

/** Records every command string the app hands to the shell, and runs nothing. */
export function recordingExec(response = { exitCode: 0, stdOut: '{}\n200', stdErr: '' }) {
  const calls = [];
  const exec = async (command, options = {}) => {
    calls.push({ command, stdIn: options.stdIn });
    return typeof response === 'function' ? response(command, options) : response;
  };
  exec.calls = calls;
  return exec;
}

/**
 * An HTTP server that reports back exactly what it received.
 *
 * @returns {Promise<{origin: string, port: number, requests: object[], close: () => Promise<void>}>}
 */
export async function startEchoServer() {
  const requests = [];

  const server = createHttpServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ received: body, url: req.url }));
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    port,
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/**
 * A TLS server presenting `certificate`, plus the bookkeeping to shut it down.
 *
 * @param {{key: string, cert: string}} credentials
 * @param {(req: import('node:http').IncomingMessage) => {status: number, body: string}} handler
 */
export async function startTlsServer(credentials, handler) {
  const requests = [];

  const server = createHttpsServer({ key: credentials.key, cert: credentials.cert }, (req, res) => {
    requests.push({ method: req.method, url: req.url });
    const { status, body } = handler(req);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(body);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    port,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** @returns {boolean} */
export function hasOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Mint a throwaway CA and a leaf certificate for `commonName`.
 *
 * Generated per run rather than committed: a private key in the repository is a
 * liability even when it only protects 127.0.0.1.
 *
 * @param {string} commonName
 * @returns {{dir: string, caPath: string, key: string, cert: string, cleanUp: () => void}}
 */
export function mintCertificate(commonName) {
  const dir = mkdtempSync(join(tmpdir(), 'pia-wg-test-'));
  const path = (name) => join(dir, name);
  const openssl = (args) => execFileSync('openssl', args, { stdio: 'pipe' });

  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', path('ca.key'), '-out', path('ca.crt'),
    '-days', '2', '-subj', '/CN=Throwaway Test CA',
    '-addext', 'basicConstraints=critical,CA:TRUE']);

  openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', path('server.key'), '-out', path('server.csr'),
    '-subj', `/CN=${commonName}`]);

  writeFileSync(path('ext.cnf'), `subjectAltName=DNS:${commonName}\n`);

  openssl(['x509', '-req', '-in', path('server.csr'),
    '-CA', path('ca.crt'), '-CAkey', path('ca.key'), '-CAcreateserial',
    '-out', path('server.crt'), '-days', '2', '-extfile', path('ext.cnf')]);

  return {
    dir,
    caPath: path('ca.crt'),
    key: readFileSync(path('server.key'), 'utf8'),
    cert: readFileSync(path('server.crt'), 'utf8'),
    cleanUp: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Mint a self-signed certificate for `commonName` — what a UniFi console presents
 * out of the box, and what a user exports from the browser to pin it.
 *
 * @param {string} commonName
 * @returns {{dir: string, key: string, cert: string, cleanUp: () => void}}
 */
export function mintSelfSignedCertificate(commonName) {
  const dir = mkdtempSync(join(tmpdir(), 'pia-wg-test-'));
  const path = (name) => join(dir, name);

  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', path('server.key'), '-out', path('server.crt'),
    '-days', '2', '-subj', `/CN=${commonName}`,
    '-addext', `subjectAltName=DNS:${commonName}`], { stdio: 'pipe' });

  return {
    dir,
    key: readFileSync(path('server.key'), 'utf8'),
    cert: readFileSync(path('server.crt'), 'utf8'),
    cleanUp: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** A server-list payload shaped like the real v6 endpoint: JSON line, then a signature. */
export function serverListPayload(regions) {
  const document = {
    groups: { wg: [{ name: 'wireguard', ports: [1337] }] },
    regions,
  };
  return `${JSON.stringify(document)}\n\nc2lnbmF0dXJlLXBsYWNlaG9sZGVy\n`;
}

/**
 * @param {object} overrides
 * @returns {object} one region in the shape PIA publishes
 */
export function region(overrides = {}) {
  return {
    id: 'de-berlin',
    name: 'Germany Berlin',
    country: 'DE',
    auto_region: true,
    dns: 'de-berlin.privacy.network',
    port_forward: false,
    geo: false,
    offline: false,
    servers: {
      wg: [{ ip: '193.176.86.1', cn: 'berlin401' }],
      meta: [{ ip: '193.176.86.2', cn: 'berlin402' }],
    },
    ...overrides,
  };
}

/** An in-memory {@link import('../resources/js/core/prefs.js').StorageAdapter}. */
export function memoryStorage(seed = {}) {
  const map = new Map(Object.entries(seed));
  return {
    map,
    async getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async setItem(key, value) {
      map.set(key, value);
    },
    async removeItem(key) {
      map.delete(key);
    },
  };
}

/**
 * Load the vendored tweetnacl build the way the webview does — as a classic
 * script that assigns a global — so the tests exercise the same artefact that
 * ships, not a differently-packaged copy from npm.
 *
 * @returns {object} the `nacl` global
 */
export function loadNacl() {
  const source = readFileSync(new URL('../resources/js/vendor/tweetnacl.js', import.meta.url), 'utf8');

  // Run it in *this* realm rather than a fresh vm context: tweetnacl guards its
  // inputs with `instanceof Uint8Array`, which is false across realms, so a
  // separate context would reject every array the tests hand it.
  const factory = runInThisContext(
    `(function (self, window, module, require) {\n${source}\nreturn self.nacl;\n})`,
    { filename: 'tweetnacl.js' },
  );

  const container = { crypto: globalThis.crypto };
  const nacl = factory(container, container, undefined, undefined);

  if (!nacl || !nacl.box) throw new Error('tweetnacl did not expose a `nacl` global');
  return nacl;
}

/**
 * Derive an X25519 public key using Node's own implementation, for cross-checking
 * against the vendored library.
 *
 * @param {Uint8Array} secretKey 32 raw bytes
 * @returns {Uint8Array} 32 raw bytes
 */
export function nodeScalarMultBase(secretKey) {
  // PKCS#8 prologue for an X25519 private key, then the raw scalar.
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'),
    Buffer.from(secretKey),
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return new Uint8Array(spki.subarray(spki.length - 32));
}
