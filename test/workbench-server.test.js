import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AppError } from '../resources/js/core/errors.js';
import { startWorkbench } from '../scripts/workbench/server.mjs';

/**
 * An engine that records what it was asked and answers from a script. The server must not care
 * what an engine does, only that each route reaches the right method with the right arguments.
 */
function stubEngine() {
  const engine = { calls: [], failWith: null };
  for (const name of ['getState', 'inspectConsole', 'trustConsole', 'setUnifiKey',
    'setPiaCredentials', 'forgetCredentials', 'explore', 'listTunnels']) {
    engine[name] = async (...args) => {
      engine.calls.push([name, ...args]);
      if (engine.failWith) throw engine.failWith;
      return { answeredBy: name };
    };
  }
  return engine;
}

/**
 * A public/ with one file of every served type, plus things that must never come out of it: a
 * text file, a dotfile, a directory, and an .html file one level above public/ that traversal
 * would reach.
 */
function makePublicDir() {
  const root = mkdtempSync(join(tmpdir(), 'workbench-test-'));
  const publicDir = join(root, 'public');
  mkdirSync(join(publicDir, 'sub'), { recursive: true });
  writeFileSync(join(publicDir, 'index.html'), '<!doctype html><title>Workbench</title>');
  writeFileSync(join(publicDir, 'app.js'), 'export {};');
  writeFileSync(join(publicDir, 'styles.css'), 'body{}');
  writeFileSync(join(publicDir, 'logo.svg'), '<svg xmlns="http://www.w3.org/2000/svg"/>');
  writeFileSync(join(publicDir, 'icon.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  writeFileSync(join(publicDir, 'notes.txt'), 'not part of the UI');
  writeFileSync(join(publicDir, '.hidden.js'), 'nope');
  writeFileSync(join(publicDir, 'sub', 'page.html'), '<p>nested</p>');
  writeFileSync(join(root, 'outside.html'), 'TRAVERSED');
  return { root, publicDir };
}

/** Start a server on a free port, and tear it and its files down when the test ends. */
async function workbench(t, { engine = stubEngine() } = {}) {
  const { root, publicDir } = makePublicDir();
  const logLines = [];
  const server = await startWorkbench({ engine, port: 0, publicDir, log: (line) => logLines.push(line) });
  t.after(async () => {
    await server.close();
    rmSync(root, { recursive: true, force: true });
  });

  const token = new URL(server.url).searchParams.get('token');
  const host = `127.0.0.1:${server.port}`;

  /** A raw HTTP request, so headers the browser would set (or not) are entirely up to the test. */
  function send({ method = 'GET', path = '/', headers = {}, body, setHost = true, declareLength, flushOnly = false }) {
    return new Promise((resolve, reject) => {
      const req = httpRequest({
        host: '127.0.0.1', port: server.port, method, path, setHost: false,
        headers: { ...(setHost ? { host } : {}), ...headers },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) });
        });
      });
      req.on('error', reject);
      if (declareLength !== undefined) req.setHeader('content-length', declareLength);
      if (flushOnly) {
        req.flushHeaders();
        return;
      }
      if (body !== undefined) {
        const bytes = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
        if (declareLength === undefined) req.setHeader('content-length', bytes.length);
        req.end(bytes);
      } else {
        req.end();
      }
    });
  }

  /** Exchange the token the way a browser following the printed link would. */
  async function login() {
    const res = await send({ path: `/?token=${token}` });
    assert.equal(res.status, 303);
    return res.headers['set-cookie'][0].split(';')[0];
  }

  /** What the UI sends on every API call. */
  async function api(cookie, method, path, body, extraHeaders = {}) {
    const headers = { cookie, 'x-workbench': '1', ...extraHeaders };
    if (body !== undefined) headers['content-type'] = 'application/json';
    return send({ method, path, headers, body });
  }

  return { server, engine, token, host, logLines, send, login, api };
}

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};

function assertSecurityHeaders(res) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    assert.equal(res.headers[name], value, `${name} on a ${res.status}`);
  }
}

describe('the Workbench server', () => {
  describe('the one-time link', () => {
    it('prints a 127.0.0.1 URL whose token is 32 bytes of base64url', async (t) => {
      const { server, token } = await workbench(t);

      assert.match(server.url, /^http:\/\/127\.0\.0\.1:\d+\/\?token=/);
      assert.match(token, /^[A-Za-z0-9_-]{43}$/);
      assert.notEqual(server.port, 0, 'port 0 means "pick one", and the caller needs to know which');
    });

    it('trades the token for an HttpOnly, SameSite=Strict cookie and strips it from the address bar', async (t) => {
      const { send, token } = await workbench(t);

      const res = await send({ path: `/?token=${token}` });

      assert.equal(res.status, 303);
      assert.equal(res.headers.location, '/', 'the token must not stay in the URL, the history, or a Referer');
      const cookie = res.headers['set-cookie'][0];
      assert.match(cookie, /^wb_session=[A-Za-z0-9_-]{43}; /);
      assert.match(cookie, /; HttpOnly/);
      assert.match(cookie, /; SameSite=Strict/);
      assert.match(cookie, /; Path=\//);
      assert.ok(!cookie.includes(token), 'the session id is fresh, not the token reused');
    });

    it('refuses the same token a second time', async (t) => {
      const { send, token } = await workbench(t);
      await send({ path: `/?token=${token}` });

      // Someone scrolling back through the terminal later must not get a session of their own.
      const again = await send({ path: `/?token=${token}` });

      assert.equal(again.status, 401);
      assert.equal(again.headers['set-cookie'], undefined);
    });

    it('refuses a wrong token and grants nothing', async (t) => {
      const { send, token } = await workbench(t);
      const wrong = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');

      const res = await send({ path: `/?token=${wrong}` });
      assert.equal(res.status, 401);
      assert.equal(res.headers['set-cookie'], undefined);

      // And a wrong guess does not burn the real token.
      assert.equal((await send({ path: `/?token=${token}` })).status, 303);
    });

    it('still just redirects a signed-in browser that revisits the spent link', async (t) => {
      const { send, login, token } = await workbench(t);
      const cookie = await login();

      const res = await send({ path: `/?token=${token}`, headers: { cookie } });

      assert.equal(res.status, 303);
      assert.equal(res.headers.location, '/');
    });
  });

  describe('the session', () => {
    it('is required for pages', async (t) => {
      const { send } = await workbench(t);

      const res = await send({ path: '/' });

      assert.equal(res.status, 401);
      assert.ok(!res.text.includes('Workbench</title>'), 'the UI itself is behind the cookie');
    });

    it('is required for the API, answered in the contract error shape', async (t) => {
      const { send, engine } = await workbench(t);

      const res = await send({ path: '/api/state', headers: { 'x-workbench': '1' } });

      assert.equal(res.status, 401);
      assert.equal(res.json().error.code, 'UNAUTHORIZED');
      assert.equal(engine.calls.length, 0);
    });

    it('rejects a cookie that is almost right', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();
      const tampered = cookie.slice(0, -1) + (cookie.endsWith('A') ? 'B' : 'A');

      assert.equal((await api(tampered, 'GET', '/api/state')).status, 401);
      assert.equal(engine.calls.length, 0);
    });
  });

  describe('the Host header', () => {
    // A DNS-rebinding page talks to this socket under its own hostname; only the printed address counts.
    for (const host of ['localhost:PORT', 'evil.example', '127.0.0.1', '127.0.0.1:1']) {
      it(`refuses "${host}"`, async (t) => {
        const { send, login, server } = await workbench(t);
        const cookie = await login();

        const res = await send({
          path: '/api/state', setHost: false,
          headers: { host: host.replace('PORT', String(server.port)), cookie, 'x-workbench': '1' },
        });

        assert.equal(res.status, 421);
        assertSecurityHeaders(res);
      });
    }

    it('refuses a request with no Host at all', async (t) => {
      const { send } = await workbench(t);

      const res = await send({ path: '/', setHost: false });

      // Node itself answers 400 to an HTTP/1.1 request without Host; either refusal is fine.
      assert.ok([400, 421].includes(res.status), `got ${res.status}`);
    });

    it('checks Host before spending the token', async (t) => {
      const { send, token } = await workbench(t);

      const rebound = await send({ path: `/?token=${token}`, setHost: false, headers: { host: 'evil.example' } });
      assert.equal(rebound.status, 421);

      assert.equal((await send({ path: `/?token=${token}` })).status, 303, 'the token must still be good');
    });
  });

  describe('API request checks', () => {
    it('refuses a foreign Origin', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      for (const origin of ['http://evil.example', 'null', 'http://localhost']) {
        const res = await api(cookie, 'POST', '/api/unifi-key', { apiKey: 'k' }, { origin });
        assert.equal(res.status, 403, origin);
        assert.equal(res.json().error.code, 'FORBIDDEN');
      }
      assert.equal(engine.calls.length, 0);
    });

    it('accepts its own Origin, and none (a same-origin GET carries none)', async (t) => {
      const { api, login, server } = await workbench(t);
      const cookie = await login();

      assert.equal((await api(cookie, 'GET', '/api/state', undefined, { origin: `http://127.0.0.1:${server.port}` })).status, 200);
      assert.equal((await api(cookie, 'GET', '/api/state')).status, 200);
    });

    it('requires X-Workbench: 1, which no cross-site form can send', async (t) => {
      const { send, login, engine } = await workbench(t);
      const cookie = await login();

      const missing = await send({ method: 'DELETE', path: '/api/credentials', headers: { cookie } });
      const wrong = await send({ method: 'DELETE', path: '/api/credentials', headers: { cookie, 'x-workbench': 'true' } });

      assert.equal(missing.status, 403);
      assert.equal(wrong.status, 403);
      assert.equal(engine.calls.length, 0, 'forgetting credentials is exactly what a CSRF would try');
    });

    it('answers an unknown API path with a JSON 404', async (t) => {
      const { api, login } = await workbench(t);
      const cookie = await login();

      const res = await api(cookie, 'GET', '/api/nope');

      assert.equal(res.status, 404);
      assert.match(res.headers['content-type'], /^application\/json/);
      assert.equal(res.json().error.code, 'NOT_FOUND');
    });

    it('answers a known path with the wrong method with 405 and what is allowed', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      const res = await api(cookie, 'POST', '/api/state', {});

      assert.equal(res.status, 405);
      assert.equal(res.headers.allow, 'GET');
      assert.equal(res.json().error.code, 'METHOD_NOT_ALLOWED');
      assert.equal(engine.calls.length, 0);
    });
  });

  describe('security headers', () => {
    it('are on successes, refusals and errors alike', async (t) => {
      const { send, api, login } = await workbench(t);
      assertSecurityHeaders(await send({ path: '/' }));
      const cookie = await login();

      assertSecurityHeaders(await send({ path: '/', headers: { cookie } }));
      assertSecurityHeaders(await send({ path: '/missing.js', headers: { cookie } }));
      assertSecurityHeaders(await api(cookie, 'GET', '/api/state'));
      assertSecurityHeaders(await api(cookie, 'GET', '/api/nope'));
      assertSecurityHeaders(await send({ path: '/api/state', headers: { cookie } }));
    });
  });

  describe('request bodies', () => {
    it('are capped at 64 KB', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      const res = await api(cookie, 'POST', '/api/unifi-key', { apiKey: 'x'.repeat(70 * 1024) });

      assert.equal(res.status, 413);
      assert.equal(res.json().error.code, 'PAYLOAD_TOO_LARGE');
      assert.equal(engine.calls.length, 0);
    });

    it('take a body just under the cap', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      const res = await api(cookie, 'POST', '/api/unifi-key', { apiKey: 'x'.repeat(60 * 1024) });

      assert.equal(res.status, 200);
      assert.equal(engine.calls[0][1].length, 60 * 1024);
    });

    it('refuse a huge declared length without waiting for the body', async (t) => {
      const { send, login } = await workbench(t);
      const cookie = await login();

      const res = await send({
        method: 'POST', path: '/api/pia', flushOnly: true, declareLength: 10 * 1024 * 1024,
        headers: { cookie, 'x-workbench': '1', 'content-type': 'application/json' },
      });

      assert.equal(res.status, 413);
    });

    it('must be a JSON object', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      assert.equal((await api(cookie, 'POST', '/api/pia', '{not json')).status, 400);
      assert.equal((await api(cookie, 'POST', '/api/pia', '[1,2]')).status, 400);
      const missing = await api(cookie, 'POST', '/api/pia', { username: 'p1234567' });
      assert.equal(missing.status, 400);
      assert.equal(missing.json().error.code, 'INVALID_INPUT');
      assert.equal(engine.calls.length, 0);
    });
  });

  describe('static files', () => {
    it('serve index.html for / and each UI file with its content type', async (t) => {
      const { send, login } = await workbench(t);
      const cookie = await login();

      const expected = {
        '/': ['text/html; charset=utf-8', '<!doctype html>'],
        '/index.html': ['text/html; charset=utf-8', '<!doctype html>'],
        '/app.js': ['text/javascript; charset=utf-8', 'export'],
        '/styles.css': ['text/css; charset=utf-8', 'body'],
        '/logo.svg': ['image/svg+xml', '<svg'],
        '/icon.png': ['image/png', 'PNG'],
        '/sub/page.html': ['text/html; charset=utf-8', 'nested'],
      };
      for (const [path, [type, start]] of Object.entries(expected)) {
        const res = await send({ path, headers: { cookie } });
        assert.equal(res.status, 200, path);
        assert.equal(res.headers['content-type'], type, path);
        assert.ok(res.text.includes(start), path);
      }
    });

    it('serve nothing that is not a UI file type, hidden, or a directory', async (t) => {
      const { send, login } = await workbench(t);
      const cookie = await login();

      for (const path of ['/notes.txt', '/.hidden.js', '/sub', '/sub/', '/missing.html']) {
        assert.equal((await send({ path, headers: { cookie } })).status, 404, path);
      }
    });

    it('cannot be used to climb out of public/', async (t) => {
      const { send, login } = await workbench(t);
      const cookie = await login();

      const attempts = [
        '/..%2f..%2fpackage.json',
        '/..%2foutside.html',
        '/%2e%2e%2foutside.html',
        '/..%5coutside.html',
        '/sub%5c..%5c..%5coutside.html',
        '/%5c..%5coutside.html',
        '/../outside.html',
        '/sub/../../outside.html',
        '/%2e%2e/outside.html',
        '/index.html%00.js',
        '/%E0%A4%A.html',
      ];
      for (const path of attempts) {
        const res = await send({ path, headers: { cookie } });
        assert.equal(res.status, 404, path);
        assert.ok(!res.text.includes('TRAVERSED'), path);
      }
    });

    it('refuse methods other than GET and HEAD', async (t) => {
      const { send, login } = await workbench(t);
      const cookie = await login();

      const res = await send({ method: 'POST', path: '/index.html', headers: { cookie }, body: 'x' });
      assert.equal(res.status, 405);
    });
  });

  describe('routes', () => {
    it('call the engine method the contract names, with the arguments it names', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      const cases = [
        ['GET', '/api/state', undefined, ['getState']],
        ['POST', '/api/console/inspect', { url: 'https://192.168.1.1' }, ['inspectConsole', 'https://192.168.1.1']],
        ['POST', '/api/console/trust', { url: 'https://192.168.1.1', fingerprint256: 'AB:CD' },
          ['trustConsole', 'https://192.168.1.1', 'AB:CD']],
        ['POST', '/api/unifi-key', { apiKey: 'local-key' }, ['setUnifiKey', 'local-key']],
        ['POST', '/api/pia', { username: 'p1234567', password: 'pw' }, ['setPiaCredentials', 'p1234567', 'pw']],
        ['DELETE', '/api/credentials', undefined, ['forgetCredentials']],
        ['GET', `/api/explore?path=${encodeURIComponent('/proxy/network/api/s/default/rest/networkconf')}`, undefined,
          ['explore', '/proxy/network/api/s/default/rest/networkconf']],
        ['GET', '/api/tunnels', undefined, ['listTunnels']],
      ];

      for (const [method, path, body, call] of cases) {
        engine.calls.length = 0;
        const res = await api(cookie, method, path, body);
        assert.equal(res.status, 200, path);
        assert.deepEqual(res.json(), { answeredBy: call[0] }, path);
        assert.deepEqual(engine.calls, [call], path);
      }
    });

    it('refuse an explore without a path rather than asking the engine about nothing', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      const res = await api(cookie, 'GET', '/api/explore');

      assert.equal(res.status, 400);
      assert.equal(engine.calls.length, 0);
    });
  });

  describe('engine errors', () => {
    const mapping = [
      ['INVALID_INPUT', 400],
      ['CERT_CHANGED', 409],
      ['NOT_CONFIGURED', 409],
      // Not 401: the Workbench session is fine, it is the console that refused the key.
      ['UNIFI_KEY_REJECTED', 422],
      ['NETWORK', 502],
      ['TLS', 502],
      ['HTTP', 502],
    ];

    for (const [code, status] of mapping) {
      it(`turn ${code} into ${status} with its message and hint`, async (t) => {
        const { api, login, engine } = await workbench(t);
        const cookie = await login();
        const err = new AppError(code, `A ${code} happened.`);
        err.hint = 'Try the other thing.';
        engine.failWith = err;

        const res = await api(cookie, 'POST', '/api/unifi-key', { apiKey: 'k' });

        assert.equal(res.status, status);
        assert.deepEqual(res.json(), { error: { code, message: `A ${code} happened.`, hint: 'Try the other thing.' } });
      });
    }

    it('leave out a hint that is not there', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();
      engine.failWith = new AppError('NOT_CONFIGURED', 'Trust a console first.');

      const res = await api(cookie, 'GET', '/api/tunnels');

      assert.deepEqual(res.json(), { error: { code: 'NOT_CONFIGURED', message: 'Trust a console first.' } });
    });

    it('never pass through what an unexpected error says', async (t) => {
      const { api, login, engine } = await workbench(t);
      const cookie = await login();

      for (const failure of [
        new Error('spawn failed with PiaPassword=hunter2'),
        new AppError('STORAGE', 'DPAPI blob for hunter2 unreadable', { detail: 'hunter2' }),
        'a thrown string mentioning hunter2',
      ]) {
        engine.failWith = failure;
        const res = await api(cookie, 'GET', '/api/state');

        assert.equal(res.status, 500);
        assert.equal(res.json().error.code, 'INTERNAL');
        assert.ok(!res.text.includes('hunter2'));
        assert.doesNotMatch(res.text, /\bat .*:\d+:\d+/, 'and no stack');
      }
    });
  });

  describe('the log', () => {
    it('records method, path and status, and never a body, query or token', async (t) => {
      const { api, login, engine, logLines, token } = await workbench(t);
      const cookie = await login();

      await api(cookie, 'POST', '/api/pia', { username: 'p1234567', password: 'hunter2-secret' });
      await api(cookie, 'POST', '/api/unifi-key', { apiKey: 'local-api-key-value' });
      await api(cookie, 'GET', '/api/explore?path=%2Fproxy%2Fnetwork%2Fprivate-query');
      engine.failWith = new Error('boom hunter2-secret');
      await api(cookie, 'GET', '/api/state');

      const all = logLines.join('\n');
      assert.ok(logLines.includes('GET / 303'), all);
      assert.ok(logLines.includes('POST /api/pia 200'), all);
      assert.ok(logLines.includes('GET /api/explore 200'), all);
      assert.ok(logLines.includes('GET /api/state 500'), all);
      for (const secret of [token, 'hunter2-secret', 'p1234567', 'local-api-key-value', 'private-query', 'token=', cookie]) {
        assert.ok(!all.includes(secret), `the log must not contain ${secret}`);
      }
    });
  });
});
