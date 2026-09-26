/**
 * The Workbench page (scripts/workbench/public) and its fake engine.
 *
 * Static checks hold the page to the server's CSP (`default-src 'self'`) and to the rule that
 * nothing from a response is ever parsed as HTML; the fetch check makes sure no request can
 * leave the page without the X-Workbench header. The fake engine is checked against the shapes
 * in scripts/workbench/CONTRACT.md, since the server's tests and the UI both lean on it.
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { AppError } from '../resources/js/core/errors.js';
import { createFakeEngine, SITE_MANAGER_KEY_HINT, FAKE_APPLICATION_VERSION } from '../scripts/workbench/fake-engine.mjs';
import {
  statusTone,
  statusLabel,
  humanise,
  fingerprintBytes,
  fingerprintRows,
  fingerprintShort,
  checkExplorePath,
  normaliseConsoleUrl,
  modeLabel,
  validityProblem,
  EXPLORE_PRESETS,
} from '../scripts/workbench/public/format.js';
import { request, api, ApiError } from '../scripts/workbench/public/api.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC = join(ROOT, 'scripts', 'workbench', 'public');
const read = (name) => readFileSync(join(PUBLIC, name), 'utf8');

const html = read('index.html');
const scriptFiles = readdirSync(PUBLIC).filter((name) => name.endsWith('.js'));
const scripts = Object.fromEntries(scriptFiles.map((name) => [name, read(name)]));
const css = read('styles.css');

/** Strip comments so prose about innerHTML in a comment does not trip the checks. */
function code(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
}

const REDACT_KEY = /key|secret|password|passphrase|token|psk|x_/i;

describe('workbench page: CSP-safe markup', () => {
  it('has no inline script bodies, and every script is same-origin', () => {
    const tags = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    assert.ok(tags.length > 0, 'expected at least one script tag');
    for (const [, attrs, body] of tags) {
      assert.equal(body.trim(), '', 'inline script body');
      const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
      assert.ok(src, 'script without src');
      assert.doesNotMatch(src[1], /^(?:[a-z]+:)?\/\//i, 'script from another origin');
    }
  });

  it('has no inline styles or event-handler attributes', () => {
    assert.doesNotMatch(html, /<style\b/i, '<style> element');
    assert.doesNotMatch(html, /\sstyle\s*=/i, 'style= attribute');
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'on*= attribute');
    assert.doesNotMatch(html, /javascript:/i, 'javascript: URL');
  });

  it('loads nothing from another origin, and every local reference exists', () => {
    for (const [, url] of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
      assert.doesNotMatch(url, /^(?:[a-z]+:)?\/\//i, `remote reference ${url}`);
      if (url.startsWith('#')) continue;
      assert.ok(existsSync(join(PUBLIC, url)), `missing ${url}`);
    }
    for (const [, url] of css.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gi)) {
      assert.doesNotMatch(url, /^(?:[a-z]+:)?\/\//i, `remote url() ${url}`);
      assert.ok(existsSync(join(PUBLIC, url)), `missing ${url}`);
    }
    assert.doesNotMatch(css, /@import/i);
  });

  it('only imports sibling modules that are served from public/', () => {
    for (const [name, source] of Object.entries(scripts)) {
      for (const [, specifier] of source.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)) {
        assert.match(specifier, /^\.\/[\w-]+\.js$/, `${name} imports ${specifier}`);
        assert.ok(existsSync(join(PUBLIC, specifier)), `${name} imports missing ${specifier}`);
      }
    }
  });
});

describe('workbench page: no HTML from strings, no eval', () => {
  for (const name of scriptFiles) {
    it(`${name} never parses strings as markup or code`, () => {
      const source = code(scripts[name]);
      assert.doesNotMatch(source, /\binnerHTML\b/, 'innerHTML');
      assert.doesNotMatch(source, /\bouterHTML\b/, 'outerHTML');
      assert.doesNotMatch(source, /insertAdjacentHTML/, 'insertAdjacentHTML');
      assert.doesNotMatch(source, /document\.write/, 'document.write');
      assert.doesNotMatch(source, /\beval\s*\(/, 'eval');
      assert.doesNotMatch(source, /new\s+Function\b/, 'new Function');
      assert.doesNotMatch(source, /\bset(?:Timeout|Interval)\s*\(\s*['"`]/, 'string timer');
      assert.doesNotMatch(source, /setAttribute\(\s*['"]style['"]/, 'inline style via setAttribute');
      assert.doesNotMatch(source, /createContextualFragment|DOMParser/, 'HTML parsing');
    });
  }
});

describe('workbench page: every request goes through one helper', () => {
  it('app.js exists and is the module the page loads', () => {
    assert.ok(scripts['app.js']);
    assert.match(html, /<script type="module" src="app\.js"><\/script>/);
  });

  it('calls fetch exactly once, inside api.js request()', () => {
    const calls = Object.entries(scripts).flatMap(([name, source]) =>
      [...code(source).matchAll(/\bfetch\s*\(/g)].map(() => name));
    assert.deepEqual(calls, ['api.js']);

    const body = /export async function request\([^)]*\)\s*\{([\s\S]*?)\n\}/.exec(code(scripts['api.js']));
    assert.ok(body, 'request() not found');
    assert.match(body[1], /\bfetch\s*\(/);
    assert.match(body[1], /'X-Workbench':\s*'1'/);
    assert.match(body[1], /credentials:\s*'same-origin'/);
  });

  it('uses no other way to make a request', () => {
    for (const [name, source] of Object.entries(scripts)) {
      const stripped = code(source);
      assert.doesNotMatch(stripped, /XMLHttpRequest|WebSocket|EventSource|sendBeacon|\bimport\s*\(/, name);
    }
  });
});

describe('workbench api helper', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function stub(respond) {
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url, init });
      return respond(url, init);
    };
    return calls;
  }

  it('sends X-Workbench and the same-origin cookie, with a JSON body', async () => {
    const calls = stub(() => new Response(JSON.stringify({ verified: true, applicationVersion: '10.0.162' }), { status: 200 }));
    const result = await api.setUnifiKey('abc');
    assert.equal(result.applicationVersion, '10.0.162');
    assert.equal(calls[0].url, '/api/unifi-key');
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.headers['X-Workbench'], '1');
    assert.equal(calls[0].init.credentials, 'same-origin');
    assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(calls[0].init.body), { apiKey: 'abc' });
  });

  it('every API method sends the header', async () => {
    const calls = stub(() => new Response('{}', { status: 200 }));
    await api.state();
    await api.inspectConsole('https://192.168.1.1');
    await api.trustConsole('https://192.168.1.1', 'AA');
    await api.setPia('u', 'p');
    await api.forgetCredentials();
    await api.explore('/proxy/network/integration/v1/info?x=1&y=2');
    await api.tunnels();
    assert.equal(calls.length, 7);
    for (const call of calls) {
      assert.equal(call.init.headers['X-Workbench'], '1', call.url);
      assert.equal(call.init.credentials, 'same-origin', call.url);
    }
    assert.equal(calls[4].init.method, 'DELETE');
    assert.equal(calls[5].url, '/api/explore?path=%2Fproxy%2Fnetwork%2Fintegration%2Fv1%2Finfo%3Fx%3D1%26y%3D2');
  });

  it('turns the contract error shape into an ApiError with the hint', async () => {
    stub(() => new Response(JSON.stringify({
      error: { code: 'UNIFI_KEY_REJECTED', message: 'Rejected.', hint: 'Use a local key.' },
    }), { status: 422 }));
    await assert.rejects(api.setUnifiKey('sitemanager'), (error) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, 'UNIFI_KEY_REJECTED');
      assert.equal(error.message, 'Rejected.');
      assert.equal(error.hint, 'Use a local key.');
      assert.equal(error.status, 422);
      assert.equal(error.retryable, false);
      return true;
    });
  });

  it('reports a dead server as OFFLINE and retryable', async () => {
    stub(() => {
      throw new TypeError('Failed to fetch');
    });
    await assert.rejects(api.state(), (error) => error.code === 'OFFLINE' && error.retryable === true);
  });

  it('reports a lost session without a JSON body as SESSION', async () => {
    stub(() => new Response('forbidden', { status: 403 }));
    await assert.rejects(api.state(), { code: 'SESSION' });
  });

  it('reports an unreadable success as PARSE', async () => {
    stub(() => new Response('<html>', { status: 200 }));
    await assert.rejects(api.state(), { code: 'PARSE' });
  });

  it('refuses to send anything outside /api/', async () => {
    const calls = stub(() => new Response('{}'));
    await assert.rejects(request('GET', 'https://example.com/api/state'));
    assert.equal(calls.length, 0);
  });
});

describe('workbench formatting helpers', () => {
  it('maps tunnel statuses to colours', () => {
    assert.equal(statusTone('CONNECTED'), 'ok');
    assert.equal(statusTone('ESTABLISHED'), 'ok');
    assert.equal(statusTone('connected'), 'ok');
    assert.equal(statusTone('UP'), 'ok');
    assert.equal(statusTone('CONNECTING'), 'pending');
    assert.equal(statusTone('RECONNECTING'), 'pending');
    assert.equal(statusTone('DISCONNECTED'), 'bad');
    assert.equal(statusTone('NOT_CONNECTED'), 'bad');
    assert.equal(statusTone('FAILED'), 'bad');
    assert.equal(statusTone('UNKNOWN'), 'unknown');
    assert.equal(statusTone(null), 'unknown');
    assert.equal(statusTone(undefined), 'unknown');
    assert.equal(statusTone(''), 'unknown');
    assert.equal(statusTone('SOMETHING_NEW'), 'unknown');
  });

  it('humanises codes', () => {
    assert.equal(humanise('CONNECTING_LONGER_THAN_USUAL'), 'Connecting longer than usual');
    assert.equal(statusLabel('CONNECTING'), 'Connecting');
    assert.equal(statusLabel(null, true), 'Unknown');
    assert.equal(statusLabel(null, false), 'Off');
    assert.equal(modeLabel('file'), 'Configuration file');
    assert.equal(modeLabel('manual'), 'Manual');
    assert.equal(modeLabel('unknown'), 'Other');
  });

  it('groups a fingerprint into bytes and rows whatever the separator', () => {
    const fp = '3B:9F:0C:D2:71:4E:A8:65:1D:C0:92:BB:47:E3:5A:08:F6:21:9C:7D:E4:30:B5:6A:8F:12:DE:49:C7:03:5B:A1';
    assert.equal(fingerprintBytes(fp).length, 32);
    assert.deepEqual(fingerprintBytes('3b9f 0c'), ['3B', '9F', '0C']);
    const rows = fingerprintRows(fp);
    assert.equal(rows.length, 4);
    assert.deepEqual(rows[0], ['3B', '9F', '0C', 'D2', '71', '4E', 'A8', '65']);
    assert.equal(fingerprintShort(fp), '3B 9F 0C D2 … 03 5B A1');
  });

  it('checks explorer paths like the engine does', () => {
    for (const preset of EXPLORE_PRESETS) assert.equal(checkExplorePath(preset).ok, true, preset);
    assert.equal(checkExplorePath(' /proxy/network/integration/v1/info ').path, '/proxy/network/integration/v1/info');
    assert.equal(checkExplorePath('/proxy/network/api/s/default/stat/sta?limit=5').ok, true);
    for (const bad of [
      '',
      '/api/self',
      '/proxy/networkx/',
      'https://192.168.1.1/proxy/network/integration/v1/info',
      '//evil.example/proxy/network/',
      '/proxy/network/../../api/auth',
      '/proxy/network//integration',
      '/proxy/network/a\\b',
      '/proxy/network/a b',
    ]) {
      assert.equal(checkExplorePath(bad).ok, false, bad);
    }
  });

  it('accepts a bare console address and hands back an origin', () => {
    assert.equal(normaliseConsoleUrl('192.168.1.1'), 'https://192.168.1.1');
    assert.equal(normaliseConsoleUrl(' https://192.168.1.1/ '), 'https://192.168.1.1');
    assert.equal(normaliseConsoleUrl('https://unifi.local:8443'), 'https://unifi.local:8443');
    assert.equal(normaliseConsoleUrl('http://192.168.1.1'), 'http://192.168.1.1', 'left for the engine to refuse');
    assert.equal(normaliseConsoleUrl(''), '');
  });

  it('notices an expired certificate', () => {
    const now = Date.parse('2026-01-01T00:00:00Z');
    assert.equal(validityProblem({ validFrom: '2025-01-01T00:00:00Z', validTo: '2035-01-01T00:00:00Z' }, now), null);
    assert.equal(validityProblem({ validFrom: '2020-01-01T00:00:00Z', validTo: 'Jan  1 00:00:00 2021 GMT' }, now), 'expired');
    assert.equal(validityProblem({ validFrom: '2027-01-01T00:00:00Z', validTo: '2035-01-01T00:00:00Z' }, now), 'not-yet-valid');
  });
});

describe('fake engine conforms to the contract', () => {
  const URL = 'https://192.168.1.1';

  async function rejects(promise, code) {
    await assert.rejects(promise, (error) => {
      assert.ok(error instanceof AppError, `expected AppError, got ${error}`);
      assert.equal(error.code, code);
      assert.equal(typeof error.message, 'string');
      assert.ok(error.message.length > 0);
      return true;
    });
  }

  function assertState(state) {
    assert.deepEqual(Object.keys(state).sort(), ['console', 'pia', 'unifiKey']);
    assert.equal(typeof state.unifiKey.stored, 'boolean');
    assert.equal(typeof state.pia.stored, 'boolean');
    if (state.console !== null) {
      assert.deepEqual(Object.keys(state.console).sort(), ['connectName', 'fingerprint256', 'site', 'trusted', 'url']);
      assert.equal(typeof state.console.trusted, 'boolean');
    }
  }

  async function trusted() {
    const engine = createFakeEngine();
    const { url, certificate } = await engine.inspectConsole(URL);
    await engine.trustConsole(url, certificate.fingerprint256);
    return engine;
  }

  it('starts empty', async () => {
    const state = await createFakeEngine().getState();
    assertState(state);
    assert.equal(state.console, null);
    assert.equal(state.unifiKey.stored, false);
    assert.equal(state.pia.stored, false);
  });

  it('inspects a self-signed unifi.local certificate without trusting it', async () => {
    const engine = createFakeEngine();
    const result = await engine.inspectConsole(URL);
    assert.equal(result.url, URL);
    const cert = result.certificate;
    assert.deepEqual(Object.keys(cert).sort(),
      ['ca', 'connectName', 'fingerprint256', 'issuer', 'names', 'selfSigned', 'subject', 'validFrom', 'validTo']);
    assert.equal(cert.subject, 'CN=unifi.local');
    assert.equal(cert.selfSigned, true);
    assert.equal(cert.ca, false);
    assert.ok(Array.isArray(cert.names) && cert.names.includes('unifi.local'));
    assert.ok(!cert.names.includes('192.168.1.1'), 'the LAN IP is not among the names on a real console');
    assert.equal(cert.connectName, 'unifi.local');
    assert.match(cert.fingerprint256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    assert.equal((await engine.getState()).console, null);
  });

  it('validates console addresses and simulates unreachable ones', async () => {
    const engine = createFakeEngine();
    await rejects(engine.inspectConsole('not a url'), 'INVALID_INPUT');
    await rejects(engine.inspectConsole('http://192.168.1.1'), 'INVALID_INPUT');
    await rejects(engine.inspectConsole('https://192.168.1.1/network'), 'INVALID_INPUT');
    await rejects(engine.inspectConsole('https://console.invalid'), 'NETWORK');
    await rejects(engine.inspectConsole('https://console.tls-fail'), 'TLS');
  });

  it('trusts by fingerprint and refuses a changed certificate', async () => {
    const engine = createFakeEngine();
    const { certificate } = await engine.inspectConsole(URL);
    engine._rotateCertificate();
    await rejects(engine.trustConsole(URL, certificate.fingerprint256), 'CERT_CHANGED');
    await rejects(engine.trustConsole(URL, 'nope'), 'INVALID_INPUT');

    const fresh = await engine.inspectConsole(URL);
    const state = await engine.trustConsole(URL, fresh.certificate.fingerprint256);
    assertState(state);
    assert.equal(state.console.trusted, true);
    assert.equal(state.console.url, URL);
    assert.equal(state.console.site, 'default');
    assert.equal(state.console.fingerprint256, fresh.certificate.fingerprint256);
  });

  it('needs a trusted console before a key', async () => {
    await rejects(createFakeEngine().setUnifiKey('abc'), 'NOT_CONFIGURED');
  });

  it('rejects a Site Manager key with a hint that says where to make a local one', async () => {
    const engine = await trusted();
    await assert.rejects(engine.setUnifiKey('sitemanager'), (error) => {
      assert.ok(error instanceof AppError);
      assert.equal(error.code, 'UNIFI_KEY_REJECTED');
      assert.equal(error.hint, SITE_MANAGER_KEY_HINT);
      assert.match(error.hint, /Site Manager/);
      assert.match(error.hint, /unifi\.ui\.com/);
      assert.match(error.hint, /Settings → Control Plane → Integrations/);
      return true;
    });
    await assert.rejects(engine.setUnifiKey('  sitemanager\n'), { code: 'UNIFI_KEY_REJECTED' });
    assert.equal((await engine.getState()).unifiKey.stored, false);
    await rejects(engine.setUnifiKey('   '), 'INVALID_INPUT');
  });

  it('stores a verified key, then PIA credentials, then forgets both', async () => {
    const engine = await trusted();
    await rejects(engine.listTunnels(), 'NOT_CONFIGURED');
    await rejects(engine.explore('/proxy/network/integration/v1/info'), 'NOT_CONFIGURED');

    assert.deepEqual(await engine.setUnifiKey('local-key'), { verified: true, applicationVersion: FAKE_APPLICATION_VERSION });
    await rejects(engine.setPiaCredentials('', 'x'), 'INVALID_INPUT');
    const state = await engine.setPiaCredentials('p1234567', 'secret');
    assertState(state);
    assert.equal(state.unifiKey.stored, true);
    assert.equal(state.pia.stored, true);
    assert.ok(!JSON.stringify(state).includes('local-key'));
    assert.ok(!JSON.stringify(state).includes('secret'));

    const forgotten = await engine.forgetCredentials();
    assertState(forgotten);
    assert.equal(forgotten.unifiKey.stored, false);
    assert.equal(forgotten.pia.stored, false);
    assert.equal(forgotten.console.trusted, true, 'forgetting credentials keeps the trusted console');
  });

  it('lists tunnels in the contract shape', async () => {
    const engine = await trusted();
    await engine.setUnifiKey('local-key');
    const { tunnels } = await engine.listTunnels();
    assert.equal(tunnels.length, 3);
    for (const tunnel of tunnels) {
      assert.deepEqual(Object.keys(tunnel).sort(), ['enabled', 'id', 'mode', 'name', 'notes', 'status']);
      assert.ok(['file', 'manual', 'unknown'].includes(tunnel.mode));
      assert.equal(typeof tunnel.enabled, 'boolean');
      assert.ok(tunnel.status === null || typeof tunnel.status === 'string');
      assert.ok(Array.isArray(tunnel.notes));
    }
    const cz = tunnels.find((t) => t.name === 'WireGuard PIA CZ');
    assert.equal(cz.mode, 'file');
    assert.equal(cz.status, 'CONNECTING');
    assert.deepEqual(cz.notes, ['CONNECTING_LONGER_THAN_USUAL']);
    assert.ok(tunnels.some((t) => t.name === 'WireGuard US East' && t.mode === 'file'));
    assert.ok(tunnels.some((t) => /OpenVPN/.test(t.name) && t.status === null));
  });

  it('answers every preset path with a redacted body', async () => {
    const engine = await trusted();
    await engine.setUnifiKey('local-key');

    const unredacted = [];
    const walk = (value, path) => {
      if (Array.isArray(value)) return value.forEach((item, i) => walk(item, `${path}[${i}]`));
      if (value && typeof value === 'object') {
        for (const [key, child] of Object.entries(value)) {
          if (REDACT_KEY.test(key) && child !== '<redacted>') unredacted.push(`${path}.${key}`);
          walk(child, `${path}.${key}`);
        }
      } else if (typeof value === 'string') {
        for (const line of value.split('\n')) {
          if (/^\s*(PrivateKey|PresharedKey)\s*=/.test(line) && !/=\s*<redacted>\s*$/.test(line)) unredacted.push(path);
        }
      }
      return undefined;
    };

    for (const preset of EXPLORE_PRESETS) {
      const result = await engine.explore(preset);
      assert.deepEqual(Object.keys(result).sort(), ['body', 'status'], preset);
      assert.equal(result.status, 200, preset);
      walk(result.body, preset);
    }
    assert.deepEqual(unredacted, []);

    const info = await engine.explore('/proxy/network/integration/v1/info');
    assert.deepEqual(info.body, { applicationVersion: FAKE_APPLICATION_VERSION });
    const conf = await engine.explore('/proxy/network/api/s/default/rest/networkconf');
    const file = conf.body.data.find((row) => row.wireguard_client_mode === 'file');
    assert.match(file.wireguard_client_configuration_file, /PrivateKey = <redacted>/);
    const connections = await engine.explore('/proxy/network/v2/api/site/default/vpn/connections');
    assert.equal(connections.body.connections[0].network_id, file._id);

    const missing = await engine.explore('/proxy/network/api/s/default/rest/nothing');
    assert.equal(missing.status, 404);
  });

  it('refuses explorer paths outside /proxy/network/', async () => {
    const engine = await trusted();
    await engine.setUnifiKey('local-key');
    for (const bad of ['/api/self', '/proxy/network/../api/auth', '/proxy/network//x', 'https://x/proxy/network/', '/proxy/network/a b']) {
      await rejects(engine.explore(bad), 'INVALID_INPUT');
    }
  });

  it('keeps engines independent', async () => {
    const a = await trusted();
    await a.setUnifiKey('local-key');
    const b = createFakeEngine();
    assert.equal((await b.getState()).unifiKey.stored, false);
  });
});
