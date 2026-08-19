/**
 * Regression fences.
 *
 * Each of these encodes a property that a plausible future edit could quietly
 * undo — reaching for `-k` to make a stubborn handshake work, pasting a font
 * CDN link back into the head, adding a `console.log` while debugging a token.
 * A unit test cannot catch those; reading the source can.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync, statSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';

import { PIA_CA_PEM, PIA_CA_SHA256 } from '../resources/js/core/pia-ca.js';
import { TOKEN_ENDPOINT, SERVER_LIST_ENDPOINT } from '../resources/js/core/pia.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const APP_JS = join(ROOT, 'resources', 'js');

/** Every first-party source file — the vendored libraries are not ours to police. */
function appSources() {
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'vendor') continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (extname(entry.name) === '.js') files.push(path);
    }
  };
  walk(APP_JS);
  return files;
}

// Repo-relative and always forward-slashed, so assertions read the same on
// Windows as they do everywhere else.
const SOURCES = appSources().map((path) => ({
  path,
  rel: path.slice(ROOT.length + 1).split(sep).join('/'),
  text: readFileSync(path, 'utf8'),
}));

describe('certificate verification is never switched off', () => {
  test('no source reaches for --insecure', () => {
    for (const source of SOURCES) {
      const code = stripComments(source.text);
      assert.doesNotMatch(code, /--insecure/, `${source.rel} disables certificate verification`);
      assert.doesNotMatch(code, /\binsecure\b\s*(?:=|:)/, `${source.rel} sets an insecure option`);
      assert.doesNotMatch(code, /curl[^\n'"]*\s-k\b/, `${source.rel} passes -k to curl`);
      assert.doesNotMatch(code, /ssl-no-revoke|no-check-certificate/, `${source.rel} weakens verification`);
    }
  });

  test('the pinned CA is a real, current certificate matching its recorded fingerprint', () => {
    const certificate = new X509Certificate(PIA_CA_PEM);

    assert.equal(certificate.fingerprint256, PIA_CA_SHA256, 'the bundled CA does not match its recorded fingerprint');
    assert.equal(certificate.ca, true, 'the bundled certificate is not a CA');
    assert.match(certificate.subject, /Private Internet Access/);
    assert.ok(new Date(certificate.validTo) > new Date(), 'the bundled CA has expired');
  });
});

describe('nothing user-controlled reaches a shell', () => {
  test('execCommand is called from exactly one place', () => {
    const callers = SOURCES.filter((source) => /Neutralino\.os\.execCommand/.test(source.text));

    assert.deepEqual(callers.map((source) => source.rel), ['resources/js/platform/neutralino.js'],
      'process execution must stay behind the platform adapter');
  });

  test('no exec call is handed an interpolated command', () => {
    // The v1 bug in one line: `Neutralino.os.execCommand(`curl -s -d "${json}" ...`)`.
    // Matching the *call site* rather than any string mentioning curl keeps this
    // guard precise — user-facing messages are allowed to name the tool.
    for (const source of SOURCES) {
      const code = stripComments(source.text);
      assert.doesNotMatch(code, /exec(?:Command)?\(\s*`[^`]*\$\{/,
        `${source.rel} builds a command by interpolation`);
      assert.doesNotMatch(code, /exec(?:Command)?\(\s*['"][^'"]*['"]\s*\+/,
        `${source.rel} concatenates a command string`);
    }
  });

  test('the network layer runs only its two constant commands', () => {
    const http = stripComments(readFileSync(join(APP_JS, 'core', 'http.js'), 'utf8'));
    const invocations = [...http.matchAll(/this\.exec\(([^,)]+)/g)].map(([, argument]) => argument.trim());

    assert.deepEqual(invocations.sort(), ["'curl --version'", 'CURL_COMMAND'].sort());
  });

  test('the only command the app can run is a constant', () => {
    const curl = readFileSync(join(APP_JS, 'core', 'curl.js'), 'utf8');
    assert.match(curl, /export const CURL_COMMAND = 'curl -q --config -';/);
  });
});

describe('the app talks to nobody but PIA', () => {
  const ALLOWED_ORIGINS = new Set([
    new URL(TOKEN_ENDPOINT).origin,
    new URL(SERVER_LIST_ENDPOINT).origin,
  ]);

  test('every absolute URL in a string literal is a PIA endpoint', () => {
    for (const source of SOURCES) {
      const code = stripComments(source.text);
      for (const [, url] of code.matchAll(/['"`](https?:\/\/[^'"`\s${]+)['"`]/g)) {
        assert.ok(ALLOWED_ORIGINS.has(new URL(url).origin),
          `${source.rel} contacts ${url}, which is not a Private Internet Access endpoint`);
      }
    }
  });

  test('the markup loads nothing from a remote origin', () => {
    const html = readFileSync(join(ROOT, 'resources', 'index.html'), 'utf8');

    for (const [, attribute] of html.matchAll(/(?:src|href)\s*=\s*"([^"]+)"/g)) {
      assert.doesNotMatch(attribute, /^(?:https?:)?\/\//,
        `index.html loads ${attribute} from the network — this app must work offline`);
    }
    assert.doesNotMatch(html, /fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\./);
  });

  test('the stylesheet loads nothing from a remote origin', () => {
    const css = readFileSync(join(ROOT, 'resources', 'css', 'app.css'), 'utf8');

    for (const [, url] of css.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)) {
      assert.doesNotMatch(url, /^(?:https?:)?\/\//, `app.css loads ${url} from the network`);
    }
  });

  test('a Content-Security-Policy forbids remote content at runtime', () => {
    const html = readFileSync(join(ROOT, 'resources', 'index.html'), 'utf8');
    const meta = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(html);

    assert.ok(meta, 'index.html has no Content-Security-Policy');

    const policy = meta[1].replace(/\s+/g, ' ');
    for (const directive of [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
    ]) {
      assert.ok(policy.includes(directive), `the policy is missing ${directive}`);
    }
  });
});

describe('secrets stay out of the logs', () => {
  test('no shipped source logs to the console', () => {
    for (const source of SOURCES) {
      assert.doesNotMatch(stripComments(source.text), /\bconsole\s*\./,
        `${source.rel} writes to the console, which is where credentials end up by accident`);
    }
  });

  test('the token and password are never interpolated into an error message', () => {
    for (const source of SOURCES) {
      const code = stripComments(source.text);
      assert.doesNotMatch(code, /\$\{\s*(?:password|token|authToken|state\.token)\s*\}/,
        `${source.rel} puts a credential into a string`);
    }
  });
});

describe('every asset the markup references exists', () => {
  test('no dangling src or href', () => {
    const html = readFileSync(join(ROOT, 'resources', 'index.html'), 'utf8');

    for (const [, attribute] of html.matchAll(/(?:src|href)\s*=\s*"([^"]+)"/g)) {
      if (attribute.startsWith('#') || attribute.startsWith('data:')) continue;
      // The client library is generated by `neu update`, so it is legitimately absent here.
      if (attribute.endsWith('js/neutralino.js')) continue;

      const path = join(ROOT, 'resources', attribute);
      assert.ok(existsSync(path), `index.html references ${attribute}, which does not exist`);
    }
  });

  test('the stylesheet\'s font file is present and is a real woff2', () => {
    const font = join(ROOT, 'resources', 'assets', 'fonts', 'inter-latin-variable.woff2');

    assert.ok(existsSync(font), 'the vendored font is missing');
    assert.ok(statSync(font).size > 10_000, 'the vendored font looks truncated');
    assert.equal(readFileSync(font).subarray(0, 4).toString('latin1'), 'wOF2');
  });

  test('every vendored library ships its licence', () => {
    const vendor = join(APP_JS, 'vendor');
    const licences = readdirSync(vendor).filter((name) => name.startsWith('LICENSE-'));

    for (const library of ['tweetnacl', 'qrcode']) {
      assert.ok(licences.some((name) => name.toLowerCase().includes(library)),
        `resources/js/vendor has no licence file for ${library}`);
    }
  });
});

describe('the build cannot silently produce nothing', () => {
  test('verify-build exits non-zero on an empty dist', () => {
    const empty = mkdtempSync(join(tmpdir(), 'pia-wg-dist-'));

    try {
      const result = spawnSync(process.execPath, [join(ROOT, 'scripts', 'verify-build.mjs'), '--dist', empty], {
        encoding: 'utf8',
      });

      assert.notEqual(result.status, 0, 'an empty dist must fail the build');
      assert.match(result.stderr, /empty/i);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  test('verify-build exits non-zero when dist does not exist', () => {
    const result = spawnSync(
      process.execPath,
      [join(ROOT, 'scripts', 'verify-build.mjs'), '--dist', join(tmpdir(), 'definitely-not-here-9f3a')],
      { encoding: 'utf8' },
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /no dist directory/i);
  });

  test('verify-build rejects a directory of stub files', () => {
    const directory = mkdtempSync(join(tmpdir(), 'pia-wg-dist-'));

    try {
      writeFileSync(join(directory, 'pia-wireguard-generator-win_x64.exe'), 'not a real binary');

      const result = spawnSync(process.execPath, [join(ROOT, 'scripts', 'verify-build.mjs'), '--dist', directory], {
        encoding: 'utf8',
      });

      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /no application binary/i);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test('the build script runs neu update first, and verifies afterwards', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

    assert.match(pkg.scripts.build, /neu update\s*&&/, '`neu build` without `neu update` produces nothing');
    assert.match(pkg.scripts.build, /verify-build\.mjs/, 'the build must be checked, not trusted');
  });
});

/** Crude, but enough to keep prose in comments from tripping the source checks. */
function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
}
