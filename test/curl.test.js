/**
 * The command-injection fix, from three angles:
 *
 *  1. the escaping grammar itself,
 *  2. the invariant that the shell only ever receives a constant string,
 *  3. a demonstration that the *previous* approach really was exploitable, so
 *     these tests are known to have teeth rather than merely passing.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  quoteConfigValue,
  buildCurlConfig,
  parseCurlOutput,
  parseCurlVersion,
  isVersionAtLeast,
  CURL_COMMAND,
  MIN_CURL_VERSION_SCHANNEL,
} from '../resources/js/core/curl.js';
import { HttpClient } from '../resources/js/core/http.js';
import { PiaClient, TOKEN_ENDPOINT } from '../resources/js/core/pia.js';
import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { shellExec, recordingExec } from './helpers.js';

const isWindows = process.platform === 'win32';

/** Payloads that a shell would act on if it ever saw them. */
const HOSTILE = [
  'a`id`b',
  'a$(id)b',
  'a;rm -rf /;b',
  'a && echo pwned',
  'a | tee /tmp/pwn',
  'a > /tmp/pwn',
  '%PATH%',
  '%USERPROFILE%',
  '$HOME',
  '"; curl evil.example ; "',
  "'; id; '",
  'back\\slash',
  'quote"inside',
  'both"and\\slash',
  'newline\nsecond',
  'tab\tseparated',
  'unicode—em–dash…✓',
  '{"nested":"json"}',
];

describe('quoteConfigValue', () => {
  test('wraps in quotes and escapes only what curl defines', () => {
    assert.equal(quoteConfigValue('plain'), '"plain"');
    assert.equal(quoteConfigValue('with"quote'), '"with\\"quote"');
    assert.equal(quoteConfigValue('with\\slash'), '"with\\\\slash"');
    assert.equal(quoteConfigValue('a\nb'), '"a\\nb"');
    assert.equal(quoteConfigValue('a\tb'), '"a\\tb"');
    assert.equal(quoteConfigValue('a\rb'), '"a\\rb"');
    assert.equal(quoteConfigValue('a\vb'), '"a\\vb"');
  });

  test('leaves shell metacharacters completely alone — they are just text here', () => {
    assert.equal(quoteConfigValue('a`id`b'), '"a`id`b"');
    assert.equal(quoteConfigValue('a$(id)b'), '"a$(id)b"');
    assert.equal(quoteConfigValue('%PATH%'), '"%PATH%"');
    assert.equal(quoteConfigValue('a && b | c > d'), '"a && b | c > d"');
  });

  test('rejects control characters curl cannot represent', () => {
    for (const bad of ['\u0000', '\u0007', '\u001b', '\u007f', '\u0008']) {
      assert.throws(() => quoteConfigValue(`a${bad}b`), (err) => {
        assert.ok(err instanceof AppError);
        assert.equal(err.code, ErrorCode.INVALID_INPUT);
        return true;
      });
    }
  });

  test('rejects non-strings rather than coercing them', () => {
    assert.throws(() => quoteConfigValue(undefined), AppError);
    assert.throws(() => quoteConfigValue(42), AppError);
  });
});

describe('buildCurlConfig', () => {
  test('refuses anything that is not https', () => {
    for (const url of ['http://example.com', 'file:///etc/passwd', 'ftp://example.com', 'HTTPS://example.com']) {
      assert.throws(() => buildCurlConfig({ url }), (err) => {
        assert.ok(err instanceof AppError);
        return true;
      }, `expected ${url} to be rejected`);
    }
  });

  test('pins the transport shut', () => {
    const config = buildCurlConfig({ url: 'https://example.com/' });
    assert.match(config, /^proto = "=https"$/m);
    assert.match(config, /^proto-redir = "=https"$/m);
    assert.match(config, /^tlsv1\.2$/m);
    assert.doesNotMatch(config, /^location$/m, 'redirects must not be followed while carrying credentials');
    assert.doesNotMatch(config, /insecure/);
  });

  test('carries a hostile body without the config file losing its shape', () => {
    for (const payload of HOSTILE) {
      const body = JSON.stringify({ username: 'p1234567', password: payload });
      const config = buildCurlConfig({ url: 'https://example.com/', method: 'POST', body });

      const dataLines = config.split('\n').filter((line) => line.startsWith('data-raw = '));
      assert.equal(dataLines.length, 1, `payload ${JSON.stringify(payload)} split across lines`);
      assert.match(config, /^request = "POST"$/m);
    }
  });

  test('uses data-raw so a leading @ is not read as a filename', () => {
    const config = buildCurlConfig({ url: 'https://example.com/', method: 'POST', body: '@/etc/passwd' });
    assert.match(config, /^data-raw = "@\/etc\/passwd"$/m);
    assert.doesNotMatch(config, /^data = /m);
  });

  test('emits certificate pinning options when asked', () => {
    const config = buildCurlConfig({
      url: 'https://berlin401:1337/addKey',
      query: [['pt', 'tok en'], ['pubkey', 'abc+/=']],
      caCertPath: '/tmp/pia ca.pem',
      connectTo: { host: 'berlin401', port: 1337, toHost: '193.176.86.1', toPort: 1337 },
    });

    assert.match(config, /^cacert = "\/tmp\/pia ca\.pem"$/m);
    assert.match(config, /^connect-to = "berlin401:1337:193\.176\.86\.1:1337"$/m);
    assert.match(config, /^get$/m);
    assert.match(config, /^data-urlencode = "pt=tok en"$/m);
    assert.match(config, /^data-urlencode = "pubkey=abc\+\/="$/m);
  });

  test('rejects a query parameter name that could inject another option', () => {
    assert.throws(
      () => buildCurlConfig({ url: 'https://example.com/', query: [['pt"\ninsecure\nx', 'v']] }),
      AppError,
    );
  });
});

describe('the Windows revocation accommodation', () => {
  test('is absent unless asked for', () => {
    const config = buildCurlConfig({ url: 'https://example.com/', caCertPath: '/tmp/ca.pem' });
    assert.doesNotMatch(config, /ssl-revoke-best-effort/);
  });

  test('relaxes only unknown revocation, never verification', () => {
    const config = buildCurlConfig({
      url: 'https://example.com/',
      caCertPath: '/tmp/ca.pem',
      tolerateUnknownRevocation: true,
    });

    assert.match(config, /^ssl-revoke-best-effort$/m);
    // The distinction that matters: these would accept a revoked or unverifiable
    // certificate, and must never appear.
    assert.doesNotMatch(config, /ssl-no-revoke/);
    assert.doesNotMatch(config, /insecure/);
    assert.match(config, /^cacert = /m, 'the chain is still pinned');
  });

  test('is applied only to pinned requests, and only when configured', async () => {
    const withFlag = recordingExec();
    const client = new HttpClient(withFlag, { tolerateUnknownRevocation: true });

    await client.send({ url: 'https://example.com/plain' });
    await client.send({ url: 'https://example.com/pinned', caCertPath: '/tmp/ca.pem' });

    assert.doesNotMatch(withFlag.calls[0].stdIn, /ssl-revoke-best-effort/,
      'a request validated against the system store has revocation data available');
    assert.match(withFlag.calls[1].stdIn, /ssl-revoke-best-effort/);
  });

  test('raises the required curl version, because the option needs 7.70', async () => {
    const old = { exitCode: 0, stdOut: 'curl 7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0', stdErr: '' };

    // Fine everywhere else: 7.68 satisfies the --connect-to minimum.
    await new HttpClient(async () => old).preflight();

    await assert.rejects(
      () => new HttpClient(async () => old, { tolerateUnknownRevocation: true }).preflight(),
      (err) => {
        assert.equal(err.code, ErrorCode.CURL_TOO_OLD);
        assert.match(err.message, new RegExp(MIN_CURL_VERSION_SCHANNEL.join('\\.')));
        return true;
      },
    );
  });
});

describe('the shell only ever sees a constant', () => {
  test('CURL_COMMAND has no interpolation and disables curlrc', () => {
    assert.equal(CURL_COMMAND, 'curl -q --config -');
    assert.doesNotMatch(CURL_COMMAND, /[$`"'|&;><]/);
  });

  test('every request the PIA client makes runs the same command string', async () => {
    const exec = recordingExec({ exitCode: 0, stdOut: '{"token":"t"}\n200', stdErr: '' });
    const client = new PiaClient(new HttpClient(exec), () => '/tmp/ca.pem');

    await client.login('p1234567', 'a`id`b && rm -rf / #');

    assert.equal(exec.calls.length, 1);
    assert.equal(exec.calls[0].command, CURL_COMMAND);
    assert.ok(exec.calls[0].stdIn.includes('a`id`b && rm -rf / #'),
      'the payload must travel on stdin, not in the command');
  });

  test('the credential never appears in the command string', async () => {
    const secret = 'hunter2-super-secret';
    const exec = recordingExec({ exitCode: 0, stdOut: '{"token":"t"}\n200', stdErr: '' });

    await new PiaClient(new HttpClient(exec), () => '/tmp/ca.pem').login('p1234567', secret);

    assert.equal(exec.calls[0].command.includes(secret), false);
    assert.equal(exec.calls[0].command.includes('p1234567'), false);
    assert.equal(exec.calls[0].command.includes(TOKEN_ENDPOINT), false);
  });
});

describe('a hostile password reaches a real shell without executing', { skip: isWindows ? 'POSIX only' : false }, () => {
  test('nothing is executed, and the old escaping would have executed it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pia-wg-inject-'));
    const marker = join(dir, 'pwned');

    try {
      // A password that writes a file if a shell ever parses it.
      const password = `x$(touch ${marker})x`;

      // --- what the app does now -------------------------------------------
      const config = buildCurlConfig({
        url: 'https://127.0.0.1:1/never',
        method: 'POST',
        body: JSON.stringify({ username: 'p1', password }),
      });
      const result = await shellExec(CURL_COMMAND, { stdIn: config });

      assert.notEqual(result.exitCode, 0, 'connecting to port 1 should fail, proving curl really ran');
      assert.equal(existsSync(marker), false, 'the shell must never have evaluated the password');

      // --- what v1 did, reproduced verbatim from renderer.js ---------------
      // `const escapedJson = JSON.stringify(data).replace(/"/g, '\\"')`
      const v1Escaped = JSON.stringify({ username: 'p1', password }).replace(/"/g, '\\"');
      const v1Command = `curl -s -X POST -H "Content-Type: application/json" -d "${v1Escaped}" "https://127.0.0.1:1/never"`;
      await shellExec(v1Command);

      assert.equal(existsSync(marker), true,
        'sanity check: the v1 escaping was exploitable, so this test can actually detect a regression');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('parseCurlOutput', () => {
  test('splits the status marker off the body', () => {
    assert.deepEqual(parseCurlOutput('{"a":1}\n200'), { body: '{"a":1}', status: 200 });
    assert.deepEqual(parseCurlOutput('line1\nline2\n404'), { body: 'line1\nline2', status: 404 });
    assert.deepEqual(parseCurlOutput('\n204'), { body: '', status: 204 });
  });

  test('is not confused by a body that itself ends in digits', () => {
    assert.deepEqual(parseCurlOutput('total 500\n200'), { body: 'total 500', status: 200 });
  });

  test('reports status 0 when curl wrote nothing usable', () => {
    assert.deepEqual(parseCurlOutput(''), { body: '', status: 0 });
    assert.deepEqual(parseCurlOutput('no marker'), { body: 'no marker', status: 0 });
    assert.deepEqual(parseCurlOutput('body\nnotastatus'), { body: 'body\nnotastatus', status: 0 });
  });
});

describe('curl version detection', () => {
  test('parses the real banner', () => {
    assert.deepEqual(parseCurlVersion('curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0'), [8, 5, 0]);
    assert.deepEqual(parseCurlVersion('curl 7.49 (x86_64) libcurl/7.49'), [7, 49, 0]);
    assert.equal(parseCurlVersion('bash: curl: command not found'), null);
    assert.equal(parseCurlVersion(''), null);
  });

  test('compares versions the way a human would', () => {
    assert.equal(isVersionAtLeast([7, 49, 0], [7, 49, 0]), true);
    assert.equal(isVersionAtLeast([8, 5, 0], [7, 49, 0]), true);
    assert.equal(isVersionAtLeast([7, 48, 9], [7, 49, 0]), false);
    assert.equal(isVersionAtLeast([6, 99, 99], [7, 49, 0]), false);
  });
});
