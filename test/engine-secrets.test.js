import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createSecretStore, parseStoreStatus, decodeXml, POWERSHELL, POWERSHELL_ARGS, STORE_SCRIPT,
} from '../scripts/engine/secrets.mjs';

const SECRETS = {
  piaUsername: 'p9999999',
  piaPassword: 'hunter2-not-a-real-password',
  unifiApiKey: 'dummy-unifi-key-0123456789',
};

const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
const decode = (text) => JSON.parse(Buffer.from(text, 'base64').toString('utf8'));

/** Records every call and answers as told. Never runs PowerShell. */
function fakeExec(answer) {
  const calls = [];
  const exec = async (file, args, options) => {
    calls.push({ file, args: [...args], stdin: options.stdin, request: decode(options.stdin) });
    const result = typeof answer === 'function' ? answer(decode(options.stdin)) : answer;
    return typeof result === 'string' || result === undefined
      ? { exitCode: 0, stdout: result ?? '' }
      : result;
  };
  exec.calls = calls;
  return exec;
}

function tempStore() {
  const root = mkdtempSync(join(tmpdir(), 'engine-secrets-'));
  return { root, dir: join(root, 'pia-unifi-sync'), cleanUp: () => rmSync(root, { recursive: true, force: true }) };
}

function assertNoSecret(err) {
  const text = [err.message, err.hint, err.detail, err.stack].join('\n');
  for (const value of Object.values(SECRETS)) {
    assert.ok(!text.includes(value), 'no secret may appear in an error');
  }
  return true;
}

describe('secret store with a fake PowerShell', () => {
  test('refuses a relative directory', () => {
    assert.throws(() => createSecretStore({ storeDir: 'relative\\dir', exec: fakeExec('') }), (err) => err.code === 'INVALID_INPUT');
  });

  test('secrets travel on stdin only; the command line is a constant', async () => {
    const store = tempStore();
    try {
      const exec = fakeExec(() => encode({ ok: true, stored: { PiaUsername: true, PiaPassword: true, UnifiApiKey: true } }));
      const secrets = createSecretStore({ storeDir: store.dir, exec });

      assert.deepEqual(await secrets.write(SECRETS), { piaUsername: true, piaPassword: true, unifiApiKey: true });

      const [call] = exec.calls;
      assert.equal(call.file, POWERSHELL);
      assert.deepEqual(call.args, [...POWERSHELL_ARGS]);
      const argv = call.args.join(' ');
      const script = Buffer.from(call.args.at(-1), 'base64').toString('utf16le');
      assert.equal(script, STORE_SCRIPT);
      for (const value of Object.values(SECRETS)) {
        assert.ok(!argv.includes(value) && !script.includes(value), 'no secret on the command line');
        assert.ok(!call.stdin.includes(value), 'stdin is encoded, not plain');
      }
      assert.deepEqual(call.request, {
        dir: store.dir,
        op: 'write',
        values: { PiaUsername: SECRETS.piaUsername, PiaPassword: SECRETS.piaPassword, UnifiApiKey: SECRETS.unifiApiKey },
      });
    } finally {
      store.cleanUp();
    }
  });

  test('a partial write sends only what was given; empty values are not sent', async () => {
    const store = tempStore();
    try {
      const exec = fakeExec(() => encode({ ok: true, stored: { UnifiApiKey: true } }));
      const secrets = createSecretStore({ storeDir: store.dir, exec });
      assert.deepEqual(await secrets.write({ unifiApiKey: SECRETS.unifiApiKey, piaPassword: '' }),
        { piaUsername: false, piaPassword: false, unifiApiKey: true });
      assert.deepEqual(exec.calls[0].request.values, { UnifiApiKey: SECRETS.unifiApiKey });
    } finally {
      store.cleanUp();
    }
  });

  test('bad writes are refused before PowerShell runs', async () => {
    const exec = fakeExec('');
    const secrets = createSecretStore({ storeDir: tmpdir(), exec });
    await assert.rejects(secrets.write({}), (err) => err.code === 'INVALID_INPUT');
    await assert.rejects(secrets.write({ piaPassword: 5 }), (err) => err.code === 'INVALID_INPUT');
    await assert.rejects(secrets.write({ unifiApiKey: 'x', other: 'y' }), (err) => err.code === 'INVALID_INPUT');
    await assert.rejects(secrets.write(null), (err) => err.code === 'INVALID_INPUT');
    assert.equal(exec.calls.length, 0);
  });

  test('read maps absent values to empty strings', async () => {
    const exec = fakeExec(() => encode({ ok: true, values: { UnifiApiKey: SECRETS.unifiApiKey } }));
    const secrets = createSecretStore({ storeDir: tmpdir(), exec });
    assert.deepEqual(await secrets.read(), { piaUsername: '', piaPassword: '', unifiApiKey: SECRETS.unifiApiKey });
    assert.equal(exec.calls[0].request.op, 'read');
  });

  test('failures become STORAGE errors that carry no secret and no PowerShell output', async () => {
    const answers = [
      { exitCode: 1, stdout: `garbage ${SECRETS.piaPassword}`, stderr: `echo ${SECRETS.piaPassword}` },
      encode({ ok: false, error: 'UNREADABLE' }),
      encode({ ok: false, error: 'WRITE_FAILED' }),
      encode({ ok: false, error: `something ${SECRETS.unifiApiKey}` }),
    ];
    for (const answer of answers) {
      const secrets = createSecretStore({ storeDir: tmpdir(), exec: fakeExec(answer) });
      await assert.rejects(secrets.write(SECRETS), (err) => err.code === 'STORAGE' && assertNoSecret(err));
      await assert.rejects(secrets.read(), (err) => err.code === 'STORAGE' && assertNoSecret(err));
    }

    const throwing = async () => { throw new Error(`spawn failed ${SECRETS.piaPassword}`); };
    const secrets = createSecretStore({ storeDir: tmpdir(), exec: throwing });
    await assert.rejects(secrets.write(SECRETS), (err) => err.code === 'STORAGE' && assertNoSecret(err));
  });

  test('clear and protectDirectory are single operations', async () => {
    const exec = fakeExec(() => encode({ ok: true }));
    const secrets = createSecretStore({ storeDir: tmpdir(), exec });
    await secrets.clear();
    await secrets.protectDirectory();
    assert.deepEqual(exec.calls.map((call) => call.request.op), ['clear', 'protect']);
  });

  test('status reads the XML without PowerShell, in either encoding', async () => {
    const store = tempStore();
    try {
      const exec = fakeExec('');
      const secrets = createSecretStore({ storeDir: store.dir, exec });
      assert.deepEqual(await secrets.status(), { piaUsername: false, piaPassword: false, unifiApiKey: false, version: null });

      const xml = '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj RefId="0">'
        + '<TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS>'
        + '<I32 N="Version">2</I32><SS N="UnifiApiKey">01000000d08c9ddf0115d1118c7a00c04fc297eb</SS></MS></Obj></Objs>';
      mkdirSync(store.dir, { recursive: true });
      writeFileSync(join(store.dir, 'credentials.xml'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(xml, 'utf16le')]));
      assert.deepEqual(await secrets.status(), { piaUsername: false, piaPassword: false, unifiApiKey: true, version: 2 });

      writeFileSync(join(store.dir, 'credentials.xml'), xml.replace('>2<', '>1<'), 'utf8');
      assert.deepEqual(await secrets.status(), { piaUsername: false, piaPassword: false, unifiApiKey: true, version: 1 });
      assert.equal(exec.calls.length, 0);
    } finally {
      store.cleanUp();
    }
  });

  test('parseStoreStatus ignores empty SecureStrings and lookalikes', () => {
    assert.deepEqual(parseStoreStatus('<SS N="PiaUsername"></SS><S N="PiaPassword">plain</S>'),
      { piaUsername: false, piaPassword: false, unifiApiKey: false, version: null });
    assert.equal(decodeXml(Buffer.from([0xef, 0xbb, 0xbf, 0x61])), 'a');
  });
});

describe('secret store through real DPAPI', { skip: process.platform !== 'win32' ? 'DPAPI exists only on Windows' : false }, () => {
  test('round-trips dummy values, writes Version 2 when partial and Version 1 when complete', { timeout: 120_000 }, async () => {
    const store = tempStore();
    try {
      const secrets = createSecretStore({ storeDir: store.dir });
      const file = join(store.dir, 'credentials.xml');

      assert.deepEqual(await secrets.read(), { piaUsername: '', piaPassword: '', unifiApiKey: '' }, 'nothing stored yet');

      assert.deepEqual(await secrets.write({ unifiApiKey: SECRETS.unifiApiKey }),
        { piaUsername: false, piaPassword: false, unifiApiKey: true });
      assert.deepEqual(await secrets.status(), { piaUsername: false, piaPassword: false, unifiApiKey: true, version: 2 });
      assert.deepEqual(await secrets.read(), { piaUsername: '', piaPassword: '', unifiApiKey: SECRETS.unifiApiKey });

      assert.deepEqual(await secrets.write({ piaUsername: SECRETS.piaUsername, piaPassword: SECRETS.piaPassword }),
        { piaUsername: true, piaPassword: true, unifiApiKey: true }, 'a partial write merges with what is stored');
      assert.deepEqual(await secrets.status(), { piaUsername: true, piaPassword: true, unifiApiKey: true, version: 1 },
        'a complete set is the launcher\'s own Version 1 format');
      assert.deepEqual(await secrets.read(), SECRETS);

      const onDisk = decodeXml(readFileSync(file));
      for (const value of Object.values(SECRETS)) {
        assert.ok(!onDisk.includes(value), 'the file holds no plaintext');
      }

      const unicode = 'pässwörd "quoted" \\ back€slash';
      await secrets.write({ piaPassword: unicode });
      assert.equal((await secrets.read()).piaPassword, unicode, 'non-ASCII survives the trip');

      await secrets.clear();
      assert.equal(existsSync(file), false);
      assert.deepEqual(await secrets.status(), { piaUsername: false, piaPassword: false, unifiApiKey: false, version: null });
    } finally {
      store.cleanUp();
    }
  });
});
