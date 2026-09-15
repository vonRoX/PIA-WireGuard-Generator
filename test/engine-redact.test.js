import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { redact, redactString, REDACTED } from '../scripts/engine/redact.mjs';

// Shaped like a WireGuard key, and used nowhere but here.
const PRIVATE_KEY = 'cGhvbnktcHJpdmF0ZS1rZXktZm9yLXJlZGFjdGlvbi0x';
const PRESHARED = 'cGhvbnktcHJlc2hhcmVkLWtleS1mb3ItcmVkYWN0aW9u';

const conf = [
  '[Interface]',
  `PrivateKey = ${PRIVATE_KEY}`,
  'Address = 10.7.0.2/32',
  'DNS = 10.0.0.243',
  '',
  '[Peer]',
  'PublicKey = cHVibGljLWtleS1pcy1ub3Qtc2VjcmV0LWJ1dC1tYXRjaGVz',
  `PresharedKey=${PRESHARED}`,
  'Endpoint = 203.0.113.9:1337',
  'AllowedIPs = 0.0.0.0/0',
].join('\r\n');

/** A file-mode VPN Client row as a UCG Ultra returns it. */
const fileRow = {
  _id: '66f0c0ffee0000000000abcd',
  name: 'PIA Czech',
  purpose: 'vpn-client',
  vpn_type: 'wireguard-client',
  wireguard_client_mode: 'file',
  wireguard_client_configuration_file: conf,
  wireguard_client_configuration_filename: 'PIA-czech.conf',
  x_wireguard_private_key: PRIVATE_KEY,
  enabled: true,
};

describe('redact', () => {
  test('a file-mode row keeps its shape and loses every secret', () => {
    const payload = { meta: { rc: 'ok' }, data: [fileRow, { _id: 'b', name: 'LAN', purpose: 'corporate' }] };
    const out = redact(payload);
    const json = JSON.stringify(out);

    assert.ok(!json.includes(PRIVATE_KEY), 'the private key must appear nowhere');
    assert.ok(!json.includes(PRESHARED), 'the preshared key must appear nowhere');
    assert.equal(out.data[0].x_wireguard_private_key, REDACTED);
    assert.match(out.data[0].wireguard_client_configuration_file, /^PrivateKey = <redacted>$/m);
    assert.match(out.data[0].wireguard_client_configuration_file, /^PresharedKey = <redacted>$/m);
    assert.match(out.data[0].wireguard_client_configuration_file, /^Address = 10\.7\.0\.2\/32\r$/m, 'the rest of the file is left alone');
    assert.equal(out.data[0].wireguard_client_configuration_filename, 'PIA-czech.conf');
    assert.equal(out.data[1].name, 'LAN');
    assert.equal(out.meta.rc, 'ok');
  });

  test('the input is not modified', () => {
    const input = structuredClone(fileRow);
    redact(input);
    assert.deepEqual(input, fileRow);
  });

  test('matching keys are redacted whatever their value, case-insensitively', () => {
    const out = redact({
      apiKey: 'a', X_PASSPHRASE: 'b', Secret: { nested: 'c' }, password: 42, token: null,
      wireguard_client_psk: ['d'], x_ssh_keys: 'e', refreshToken: true, name: 'plain',
    });
    for (const key of ['apiKey', 'X_PASSPHRASE', 'Secret', 'password', 'token', 'wireguard_client_psk', 'x_ssh_keys', 'refreshToken']) {
      assert.equal(out[key], REDACTED, key);
    }
    assert.equal(out.name, 'plain');
  });

  test('nested arrays and objects are walked all the way down', () => {
    const out = redact([[[{ deep: [{ privateKey: 'k1' }, `PrivateKey = ${PRIVATE_KEY}`] }]]]);
    assert.equal(out[0][0][0].deep[0].privateKey, REDACTED);
    assert.equal(out[0][0][0].deep[1], 'PrivateKey = <redacted>');
  });

  test('cycles are cut, shared siblings are not mistaken for cycles', () => {
    const shared = { label: 'same' };
    const node = { a: shared, b: shared, list: [] };
    node.self = node;
    node.list.push(node);
    const out = redact(node);
    assert.equal(out.self, '<circular>');
    assert.equal(out.list[0], '<circular>');
    assert.deepEqual(out.a, { label: 'same' });
    assert.deepEqual(out.b, { label: 'same' });
    assert.doesNotThrow(() => JSON.stringify(out));
  });

  test('plain text bodies are redacted too, including escaped newlines', () => {
    assert.equal(redactString(`x\nPrivateKey = ${PRIVATE_KEY}\ny`), 'x\nPrivateKey = <redacted>\ny');
    const text = redactString(`{"file":"[Interface]\\nPrivateKey = ${PRIVATE_KEY}\\nAddress = 1"}`);
    assert.ok(!text.includes(PRIVATE_KEY));
    assert.equal(redact(`  privatekey=${PRIVATE_KEY}`), '  privatekey = <redacted>');
  });

  test('scalars pass through', () => {
    assert.equal(redact(5), 5);
    assert.equal(redact(null), null);
    assert.equal(redact(false), false);
    assert.equal(redact('hello'), 'hello');
  });
});
