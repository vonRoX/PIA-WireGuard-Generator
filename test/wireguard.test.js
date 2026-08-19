import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
  generateKeyPair,
  buildConfig,
  validateAddKeyResponse,
  maskPrivateKey,
  configFileName,
  isBase64Key,
  isIpv4,
  isPort,
} from '../resources/js/core/wireguard.js';
import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { loadNacl, nodeScalarMultBase } from './helpers.js';

const nacl = loadNacl();

/** The provider the app installs in the browser. */
const browserCrypto = {
  randomBytes(length) {
    const bytes = new Uint8Array(length);
    webcrypto.getRandomValues(bytes);
    return bytes;
  },
  scalarMultBase(secretKey) {
    return nacl.box.keyPair.fromSecretKey(secretKey).publicKey;
  },
};

const PEER = {
  peerIp: '10.13.14.15',
  serverKey: 'sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
  serverIp: '193.176.86.1',
  serverPort: 1337,
};

describe('key generation', () => {
  test('agrees with Node\'s own X25519 for every generated key', () => {
    for (let i = 0; i < 40; i++) {
      const captured = [];
      const keys = generateKeyPair({
        randomBytes: (length) => {
          const bytes = browserCrypto.randomBytes(length);
          captured.push(bytes);
          return bytes;
        },
        scalarMultBase: browserCrypto.scalarMultBase,
      });

      const secret = captured[0];
      const expected = Buffer.from(nodeScalarMultBase(secret)).toString('base64');

      assert.equal(keys.publicKey, expected, 'tweetnacl and Node disagree on the public key');
      assert.equal(keys.privateKey, Buffer.from(secret).toString('base64'));
    }
  });

  test('clamps the scalar per RFC 7748', () => {
    const raw = new Uint8Array(32).fill(0xff);
    let observed;

    generateKeyPair({
      randomBytes: () => raw,
      scalarMultBase: (secret) => { observed = secret; return browserCrypto.scalarMultBase(secret); },
    });

    assert.equal(observed[0] & 0b111, 0, 'low three bits of the first byte must be cleared');
    assert.equal(observed[31] & 0b1000_0000, 0, 'top bit of the last byte must be cleared');
    assert.equal(observed[31] & 0b0100_0000, 0b0100_0000, 'second-highest bit must be set');
  });

  test('produces keys a WireGuard implementation will accept', () => {
    for (let i = 0; i < 200; i++) {
      const keys = generateKeyPair(browserCrypto);
      assert.ok(isBase64Key(keys.privateKey), `bad private key: ${keys.privateKey}`);
      assert.ok(isBase64Key(keys.publicKey), `bad public key: ${keys.publicKey}`);
      assert.equal(Buffer.from(keys.privateKey, 'base64').length, 32);
    }
  });

  test('never returns the same key twice', () => {
    const seen = new Set();
    for (let i = 0; i < 100; i++) seen.add(generateKeyPair(browserCrypto).privateKey);
    assert.equal(seen.size, 100);
  });

  test('refuses a random source that misbehaves', () => {
    assert.throws(() => generateKeyPair({ randomBytes: () => new Uint8Array(16), scalarMultBase: () => {} }), AppError);
    assert.throws(() => generateKeyPair({ randomBytes: () => 'nope', scalarMultBase: () => {} }), AppError);
  });
});

describe('validateAddKeyResponse', () => {
  const valid = {
    status: 'OK',
    peer_ip: '10.13.14.15',
    server_key: PEER.serverKey,
    server_ip: '193.176.86.1',
    server_port: 1337,
  };

  test('accepts a well-formed reply', () => {
    assert.deepEqual(validateAddKeyResponse(valid), PEER);
  });

  test('rejects each field going missing, rather than writing "undefined" to a file', () => {
    for (const field of ['peer_ip', 'server_key', 'server_ip', 'server_port']) {
      const broken = { ...valid };
      delete broken[field];

      assert.throws(() => validateAddKeyResponse(broken), (err) => {
        assert.equal(err.code, ErrorCode.PROTOCOL);
        assert.match(err.detail, new RegExp(field));
        assert.match(err.message, /no file was created/);
        return true;
      }, `${field} was accepted when missing`);
    }
  });

  test('rejects fields of the wrong shape', () => {
    assert.throws(() => validateAddKeyResponse({ ...valid, peer_ip: '999.1.1.1' }), AppError);
    assert.throws(() => validateAddKeyResponse({ ...valid, peer_ip: '10.0.0' }), AppError);
    assert.throws(() => validateAddKeyResponse({ ...valid, server_port: 0 }), AppError);
    assert.throws(() => validateAddKeyResponse({ ...valid, server_port: 70000 }), AppError);
    assert.throws(() => validateAddKeyResponse({ ...valid, server_key: 'not-a-key' }), AppError);
  });

  test('surfaces the server\'s own refusal message', () => {
    assert.throws(() => validateAddKeyResponse({ status: 'ERROR', message: 'Invalid token' }), (err) => {
      assert.match(err.message, /Invalid token/);
      return true;
    });
  });

  test('rejects an empty or non-object reply', () => {
    for (const bad of [null, undefined, '', 'OK', 42]) {
      assert.throws(() => validateAddKeyResponse(bad), AppError);
    }
  });
});

describe('buildConfig', () => {
  const keys = { privateKey: 'aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhIQ0=', publicKey: PEER.serverKey };

  test('renders a config a WireGuard client will parse', () => {
    const config = buildConfig({ keys, peer: PEER, dns: '10.0.0.243', regionName: 'Germany Berlin' });

    assert.equal(config, `# Private Internet Access - Germany Berlin
[Interface]
Address = 10.13.14.15/32
PrivateKey = ${keys.privateKey}
DNS = 10.0.0.243

[Peer]
PublicKey = ${PEER.serverKey}
Endpoint = 193.176.86.1:1337
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`);
  });

  test('never emits the string "undefined"', () => {
    const config = buildConfig({ keys, peer: PEER, dns: '1.1.1.1' });
    assert.doesNotMatch(config, /undefined/);
  });

  test('refuses to build around an invalid private key', () => {
    assert.throws(() => buildConfig({ keys: { privateKey: 'short' }, peer: PEER, dns: '1.1.1.1' }), AppError);
    assert.throws(() => buildConfig({ keys: null, peer: PEER, dns: '1.1.1.1' }), AppError);
  });
});

describe('maskPrivateKey', () => {
  test('hides the key and nothing else', () => {
    const keys = { privateKey: 'aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhIQ0=', publicKey: PEER.serverKey };
    const config = buildConfig({ keys, peer: PEER, dns: '10.0.0.243' });
    const masked = maskPrivateKey(config);

    assert.equal(masked.includes(keys.privateKey), false, 'the private key is still visible');
    assert.ok(masked.includes(PEER.serverKey), 'the peer public key should stay readable');
    assert.ok(masked.includes('Endpoint = 193.176.86.1:1337'));
    assert.equal(masked.split('\n').length, config.split('\n').length);
  });
});

describe('configFileName', () => {
  test('produces a filename that is safe on every platform', () => {
    assert.equal(configFileName('de-berlin'), 'PIA-de-berlin.conf');
    assert.equal(configFileName('a/b\\c:d*e?f"g<h>i|j'), 'PIA-a-b-c-d-e-f-g-h-i-j.conf');
    assert.equal(configFileName(''), 'PIA-pia.conf');
    assert.equal(configFileName(undefined), 'PIA-pia.conf');
    assert.ok(configFileName('x'.repeat(200)).length < 60);
  });
});

describe('value predicates', () => {
  test('isIpv4 rejects the things that look close enough to slip through', () => {
    for (const good of ['1.1.1.1', '10.0.0.243', '255.255.255.255', '0.0.0.0']) {
      assert.ok(isIpv4(good), good);
    }
    for (const bad of ['256.1.1.1', '1.1.1', '1.1.1.1.1', '01.1.1.1', ' 1.1.1.1', '1.1.1.1 ', 'a.b.c.d', '', null, '1.1.1.-1']) {
      assert.equal(isIpv4(bad), false, String(bad));
    }
  });

  test('isPort covers the boundaries', () => {
    assert.ok(isPort(1) && isPort(65535) && isPort('1337'));
    assert.equal(isPort(0), false);
    assert.equal(isPort(65536), false);
    assert.equal(isPort(1.5), false);
    assert.equal(isPort('abc'), false);
  });

  test('isBase64Key rejects near-misses', () => {
    assert.equal(isBase64Key('A'.repeat(43)), false, 'missing padding');
    assert.equal(isBase64Key(`${'A'.repeat(43)}=`), true);
    assert.equal(isBase64Key(`${'A'.repeat(42)}B=`), false, 'invalid trailing bits');
    assert.equal(isBase64Key(`${'A'.repeat(44)}=`), false, 'too long');
    assert.equal(isBase64Key('has spaces in it aaaaaaaaaaaaaaaaaaaaaaaaaa='), false);
  });
});
