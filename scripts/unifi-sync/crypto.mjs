/**
 * The crypto provider `generateKeyPair` needs, backed by Node itself.
 *
 * The app uses the vendored tweetnacl because a webview has nothing else; Node
 * has a native X25519 implementation, which the test suite already uses as the
 * reference to check tweetnacl against. No third-party code is involved here.
 */

import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';

/** DER prologue of a PKCS#8 X25519 private key; the raw 32-byte scalar follows. */
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

/** @type {import('../../resources/js/core/wireguard.js').CryptoProvider} */
export const nodeCrypto = {
  randomBytes: (length) => new Uint8Array(randomBytes(length)),

  scalarMultBase(secretKey) {
    const privateKey = createPrivateKey({
      key: Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(secretKey)]),
      format: 'der',
      type: 'pkcs8',
    });
    const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
    return new Uint8Array(spki.subarray(spki.length - 32));
  },
};
