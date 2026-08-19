/**
 * WireGuard key generation and configuration rendering.
 *
 * Both crypto primitives are injected rather than imported so this module can be
 * exercised in Node against an independent X25519 implementation — the test
 * suite checks tweetnacl's derived public key against Node's own, which is a
 * far better guarantee than asserting a library agrees with itself.
 */

import { AppError, ErrorCode } from './errors.js';

/**
 * WireGuard keys are 32 raw bytes: 43 base64 characters plus '=' padding.
 *
 * The final character encodes only 4 bits of key material followed by two zero
 * padding bits, so its alphabet index must be a multiple of four — that is the
 * sixteen characters below, and no others.
 */
const BASE64_KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * @typedef {object} CryptoProvider
 * @property {(length: number) => Uint8Array} randomBytes
 * @property {(secretKey: Uint8Array) => Uint8Array} scalarMultBase X25519 base-point multiplication
 */

/**
 * @typedef {object} KeyPair
 * @property {string} privateKey base64
 * @property {string} publicKey  base64
 */

/**
 * Generate a clamped Curve25519 key pair, entirely locally.
 *
 * @param {CryptoProvider} crypto
 * @returns {KeyPair}
 */
export function generateKeyPair(crypto) {
  const secret = crypto.randomBytes(32);

  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new AppError(ErrorCode.INVALID_INPUT, 'Internal error: the random source returned the wrong amount of data.');
  }

  // X25519 clamping, per RFC 7748 §5.
  secret[0] &= 248;
  secret[31] &= 127;
  secret[31] |= 64;

  const publicKey = crypto.scalarMultBase(secret);

  return {
    privateKey: toBase64(secret),
    publicKey: toBase64(publicKey),
  };
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // btoa exists in the webview; Buffer covers Node during tests.
  return typeof btoa === 'function'
    ? btoa(binary)
    : Buffer.from(bytes).toString('base64');
}

/**
 * Validate the `addKey` response before any of it reaches a config file.
 *
 * PIA answering `{status: 'OK'}` with a renamed or missing field used to produce
 * `Endpoint = undefined:undefined` in a file the user was told was ready.
 *
 * @param {any} response
 * @returns {{peerIp: string, serverKey: string, serverIp: string, serverPort: number}}
 * @throws {AppError}
 */
export function validateAddKeyResponse(response) {
  if (!response || typeof response !== 'object') {
    throw new AppError(ErrorCode.PROTOCOL, 'The registration server sent an empty reply.');
  }

  if (response.status !== 'OK') {
    const reason = typeof response.message === 'string' && response.message
      ? response.message
      : 'the server rejected the key registration';
    throw new AppError(ErrorCode.PROTOCOL, `Could not register the key: ${reason}.`, {
      detail: `status=${String(response.status)}`,
    });
  }

  const missing = [];
  if (!isIpv4(response.peer_ip)) missing.push('peer_ip');
  if (!isBase64Key(response.server_key)) missing.push('server_key');
  if (!isIpv4(response.server_ip)) missing.push('server_ip');
  if (!isPort(response.server_port)) missing.push('server_port');

  if (missing.length > 0) {
    throw new AppError(
      ErrorCode.PROTOCOL,
      'The registration server replied with an incomplete configuration, so no file was created. ' +
      'This usually means Private Internet Access changed their API.',
      { detail: `invalid or missing: ${missing.join(', ')}` },
    );
  }

  return {
    peerIp: response.peer_ip,
    serverKey: response.server_key,
    serverIp: response.server_ip,
    serverPort: Number(response.server_port),
  };
}

/**
 * Render a WireGuard configuration file.
 *
 * @param {object} input
 * @param {KeyPair} input.keys
 * @param {{peerIp: string, serverKey: string, serverIp: string, serverPort: number}} input.peer
 * @param {string} input.dns comma-separated addresses, already validated
 * @param {string} [input.regionName] included as a comment for the user's benefit
 * @returns {string}
 */
export function buildConfig({ keys, peer, dns, regionName }) {
  if (!keys || !isBase64Key(keys.privateKey)) {
    throw new AppError(ErrorCode.INVALID_INPUT, 'Internal error: the generated private key is not valid.');
  }

  const header = regionName ? `# Private Internet Access - ${regionName}\n` : '';

  return `${header}[Interface]
Address = ${peer.peerIp}/32
PrivateKey = ${keys.privateKey}
DNS = ${dns}

[Peer]
PublicKey = ${peer.serverKey}
Endpoint = ${peer.serverIp}:${peer.serverPort}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`;
}

/**
 * Replace the private key with a mask, for on-screen preview.
 *
 * @param {string} config
 * @returns {string}
 */
export function maskPrivateKey(config) {
  return config.replace(/^(PrivateKey\s*=\s*).*$/m, (_match, prefix) => `${prefix}${'•'.repeat(43)}=`);
}

/**
 * A filename that is safe on every platform we ship to.
 *
 * @param {string} regionId
 * @returns {string}
 */
export function configFileName(regionId) {
  const safe = String(regionId || 'pia').replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 48) || 'pia';
  return `PIA-${safe}.conf`;
}

/** @param {unknown} value */
export function isBase64Key(value) {
  return typeof value === 'string' && BASE64_KEY.test(value);
}

/** @param {unknown} value */
export function isIpv4(value) {
  if (typeof value !== 'string') return false;
  const match = IPV4.exec(value);
  if (!match) return false;
  return match.slice(1).every((octet) => octet.length <= 3 && Number(octet) <= 255 && String(Number(octet)) === octet);
}

/** @param {unknown} value */
export function isPort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}
