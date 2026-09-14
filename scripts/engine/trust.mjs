/**
 * Reading a console's certificate before it is trusted, and turning the one the
 * user confirmed into a pin.
 *
 * The read is the only unverified connection the engine makes: a TLS handshake
 * with `rejectUnauthorized: false`, after which the socket is destroyed without
 * a single byte of application data — no request, no header, no credential.
 */

import { connect as tlsConnect } from 'node:tls';
import { isIP } from 'node:net';
import { X509Certificate } from 'node:crypto';

import { trustFromPem } from '../unifi-sync/unifi.mjs';
import { EngineErrorCode, engineError } from './errors.mjs';

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * @typedef {object} Certificate
 * @property {string}   subject
 * @property {string}   issuer
 * @property {boolean}  selfSigned
 * @property {boolean}  ca
 * @property {string[]} names          subjectAltName entries, e.g. `DNS:unifi.local`, `IP Address:192.168.1.1`
 * @property {string}   fingerprint256 colon-separated upper-case hex, as Node prints it
 * @property {string}   validFrom
 * @property {string}   validTo
 * @property {string}   connectName    first DNS name, else the subject CN, else ''
 * @property {string}   pem
 */

/**
 * Normalise what a user types as a console address to an `https://` origin.
 *
 * A bare host (`192.168.1.1`, `unifi.local:8443`) gets `https://`; anything with
 * a path, query, fragment, credentials or another scheme is refused, because
 * every later request is built from this origin.
 *
 * @param {unknown} input
 * @returns {string}
 */
export function normalizeConsoleUrl(input) {
  const invalid = (message) => engineError(EngineErrorCode.INVALID_INPUT, message, {
    hint: 'Enter the address you open the console at, for example https://192.168.1.1.',
  });

  if (typeof input !== 'string' || !input.trim()) throw invalid('Enter the console address.');
  const text = input.trim();
  if (text.length > 255 || /[\s\\]/.test(text)) throw invalid('That is not a console address.');

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw invalid('That is not a console address.');
  }

  if (url.protocol !== 'https:') throw invalid('The console address must use https://.');
  if (url.username || url.password) throw invalid('The console address must not contain a user name or password.');
  if ((url.pathname && url.pathname !== '/') || url.search || url.hash || /[?#]/.test(text)) {
    throw invalid('Enter only the console address, without a path.');
  }
  if (!url.hostname) throw invalid('That is not a console address.');
  return url.origin;
}

/**
 * @param {string} subject X509Certificate#subject, newline-separated
 * @returns {string}
 */
function commonName(subject) {
  const match = /^CN=(.*)$/m.exec(subject || '');
  return match ? match[1].trim() : '';
}

/**
 * @param {string|undefined} subjectAltName X509Certificate#subjectAltName
 * @returns {string[]}
 */
export function splitNames(subjectAltName) {
  if (!subjectAltName) return [];
  return subjectAltName.split(/,\s*/).map((name) => name.trim()).filter(Boolean);
}

/**
 * @param {X509Certificate} certificate
 * @returns {Certificate}
 */
export function describeCertificate(certificate) {
  const names = splitNames(certificate.subjectAltName);
  const dns = names.find((name) => name.startsWith('DNS:'));
  return {
    subject: certificate.subject.replace(/\n/g, ', '),
    issuer: certificate.issuer.replace(/\n/g, ', '),
    selfSigned: certificate.subject === certificate.issuer,
    ca: certificate.ca,
    names,
    fingerprint256: certificate.fingerprint256,
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    connectName: dns ? dns.slice(4) : commonName(certificate.subject),
    pem: certificate.toString(),
  };
}

/**
 * Read the certificate a server presents, trusting nothing and sending nothing.
 *
 * @param {string} url an https origin (see {@link normalizeConsoleUrl})
 * @param {{connect?: typeof tlsConnect, timeoutMs?: number}} [options]
 * @returns {Promise<Certificate>}
 */
export function inspectCertificate(url, options = {}) {
  const target = new URL(normalizeConsoleUrl(url));
  const connect = options.connect || tlsConnect;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const host = target.hostname.replace(/^\[|\]$/g, '');
  const port = target.port ? Number(target.port) : 443;

  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    /** @type {import('node:tls').ConnectionOptions} */
    const connectOptions = { host, port, rejectUnauthorized: false };
    // SNI may not carry an IP address (RFC 6066), and Node warns if asked to.
    if (!isIP(host)) connectOptions.servername = host;

    const socket = connect(connectOptions, () => {
      try {
        const peer = socket.getPeerCertificate(true);
        if (!peer || !peer.raw) {
          settle(reject, engineError(EngineErrorCode.TLS, 'The console completed a handshake but presented no certificate.'));
          return;
        }
        settle(resolve, describeCertificate(new X509Certificate(peer.raw)));
      } catch (err) {
        settle(reject, engineError(EngineErrorCode.TLS, 'The console certificate could not be read.', {
          cause: err, detail: err instanceof Error ? err.message : String(err),
        }));
      } finally {
        socket.destroy();
      }
    });

    socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`no handshake within ${timeoutMs / 1000}s`)));
    socket.on('error', (err) => settle(reject, engineError(EngineErrorCode.NETWORK,
      'Could not reach the console to read its certificate.', {
        hint: 'Check the address, and that this computer is on the same network as the console.',
        cause: err,
        detail: err instanceof Error ? err.message : String(err),
      })));
    socket.on('close', () => settle(reject, engineError(EngineErrorCode.NETWORK,
      'The console closed the connection before presenting a certificate.')));
  });
}

/**
 * A pin for exactly this certificate, in the shape `UnifiClient` takes.
 *
 * @param {string} pem
 * @returns {import('../unifi-sync/unifi.mjs').Trust}
 */
export function pinnedTrust(pem) {
  return trustFromPem(pem);
}

/**
 * Accept a fingerprint however it was copied — colons or not, any case — and
 * return it the way Node prints one.
 *
 * @param {unknown} input
 * @returns {string}
 */
export function normalizeFingerprint(input) {
  const hex = typeof input === 'string' ? input.replace(/[:\s]/g, '').toUpperCase() : '';
  if (!/^[0-9A-F]{64}$/.test(hex)) {
    throw engineError(EngineErrorCode.INVALID_INPUT, 'That is not a SHA-256 certificate fingerprint.');
  }
  return hex.match(/../g).join(':');
}
