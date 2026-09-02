/**
 * A minimal client for the UniFi Network application's local API.
 *
 * Ubiquiti publishes no schema for the endpoints their own web UI uses, but the
 * shape has been stable for years: a UniFi OS console (UCG, UDM, UDR) signs in
 * at `/api/auth/login` and proxies the Network application under
 * `/proxy/network`; a self-hosted Network application signs in at `/api/login`
 * and serves the same routes at the root. A VPN Client is a `networkconf` row
 * with `purpose: "vpn-client"` and `vpn_type: "wireguard-client"`, and updating
 * one is a PUT of the whole row back to `rest/networkconf/<id>`, which makes
 * the gateway re-provision the tunnel.
 *
 * Every request is a plain `node:https` call. No shell, no curl: this is the
 * gateway on the LAN, and a console ships with a self-signed certificate, so
 * the trust decision is made explicitly in {@link trustFromPem} rather than
 * with `rejectUnauthorized: false`.
 */

import { request as httpsRequest } from 'node:https';
import { checkServerIdentity as defaultCheckServerIdentity } from 'node:tls';
import { X509Certificate } from 'node:crypto';

import { AppError, ErrorCode } from '../../resources/js/core/errors.js';

const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_BODY_BYTES = 8 * 1024 * 1024;

/**
 * @typedef {object} Trust
 * @property {string[]} ca            PEM certificates handed to TLS as the trust store
 * @property {Set<string>} fingerprints SHA-256 fingerprints of those certificates
 */

/**
 * Turn an exported console certificate into a trust decision.
 *
 * A UniFi console's default certificate is self-signed and carries no name that
 * matches the address you reach it by, so verifying it "properly" is impossible
 * and the usual answer is to switch verification off. This does something
 * narrower: the certificate in the file is the trust store, and a server that
 * presents *exactly that certificate* is accepted whatever it is called. Any
 * other certificate — a different self-signed one, say, from a device sitting in
 * the middle — still fails the chain check and the connection is refused.
 *
 * A certificate issued by a private CA works too, provided the file holds the
 * issuer as well, in which case the ordinary host-name check applies.
 *
 * @param {string} pem
 * @returns {Trust}
 */
export function trustFromPem(pem) {
  const blocks = String(pem || '').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  if (blocks.length === 0) {
    throw new AppError(ErrorCode.INVALID_INPUT,
      'The UniFi certificate file contains no PEM certificate. Export the console certificate as Base64/PEM.');
  }

  const fingerprints = new Set();
  for (const block of blocks) {
    try {
      fingerprints.add(new X509Certificate(block).fingerprint256);
    } catch (err) {
      throw new AppError(ErrorCode.INVALID_INPUT, 'The UniFi certificate file could not be parsed.', {
        cause: err, detail: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { ca: blocks, fingerprints };
}

/**
 * Pull the CSRF token out of a UniFi OS session cookie.
 *
 * Newer consoles stop sending `X-CSRF-Token` on the login response and instead
 * embed it in the JWT they set as the `TOKEN` cookie. No signature check is
 * needed — the value came from the console itself and goes straight back to it.
 *
 * @param {string} jwt
 * @returns {string} empty when the token carries none
 */
export function csrfTokenFromJwt(jwt) {
  const parts = String(jwt || '').split('.');
  if (parts.length < 2) return '';
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload && typeof payload.csrfToken === 'string' ? payload.csrfToken : '';
  } catch {
    return '';
  }
}

/**
 * @param {string[]} setCookie `set-cookie` header values
 * @returns {Map<string,string>} name → value
 */
export function parseSetCookie(setCookie) {
  const cookies = new Map();
  for (const line of setCookie || []) {
    const pair = line.split(';', 1)[0];
    const eq = pair.indexOf('=');
    if (eq > 0) cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  return cookies;
}

export class UnifiClient {
  /**
   * @param {object} options
   * @param {string}  options.url        origin of the console, e.g. `https://192.168.1.1`
   * @param {string}  [options.site]     Network site name; `default` unless renamed
   * @param {boolean} [options.selfHosted] a Network application not running on a UniFi OS console
   * @param {Trust|null} [options.trust] from {@link trustFromPem}; omit to use the system store
   * @param {string}  [options.apiKey]   an API key from Control Plane → Integrations, instead of a login
   * @param {number}  [options.timeoutMs]
   * @param {typeof httpsRequest} [options.request] injectable for tests
   */
  constructor(options) {
    const url = new URL(options.url);
    if (url.protocol !== 'https:') {
      throw new AppError(ErrorCode.PROTOCOL, 'The UniFi console address must start with https://.');
    }
    this.origin = url.origin;
    this.site = options.site || 'default';
    this.selfHosted = Boolean(options.selfHosted);
    this.trust = options.trust || null;
    this.apiKey = options.apiKey || '';
    this.timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    this.request = options.request || httpsRequest;

    /** @type {Map<string,string>} */
    this.cookies = new Map();
    this.csrfToken = '';
  }

  /** Path prefix of the Network application on this host. */
  get networkBase() {
    return this.selfHosted ? '/api' : '/proxy/network/api';
  }

  /**
   * Sign in with a local account. Not needed when an API key was given.
   *
   * @param {string} username
   * @param {string} password
   */
  async login(username, password) {
    if (!username || !password) {
      throw new AppError(ErrorCode.INVALID_INPUT, 'Set UNIFI_USERNAME and UNIFI_PASSWORD, or UNIFI_API_KEY.');
    }

    const path = this.selfHosted ? '/api/login' : '/api/auth/login';
    const body = this.selfHosted
      ? { username, password, remember: false }
      : { username, password, rememberMe: false };

    const response = await this.send({ method: 'POST', path, body, authenticated: false });

    if (response.status === 499) {
      throw new AppError(ErrorCode.AUTH,
        'That UniFi account requires multi-factor authentication, which an unattended script cannot answer. ' +
        'Create a local admin without MFA for this job, or use an API key.');
    }
    if (response.status === 401 || response.status === 403 || response.status === 400) {
      throw new AppError(ErrorCode.AUTH, 'The UniFi console rejected those credentials.', {
        detail: `HTTP ${response.status}`,
      });
    }
    if (response.status < 200 || response.status >= 300) {
      throw new AppError(ErrorCode.HTTP, `The UniFi console returned HTTP ${response.status} at sign-in.`);
    }

    if (this.cookies.size === 0) {
      throw new AppError(ErrorCode.PROTOCOL, 'The UniFi console accepted the sign-in but set no session cookie.');
    }
  }

  /**
   * Every network configuration row on the site, VPN clients included.
   *
   * @returns {Promise<object[]>}
   */
  async listNetworks() {
    const { data } = await this.network('GET', `/s/${encodeURIComponent(this.site)}/rest/networkconf`);
    return data;
  }

  /**
   * Replace one network configuration row. The gateway re-provisions on save.
   *
   * @param {string} id the row's `_id`
   * @param {object} entry the complete row
   * @returns {Promise<object>} the row as stored
   */
  async updateNetwork(id, entry) {
    if (!/^[A-Za-z0-9]+$/.test(String(id))) {
      throw new AppError(ErrorCode.INVALID_INPUT, 'Internal error: the network id is not a plain identifier.');
    }
    const { data } = await this.network('PUT', `/s/${encodeURIComponent(this.site)}/rest/networkconf/${id}`, entry);
    return Array.isArray(data) ? data[0] : data;
  }

  /**
   * A Network-application call, with its `{meta, data}` envelope unwrapped.
   *
   * @param {'GET'|'PUT'|'POST'} method
   * @param {string} path relative to the Network application's `/api`
   * @param {object} [body]
   * @returns {Promise<{meta: object, data: any}>}
   */
  async network(method, path, body) {
    const response = await this.send({ method, path: this.networkBase + path, body, authenticated: true });

    if (response.status === 401 || response.status === 403) {
      throw new AppError(ErrorCode.AUTH,
        'The UniFi console refused the request. Check that the account (or API key) is an administrator of the site.',
        { detail: `HTTP ${response.status} ${method} ${path}` });
    }

    let payload;
    try {
      payload = JSON.parse(response.body);
    } catch (err) {
      throw new AppError(ErrorCode.PARSE, `The UniFi console did not answer ${method} ${path} with JSON.`, {
        cause: err, detail: `HTTP ${response.status}: ${response.body.slice(0, 200)}`,
      });
    }

    const rc = payload && payload.meta && payload.meta.rc;
    if (response.status < 200 || response.status >= 300 || rc !== 'ok') {
      const msg = payload && payload.meta && typeof payload.meta.msg === 'string' ? payload.meta.msg : '';
      throw new AppError(ErrorCode.HTTP, `The UniFi console rejected ${method} ${path}${msg ? `: ${msg}` : ''}.`, {
        detail: `HTTP ${response.status}`,
      });
    }

    return { meta: payload.meta, data: payload.data };
  }

  /**
   * One HTTPS exchange. Session cookies and CSRF tokens are harvested from
   * every response, because a console rotates the CSRF token on some replies.
   *
   * @param {{method: string, path: string, body?: object, authenticated: boolean}} options
   * @returns {Promise<{status: number, headers: object, body: string}>}
   */
  send({ method, path, body, authenticated }) {
    const headers = {
      accept: 'application/json',
    };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.apiKey) headers['x-api-key'] = this.apiKey;
    if (authenticated && this.cookies.size > 0) {
      headers.cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    }
    if (authenticated && this.csrfToken && method !== 'GET') {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const url = new URL(path, this.origin);
    const trust = this.trust;

    /** @type {import('node:https').RequestOptions} */
    const options = {
      method,
      headers,
      timeout: this.timeoutMs,
      // Never `rejectUnauthorized: false`. With a pinned certificate the chain
      // check passes because that certificate *is* the store; the host-name
      // check is then the only thing relaxed, and only for that exact leaf.
      ca: trust ? trust.ca : undefined,
      checkServerIdentity(host, cert) {
        if (trust && trust.fingerprints.has(cert.fingerprint256)) return undefined;
        return defaultCheckServerIdentity(host, cert);
      },
    };

    return new Promise((resolve, reject) => {
      const req = this.request(url, options, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_BODY_BYTES) {
            req.destroy(new Error('response too large'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          const setCookie = res.headers['set-cookie'];
          for (const [name, value] of parseSetCookie(Array.isArray(setCookie) ? setCookie : [])) {
            this.cookies.set(name, value);
          }

          const rotated = res.headers['x-updated-csrf-token'] || res.headers['x-csrf-token'];
          if (typeof rotated === 'string' && rotated) {
            this.csrfToken = rotated;
          } else if (!this.csrfToken && this.cookies.has('TOKEN')) {
            this.csrfToken = csrfTokenFromJwt(this.cookies.get('TOKEN'));
          }

          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
        res.on('error', (err) => reject(transportError(err)));
      });

      req.on('timeout', () => req.destroy(new Error(`no response within ${this.timeoutMs / 1000}s`)));
      req.on('error', (err) => reject(transportError(err)));

      if (body !== undefined) req.write(JSON.stringify(body));
      req.end();
    });
  }
}

/** @param {unknown} err */
function transportError(err) {
  const message = err instanceof Error ? err.message : String(err);
  const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : '';

  if (/CERT|certificate|self.signed|altname|unable to verify/i.test(code + ' ' + message)) {
    return new AppError(ErrorCode.TLS,
      "The UniFi console's certificate could not be verified. If the console uses its factory self-signed " +
      'certificate, export it and point `unifi.certificate` in the config at the file.',
      { cause: err, detail: message });
  }
  if (code === 'ECONNREFUSED' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return new AppError(ErrorCode.NETWORK, 'Could not connect to the UniFi console. Check the address.', {
      cause: err, detail: message,
    });
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return new AppError(ErrorCode.NETWORK, 'Could not resolve the UniFi console address.', { cause: err, detail: message });
  }
  return new AppError(ErrorCode.NETWORK, 'The request to the UniFi console failed.', { cause: err, detail: message });
}
