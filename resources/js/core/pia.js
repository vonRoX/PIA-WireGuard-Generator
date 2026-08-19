/**
 * The Private Internet Access API surface this app uses — three calls, no more.
 *
 * Nothing here interpolates a value into a command line; every request is a
 * descriptor handed to {@link HttpClient}, which sends it to curl over stdin.
 */

import { AppError, ErrorCode } from './errors.js';
import { extractServerListJson, toRegions, wireGuardPort } from './serverlist.js';
import { validateAddKeyResponse } from './wireguard.js';

export const TOKEN_ENDPOINT = 'https://www.privateinternetaccess.com/api/client/v2/token';
export const SERVER_LIST_ENDPOINT = 'https://serverlist.piaservers.net/vpninfo/servers/v6';
export const WIREGUARD_PORT = 1337;

/**
 * PIA does not tell us when a token expires. Their apps treat one as good for a
 * day; we record the issue time and stop trusting a stored token after this, so
 * a stale token produces a clear "please sign in again" instead of a confusing
 * failure three screens later.
 */
export const TOKEN_LIFETIME_MS = 23 * 60 * 60 * 1000;

export class PiaClient {
  /**
   * @param {import('./http.js').HttpClient} http
   * @param {() => string} caCertPathProvider path to the materialised PIA CA bundle
   */
  constructor(http, caCertPathProvider) {
    this.http = http;
    this.caCertPathProvider = caCertPathProvider;
    /** Overwritten from the server list once it has been fetched. */
    this.wireguardPort = WIREGUARD_PORT;
  }

  /**
   * Exchange credentials for an API token.
   *
   * The password goes into the request body, which travels to curl on stdin — it
   * never appears in a command line, so it is not visible to `ps` or to shell
   * history, and shell metacharacters in it are just characters.
   *
   * @param {string} username
   * @param {string} password
   * @returns {Promise<string>} the token
   */
  async login(username, password) {
    if (!username || !password) {
      throw new AppError(ErrorCode.INVALID_INPUT, 'Enter both your username and password.');
    }

    let payload;
    try {
      payload = await this.http.sendJson({
        url: TOKEN_ENDPOINT,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      }, 'the sign-in response');
    } catch (err) {
      // A 401 here really does mean bad credentials, unlike a 500.
      if (err instanceof AppError && err.code === ErrorCode.AUTH) {
        throw new AppError(ErrorCode.AUTH,
          'Those credentials were not accepted. Check your PIA username (it starts with "p") and password.',
          { detail: err.detail });
      }
      throw err;
    }

    if (!payload || typeof payload.token !== 'string' || payload.token === '') {
      throw new AppError(ErrorCode.AUTH,
        'Private Internet Access accepted the request but returned no token. Try again in a moment.',
        { detail: `keys: ${payload && typeof payload === 'object' ? Object.keys(payload).join(',') : typeof payload}` });
    }

    return payload.token;
  }

  /**
   * Fetch the list of regions offering WireGuard.
   *
   * @returns {Promise<import('./serverlist.js').Region[]>}
   */
  async fetchRegions() {
    const { body } = await this.http.send({ url: SERVER_LIST_ENDPOINT });
    const document = extractServerListJson(body);
    this.wireguardPort = wireGuardPort(document, WIREGUARD_PORT);
    return toRegions(document);
  }

  /**
   * Register a public key with a specific WireGuard server.
   *
   * The certificate is verified against PIA's own CA, and the handshake is
   * completed against the server's certificate common name while connecting to
   * its address — the same approach PIA's published shell scripts use. If a
   * server entry carries no common name we fail rather than skipping
   * verification.
   *
   * @param {object} input
   * @param {string} input.token
   * @param {string} input.publicKey base64
   * @param {import('./serverlist.js').WireGuardServer} input.server
   * @returns {Promise<{peerIp: string, serverKey: string, serverIp: string, serverPort: number}>}
   */
  async addKey({ token, publicKey, server }) {
    if (!token) {
      throw new AppError(ErrorCode.AUTH, 'Your session has expired. Please sign in again.');
    }
    if (!server || !server.cn || !server.ip) {
      throw new AppError(
        ErrorCode.PROTOCOL,
        'That server did not publish the certificate name needed to verify the connection, so it was not used. ' +
        'Try generating again to pick a different server.',
      );
    }

    const caCertPath = this.caCertPathProvider();
    if (!caCertPath) {
      throw new AppError(
        ErrorCode.FILESYSTEM,
        "Could not prepare Private Internet Access's certificate for verification, so no request was made.",
      );
    }

    const port = this.wireguardPort;
    const payload = await this.http.sendJson({
      url: `https://${server.cn}:${port}/addKey`,
      query: [['pt', token], ['pubkey', publicKey]],
      caCertPath,
      connectTo: { host: server.cn, port, toHost: server.ip, toPort: port },
      // These are single-server endpoints; they answer fast or not at all.
      connectTimeoutSeconds: 10,
      maxTimeSeconds: 20,
    }, 'the key registration');

    return validateAddKeyResponse(payload);
  }
}

/**
 * @param {number} issuedAt epoch millis
 * @param {number} [now]
 * @returns {boolean}
 */
export function isTokenExpired(issuedAt, now = Date.now()) {
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return true;
  return now - issuedAt >= TOKEN_LIFETIME_MS;
}
