/**
 * A read-only, API-key client for one pinned UniFi console.
 *
 * Every request goes through {@link UnifiClient#send} with the console's pinned
 * certificate as the whole trust store, `X-API-KEY` as the only credential, and
 * `authenticated: false` so no cookie or CSRF token is ever attached — a key
 * needs neither (measured on a UCG Ultra; see scripts/workbench/CONTRACT.md).
 */

import { UnifiClient } from '../unifi-sync/unifi.mjs';
import { ErrorCode } from '../../resources/js/core/errors.js';
import { EngineErrorCode, engineError } from './errors.mjs';
import { inspectCertificate, pinnedTrust } from './trust.mjs';

export const KEY_REJECTED_HINT = 'The console rejected this key. It must be a local key created on the console under ' +
  'Settings → Control Plane → Integrations — a Site Manager key from unifi.ui.com does not work here.';

const SITE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * @param {string} site
 * @returns {string}
 */
function checkSite(site) {
  if (typeof site !== 'string' || !SITE.test(site)) {
    throw engineError(EngineErrorCode.INVALID_INPUT, 'The site name is not a plain identifier.');
  }
  return site;
}

/**
 * @param {object} options
 * @param {string} options.url            https origin of the console
 * @param {string} options.pem            the pinned certificate
 * @param {string} options.fingerprint256 its fingerprint, for telling a changed certificate from a broken connection
 * @param {string} options.apiKey
 * @param {Function} [options.request]    `https.request` stand-in
 * @param {Function} [options.connect]    `tls.connect` stand-in, for the changed-certificate check
 * @param {number} [options.timeoutMs]
 */
export function createConsoleClient({ url, pem, fingerprint256, apiKey, request, connect, timeoutMs }) {
  const client = new UnifiClient({ url, trust: pinnedTrust(pem), apiKey, request, timeoutMs });

  /**
   * A TLS failure against a pinned console is either a changed certificate or
   * something else entirely. Looking again — unverified, sending nothing — is
   * the only way to tell which.
   */
  async function explainTls(err) {
    let presented;
    try {
      presented = await inspectCertificate(url, { connect, timeoutMs });
    } catch {
      return err;
    }
    if (presented.fingerprint256 !== fingerprint256) {
      return engineError(EngineErrorCode.CERT_CHANGED,
        'The console presented a different certificate from the one you trusted. Nothing was sent to it.', {
          hint: 'If you replaced the console or its certificate, trust the new one again. Otherwise, something ' +
            'between this computer and the console may be intercepting the connection.',
          detail: `expected ${fingerprint256}, got ${presented.fingerprint256}`,
        });
    }
    return err;
  }

  /**
   * @param {string} path
   * @returns {Promise<{status: number, headers: object, text: string}>}
   */
  async function get(path) {
    let response;
    try {
      response = await client.send({ method: 'GET', path, authenticated: false });
    } catch (err) {
      if (err && err.code === ErrorCode.TLS) throw await explainTls(err);
      throw err;
    }
    if (response.status === 401) {
      throw engineError(EngineErrorCode.UNIFI_KEY_REJECTED, 'The console rejected the UniFi API key.', {
        hint: KEY_REJECTED_HINT,
        detail: `HTTP 401 GET ${path.split('?')[0]}`,
      });
    }
    return { status: response.status, headers: response.headers, text: response.body };
  }

  /**
   * @param {string} path
   * @returns {Promise<any>} the parsed body of a 2xx answer
   */
  async function getJson(path) {
    const { status, text } = await get(path);
    if (status < 200 || status >= 300) {
      throw engineError(EngineErrorCode.HTTP, `The console answered HTTP ${status}.`, {
        detail: `HTTP ${status} GET ${path}`,
      });
    }
    try {
      return JSON.parse(text);
    } catch {
      throw engineError(EngineErrorCode.HTTP, 'The console did not answer with JSON.', { detail: `GET ${path}` });
    }
  }

  return {
    get,

    /** @returns {Promise<{applicationVersion: string}>} */
    async info() {
      const body = await getJson('/proxy/network/integration/v1/info');
      return { applicationVersion: body && typeof body.applicationVersion === 'string' ? body.applicationVersion : '' };
    },

    /**
     * Every `purpose: "vpn-client"` network row on the site. The rows still
     * carry their secrets; redact before they go anywhere.
     *
     * @param {string} site
     * @returns {Promise<object[]>}
     */
    async listVpnClients(site) {
      const body = await getJson(`/proxy/network/api/s/${checkSite(site)}/rest/networkconf`);
      const rows = body && Array.isArray(body.data) ? body.data : null;
      if (!rows) throw engineError(EngineErrorCode.HTTP, 'The console answered the network list in an unexpected shape.');
      return rows.filter((row) => row && typeof row === 'object' && row.purpose === 'vpn-client');
    },

    /**
     * @param {string} site
     * @returns {Promise<Array<{network_id: string, status: string, type: string, notes?: string[]}>>}
     */
    async vpnStatus(site) {
      const body = await getJson(`/proxy/network/v2/api/site/${checkSite(site)}/vpn/connections`);
      return body && Array.isArray(body.connections) ? body.connections : [];
    },
  };
}
