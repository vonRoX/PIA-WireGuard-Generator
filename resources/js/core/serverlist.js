/**
 * Parsing Private Internet Access's v6 server list.
 *
 * The endpoint returns a JSON object on the first line followed by a blank line
 * and a base64 RSA signature — it is not a plain JSON document, which is why
 * `JSON.parse` on the raw body fails. PIA's own scripts take the first line, and
 * so do we; the previous `lastIndexOf('}')` trick produced a nonsense fragment
 * whenever the body was an HTML error page instead.
 */

import { AppError, ErrorCode } from './errors.js';
import { isIpv4 } from './wireguard.js';

/**
 * @typedef {object} WireGuardServer
 * @property {string} ip common name's address
 * @property {string} cn certificate common name, required for certificate verification
 */

/**
 * @typedef {object} Region
 * @property {string} id
 * @property {string} name
 * @property {string} country
 * @property {boolean} portForward
 * @property {boolean} geo
 * @property {WireGuardServer[]} servers
 */

/**
 * Pull the JSON document out of a v6 server-list response.
 *
 * @param {string} rawBody
 * @returns {any}
 * @throws {AppError}
 */
export function extractServerListJson(rawBody) {
  const firstLine = (rawBody || '').split('\n', 1)[0].trim();

  if (firstLine === '') {
    throw new AppError(ErrorCode.PARSE, 'The server list came back empty. Try again in a moment.');
  }

  if (!firstLine.startsWith('{')) {
    const looksLikeHtml = /^\s*<(?:!doctype|html)/i.test(firstLine);
    throw new AppError(
      ErrorCode.PARSE,
      looksLikeHtml
        ? 'Received a web page instead of the server list. A network portal may be intercepting the connection.'
        : 'The server list was not in the expected format.',
      { detail: firstLine.slice(0, 200) },
    );
  }

  try {
    return JSON.parse(firstLine);
  } catch (err) {
    throw new AppError(ErrorCode.PARSE, 'The server list could not be read — it was not valid JSON.', {
      cause: err,
      detail: firstLine.slice(0, 200),
    });
  }
}

/**
 * Reduce a parsed server list to the regions this app can actually use.
 *
 * A region is usable only if it offers at least one WireGuard server that
 * carries both an address and a certificate common name — without the `cn`
 * there is nothing to verify the TLS certificate against, and this app will not
 * fall back to an unverified connection.
 *
 * @param {any} document parsed output of {@link extractServerListJson}
 * @returns {Region[]} sorted by display name
 * @throws {AppError} when the payload has no usable region list at all
 */
export function toRegions(document) {
  if (!document || typeof document !== 'object' || !Array.isArray(document.regions)) {
    throw new AppError(
      ErrorCode.PROTOCOL,
      'Private Internet Access returned a server list in an unexpected shape. ' +
      'The app may need an update to keep working with their API.',
      { detail: `keys: ${document && typeof document === 'object' ? Object.keys(document).join(',') : typeof document}` },
    );
  }

  const regions = document.regions
    .filter((region) => region && typeof region.id === 'string' && typeof region.name === 'string')
    .map((region) => ({
      id: region.id,
      name: region.name,
      country: typeof region.country === 'string' ? region.country : '',
      portForward: Boolean(region.port_forward),
      geo: Boolean(region.geo),
      servers: usableServers(region),
    }))
    .filter((region) => region.servers.length > 0)
    .sort((a, b) => a.name.localeCompare(b.name));

  if (regions.length === 0) {
    throw new AppError(
      ErrorCode.NO_SERVERS,
      'Private Internet Access is not currently offering any WireGuard regions this app can verify.',
    );
  }

  return regions;
}

/**
 * The port PIA publishes for the WireGuard key-registration endpoint.
 *
 * It has been 1337 for years, but it is a value in the payload rather than a
 * constant of the universe, so read it when it is there.
 *
 * @param {any} document
 * @param {number} [fallback]
 * @returns {number}
 */
export function wireGuardPort(document, fallback = 1337) {
  const groups = document && document.groups;
  const ports = groups && Array.isArray(groups.wg) && groups.wg[0] ? groups.wg[0].ports : null;
  const port = Array.isArray(ports) ? Number(ports[0]) : NaN;
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : fallback;
}

/**
 * Pick a server to register against.
 *
 * @param {Region} region
 * @param {() => number} [random] injectable for deterministic tests
 * @returns {WireGuardServer}
 * @throws {AppError}
 */
export function pickServer(region, random = Math.random) {
  if (!region || !Array.isArray(region.servers) || region.servers.length === 0) {
    throw new AppError(ErrorCode.NO_SERVERS, 'That region has no WireGuard servers available right now.');
  }
  const index = Math.min(region.servers.length - 1, Math.floor(random() * region.servers.length));
  return region.servers[index];
}

/**
 * @param {Region[]} regions
 * @param {string} id
 * @returns {Region | undefined}
 */
export function findRegionById(regions, id) {
  return regions.find((region) => region.id === id);
}

/**
 * A syntactically valid DNS host name, and nothing else.
 *
 * The common name goes on to be interpolated into the request URL and into
 * curl's `--connect-to` field, both of which have structure that a stray `@`,
 * `/` or `:` would change. Certificate pinning means a tampered value fails the
 * handshake rather than leaking anything — but validating at the boundary is
 * where this belongs, so a malformed entry never reaches URL construction.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isHostname(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253) return false;
  if (value.startsWith('.') || value.endsWith('.')) return false;

  return value.split('.').every((label) =>
    label.length > 0 && label.length <= 63 && /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label));
}

function usableServers(region) {
  const servers = region.servers && Array.isArray(region.servers.wg) ? region.servers.wg : [];
  return servers
    .filter((server) => server && isIpv4(server.ip) && isHostname(server.cn))
    .map((server) => ({ ip: server.ip, cn: server.cn }));
}
