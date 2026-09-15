/**
 * Pure helpers: no DOM, no network. Imported by the page and by the Node tests.
 */

export const DEFAULT_CONSOLE_URL = 'https://192.168.1.1';
export const EXPLORE_PREFIX = '/proxy/network/';

export const EXPLORE_PRESETS = Object.freeze([
  '/proxy/network/integration/v1/info',
  '/proxy/network/integration/v1/sites',
  '/proxy/network/api/s/default/rest/networkconf',
  '/proxy/network/v2/api/site/default/vpn/connections',
  '/proxy/network/api/s/default/stat/health',
]);

/**
 * Accept what people actually type ("192.168.1.1", "https://192.168.1.1/") and hand the
 * engine an origin. Anything odd is passed through so the engine's own validation explains it.
 * @param {string} input
 */
export function normaliseConsoleUrl(input) {
  const text = String(input ?? '').trim();
  if (!text) return '';
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`;
  try {
    const url = new URL(withScheme);
    if (url.protocol === 'https:' && (url.pathname === '/' || url.pathname === '') && !url.search && !url.hash) {
      return url.origin;
    }
  } catch {
    // fall through
  }
  return withScheme;
}

/**
 * Split a SHA-256 fingerprint into its bytes ("3B", "9F", …) whatever separator it came with.
 * @param {string} fingerprint
 * @returns {string[]}
 */
export function fingerprintBytes(fingerprint) {
  const hex = String(fingerprint ?? '').replace(/[^0-9a-f]/gi, '').toUpperCase();
  const bytes = [];
  for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(hex.slice(i, i + 2));
  return bytes;
}

/**
 * Bytes in rows of `perRow`, for side-by-side comparison with a browser's certificate viewer.
 * @param {string} fingerprint
 * @param {number} [perRow]
 * @returns {string[][]}
 */
export function fingerprintRows(fingerprint, perRow = 8) {
  const bytes = fingerprintBytes(fingerprint);
  const rows = [];
  for (let i = 0; i < bytes.length; i += perRow) rows.push(bytes.slice(i, i + perRow));
  return rows;
}

/** A short, recognisable prefix of a fingerprint for summaries: "3B 9F 0C D2 … 03 5B A1". */
export function fingerprintShort(fingerprint) {
  const bytes = fingerprintBytes(fingerprint);
  if (bytes.length <= 8) return bytes.join(' ');
  return `${bytes.slice(0, 4).join(' ')} … ${bytes.slice(-3).join(' ')}`;
}

/** "CONNECTING_LONGER_THAN_USUAL" → "Connecting longer than usual". */
export function humanise(code) {
  const text = String(code ?? '').trim().replace(/[_\s]+/g, ' ').toLowerCase();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
}

/**
 * The colour a tunnel status deserves.
 * @param {string|null|undefined} status
 * @returns {'ok'|'pending'|'bad'|'unknown'}
 */
export function statusTone(status) {
  if (typeof status !== 'string' || !status.trim()) return 'unknown';
  const s = status.trim().toUpperCase();
  if (/^(UNKNOWN|NONE|N\/A)$/.test(s)) return 'unknown';
  if (/(^|_)(DIS|NOT_|UN)|DOWN|FAIL|ERROR|DENIED|REJECT|TIMEOUT|OFFLINE|STOPPED/.test(s)) return 'bad';
  if (/CONNECTING|PENDING|STARTING|INIT|NEGOTIAT|HANDSHAK|RETRY|WAIT/.test(s)) return 'pending';
  if (/CONNECTED|ESTABLISHED|^UP$|ACTIVE|ONLINE|RUNNING|^OK$/.test(s)) return 'ok';
  return 'unknown';
}

/** Label for a status badge. */
export function statusLabel(status, enabled = true) {
  if (typeof status !== 'string' || !status.trim()) return enabled ? 'Unknown' : 'Off';
  return humanise(status);
}

export function modeLabel(mode) {
  if (mode === 'file') return 'Configuration file';
  if (mode === 'manual') return 'Manual';
  return 'Other';
}

/**
 * Check an explorer path the way the engine will, so obvious mistakes never leave the page.
 * @param {string} input
 * @returns {{ ok: true, path: string } | { ok: false, message: string }}
 */
export function checkExplorePath(input) {
  const path = String(input ?? '').trim();
  if (!path) return { ok: false, message: `Enter a path starting with ${EXPLORE_PREFIX}` };
  if (/^[a-z][a-z0-9+.-]*:/i.test(path)) {
    return { ok: false, message: `Enter only the path, without https:// or an address — it must start with ${EXPLORE_PREFIX}` };
  }
  if (!path.startsWith(EXPLORE_PREFIX)) return { ok: false, message: `The path must start with ${EXPLORE_PREFIX}` };
  if (path.includes('..') || path.includes('//') || path.includes('\\')) {
    return { ok: false, message: 'The path may not contain "..", "//" or backslashes.' };
  }
  // eslint-disable-next-line no-control-regex
  if (/[\s\x00-\x1f\x7f]/.test(path)) return { ok: false, message: 'The path may not contain spaces.' };
  return { ok: true, path };
}

/** Dates may arrive as ISO strings or OpenSSL's "Mar  2 10:14:07 2025 GMT". */
export function formatDate(value) {
  if (value === null || value === undefined || value === '') return '—';
  const time = Date.parse(String(value));
  if (Number.isNaN(time)) return String(value);
  return new Date(time).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Whether a certificate is outside its validity period at `now`. */
export function validityProblem(certificate, now = Date.now()) {
  const from = Date.parse(String(certificate?.validFrom ?? ''));
  const to = Date.parse(String(certificate?.validTo ?? ''));
  if (!Number.isNaN(to) && to < now) return 'expired';
  if (!Number.isNaN(from) && from > now) return 'not-yet-valid';
  return null;
}

/** JSON for a clipboard, stable across calls. */
export function toPrettyJson(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}
