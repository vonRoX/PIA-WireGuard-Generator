/**
 * The Workbench's front door: who may talk to the server, and what it will hand out.
 *
 * The server holds the only path to the UniFi API key and the PIA password, and it listens on a
 * port any local process — and any web page the user has open — can reach. Everything here exists
 * to make "can open a socket to 127.0.0.1" insufficient:
 *
 * - a one-time token, printed to the terminal, buys exactly one session cookie;
 * - the Host header must name this server exactly, so a DNS-rebinding page cannot pose as it;
 * - `/api` needs a same-origin Origin (when one is sent) and a custom header no cross-site form or
 *   simple request can carry.
 *
 * See "Server security (binding)" in CONTRACT.md.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { realpath, stat } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';

export const SESSION_COOKIE = 'wb_session';
export const MAX_BODY_BYTES = 64 * 1024;

export const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
});

/** Only what the UI is made of. Anything else in `public/` is not ours to serve. */
export const CONTENT_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
});

/** 32 random bytes, base64url: the shape the contract prescribes for the token and the session id. */
export function randomSecret() {
  return randomBytes(32).toString('base64url');
}

/**
 * Compare a presented secret with the real one without leaking, through timing, how much of it
 * matched. Hashing first makes both sides the same length, so even the length check is not a tell.
 * @param {string | null | undefined} presented
 * @param {string | null} expected `null` once the secret has been spent
 */
export function secretMatches(presented, expected) {
  if (typeof presented !== 'string' || typeof expected !== 'string') return false;
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * The single-use token and the session it turns into.
 *
 * There is one token and therefore at most one session: the person who started the server opens
 * the link once, and nobody who later reads the terminal scrollback can open it again.
 */
export function createGate() {
  let token = randomSecret();
  let session = null;

  return {
    get token() { return token; },

    /** Spend the token. Returns the new session id, or `null` if the token is wrong or already used. */
    exchange(presented) {
      if (token === null || !secretMatches(presented, token)) return null;
      token = null;
      session = randomSecret();
      return session;
    },

    /** @param {string | undefined} cookieHeader */
    hasSession(cookieHeader) {
      if (session === null) return false;
      return secretMatches(readCookie(cookieHeader, SESSION_COOKIE), session);
    },
  };
}

/**
 * @param {string | undefined} header the raw Cookie header
 * @param {string} name
 * @returns {string | null}
 */
export function readCookie(header, name) {
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export function sessionCookie(value) {
  return `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/`;
}

/**
 * A DNS-rebinding page reaches this socket with its own hostname in Host. Only the exact
 * `127.0.0.1:<port>` the server printed is ours; `localhost` is refused too, because the cookie
 * was issued for the IP origin and a second name would only be a second way in.
 */
export function hostAllowed(hostHeader, port) {
  return hostHeader === `127.0.0.1:${port}`;
}

/**
 * Browsers omit Origin on a same-origin GET made with fetch, so its absence is not suspicious; a
 * cross-site request that could matter always carries one. `null` (sandboxed frames, file://) is
 * a foreign origin like any other.
 */
export function originAllowed(originHeader, port) {
  return originHeader === undefined || originHeader === `http://127.0.0.1:${port}`;
}

/**
 * Map a URL path to a file inside `publicDir`, or `null` if it must not be served.
 *
 * Checked on the decoded path, because that is what the filesystem sees: `..%2f` and `%5c` are
 * harmless in a URL and lethal in a path. Symlinks are resolved and checked again, so a link
 * inside `public/` cannot point out of it.
 *
 * @param {string} publicDir absolute
 * @param {string} rawPathname URL pathname, still percent-encoded, without the query
 * @returns {Promise<{file: string, contentType: string} | null>}
 */
export async function resolveStatic(publicDir, rawPathname) {
  let pathname;
  try {
    pathname = decodeURIComponent(rawPathname);
  } catch {
    return null;
  }
  if (pathname === '/') pathname = '/index.html';

  if (!pathname.startsWith('/') || /[\\\0]/.test(pathname)) return null;
  const segments = pathname.slice(1).split('/');
  // Empty segments ("//", trailing "/") would mean a directory; dot segments mean escaping or
  // hidden files. None of them name something the UI ships.
  if (segments.some((s) => s === '' || s.startsWith('.'))) return null;

  const contentType = CONTENT_TYPES[extname(pathname).toLowerCase()];
  if (!contentType) return null;

  const root = resolve(publicDir);
  const candidate = resolve(root, ...segments);
  if (!candidate.startsWith(root + sep)) return null;

  try {
    const [realRoot, realFile] = await Promise.all([realpath(root), realpath(candidate)]);
    if (!realFile.startsWith(realRoot + sep)) return null;
    if (!(await stat(realFile)).isFile()) return null;
    return { file: realFile, contentType };
  } catch {
    return null;
  }
}
