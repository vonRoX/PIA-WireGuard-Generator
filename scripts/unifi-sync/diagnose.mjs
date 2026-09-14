/**
 * Answer the questions that decide whether the UniFi half can be ported into
 * the desktop app, by asking the console rather than guessing.
 *
 * The app talks to the network only through curl, and its curl layer reduces
 * every response to a body and a status code — response headers are invisible
 * to it. That is fine only if the console never requires a header the app
 * cannot see. Three facts decide it, and none can be established anywhere but
 * on a real console:
 *
 *   1. Does a write *need* a cookie? `UnifiClient` harvests `set-cookie` from
 *      every response regardless of how it authenticated, and sends the cookie
 *      (and a CSRF token derived from it) on the next write — so a write it
 *      makes after a read proves nothing about a client that cannot see
 *      headers. The probe therefore writes first from a client that has sent
 *      nothing, and only falls back to the client holding the session if that
 *      is refused. A console that sets a cookie it never checks is not a
 *      blocker; one that refuses a write without it is.
 *   2. Is the API key accepted for a write, or only for a read? A key good for
 *      GET but not PUT fails only after fresh keys have been registered.
 *   3. What does the console certificate carry — is it self-signed, is it a
 *      leaf, and under which names? That decides what to pin and what name to
 *      pin it under. It is no longer a question of *whether* pinning works:
 *      `test/unifi-pinning.test.js` proves on the `windows-latest` CI leg that
 *      genuine Schannel accepts a self-signed CA:FALSE leaf as its own trust
 *      anchor when it is the whole `cacert` store.
 *
 * Nothing here prints a secret: header *names* are listed, never their values,
 * and the write probe sends the row back exactly as it arrived.
 */

import { connect as tlsConnect } from 'node:tls';
import { X509Certificate } from 'node:crypto';

import { AppError, ErrorCode } from '../../resources/js/core/errors.js';
import { REQUIRED_FIELDS, findWireGuardClient } from '../../resources/js/core/unifi-sync.js';
import { isBase64Key } from '../../resources/js/core/wireguard.js';

/**
 * Fields whose value must never be printed. Their *presence* is reported, which
 * is the interesting part: a controller that redacts a secret on GET hands back
 * a row that would destroy that secret if written straight back.
 */
const SECRET_FIELDS = Object.freeze([
  'x_wireguard_private_key',
  'wireguard_client_preshared_key',
  'wireguard_client_configuration_file',
]);

/**
 * Secrets that are WireGuard keys, and so have a shape. Checking the shape
 * catches every way of hiding a key — a blank, `xxxx`, `REDACTED`, a non-string
 * — rather than only the masks someone thought to list.
 */
const KEY_FIELDS = new Set(['x_wireguard_private_key', 'wireguard_client_preshared_key']);

/**
 * Fields short enough, and dull enough, to print in full — and decisive enough
 * to be worth printing. `wireguard_client_mode` in particular determines whether
 * writing the manual fields has any effect at all.
 */
const REVEALED_FIELDS = Object.freeze([
  'enabled',
  'wireguard_client_mode',
  'wireguard_client_preshared_key_enabled',
  'vpn_client_pull_dns',
  'vpn_client_default_route',
  'wireguard_interface',
]);

/**
 * Read the certificate the console presents, without sending it anything.
 *
 * Verification is disabled for this probe alone, deliberately: the whole point
 * is to see what an *unverifiable* certificate contains, and reporting it is
 * why the connection exists. No request is made and no credential is sent — the
 * socket is destroyed as soon as the peer certificate has been read. This is
 * what `openssl s_client` does, and it is not on any path that carries data.
 *
 * @param {string} url the console address
 * @param {number} [timeoutMs]
 * @returns {Promise<{subject: string, issuer: string, selfSigned: boolean, ca: boolean|undefined, names: string, fingerprint: string}>}
 */
export function probeCertificate(url, timeoutMs = 10_000) {
  const target = new URL(url);
  const port = target.port ? Number(target.port) : 443;

  return new Promise((resolve, reject) => {
    const socket = tlsConnect(
      { host: target.hostname, port, servername: target.hostname, rejectUnauthorized: false },
      () => {
        try {
          const peer = socket.getPeerCertificate(true);
          if (!peer || !peer.raw) {
            reject(new AppError(ErrorCode.TLS, 'The console completed a handshake but presented no certificate.'));
            return;
          }
          const certificate = new X509Certificate(peer.raw);
          resolve({
            subject: certificate.subject.replace(/\n/g, ', '),
            issuer: certificate.issuer.replace(/\n/g, ', '),
            selfSigned: certificate.subject === certificate.issuer,
            ca: certificate.ca,
            names: certificate.subjectAltName || '(no subjectAltName)',
            fingerprint: certificate.fingerprint256,
          });
        } catch (err) {
          reject(new AppError(ErrorCode.TLS, 'The console certificate could not be read.', {
            cause: err, detail: err instanceof Error ? err.message : String(err),
          }));
        } finally {
          socket.destroy();
        }
      },
    );

    socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`no handshake within ${timeoutMs / 1000}s`)));
    socket.on('error', (err) => reject(new AppError(ErrorCode.NETWORK, 'Could not reach the console to read its certificate.', {
      cause: err, detail: err instanceof Error ? err.message : String(err),
    })));
  });
}

/**
 * Perform the read the app would perform, and report what the console sent back
 * that the app would not be able to see.
 *
 * @param {import('./unifi.mjs').UnifiClient} unifi
 * @param {string} site
 * @returns {Promise<{status: number, headerNames: string[], setCookie: boolean, cookiesHeld: string[], csrfToken: 'derived'|'from header'|'none', rows: object[]}>}
 */
export async function probeRead(unifi, site) {
  const csrfBefore = unifi.csrfToken;
  const response = await unifi.send({
    method: 'GET',
    path: `${unifi.networkBase}/s/${encodeURIComponent(site)}/rest/networkconf`,
    authenticated: true,
  });

  const headerNames = Object.keys(response.headers || {}).sort();
  let rows = [];
  try {
    const payload = JSON.parse(response.body);
    rows = Array.isArray(payload.data) ? payload.data : [];
  } catch {
    // Reported through `status` and the header list instead.
  }

  const rotated = Boolean(response.headers['x-updated-csrf-token'] || response.headers['x-csrf-token']);

  return {
    status: response.status,
    headerNames,
    setCookie: Boolean(response.headers['set-cookie']),
    cookiesHeld: [...unifi.cookies.keys()],
    csrfToken: rotated ? 'from header' : (unifi.csrfToken && unifi.csrfToken !== csrfBefore ? 'derived' : (unifi.csrfToken ? 'already held' : 'none')),
    rows,
  };
}

/**
 * Write a row back exactly as it arrived.
 *
 * This is the only honest way to learn whether the credential authorises a
 * write, short of changing something. The body is byte-identical to what the
 * console just sent, so the worst case is that the gateway re-provisions an
 * unchanged tunnel — a brief drop, not a configuration change.
 *
 * **Unless the console hid a secret on the read.** Then "byte-identical" is a
 * lie: the row carries a mask or a blank where a key should be, and writing it
 * back tells the controller to forget the key. The tunnel stops handshaking and
 * the response says nothing about it. So the probe checks first and refuses,
 * which is itself a useful finding — it is the thing that would have gone wrong.
 *
 * @param {import('./unifi.mjs').UnifiClient} unifi
 * @param {object} row a row exactly as `listNetworks` returned it
 * @returns {Promise<WriteResult>}
 */
export async function probeWrite(unifi, row) {
  const refusal = refuseUnsafeWrite(row);
  if (refusal) return { ok: false, attempted: false, error: refusal };
  return attemptWrite(unifi, row);
}

/**
 * @typedef {{ok: true, attempted: true} | {ok: false, attempted: boolean, error: AppError} | {ok: false, attempted: false, skipped: string}} WriteResult
 */

/**
 * Learn whether a write needs the session the read left behind.
 *
 * The client that performed the read holds whatever cookie and CSRF token the
 * console handed out, and replays them. A write from it that succeeds says the
 * credential can write, and nothing about whether a client that cannot see
 * headers could. So the first write comes from a client that has sent nothing
 * at all: its PUT is its first request, and it has no cookie to offer.
 *
 * Each attempt re-provisions the tunnel, so the second is made only when it can
 * change the answer — the first was refused on authorisation or by the
 * console, and the reading client actually holds something the first lacked.
 *
 * @param {object} options
 * @param {import('./unifi.mjs').UnifiClient} options.session the client that performed the read
 * @param {(() => import('./unifi.mjs').UnifiClient)|null} options.fresh builds a client that has sent
 *        nothing; null when the credential is itself a session (a password sign-in), where the question
 *        does not arise
 * @param {object} options.row a WireGuard VPN Client row exactly as the read returned it
 * @returns {Promise<{refused: AppError|null, withoutSession: WriteResult|null, withSession: WriteResult|null}>}
 */
export async function probeWriteAccess({ session, fresh, row }) {
  const refused = refuseUnsafeWrite(row);
  if (refused) return { refused, withoutSession: null, withSession: null };

  if (!fresh) return { refused: null, withoutSession: null, withSession: await attemptWrite(session, row) };

  const withoutSession = await attemptWrite(fresh(), row);
  if (withoutSession.ok) {
    return { refused: null, withoutSession, withSession: { ok: false, attempted: false, skipped: 'not needed' } };
  }
  if (withoutSession.error.code !== ErrorCode.AUTH && withoutSession.error.code !== ErrorCode.HTTP) {
    return {
      refused: null, withoutSession,
      withSession: { ok: false, attempted: false, skipped: 'the first write failed for a reason a cookie would not change' },
    };
  }
  if (session.cookies.size === 0 && !session.csrfToken) {
    return {
      refused: null, withoutSession,
      withSession: { ok: false, attempted: false, skipped: 'the read left no cookie or token, so it would repeat the same request' },
    };
  }
  return { refused: null, withoutSession, withSession: await attemptWrite(session, row) };
}

/**
 * @param {import('./unifi.mjs').UnifiClient} unifi
 * @param {object} row
 * @returns {Promise<WriteResult>}
 */
async function attemptWrite(unifi, row) {
  try {
    await unifi.updateNetwork(row._id, row);
    return { ok: true, attempted: true };
  } catch (err) {
    return {
      ok: false, attempted: true,
      error: err instanceof AppError ? err : new AppError(ErrorCode.HTTP, 'The write probe failed.', { cause: err }),
    };
  }
}

/**
 * Why writing this row back unchanged could damage it, or null if it could not.
 *
 * @param {object} row
 * @returns {AppError|null}
 */
export function refuseUnsafeWrite(row) {
  const hazards = writeHazards(row);
  if (hazards.length === 0) return null;
  return new AppError(ErrorCode.INVALID_INPUT,
    `Not written: ${hazards.join('; ')}. Written back unchanged, this row could replace a real value with a ` +
    'mask or a blank and break the tunnel, so the probe refuses. That is itself the finding — no tool can ' +
    'safely round-trip this row as the console returned it.');
}

/**
 * Everything about a row that makes a byte-identical write unsafe.
 *
 * The private key must be a real key: every WireGuard VPN Client has one, so
 * anything else is the console hiding it. A preshared key must be real when the
 * row says one is in use, and must not be a mask regardless. Any other `x_`
 * field — the controller's prefix for a stored secret — must not come back
 * masked or blank.
 *
 * @param {object} row
 * @returns {string[]} one phrase per hazard, naming fields but never values
 */
export function writeHazards(row) {
  const detail = describeRowFields(row);
  const hazards = [];

  if (!row || typeof row._id !== 'string') hazards.push('the row has no id');
  if (detail.missingRequired.length > 0) hazards.push(`the row lacks ${detail.missingRequired.join(', ')}`);

  for (const [field, state] of detail.secrets) {
    if (isSecretHazard(row, field, state)) hazards.push(`${field} is ${state}`);
  }

  return hazards;
}

/**
 * @param {object} row
 * @param {string} field
 * @param {SecretState} state
 * @returns {boolean}
 */
function isSecretHazard(row, field, state) {
  if (state === 'present') return false;
  if (field === 'x_wireguard_private_key') {
    // A row created by uploading a `.conf` keeps its key inside the file and
    // carries no key field at all. Absent is then simply the shape of the row;
    // what matters is that the file itself holds a real key.
    return !(state === 'absent' && isFileMode(row));
  }
  if (field === 'wireguard_client_configuration_file' && isFileMode(row)) return true;
  if (field === 'wireguard_client_preshared_key') {
    return row.wireguard_client_preshared_key_enabled === true || state === 'looks redacted' || state === 'not a key';
  }
  return state === 'looks redacted' || (state === 'blank' && field.startsWith('x_'));
}

/**
 * @param {WriteResult} result
 * @returns {string}
 */
function describeWrite(result) {
  if (result.ok) return 'accepted';
  if (!result.attempted) return `skipped — ${result.skipped || result.error.message}`;
  return `REFUSED — ${result.error.message}`;
}

/**
 * The WireGuard VPN Client a tunnel names, or why there is none.
 *
 * By name *and* type: a configuration that names the LAN by mistake must not
 * have the LAN written back to the gateway, which re-provisions every client on
 * it and carries secrets this module knows nothing about.
 *
 * @param {object[]} rows
 * @param {string} name
 * @returns {{row: object, error: null} | {row: null, error: AppError}}
 */
export function resolveTunnelRow(rows, name) {
  try {
    return { row: findWireGuardClient(rows, name), error: null };
  } catch (err) {
    return {
      row: null,
      error: err instanceof AppError ? err : new AppError(ErrorCode.INVALID_INPUT, err instanceof Error ? err.message : String(err)),
    };
  }
}

/**
 * Describe one VPN Client row without disclosing it.
 *
 * Ubiquiti publishes no schema for `networkconf`, so the only way to know what
 * a particular console puts in a row is to look at one. Field *names* are the
 * useful part and are safe to print; values are not, with the exception of a
 * few short flags that decide how the row must be written.
 *
 * A secret is reported by its state — present, absent, blank, redacted, or not
 * shaped like a key — and never shown. That distinction matters more than it
 * looks: a controller that hides a secret on GET returns a row which, written
 * straight back, tells the controller to forget that secret. For a preshared
 * key the tunnel then stops handshaking, and nothing in the response says so.
 *
 * Every `x_` field counts as a secret, since that is the prefix the controller
 * gives the values it stores encrypted.
 *
 * @param {object} row a row exactly as `listNetworks` returned it
 * @returns {{name: string, fields: string[], revealed: Array<[string, string]>, secrets: Array<[string, SecretState]>, missingRequired: string[]}}
 */
export function describeRowFields(row) {
  const fields = Object.keys(row || {}).sort();

  const revealed = REVEALED_FIELDS
    .filter((field) => field in (row || {}))
    .map((field) => [field, JSON.stringify(row[field])]);

  const presharedInUse = Boolean(row && row.wireguard_client_preshared_key_enabled === true);
  const secretFields = new Set([
    ...SECRET_FIELDS.filter((field) => fields.includes(field) || field === 'x_wireguard_private_key'
      || (field === 'wireguard_client_preshared_key' && presharedInUse)
      || (field === 'wireguard_client_configuration_file' && isFileMode(row))),
    ...fields.filter((field) => field.startsWith('x_')),
  ]);
  const secrets = [...secretFields].map((field) => [field, secretState(row, field)]);

  return {
    name: row && typeof row.name === 'string' ? row.name : '(unnamed)',
    fields,
    revealed,
    secrets,
    // The manual-mode fields describe the tunnel only when there is no file to
    // describe it; a file-mode row does without them.
    missingRequired: isFileMode(row) ? [] : REQUIRED_FIELDS.filter((field) => !(field in (row || {}))),
  };
}

/** @param {object} row */
function isFileMode(row) {
  return Boolean(row && row.wireguard_client_mode === 'file');
}

/** @typedef {'present'|'absent'|'blank'|'looks redacted'|'not a key'} SecretState */

/**
 * @param {object} row
 * @param {string} field
 * @returns {SecretState}
 */
function secretState(row, field) {
  const value = row ? row[field] : undefined;
  if (value === undefined || value === null) return 'absent';
  if (value === '') return 'blank';
  // A controller that hides a secret usually substitutes a fixed mask rather
  // than dropping the field, so a value of nothing but punctuation is a
  // redaction, not a key.
  if (typeof value === 'string' && /^[*\u2022.\s]+$/.test(value)) return 'looks redacted';
  if (KEY_FIELDS.has(field)) return keyState(value);
  if (field === 'wireguard_client_configuration_file' && typeof value === 'string') {
    // A console could as easily mask the key *inside* the file as the file
    // itself, so the file is judged by the key it carries.
    const privateKey = /^\s*PrivateKey\s*=\s*(.*?)\s*$/mi.exec(value);
    if (!privateKey) return /\[Interface\]/i.test(value) ? 'not a key' : 'present';
    if (/^[*\u2022.\s]+$/.test(privateKey[1])) return 'looks redacted';
    return keyState(privateKey[1]);
  }
  return 'present';
}

/**
 * @param {unknown} value
 * @returns {'present'|'not a key'}
 */
function keyState(value) {
  // All zeros is shaped like a key and is exactly what a placeholder is.
  return isBase64Key(value) && !/^A{43}=$/.test(value) ? 'present' : 'not a key';
}

/**
 * Render a report. Returns lines; the caller decides where they go.
 *
 * @param {{certificate?: object, certificateError?: AppError, read: object, writes?: Array<{name: string, result: {refused: AppError|null, withoutSession: WriteResult|null, withSession: WriteResult|null}}>, tunnels?: string[]}} findings
 *        `tunnels` names the VPN Clients the configuration refers to; their rows
 *        are described field by field.
 * @returns {string[]}
 */
export function formatDiagnosis(findings) {
  const lines = [];
  const { certificate, certificateError, read, writes, tunnels } = findings;

  lines.push('Certificate');
  if (certificateError) {
    lines.push(`  could not be read: ${certificateError.message}`);
  } else if (certificate) {
    lines.push(`  subject      ${certificate.subject}`);
    lines.push(`  issuer       ${certificate.issuer}`);
    lines.push(`  self-signed  ${certificate.selfSigned ? 'yes' : 'no'}`);
    lines.push(`  CA:TRUE      ${certificate.ca ? 'yes' : 'no'}${certificate.ca === false ? '   <- a leaf, which is normal for a factory console and is pinnable' : ''}`);
    lines.push(`  names        ${certificate.names}`);
    lines.push(`  sha256       ${certificate.fingerprint}`);
  }

  lines.push('');
  lines.push('Read (GET rest/networkconf)');
  lines.push(`  status               ${read.status}`);
  lines.push(`  response headers     ${read.headerNames.join(', ') || '(none)'}`);
  lines.push(`  set-cookie present   ${read.setCookie ? 'yes' : 'no'}${read.setCookie ? '   <- the app cannot see this through curl' : ''}`);
  lines.push(`  cookies now held     ${read.cookiesHeld.length ? read.cookiesHeld.join(', ') : '(none)'}`);
  lines.push(`  csrf token           ${read.csrfToken}`);
  lines.push(`  vpn-client rows      ${read.rows.filter((r) => r && r.purpose === 'vpn-client').length}`);

  const described = (tunnels || []).map((name) => {
    const { row, error } = resolveTunnelRow(read.rows, name);
    return { name, row, error, detail: row ? describeRowFields(row) : null };
  });

  for (const { name, row, error, detail } of described) {
    lines.push('');
    lines.push(`Row "${name}"`);
    if (!detail) {
      lines.push(`  not described: ${error.message}`);
      continue;
    }
    lines.push(`  fields (${detail.fields.length})`);
    for (const line of wrap(detail.fields.join(', '), 72)) lines.push(`    ${line}`);
    for (const [field, value] of detail.revealed) lines.push(`  ${field.padEnd(40)} ${value}`);
    for (const [field, state] of detail.secrets) {
      lines.push(`  ${field.padEnd(40)} ${state}${isSecretHazard(row, field, state) ? `   <- ${redactionCost(field)}` : ''}`);
    }
    if (detail.missingRequired.length > 0) {
      lines.push(`  missing fields this tool needs: ${detail.missingRequired.join(', ')}`);
    }
  }

  if (writes && writes.length > 0) {
    lines.push('');
    lines.push('Write probe (PUT each row back unchanged)');
    for (const { name, result } of writes) {
      lines.push(`  "${name}"`);
      if (result.refused) {
        lines.push(`    not written              ${result.refused.message}`);
        continue;
      }
      lines.push(`    without session cookie   ${result.withoutSession
        ? describeWrite(result.withoutSession)
        : 'not tried — a password sign-in is itself a session'}`);
      lines.push(`    with session cookie      ${result.withSession ? describeWrite(result.withSession) : 'not tried'}`);
    }
  }

  lines.push('');
  lines.push('What this means for the desktop app');
  const blockers = [];
  const notes = [];
  const cookieSeen = read.setCookie || read.cookiesHeld.length > 0;

  if (!writes) {
    if (cookieSeen) {
      blockers.push('the console sets a cookie, which an API-key-only curl client cannot carry — run with ' +
        '--probe-write to learn whether a write actually needs it');
    }
  } else {
    let cookieQuestionOpen = cookieSeen;
    let answeredWithoutCookie = false;

    for (const { name, result } of writes) {
      if (result.refused) {
        blockers.push(`"${name}": not probed — ${result.refused.message}`);
        continue;
      }
      const bare = result.withoutSession;
      const session = result.withSession;

      if (bare && bare.ok) {
        answeredWithoutCookie = true;
        continue;
      }
      if (bare && session && session.ok) {
        blockers.push(`"${name}": the console accepted the write only with the session cookie from the read, ` +
          'which an API-key-only curl client cannot carry');
        cookieQuestionOpen = false;
        continue;
      }

      const failure = session && session.attempted ? session : bare || session;
      if (failure && failure.error && failure.error.code === ErrorCode.AUTH) {
        blockers.push(`"${name}": the credential does not authorise a write`);
      } else if (failure && failure.error) {
        blockers.push(`"${name}": the write probe failed — ${failure.error.message}`);
      }
    }

    if (cookieSeen && answeredWithoutCookie && writes.every(({ result }) => !result.withoutSession || result.withoutSession.ok)) {
      notes.push('The console sets a cookie, but the write succeeded without it, so the cookie does not block the port.');
      cookieQuestionOpen = false;
    }
    if (cookieQuestionOpen) {
      blockers.push('the console sets a cookie, and no write succeeded without it, so whether a curl client ' +
        'could manage without it is still unknown');
    }
  }

  for (const { name, row, detail } of described) {
    if (!detail) continue;
    for (const [field, state] of detail.secrets) {
      if (!isSecretHazard(row, field, state)) continue;
      blockers.push(`"${name}": the console returns ${field} ${state} — ${redactionCost(field)}`);
    }
    if (detail.missingRequired.length > 0) {
      blockers.push(`"${name}" does not carry ${detail.missingRequired.join(', ')}, so this tool would refuse to write it`);
    }
    if (isFileMode(row)) {
      blockers.push(`"${name}" is a file-mode VPN Client (created by uploading a .conf); the sync patches ` +
        'manual-mode fields and cannot refresh it yet');
    }
  }

  for (const note of notes) lines.push(`  ${note}`);
  if (blockers.length === 0) {
    lines.push('  Nothing here blocks the port.');
  } else {
    for (const blocker of blockers) lines.push(`  - ${blocker}`);
  }

  return lines;
}

/**
 * What a masked value actually costs, which depends on the field.
 *
 * A masked private key breaks the *write probe*, which round-trips the row
 * untouched — but not a real sync, which replaces that key anyway. A masked
 * preshared key breaks both, because nothing replaces it: the sync carries it
 * over from the row it read.
 *
 * @param {string} field
 * @returns {string}
 */
function redactionCost(field) {
  if (field === 'x_wireguard_private_key') {
    return 'the write probe cannot run (a real refresh replaces this field, so it is unaffected)';
  }
  if (field === 'wireguard_client_configuration_file') {
    return 'harmless in file mode, where a refresh rewrites it; otherwise a refresh would erase it';
  }
  if (field === 'wireguard_client_preshared_key') {
    return 'a refresh would erase it, and the tunnel would stop handshaking';
  }
  return 'a refresh carries this field over unchanged, so it would store this in place of the real value';
}

/**
 * Break a long comma-separated list across lines without splitting an item.
 *
 * @param {string} text
 * @param {number} width
 * @returns {string[]}
 */
function wrap(text, width) {
  const out = [];
  let line = '';
  for (const item of text.split(', ')) {
    if (line && line.length + item.length + 2 > width) { out.push(line); line = ''; }
    line += (line ? ', ' : '') + item;
  }
  if (line) out.push(line);
  return out.length > 0 ? out : ['(none)'];
}
