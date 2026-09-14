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
 *   1. Does the console set a cookie on an API-key request? `UnifiClient`
 *      harvests `set-cookie` from every response regardless of how it
 *      authenticated, and sends the cookie (and a CSRF token derived from it)
 *      on the next write. If that happens, an API-key-only curl client cannot
 *      reproduce it.
 *   2. Is the API key accepted for a write, or only for a read? A key good for
 *      GET but not PUT fails only after fresh keys have been registered.
 *   3. Is the console certificate a self-signed *leaf*? Windows curl builds on
 *      Schannel, which may refuse a CA:FALSE certificate as a trust anchor
 *      where OpenSSL accepts it.
 *
 * Nothing here prints a secret: header *names* are listed, never their values,
 * and the write probe sends the row back exactly as it arrived.
 */

import { connect as tlsConnect } from 'node:tls';
import { X509Certificate } from 'node:crypto';

import { AppError, ErrorCode } from '../../resources/js/core/errors.js';
import { REQUIRED_FIELDS } from '../../resources/js/core/unifi-sync.js';

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
 * **Unless the console redacted a secret on the read.** Then "byte-identical"
 * is a lie: the row carries a mask where a key should be, and writing it back
 * tells the controller to forget the key. The tunnel stops handshaking and the
 * response says nothing about it. So the probe checks first and refuses, which
 * is itself a useful finding — it is the thing that would have gone wrong.
 *
 * @param {import('./unifi.mjs').UnifiClient} unifi
 * @param {object} row a row exactly as `listNetworks` returned it
 * @returns {Promise<{ok: true} | {ok: false, error: AppError}>}
 */
export async function probeWrite(unifi, row) {
  const redacted = describeRowFields(row).secrets
    .filter(([, state]) => state === 'looks redacted')
    .map(([field]) => field);

  if (redacted.length > 0) {
    return {
      ok: false,
      error: new AppError(ErrorCode.INVALID_INPUT,
        `Not written: the console returned ${redacted.join(', ')} masked rather than in full, so writing this ` +
        'row back would replace the real value with the mask and break the tunnel. That the console does this ' +
        'is the finding — it means no tool can safely round-trip one of its rows.'),
    };
  }

  try {
    await unifi.updateNetwork(row._id, row);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof AppError ? err : new AppError(ErrorCode.HTTP, 'The write probe failed.', { cause: err }) };
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
 * A secret is reported as present, absent, or redacted — never shown. That
 * distinction matters more than it looks: a controller that redacts a secret on
 * GET returns a row which, written straight back, tells the controller to
 * forget that secret. For a preshared key the tunnel then stops handshaking,
 * and nothing in the response says so.
 *
 * @param {object} row a row exactly as `listNetworks` returned it
 * @returns {{name: string, fields: string[], revealed: Array<[string, string]>, secrets: Array<[string, 'present'|'absent'|'looks redacted']>, missingRequired: string[]}}
 */
export function describeRowFields(row) {
  const fields = Object.keys(row || {}).sort();

  const revealed = REVEALED_FIELDS
    .filter((field) => field in (row || {}))
    .map((field) => [field, JSON.stringify(row[field])]);

  const secrets = SECRET_FIELDS
    .filter((field) => fields.includes(field) || field === 'x_wireguard_private_key')
    .map((field) => [field, secretState(row, field)]);

  return {
    name: row && typeof row.name === 'string' ? row.name : '(unnamed)',
    fields,
    revealed,
    secrets,
    missingRequired: REQUIRED_FIELDS.filter((field) => !(field in (row || {}))),
  };
}

/**
 * @param {object} row
 * @param {string} field
 * @returns {'present'|'absent'|'looks redacted'}
 */
function secretState(row, field) {
  const value = row ? row[field] : undefined;
  if (value === undefined || value === null || value === '') return 'absent';
  if (typeof value !== 'string') return 'present';
  // A controller that hides a secret usually substitutes a fixed mask rather
  // than dropping the field, so a value of nothing but punctuation is a
  // redaction, not a key.
  if (/^[*\u2022.\s]+$/.test(value)) return 'looks redacted';
  return 'present';
}

/**
 * Render a report. Returns lines; the caller decides where they go.
 *
 * @param {{certificate?: object, certificateError?: AppError, read: object, writes?: Array<{name: string, result: object}>, tunnels?: string[]}} findings
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
    lines.push(`  CA:TRUE      ${certificate.ca ? 'yes' : 'no'}${certificate.ca === false ? '   <- a leaf; Windows curl may refuse it as a trust anchor' : ''}`);
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
    const row = read.rows.find((candidate) => candidate && candidate.name === name);
    return { name, row, described: row ? describeRowFields(row) : null };
  });

  for (const { name, described: detail } of described) {
    lines.push('');
    lines.push(`Row "${name}"`);
    if (!detail) {
      lines.push('  the console returned no row with this name');
      continue;
    }
    lines.push(`  fields (${detail.fields.length})`);
    for (const line of wrap(detail.fields.join(', '), 72)) lines.push(`    ${line}`);
    for (const [field, value] of detail.revealed) lines.push(`  ${field.padEnd(40)} ${value}`);
    for (const [field, state] of detail.secrets) {
      lines.push(`  ${field.padEnd(40)} ${state}${state === 'looks redacted' ? `   <- ${redactionCost(field)}` : ''}`);
    }
    if (detail.missingRequired.length > 0) {
      lines.push(`  missing fields this tool needs: ${detail.missingRequired.join(', ')}`);
    }
  }

  if (writes && writes.length > 0) {
    lines.push('');
    lines.push('Write probe (PUT the row back unchanged)');
    for (const { name, result } of writes) {
      lines.push(result.ok
        ? `  ${String(name).padEnd(32)} accepted`
        : `  ${String(name).padEnd(32)} REFUSED — ${result.error.message}`);
    }
  }

  lines.push('');
  lines.push('What this means for the desktop app');
  const blockers = [];
  if (read.setCookie || read.cookiesHeld.length > 0) {
    blockers.push('the console sets a cookie, which an API-key-only curl client cannot carry');
  }
  if (writes && writes.some(({ result }) => !result.ok)) {
    blockers.push('the credential does not authorise a write');
  }
  if (certificate && certificate.ca === false) {
    blockers.push('the certificate is a self-signed leaf, which Windows curl may refuse to pin against');
  }
  for (const { name, described: detail } of described) {
    if (!detail) continue;
    for (const [field, state] of detail.secrets) {
      if (state !== 'looks redacted') continue;
      blockers.push(`"${name}": the console masks ${field} on read — ${redactionCost(field)}`);
    }
    if (detail.missingRequired.length > 0) {
      blockers.push(`"${name}" does not carry ${detail.missingRequired.join(', ')}, so this tool would refuse to write it`);
    }
  }
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
  return 'a refresh would erase it, and the tunnel would stop handshaking';
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
