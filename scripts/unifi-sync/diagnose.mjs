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
 * @param {import('./unifi.mjs').UnifiClient} unifi
 * @param {object} row a row exactly as `listNetworks` returned it
 * @returns {Promise<{ok: true} | {ok: false, error: AppError}>}
 */
export async function probeWrite(unifi, row) {
  try {
    await unifi.updateNetwork(row._id, row);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof AppError ? err : new AppError(ErrorCode.HTTP, 'The write probe failed.', { cause: err }) };
  }
}

/**
 * Render a report. Returns lines; the caller decides where they go.
 *
 * @param {{certificate?: object, certificateError?: AppError, read: object, writes?: Array<{name: string, result: object}>}} findings
 * @returns {string[]}
 */
export function formatDiagnosis(findings) {
  const lines = [];
  const { certificate, certificateError, read, writes } = findings;

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
  if (blockers.length === 0) {
    lines.push('  Nothing here blocks the port.');
  } else {
    for (const blocker of blockers) lines.push(`  - ${blocker}`);
  }

  return lines;
}
