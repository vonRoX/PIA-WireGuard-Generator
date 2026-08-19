/**
 * The one place in the app that runs a process.
 *
 * Everything above this file deals in request descriptors; everything below is
 * the constant string `curl -q --config -` plus a document on stdin.
 */

import {
  buildCurlConfig, parseCurlOutput, parseCurlVersion,
  CURL_COMMAND, MIN_CURL_VERSION, MIN_CURL_VERSION_SCHANNEL, isVersionAtLeast,
} from './curl.js';
import { AppError, ErrorCode, curlExitToError, httpStatusToError } from './errors.js';

/**
 * @typedef {object} ExecResult
 * @property {number} exitCode
 * @property {string} stdOut
 * @property {string} stdErr
 */

/**
 * @callback ExecFn
 * @param {string} command
 * @param {{stdIn?: string}} [options]
 * @returns {Promise<ExecResult>}
 */

export class HttpClient {
  /**
   * @param {ExecFn} exec
   * @param {{tolerateUnknownRevocation?: boolean}} [options]
   *        Set `tolerateUnknownRevocation` on Windows, whose Schannel backend
   *        rejects a CA that publishes no revocation endpoint.
   */
  constructor(exec, options = {}) {
    this.exec = exec;
    this.tolerateUnknownRevocation = Boolean(options.tolerateUnknownRevocation);
  }

  /**
   * Perform a request and return the decoded body.
   *
   * @param {import('./curl.js').CurlRequest} request
   * @returns {Promise<{body: string, status: number}>}
   * @throws {AppError} on transport failure, TLS failure or a non-2xx status
   */
  async send(request) {
    // Only the pinned requests need the Schannel accommodation; everything else
    // is validated against the system trust store, which has revocation data.
    const config = buildCurlConfig(
      request.caCertPath && this.tolerateUnknownRevocation
        ? { ...request, tolerateUnknownRevocation: true }
        : request,
    );

    let result;
    try {
      result = await this.exec(CURL_COMMAND, { stdIn: config });
    } catch (err) {
      throw new AppError(ErrorCode.NETWORK, 'The network request could not be started.', {
        cause: err,
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    if (result.exitCode !== 0) {
      throw curlExitToError(result.exitCode, result.stdErr);
    }

    const { body, status } = parseCurlOutput(result.stdOut);

    if (status === 0) {
      throw new AppError(ErrorCode.NETWORK,
        'The server closed the connection without sending a response.',
        { detail: (result.stdErr || '').trim().slice(0, 300) });
    }

    if (status < 200 || status >= 300) {
      throw httpStatusToError(status, body);
    }

    return { body, status };
  }

  /**
   * Perform a request and parse the body as JSON.
   *
   * A response that is not JSON (an HTML error page from a captive portal or a
   * CDN, say) becomes a readable message rather than "Unexpected token <".
   *
   * @param {import('./curl.js').CurlRequest} request
   * @param {string} what human-readable name of the thing being fetched
   * @returns {Promise<any>}
   */
  async sendJson(request, what) {
    const { body } = await this.send(request);
    return parseJsonOrThrow(body, what);
  }

  /**
   * Verify curl exists and is new enough for certificate pinning.
   *
   * @returns {Promise<[number,number,number]>} the detected version
   * @throws {AppError} when curl is missing or too old to verify certificates the way we need
   */
  async preflight() {
    let result;
    try {
      result = await this.exec('curl --version');
    } catch (err) {
      throw new AppError(ErrorCode.CURL_MISSING, CURL_MISSING_MESSAGE, { cause: err });
    }

    if (result.exitCode !== 0 || !result.stdOut) {
      throw new AppError(ErrorCode.CURL_MISSING, CURL_MISSING_MESSAGE, {
        detail: (result.stdErr || '').trim().slice(0, 300),
      });
    }

    const version = parseCurlVersion(result.stdOut);
    if (!version) {
      throw new AppError(ErrorCode.CURL_MISSING, CURL_MISSING_MESSAGE, {
        detail: `unrecognised output: ${result.stdOut.slice(0, 120)}`,
      });
    }

    const minimum = this.tolerateUnknownRevocation ? MIN_CURL_VERSION_SCHANNEL : MIN_CURL_VERSION;

    if (!isVersionAtLeast(version, minimum)) {
      throw new AppError(
        ErrorCode.CURL_TOO_OLD,
        `curl ${version.join('.')} is too old — ${minimum.join('.')} or newer is required to verify ` +
        "Private Internet Access's certificates. Please update curl.",
      );
    }

    return version;
  }
}

const CURL_MISSING_MESSAGE =
  'curl was not found on this system. This app uses curl for every network request. ' +
  'Install it (Windows 10+ and macOS ship with it; on Linux try your package manager) and restart the app.';

/**
 * @param {string} text
 * @param {string} what
 * @returns {any}
 */
export function parseJsonOrThrow(text, what) {
  const trimmed = (text || '').trim();

  if (trimmed === '') {
    throw new AppError(ErrorCode.PARSE, `Private Internet Access returned an empty response for ${what}.`);
  }

  try {
    return JSON.parse(trimmed);
  } catch (err) {
    const looksLikeHtml = /^\s*<(?:!doctype|html)/i.test(trimmed);
    throw new AppError(
      ErrorCode.PARSE,
      looksLikeHtml
        ? `Received a web page instead of ${what}. Private Internet Access may be down, or a network ` +
          'portal may be intercepting the connection.'
        : `Could not read the response for ${what} — it was not in the expected format.`,
      { cause: err, detail: trimmed.slice(0, 200) },
    );
  }
}
