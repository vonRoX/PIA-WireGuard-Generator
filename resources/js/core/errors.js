/**
 * Typed errors with messages that are safe to put in front of a user.
 *
 * Every failure path in the app raises an AppError so the UI never has to
 * surface a raw `JSON.parse` message ("Unexpected end of JSON input") or a
 * curl exit code at someone who just wanted a VPN config.
 */

export const ErrorCode = Object.freeze({
  CURL_MISSING: 'CURL_MISSING',
  CURL_TOO_OLD: 'CURL_TOO_OLD',
  NETWORK: 'NETWORK',
  TIMEOUT: 'TIMEOUT',
  TLS: 'TLS',
  HTTP: 'HTTP',
  AUTH: 'AUTH',
  PARSE: 'PARSE',
  PROTOCOL: 'PROTOCOL',
  NO_SERVERS: 'NO_SERVERS',
  INVALID_INPUT: 'INVALID_INPUT',
  STORAGE: 'STORAGE',
  FILESYSTEM: 'FILESYSTEM',
});

export class AppError extends Error {
  /**
   * @param {string} code    one of ErrorCode
   * @param {string} message user-facing, complete sentence, no jargon
   * @param {{cause?: unknown, detail?: string}} [options] `detail` is technical
   *        context for the "Details" disclosure — never secrets.
   */
  constructor(code, message, options = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'AppError';
    this.code = code;
    this.detail = options.detail || '';
  }
}

/**
 * Turn anything thrown anywhere into something worth showing a user.
 * @param {unknown} err
 * @param {string} fallbackMessage
 * @returns {AppError}
 */
export function toAppError(err, fallbackMessage) {
  if (err instanceof AppError) return err;
  const detail = err instanceof Error ? err.message : String(err);
  return new AppError(ErrorCode.NETWORK, fallbackMessage, { cause: err, detail });
}

/**
 * curl's documented exit codes, mapped to something actionable.
 * @see https://curl.se/docs/manpage.html#EXIT
 * @param {number} exitCode
 * @param {string} stdErr
 * @returns {AppError}
 */
export function curlExitToError(exitCode, stdErr = '') {
  const detail = stdErr.trim().slice(0, 500);

  switch (exitCode) {
    case 5:
    case 6:
      return new AppError(ErrorCode.NETWORK,
        'Could not resolve the server address. Check your internet connection or DNS.', { detail });
    case 7:
      return new AppError(ErrorCode.NETWORK,
        'Could not connect to the server. It may be down, or a firewall may be blocking the connection.', { detail });
    case 28:
      return new AppError(ErrorCode.TIMEOUT,
        'The request timed out. Check your connection and try again.', { detail });
    case 35:
    case 51:
    case 58:
    case 59:
    case 77:
      return new AppError(ErrorCode.TLS,
        'The secure connection could not be established.', { detail });
    case 60:
      return new AppError(ErrorCode.TLS,
        "The server's certificate could not be verified against Private Internet Access's certificate authority. " +
        'This can mean the connection is being intercepted. No key was registered and no configuration was created.',
        { detail });
    case 127:
      return new AppError(ErrorCode.CURL_MISSING,
        'curl was not found on this system. Install curl and restart the app.', { detail });
    default:
      return new AppError(ErrorCode.NETWORK,
        `The network request failed (curl exit code ${exitCode}).`, { detail });
  }
}

/**
 * @param {number} status HTTP status code
 * @param {string} body   response body, used only for `detail`
 * @returns {AppError}
 */
export function httpStatusToError(status, body = '') {
  const detail = `HTTP ${status}: ${body.trim().slice(0, 300)}`;

  if (status === 401 || status === 403) {
    return new AppError(ErrorCode.AUTH, 'Your session is no longer valid. Please sign in again.', { detail });
  }
  if (status === 429) {
    return new AppError(ErrorCode.HTTP,
      'Private Internet Access is rate-limiting this account. Wait a minute and try again.', { detail });
  }
  if (status >= 500) {
    return new AppError(ErrorCode.HTTP,
      `Private Internet Access returned a server error (HTTP ${status}). This is on their end — try again shortly.`,
      { detail });
  }
  return new AppError(ErrorCode.HTTP, `The server rejected the request (HTTP ${status}).`, { detail });
}
