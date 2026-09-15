/**
 * The error codes the Workbench UI handles (scripts/workbench/CONTRACT.md), on
 * top of the app's own {@link AppError}.
 *
 * `AppError` takes any code string, so the three the desktop app never needed —
 * `CERT_CHANGED`, `UNIFI_KEY_REJECTED`, `NOT_CONFIGURED` — live here rather than
 * in `resources/js/core/errors.js`. A `hint` is the one sentence that tells the
 * user what to do next; like `message` and `detail`, it never carries a secret.
 */

import { AppError, ErrorCode } from '../../resources/js/core/errors.js';

export const EngineErrorCode = Object.freeze({
  INVALID_INPUT: ErrorCode.INVALID_INPUT,
  NETWORK: ErrorCode.NETWORK,
  TLS: ErrorCode.TLS,
  HTTP: ErrorCode.HTTP,
  STORAGE: ErrorCode.STORAGE,
  CERT_CHANGED: 'CERT_CHANGED',
  UNIFI_KEY_REJECTED: 'UNIFI_KEY_REJECTED',
  NOT_CONFIGURED: 'NOT_CONFIGURED',
});

/**
 * @param {string} code
 * @param {string} message
 * @param {{hint?: string, detail?: string, cause?: unknown}} [options]
 * @returns {AppError & {hint?: string}}
 */
export function engineError(code, message, options = {}) {
  const err = new AppError(code, message, { detail: options.detail, cause: options.cause });
  if (options.hint) err.hint = options.hint;
  return err;
}

export { AppError };
