/**
 * The only way this page talks to the Workbench server.
 *
 * Every request carries `X-Workbench: 1` (the server refuses /api/* without it, which a
 * cross-site form or image can never set) and the same-origin session cookie. Nothing else in
 * the page may call fetch — test/workbench-ui.test.js checks.
 */

const TIMEOUT_MS = 45_000;

export class ApiError extends Error {
  /**
   * @param {{ code: string, message: string, hint?: string, status?: number }} fields
   */
  constructor({ code, message, hint = '', status = 0 }) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.hint = hint;
    this.status = status;
  }

  /** Worth offering "Try again" for: the request may not have reached the engine. */
  get retryable() {
    return this.code === 'OFFLINE' || this.code === 'TIMEOUT' || this.code === 'NETWORK';
  }
}

/**
 * @param {'GET'|'POST'|'DELETE'} method
 * @param {string} path  must start with /api/
 * @param {unknown} [body]
 * @returns {Promise<any>}
 */
export async function request(method, path, body) {
  if (!path.startsWith('/api/')) throw new Error(`Not an API path: ${path}`);

  const headers = { 'X-Workbench': '1', Accept: 'application/json' };
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'manual' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  init.signal = controller.signal;

  let response;
  try {
    response = await fetch(path, init);
  } catch {
    if (controller.signal.aborted) {
      throw new ApiError({
        code: 'TIMEOUT',
        message: 'The Workbench took too long to answer.',
        hint: 'The console may be slow or unreachable. Try again in a moment.',
      });
    }
    throw new ApiError({
      code: 'OFFLINE',
      message: 'Could not reach the Workbench.',
      hint: 'Check that the Workbench window is still running, then try again.',
    });
  } finally {
    clearTimeout(timer);
  }

  let text = '';
  try {
    text = await response.text();
  } catch {
    text = '';
  }
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!response.ok) {
    const error = data && typeof data === 'object' ? data.error : null;
    if (error && typeof error.code === 'string') {
      throw new ApiError({
        code: error.code,
        message: typeof error.message === 'string' && error.message ? error.message : 'The request failed.',
        hint: typeof error.hint === 'string' ? error.hint : '',
        status: response.status,
      });
    }
    if (response.type === 'opaqueredirect' || response.status === 401 || response.status === 403) {
      throw new ApiError({
        code: 'SESSION',
        message: 'This page is no longer signed in to the Workbench.',
        hint: 'Open the link the Workbench printed when it started. If it was restarted, use the new link.',
        status: response.status,
      });
    }
    throw new ApiError({
      code: 'HTTP',
      message: `The Workbench answered with an error (HTTP ${response.status}).`,
      status: response.status,
    });
  }

  if (data === null) {
    throw new ApiError({ code: 'PARSE', message: 'The Workbench sent an answer this page could not read.', status: response.status });
  }
  return data;
}

export const api = {
  state: () => request('GET', '/api/state'),
  inspectConsole: (url) => request('POST', '/api/console/inspect', { url }),
  trustConsole: (url, fingerprint256) => request('POST', '/api/console/trust', { url, fingerprint256 }),
  setUnifiKey: (apiKey) => request('POST', '/api/unifi-key', { apiKey }),
  setPia: (username, password) => request('POST', '/api/pia', { username, password }),
  forgetCredentials: () => request('DELETE', '/api/credentials'),
  explore: (path) => request('GET', `/api/explore?path=${encodeURIComponent(path)}`),
  tunnels: () => request('GET', '/api/tunnels'),
};
