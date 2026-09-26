#!/usr/bin/env node
/**
 * The Workbench server: a local web UI for setting up and exercising the UniFi refresh.
 *
 * It is deliberately thin. The engine owns secrets, trust and redaction; this file owns the HTTP
 * surface — who may reach the engine (see security.mjs), how a browser request becomes an engine
 * call, and how an engine failure becomes a status code the UI can act on.
 *
 * Usage: node scripts/workbench/server.mjs [--fake] [--port N] [--no-open]
 *
 * The contract this implements is scripts/workbench/CONTRACT.md.
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { AppError } from '../../resources/js/core/errors.js';
import {
  MAX_BODY_BYTES, SECURITY_HEADERS, createGate, hostAllowed, originAllowed, resolveStatic, sessionCookie,
} from './security.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PUBLIC_DIR = join(HERE, 'public');

/**
 * Past this, a body that is already over the cap is not worth draining: the connection is cut.
 * Below it we read to the end before answering 413, because closing a socket with unread data
 * makes Windows send a reset, and the browser would show a network error instead of our answer.
 */
const DRAIN_LIMIT_BYTES = 1024 * 1024;

/**
 * Engine error codes the UI is built to handle, and the status each deserves. The message and
 * hint of these travel to the browser; anything else is reported generically.
 *
 * UNIFI_KEY_REJECTED is 422, not 401: the Workbench session is fine, it is the console that said
 * no — and a 401 is what the UI reserves for "your Workbench session is gone".
 */
const STATUS_BY_CODE = Object.freeze({
  INVALID_INPUT: 400,
  CERT_CHANGED: 409,
  NOT_CONFIGURED: 409,
  UNIFI_KEY_REJECTED: 422,
  NETWORK: 502,
  TLS: 502,
  HTTP: 502,
});

/** An error the server itself raises, already in the contract's shape. */
class HttpError extends Error {
  constructor(status, code, message, headers = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

/**
 * @param {object} options
 * @param {object} options.engine   the contract's engine interface
 * @param {number} [options.port]   0 picks a free port
 * @param {string} [options.publicDir]
 * @param {(line: string) => void} [options.log] receives "METHOD /path STATUS" — never a body or query
 * @returns {Promise<{url: string, port: number, close: () => Promise<void>}>}
 */
export async function startWorkbench({ engine, port = 0, publicDir = DEFAULT_PUBLIC_DIR, log = () => {} }) {
  if (!engine) throw new TypeError('startWorkbench needs an engine');

  const gate = createGate();
  const routes = apiRoutes(engine);
  const root = resolve(publicDir);
  let boundPort = port;

  const server = createServer((request, response) => {
    // Security headers go on everything, including the refusals.
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.setHeader(name, value);

    const pathname = pathOf(request.url);
    response.on('finish', () => log(`${request.method} ${pathname} ${response.statusCode}`));

    handle(request, response).catch((err) => {
      // Something in the plumbing itself failed; nothing about it belongs in front of the user.
      if (!response.headersSent) sendError(response, internalError(err));
      else response.destroy();
    });
  });

  async function handle(request, response) {
    if (typeof request.url !== 'string' || !request.url.startsWith('/')) {
      sendText(response, 400, 'Malformed request.');
      return;
    }
    if (!hostAllowed(request.headers.host, boundPort)) {
      // 421 Misdirected Request: this server does not answer for the name the client used.
      sendText(response, 421, 'This server only answers at the address it printed.');
      return;
    }

    const url = new URL(request.url, `http://127.0.0.1:${boundPort}`);
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      await handleApi(request, response, url);
    } else {
      await handlePage(request, response, url);
    }
  }

  async function handlePage(request, response, url) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.setHeader('allow', 'GET, HEAD');
      sendText(response, 405, 'Method not allowed.');
      return;
    }

    if (url.pathname === '/' && url.searchParams.has('token')) {
      const session = gate.exchange(url.searchParams.get('token'));
      if (session !== null) {
        response.setHeader('set-cookie', sessionCookie(session));
      } else if (!gate.hasSession(request.headers.cookie)) {
        sendText(response, 401, 'This link has already been used. Restart the Workbench for a new one.');
        return;
      }
      // Either way, get the token out of the address bar and the history.
      response.writeHead(303, { location: '/' }).end();
      return;
    }

    if (!gate.hasSession(request.headers.cookie)) {
      sendText(response, 401, 'Open the link printed in the terminal that started the Workbench.');
      return;
    }

    const found = await resolveStatic(root, url.pathname);
    if (!found) {
      sendText(response, 404, 'Not found.');
      return;
    }
    const body = await readFile(found.file);
    response.writeHead(200, { 'content-type': found.contentType, 'content-length': body.length });
    response.end(request.method === 'HEAD' ? undefined : body);
  }

  async function handleApi(request, response, url) {
    try {
      if (!originAllowed(request.headers.origin, boundPort)) {
        throw new HttpError(403, 'FORBIDDEN', 'Cross-origin requests are not allowed.');
      }
      if (request.headers['x-workbench'] !== '1') {
        throw new HttpError(403, 'FORBIDDEN', 'Missing the X-Workbench header.');
      }
      if (!gate.hasSession(request.headers.cookie)) {
        throw new HttpError(401, 'UNAUTHORIZED',
          'The Workbench session is missing or has expired. Open the link printed in the terminal.');
      }

      const route = routes.get(url.pathname);
      if (!route) throw new HttpError(404, 'NOT_FOUND', 'No such API endpoint.');
      const handler = route[request.method];
      if (!handler) {
        throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed.', { allow: Object.keys(route).join(', ') });
      }

      const body = request.method === 'POST' ? await readJsonBody(request, response) : (request.resume(), {});
      if (body === undefined) return; // the connection went away, or 413 was already sent
      const result = await handler(body, url);
      sendJson(response, 200, result === undefined ? null : result);
    } catch (err) {
      if (err instanceof HttpError) {
        sendError(response, err);
      } else if (isAppError(err) && Object.hasOwn(STATUS_BY_CODE, err.code)) {
        sendError(response, { status: STATUS_BY_CODE[err.code], code: err.code, message: err.message, hint: err.hint });
      } else {
        sendError(response, internalError(err));
      }
    }
  }

  /**
   * @returns {Promise<object | undefined>} the parsed body, or `undefined` when a response has
   *          already been decided (413) or the client disappeared
   */
  async function readJsonBody(request, response) {
    const declared = Number(request.headers['content-length']);
    if (declared > DRAIN_LIMIT_BYTES) {
      // Not reading a megabyte just to refuse it; the socket is closed after the answer.
      response.setHeader('connection', 'close');
      sendError(response, tooLarge());
      return undefined;
    }

    const outcome = await new Promise((resolveBody) => {
      const chunks = [];
      let size = 0;
      request.on('data', (chunk) => {
        size += chunk.length;
        if (size > DRAIN_LIMIT_BYTES) request.destroy();
        else if (size <= MAX_BODY_BYTES) chunks.push(chunk);
      });
      request.on('end', () => resolveBody(size > MAX_BODY_BYTES ? 'too large' : Buffer.concat(chunks)));
      request.on('close', () => resolveBody('gone'));
      request.on('error', () => resolveBody('gone'));
    });

    if (outcome === 'gone') return undefined;
    if (outcome === 'too large') {
      sendError(response, tooLarge());
      return undefined;
    }

    if (outcome.length === 0) return {};
    let parsed;
    try {
      parsed = JSON.parse(outcome.toString('utf8'));
    } catch {
      throw new HttpError(400, 'INVALID_INPUT', 'The request body is not valid JSON.');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new HttpError(400, 'INVALID_INPUT', 'The request body must be a JSON object.');
    }
    return parsed;
  }

  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', rejectListen);
      resolveListen();
    });
  });
  boundPort = server.address().port;

  return {
    url: `http://127.0.0.1:${boundPort}/?token=${gate.token}`,
    port: boundPort,
    close() {
      return new Promise((resolveClose) => {
        server.close(() => resolveClose());
        server.closeAllConnections();
      });
    },
  };
}

/** The route table from CONTRACT.md. Handlers receive the parsed body and the request URL. */
function apiRoutes(engine) {
  return new Map([
    ['/api/state', { GET: () => engine.getState() }],
    ['/api/console/inspect', { POST: (body) => engine.inspectConsole(field(body, 'url')) }],
    ['/api/console/trust', {
      POST: (body) => engine.trustConsole(field(body, 'url'), field(body, 'fingerprint256')),
    }],
    ['/api/unifi-key', { POST: (body) => engine.setUnifiKey(field(body, 'apiKey')) }],
    ['/api/pia', { POST: (body) => engine.setPiaCredentials(field(body, 'username'), field(body, 'password')) }],
    ['/api/credentials', { DELETE: () => engine.forgetCredentials() }],
    ['/api/explore', {
      GET: (_body, url) => {
        const path = url.searchParams.get('path');
        if (path === null) throw new HttpError(400, 'INVALID_INPUT', 'Missing the "path" query parameter.');
        return engine.explore(path);
      },
    }],
    ['/api/tunnels', { GET: () => engine.listTunnels() }],
  ]);
}

/**
 * The server checks only that a field is a string; what a valid URL or key looks like is the
 * engine's call, and its INVALID_INPUT carries a better message than this layer could.
 */
function field(body, name) {
  const value = body[name];
  if (typeof value !== 'string') {
    throw new HttpError(400, 'INVALID_INPUT', `The request body needs a "${name}" string.`);
  }
  return value;
}

function isAppError(err) {
  // By name as well as by class: the engine may reach errors.js by a different module URL.
  return err instanceof AppError || (err instanceof Error && err.name === 'AppError' && typeof err.code === 'string');
}

function tooLarge() {
  return new HttpError(413, 'PAYLOAD_TOO_LARGE', `Request bodies are limited to ${MAX_BODY_BYTES / 1024} KB.`);
}

function internalError(_err) {
  // Deliberately discards the error: its message or stack may quote a secret the engine was handling.
  return new HttpError(500, 'INTERNAL', 'Something went wrong inside the Workbench. Check the terminal and try again.');
}

/** The path for the log line: never the query, which is where the token and explore paths live. */
function pathOf(rawUrl) {
  if (typeof rawUrl !== 'string') return '?';
  const end = rawUrl.search(/[?#]/);
  return (end === -1 ? rawUrl : rawUrl.slice(0, end)).slice(0, 200);
}

function sendJson(response, status, value) {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length });
  response.end(body);
}

function sendError(response, { status, code, message, hint, headers = {} }) {
  for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
  const error = { code, message };
  if (typeof hint === 'string' && hint) error.hint = hint;
  sendJson(response, status, { error });
}

function sendText(response, status, text) {
  const body = Buffer.from(text, 'utf8');
  response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'content-length': body.length });
  response.end(body);
}

/**
 * Hand the URL to the default browser. The URL is ours and contains only [A-Za-z0-9:/.?=_-], which
 * matters on Windows: `cmd /c start` re-parses its command line, so it is checked before it goes near
 * cmd, and passed as an argument rather than spliced into a command string.
 */
function openBrowser(url) {
  if (!/^http:\/\/127\.0\.0\.1:\d+\/\?token=[A-Za-z0-9_-]+$/.test(url)) return;
  const [command, args] = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
    : process.platform === 'darwin' ? ['open', [url]]
      : ['xdg-open', [url]];
  execFile(command, args, { windowsHide: true }, () => {
    // Failing to open a browser is not fatal: the URL is on the terminal.
  });
}

async function loadEngine(fake) {
  const [specifier, factory, label] = fake
    ? ['./fake-engine.mjs', 'createFakeEngine', 'the fake engine (scripts/workbench/fake-engine.mjs)']
    : ['../engine/engine.mjs', 'createEngine', 'the engine (scripts/engine/engine.mjs)'];

  let module;
  try {
    module = await import(specifier);
  } catch (err) {
    throw new Error(`Could not load ${label}: ${err.message}`, { cause: err });
  }
  if (typeof module[factory] !== 'function') throw new Error(`${label} does not export ${factory}().`);
  return module[factory]();
}

async function main() {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        fake: { type: 'boolean', default: false },
        port: { type: 'string', default: '0' },
        'no-open': { type: 'boolean', default: false },
      },
    }));
  } catch (err) {
    console.error(`${err.message}\nUsage: node scripts/workbench/server.mjs [--fake] [--port N] [--no-open]`);
    process.exit(1);
  }

  const port = Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    console.error(`--port must be a number between 0 and 65535, not "${values.port}".`);
    process.exit(1);
  }

  let workbench;
  try {
    const engine = await loadEngine(values.fake);
    workbench = await startWorkbench({
      engine,
      port,
      log: (line) => process.stderr.write(`${line}\n`),
    });
  } catch (err) {
    console.error(err.code === 'EADDRINUSE' ? `Port ${port} is already in use.` : err.message);
    process.exit(1);
  }

  console.log(`Workbench${values.fake ? ' (fake engine)' : ''}: ${workbench.url}`);
  if (!values['no-open']) openBrowser(workbench.url);

  const stop = () => workbench.close().then(() => process.exit(0));
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

const invokedDirectly = process.argv[1]
  && resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
if (invokedDirectly) main();
