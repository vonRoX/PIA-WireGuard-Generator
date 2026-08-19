#!/usr/bin/env node
/**
 * A static server for `resources/`, used by the browser tests and the
 * screenshot script.
 *
 * The app's modules are ES modules, which browsers refuse to load over
 * `file://`, so the UI cannot be driven without an origin. This mimics what
 * Neutralino's own embedded server does — including serving the client library
 * route, which the tests intercept.
 *
 * Usage: node scripts/serve.mjs [--port 4173]
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, resolve, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'resources');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

const portFlag = process.argv.indexOf('--port');
const PORT = portFlag === -1 ? 4173 : Number(process.argv[portFlag + 1]);

const server = createServer(async (request, response) => {
  const path = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
  const relative = normalize(path === '/' ? '/index.html' : path).replace(/^(\.\.[/\\])+/, '');
  const file = join(ROOT, relative);

  if (!file.startsWith(ROOT)) {
    response.writeHead(403).end('forbidden');
    return;
  }

  try {
    const body = await readFile(file);
    response.writeHead(200, {
      'content-type': MIME[extname(file)] || 'application/octet-stream',
      'cache-control': 'no-store',
    });
    response.end(body);
  } catch {
    response.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  }
});

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`serving ${ROOT} on http://127.0.0.1:${PORT}\n`);
});
