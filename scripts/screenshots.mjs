#!/usr/bin/env node
/**
 * Capture the README screenshots from the real application.
 *
 * Drives the same page the browser tests drive, with the same Neutralino stub,
 * so the images can never drift from what the app actually renders — and no PIA
 * account or network access is involved in producing them.
 *
 * Usage: npm run screenshots
 */

import { chromium } from '@playwright/test';
import { spawn } from 'node:child_process';
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'docs', 'images');
const PORT = 4199;
const STUB = readFileSync(join(ROOT, 'test', 'e2e', 'neutralino-stub.js'), 'utf8');

const SERVER_LIST = {
  groups: { wg: [{ name: 'wireguard', ports: [1337] }] },
  regions: [
    wg('ch-zurich', 'Switzerland', 'CH'),
    wg('de-berlin', 'Germany Berlin', 'DE', { port_forward: true }),
    wg('jp-tokyo', 'Japan', 'JP'),
    wg('nl-amsterdam', 'Netherlands', 'NL', { port_forward: true }),
    wg('se-stockholm', 'Sweden', 'SE'),
    wg('uk-london', 'UK London', 'GB'),
    wg('us-chicago', 'US Chicago', 'US'),
    wg('us-seattle', 'US Seattle', 'US'),
  ],
};

const ADD_KEY = {
  status: 'OK',
  server_key: 'sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
  server_port: 1337,
  server_ip: '193.176.86.1',
  peer_ip: '10.13.14.15',
};

function wg(id, name, country, extra = {}) {
  return {
    id, name, country, port_forward: false, geo: false,
    servers: { wg: [{ ip: '193.176.86.1', cn: `${id}-401` }] },
    ...extra,
  };
}

const ok = (body) => ({ exitCode: 0, stdOut: `${JSON.stringify(body)}\n200`, stdErr: '' });

const FIXTURES = {
  storage: { schemaVersion: '2', username: 'p1234567', favouriteRegionIds: '["nl-amsterdam"]' },
  responses: {
    token: ok({ token: 'screenshot-token' }),
    serverList: {
      exitCode: 0,
      stdOut: `${JSON.stringify(SERVER_LIST)}\n\nc2ln\n200`,
      stdErr: '',
    },
    addKey: ok(ADD_KEY),
  },
};

async function main() {
  mkdirSync(OUT, { recursive: true });

  const server = spawn(process.execPath, [join(ROOT, 'scripts', 'serve.mjs'), '--port', String(PORT)], {
    stdio: 'ignore',
  });

  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || undefined,
  });

  try {
    await waitForServer();

    const page = await browser.newPage({ viewport: { width: 820, height: 760 }, deviceScaleFactor: 2 });

    await page.addInitScript((value) => { window.__FIXTURES__ = value; }, FIXTURES);
    await page.route('**/js/neutralino.js', (route) =>
      route.fulfill({ status: 200, contentType: 'text/javascript; charset=utf-8', body: STUB }));

    await page.goto(`http://127.0.0.1:${PORT}/index.html`);
    await page.waitForSelector('#view-login.is-active');

    // 1 — sign in
    await page.fill('#password', 'not-a-real-password');
    await shoot(page, '01-sign-in.png');

    // 2 — choose a region
    await page.click('#login-btn');
    await page.waitForSelector('#view-config.is-active');
    await page.waitForFunction(() => document.querySelectorAll('#region-select option').length > 1);
    await page.selectOption('#region-select', 'se-stockholm');
    await shoot(page, '02-choose-region.png');

    // 3 — the result
    await page.click('#generate-btn');
    await page.waitForSelector('#view-success.is-active');
    await shoot(page, '03-configuration-ready.png');

    // 4 — the QR panel, for importing on a phone
    await page.click('#qr-btn');
    await page.waitForSelector('#qr-target img');
    await page.locator('#qr-panel').scrollIntoViewIfNeeded();
    await shoot(page, '04-qr-import.png');

    process.stdout.write(`\nWrote 4 screenshots to ${OUT}\n\n`);
  } finally {
    await browser.close();
    server.kill();
  }
}

async function shoot(page, name) {
  // Let the view transition settle so nothing is captured mid-fade.
  await page.waitForTimeout(350);
  await page.screenshot({ path: join(OUT, name) });
  process.stdout.write(`  ${name}\n`);
}

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const response = await fetch(`http://127.0.0.1:${PORT}/index.html`);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((done) => setTimeout(done, 100));
  }
  throw new Error('the static server did not start');
}

await main();
