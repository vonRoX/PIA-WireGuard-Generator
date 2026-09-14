/**
 * The Workbench page driven in a real browser against the in-memory fake engine.
 *
 * The real server (scripts/workbench/server.mjs) is built separately, so this spec mounts
 * `public/` on a throwaway server of its own that keeps the parts of the contract the page
 * depends on: the CSP header, the X-Workbench header requirement, and the
 * `{ error: { code, message, hint } }` shape.
 */

import { test as base, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFakeEngine } from '../../scripts/workbench/fake-engine.mjs';

const PUBLIC = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'workbench', 'public');
const CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const SCREENSHOTS = process.env.WORKBENCH_SCREENSHOTS || '';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
};

const STATUS = {
  INVALID_INPUT: 400,
  UNIFI_KEY_REJECTED: 422,
  NOT_CONFIGURED: 409,
  CERT_CHANGED: 409,
  NETWORK: 502,
  TLS: 502,
  HTTP: 502,
};

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : {};
}

async function startWorkbench() {
  const engine = createFakeEngine();
  const apiRequests = [];

  const routes = {
    'GET /api/state': () => engine.getState(),
    'POST /api/console/inspect': (_q, b) => engine.inspectConsole(b.url),
    'POST /api/console/trust': (_q, b) => engine.trustConsole(b.url, b.fingerprint256),
    'POST /api/unifi-key': (_q, b) => engine.setUnifiKey(b.apiKey),
    'POST /api/pia': (_q, b) => engine.setPiaCredentials(b.username, b.password),
    'DELETE /api/credentials': () => engine.forgetCredentials(),
    'GET /api/explore': (q) => engine.explore(q.get('path')),
    'GET /api/tunnels': () => engine.listTunnels(),
  };

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const headers = { 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' };

    if (url.pathname.startsWith('/api/')) {
      apiRequests.push({ method: request.method, path: url.pathname, workbench: request.headers['x-workbench'] });
      const json = (status, value) => {
        response.writeHead(status, { ...headers, 'Content-Type': 'application/json' });
        response.end(JSON.stringify(value));
      };
      if (request.headers['x-workbench'] !== '1') {
        json(403, { error: { code: 'FORBIDDEN', message: 'Missing X-Workbench header.' } });
        return;
      }
      const route = routes[`${request.method} ${url.pathname}`];
      if (!route) {
        json(404, { error: { code: 'NOT_FOUND', message: 'No such endpoint.' } });
        return;
      }
      try {
        const body = request.method === 'POST' ? await readBody(request) : {};
        json(200, await route(url.searchParams, body));
      } catch (error) {
        const code = error.code || 'INTERNAL';
        json(STATUS[code] || 500, { error: { code, message: error.message, ...(error.hint ? { hint: error.hint } : {}) } });
      }
      return;
    }

    const relative = normalize(url.pathname === '/' ? '/index.html' : url.pathname).replace(/^(\.\.[/\\])+/, '');
    const file = join(PUBLIC, relative);
    if (!file.startsWith(PUBLIC)) {
      response.writeHead(403, headers).end();
      return;
    }
    try {
      const body = await readFile(file);
      response.writeHead(200, { ...headers, 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
      response.end(body);
    } catch {
      response.writeHead(404, headers).end('not found');
    }
  });

  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`,
    engine,
    apiRequests,
    close: () => new Promise((done) => {
      server.close(done);
      server.closeAllConnections();
    }),
  };
}

const test = base.extend({
  workbench: async ({ page }, use) => {
    const workbench = await startWorkbench();
    const problems = [];
    page.on('console', (message) => {
      // A 4xx from the API is logged by the browser and is expected; anything else is not.
      if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) problems.push(message.text());
    });
    page.on('pageerror', (error) => problems.push(error.message));
    workbench.problems = problems;
    await use(workbench);
    await workbench.close();
  },
});

async function shot(page, name) {
  if (SCREENSHOTS) await page.screenshot({ path: join(SCREENSHOTS, `${name}.png`), fullPage: true, animations: 'disabled' });
}

async function completeSetup(page) {
  await page.getByRole('button', { name: 'Check certificate' }).click();
  await page.getByRole('button', { name: 'Trust this certificate' }).click();
  await page.getByLabel('API key', { exact: true }).fill('  local-key-123  ');
  await page.getByRole('button', { name: 'Check and store key' }).click();
  await page.getByLabel('PIA username').fill('p1234567');
  await page.getByLabel('PIA password').fill('hunter2');
  await page.getByRole('button', { name: 'Store login' }).click();
  await expect(page.getByRole('heading', { name: 'Setup is complete' })).toBeVisible();
}

test.describe('Workbench setup', () => {
  test('walks from console address to a finished setup', async ({ page, workbench }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto(`${workbench.origin}/`);

    await expect(page.getByRole('heading', { name: 'Connect your UniFi console' })).toBeVisible();
    await expect(page.locator('#step-console')).toHaveAttribute('data-state', 'current');
    await expect(page.locator('#step-key')).toHaveAttribute('data-state', 'upcoming');
    await expect(page.getByLabel('Console address')).toHaveValue('https://192.168.1.1');
    await shot(page, '01-setup-start');

    await page.getByRole('button', { name: 'Check certificate' }).click();
    await expect(page.locator('#cert-title')).toBeFocused();
    await expect(page.locator('#cert-subject')).toHaveText('CN=unifi.local');
    await expect(page.locator('#cert-names')).toContainText('unifi.local');
    await expect(page.locator('.fingerprint__byte')).toHaveCount(32);
    await expect(page.locator('.fingerprint__row').first()).toContainText('3B 9F');
    await expect(page.getByText('Compare this with the certificate your browser shows at this address. Trust it only if they match.')).toBeVisible();
    await shot(page, '02-certificate');

    await page.getByRole('button', { name: 'Trust this certificate' }).click();
    await expect(page.locator('#step-console')).toHaveAttribute('data-state', 'done');
    await expect(page.locator('#step-console-summary')).toContainText('https://192.168.1.1');
    await expect(page.locator('#step-key-title')).toBeFocused();
    await expect(page.getByText('A key from unifi.ui.com (Site Manager) will not work.')).toBeVisible();

    // The Site Manager mistake.
    await page.getByLabel('API key', { exact: true }).fill('sitemanager');
    await page.getByRole('button', { name: 'Check and store key' }).click();
    const rejected = page.locator('#key-error [data-code="UNIFI_KEY_REJECTED"]');
    await expect(rejected).toBeVisible();
    await expect(rejected.locator('.alert__hint--prominent')).toContainText('Settings → Control Plane → Integrations');
    await expect(page.locator('#step-key')).toHaveAttribute('data-state', 'current');
    await shot(page, '03-key-rejected');

    await page.getByLabel('API key', { exact: true }).fill('  local-key-123\n');
    await page.getByRole('button', { name: 'Check and store key' }).click();
    await expect(page.locator('#step-key')).toHaveAttribute('data-state', 'done');
    await expect(page.locator('#step-key-summary')).toContainText('UniFi Network 10.0.162');
    await expect(page.locator('#step-pia-title')).toBeFocused();

    // Client-side check before anything is sent.
    await page.getByRole('button', { name: 'Store login' }).click();
    await expect(page.locator('#pia-username-error')).toBeVisible();

    await page.getByLabel('PIA username').fill('p1234567');
    await page.getByLabel('PIA password').fill('hunter2');
    await page.getByRole('button', { name: 'Store login' }).click();
    await expect(page.getByRole('heading', { name: 'Setup is complete' })).toBeFocused();
    await expect(page.locator('#step-pia')).toHaveAttribute('data-state', 'done');
    await shot(page, '04-setup-done');

    // No secret was ever echoed back into the page.
    await expect(page.locator('body')).not.toContainText('local-key-123');
    await expect(page.locator('body')).not.toContainText('hunter2');

    expect(workbench.apiRequests.length).toBeGreaterThan(0);
    for (const call of workbench.apiRequests) expect(call.workbench).toBe('1');
    expect(workbench.problems).toEqual([]);
  });

  test('"They do not match" trusts nothing, and Change can be cancelled', async ({ page, workbench }) => {
    await page.goto(`${workbench.origin}/`);
    await page.getByRole('button', { name: 'Check certificate' }).click();
    await page.getByRole('button', { name: 'They do not match' }).click();
    await expect(page.locator('#cert-panel')).toBeHidden();
    await expect(page.getByText('Good call — nothing was trusted.')).toBeVisible();
    await expect(page.getByLabel('Console address')).toBeFocused();
    expect((await workbench.engine.getState()).console).toBeNull();

    await page.getByRole('button', { name: 'Check certificate' }).click();
    await page.getByRole('button', { name: 'Trust this certificate' }).click();
    await page.locator('#console-change').click();
    await expect(page.locator('#step-console')).toHaveAttribute('data-state', 'editing');
    await expect(page.getByLabel('Console address')).toBeFocused();
    await page.locator('#console-cancel').click();
    await expect(page.locator('#step-console')).toHaveAttribute('data-state', 'done');
    await expect(page.locator('#console-change')).toBeFocused();
  });

  test('a certificate that changes before it is trusted is refused', async ({ page, workbench }) => {
    await page.goto(`${workbench.origin}/`);
    await page.getByRole('button', { name: 'Check certificate' }).click();
    await expect(page.locator('.fingerprint__byte')).toHaveCount(32);
    workbench.engine._rotateCertificate();
    await page.getByRole('button', { name: 'Trust this certificate' }).click();
    await expect(page.locator('#trust-error [data-code="CERT_CHANGED"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Trust this certificate' })).toBeDisabled();

    await page.getByRole('button', { name: 'Check the certificate again' }).click();
    await expect(page.locator('.fingerprint__row').first()).toContainText('A4 17');
  });

  test('a console that cannot be reached says so next to the button', async ({ page, workbench }) => {
    await page.goto(`${workbench.origin}/`);
    await page.getByLabel('Console address').fill('console.invalid');
    await page.getByRole('button', { name: 'Check certificate' }).click();
    const error = page.locator('#console-error [data-code="NETWORK"]');
    await expect(error).toBeVisible();
    await expect(error.getByRole('button', { name: 'Try again' })).toBeVisible();
  });

  test('forgetting credentials asks first, then reopens the key step', async ({ page, workbench }) => {
    await page.goto(`${workbench.origin}/#setup`);
    await completeSetup(page);

    await page.getByRole('button', { name: 'Forget stored credentials' }).click();
    await expect(page.getByRole('button', { name: 'Keep them' })).toBeFocused();
    await page.getByRole('button', { name: 'Keep them' }).click();
    expect((await workbench.engine.getState()).unifiKey.stored).toBe(true);

    await page.getByRole('button', { name: 'Forget stored credentials' }).click();
    await page.getByRole('button', { name: 'Forget them' }).click();
    await expect(page.locator('#step-key')).toHaveAttribute('data-state', 'current');
    await expect(page.locator('#step-console')).toHaveAttribute('data-state', 'done');
    await expect(page.locator('#forget-zone')).toBeHidden();
    const state = await workbench.engine.getState();
    expect(state.unifiKey.stored).toBe(false);
    expect(state.pia.stored).toBe(false);
  });

  test('a Workbench that is not answering offers a retry', async ({ page, workbench }) => {
    let failures = 1;
    await page.route('**/api/state', (route) => {
      if (failures-- > 0) return route.abort('connectionrefused');
      return route.continue();
    });
    await page.goto(`${workbench.origin}/`);
    const error = page.locator('#boot-error [data-code="OFFLINE"]');
    await expect(error).toBeVisible();
    await error.getByRole('button', { name: 'Try again' }).click();
    await expect(page.getByRole('heading', { name: 'Connect your UniFi console' })).toBeVisible();
  });
});

test.describe('Workbench tunnels and explorer', () => {
  test('tunnels show humanised statuses and no write action', async ({ page, workbench }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto(`${workbench.origin}/`);
    await completeSetup(page);
    await page.getByRole('link', { name: 'View tunnels' }).click();

    await expect(page.getByRole('heading', { name: 'Tunnels', exact: true })).toBeFocused();
    const rows = page.locator('#tunnels-body tr');
    await expect(rows).toHaveCount(3);
    const cz = rows.filter({ hasText: 'WireGuard PIA CZ' });
    await expect(cz.locator('.badge')).toHaveAttribute('data-tone', 'pending');
    await expect(cz.locator('.badge')).toHaveText('Connecting');
    await expect(cz).toContainText('Connecting longer than usual');
    await expect(cz).toContainText('Configuration file');
    const ovpn = rows.filter({ hasText: 'OpenVPN Office' });
    await expect(ovpn.locator('.badge')).toHaveAttribute('data-tone', 'unknown');

    const refreshKeys = page.getByRole('button', { name: 'Refresh keys' });
    await expect(refreshKeys).toHaveAttribute('aria-disabled', 'true');
    await expect(refreshKeys).toHaveAttribute('title', 'Coming next');
    await shot(page, '05-tunnels');

    const before = workbench.apiRequests.filter((r) => r.path === '/api/tunnels').length;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect.poll(() => workbench.apiRequests.filter((r) => r.path === '/api/tunnels').length).toBeGreaterThan(before);
    expect(workbench.problems).toEqual([]);
  });

  test('tunnels before setup point back to Setup', async ({ page, workbench }) => {
    await page.goto(`${workbench.origin}/#tunnels`);
    await expect(page.locator('#tunnels-error [data-code="NOT_CONFIGURED"]')).toBeVisible();
    await page.locator('#tunnels-error').getByRole('link', { name: 'Go to Setup' }).click();
    await expect(page.getByRole('heading', { name: 'Connect your UniFi console' })).toBeFocused();
  });

  test('the explorer renders a redacted body as a tree and refuses paths outside /proxy/network/', async ({ page, workbench }) => {
    await page.goto(`${workbench.origin}/`);
    await completeSetup(page);
    await page.getByRole('link', { name: 'API explorer', exact: true }).click();

    const sentBefore = workbench.apiRequests.length;
    await page.getByRole('textbox', { name: 'Path' }).fill('/api/self');
    await page.getByRole('button', { name: 'Send GET', exact: true }).click();
    await expect(page.locator('#explore-path-error')).toContainText('/proxy/network/');
    await page.getByRole('textbox', { name: 'Path' }).fill('https://192.168.1.1/proxy/network/integration/v1/info');
    await page.getByRole('button', { name: 'Send GET', exact: true }).click();
    await expect(page.locator('#explore-path-error')).toBeVisible();
    expect(workbench.apiRequests.length).toBe(sentBefore);

    await page.getByRole('button', { name: 'Send GET /proxy/network/api/s/default/rest/networkconf' }).click();
    await expect(page.locator('#explore-status')).toHaveText('200 OK');
    await expect(page.locator('#explore-tree')).toContainText('WireGuard PIA CZ');
    await page.getByRole('button', { name: 'Expand all' }).click();
    await expect(page.locator('#explore-tree .json__redacted').first()).toHaveText('<redacted>');
    await expect(page.locator('#explore-tree')).toContainText('PrivateKey = <redacted>');
    await shot(page, '06-explorer');

    await page.getByRole('button', { name: 'Raw' }).click();
    await expect(page.locator('#explore-raw-view')).toContainText('"purpose": "vpn-client"');

    await page.getByRole('textbox', { name: 'Path' }).fill('/proxy/network/api/s/default/rest/nothing');
    await page.getByRole('button', { name: 'Send GET', exact: true }).click();
    await expect(page.locator('#explore-status')).toHaveText('404 Not found');
    expect(workbench.problems).toEqual([]);
  });

  test('works at 400 px wide without sideways scrolling', async ({ page, workbench }) => {
    await page.setViewportSize({ width: 400, height: 860 });
    await page.goto(`${workbench.origin}/`);
    await page.getByRole('button', { name: 'Check certificate' }).click();
    await expect(page.locator('.fingerprint__byte')).toHaveCount(32);
    await shot(page, '07-narrow-certificate');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);

    await completeSetupFromCertificate(page);
    await page.goto(`${workbench.origin}/#tunnels`);
    await expect(page.locator('#tunnels-body tr')).toHaveCount(3);
    await shot(page, '08-narrow-tunnels');
    const tunnelsOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(tunnelsOverflow).toBeLessThanOrEqual(0);
  });

  test('light colour scheme renders', async ({ page, workbench }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto(`${workbench.origin}/`);
    await page.getByRole('button', { name: 'Check certificate' }).click();
    await expect(page.locator('.fingerprint__byte')).toHaveCount(32);
    const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(background).toBe('rgb(241, 245, 249)');
    await shot(page, '09-light-certificate');
  });
});

async function completeSetupFromCertificate(page) {
  await page.getByRole('button', { name: 'Trust this certificate' }).click();
  await page.getByLabel('API key', { exact: true }).fill('local-key');
  await page.getByRole('button', { name: 'Check and store key' }).click();
  await page.getByLabel('PIA username').fill('p1234567');
  await page.getByLabel('PIA password').fill('pw');
  await page.getByRole('button', { name: 'Store login' }).click();
  await expect(page.getByRole('heading', { name: 'Setup is complete' })).toBeVisible();
}
