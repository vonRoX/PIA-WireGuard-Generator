import { test as base, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const STUB = readFileSync(join(HERE, 'neutralino-stub.js'), 'utf8');

export const SERVER_LIST = {
  groups: { wg: [{ name: 'wireguard', ports: [1337] }] },
  regions: [
    wgRegion('de-berlin', 'Germany Berlin', 'DE', { port_forward: true }),
    wgRegion('nl-amsterdam', 'Netherlands', 'NL'),
    wgRegion('ch-zurich', 'Switzerland', 'CH', { geo: true }),
    wgRegion('us-chicago', 'US Chicago', 'US'),
    { id: 'no-wg', name: 'Öland (no WireGuard)', country: 'SE', servers: { meta: [{ ip: '1.1.1.1', cn: 'x' }] } },
  ],
};

export const ADD_KEY_OK = {
  status: 'OK',
  server_key: 'sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
  server_port: 1337,
  server_ip: '193.176.86.1',
  server_vip: '10.4.0.1',
  peer_ip: '10.13.14.15',
  peer_pubkey: 'client',
  dns_servers: ['10.0.0.243'],
};

function wgRegion(id, name, country, extra = {}) {
  return {
    id,
    name,
    country,
    port_forward: false,
    geo: false,
    servers: { wg: [{ ip: '193.176.86.1', cn: `${id}-401` }] },
    ...extra,
  };
}

/** curl writes the body, then a newline, then the status code. */
export function curlOk(body) {
  return { exitCode: 0, stdOut: `${typeof body === 'string' ? body : JSON.stringify(body)}\n200`, stdErr: '' };
}

export function curlStatus(status, body = '') {
  return { exitCode: 0, stdOut: `${body}\n${status}`, stdErr: '' };
}

export function curlFails(exitCode, stdErr = '') {
  return { exitCode, stdOut: '', stdErr };
}

/** The v6 endpoint answers with a JSON line followed by a signature. */
export function serverListBody(document = SERVER_LIST) {
  return `${JSON.stringify(document)}\n\nc2lnbmF0dXJl\n`;
}

const DEFAULT_RESPONSES = {
  token: curlOk({ token: 'test-token-abc123' }),
  serverList: curlOk(serverListBody()),
  addKey: curlOk(ADD_KEY_OK),
};

/**
 * A page with the Neutralino runtime stubbed out.
 *
 * Fixtures are plain data on purpose: the app ships a `script-src 'self'` policy
 * with no `'unsafe-eval'`, so anything that needed `new Function` in the page
 * would be blocked — by the very policy these tests are here to keep honest.
 * Give `responses.<call>` an array to script a different answer per attempt.
 */
export const test = base.extend({
  boot: async ({ page }, use) => {
    await use(async (fixtures = {}) => {
      const merged = {
        ...fixtures,
        responses: { ...DEFAULT_RESPONSES, ...(fixtures.responses || {}) },
      };

      await page.addInitScript((value) => { window.__FIXTURES__ = value; }, merged);

      await page.route('**/js/neutralino.js', (route) =>
        route.fulfill({ status: 200, contentType: 'text/javascript; charset=utf-8', body: STUB }));

      await page.goto('/index.html');
      await expect(page.locator('.view.is-active')).toBeVisible();
    });
  },
});

/** Sign in with the default happy-path fixtures and land on the config screen. */
export async function signIn(page, { username = 'p1234567', password = 'correct horse' } = {}) {
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.locator('#view-config')).toHaveClass(/is-active/);
}

export { expect };
