/**
 * The app driven the way a person drives it, in a real browser engine.
 *
 * These cover the failures the previous version turned into dead ends: a
 * Generate button that was enabled with nothing selected, a "Loading regions…"
 * placeholder that never resolved, and a success screen shown for a config that
 * had `undefined` in it.
 */

import {
  test,
  expect,
  signIn,
  curlOk,
  curlStatus,
  curlFails,
  serverListBody,
  SERVER_LIST,
  ADD_KEY_OK,
} from './fixtures.js';

test.describe('signing in', () => {
  test('the happy path reaches the region picker', async ({ page, boot }) => {
    await boot();

    await expect(page.getByRole('heading', { name: 'Sign in to Private Internet Access' })).toBeVisible();
    await signIn(page);

    await expect(page.getByText('Signed in as p1234567')).toBeVisible();
    await expect(page.locator('#region-select option').first()).not.toHaveText(/Loading/);
  });

  test('the password never reaches a command line', async ({ page, boot }) => {
    await boot();
    await signIn(page, { password: 'p@ss`id`$(whoami) & "quoted"' });

    const calls = await page.evaluate(() => window.__CALLS__.exec);
    const network = calls.filter((call) => call.command !== 'curl --version' && call.command !== '<exit>');

    expect(network.length).toBeGreaterThan(0);
    for (const call of network) {
      expect(call.command).toBe('curl -q --config -');
      expect(call.command).not.toContain('p@ss');
    }
    // It does travel — on stdin, where no shell parses it.
    expect(network[0].stdIn).toContain('p@ss`id`$(whoami) & ');
  });

  test('bad credentials say so, and a server outage does not', async ({ page, boot }) => {
    await boot({ responses: { token: curlStatus(401, '{"message":"invalid"}') } });

    await page.getByLabel('Username').fill('p1234567');
    await page.getByLabel('Password', { exact: true }).fill('wrong');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.locator('#login-error')).toContainText('Those credentials were not accepted');
    await expect(page.locator('#view-login')).toHaveClass(/is-active/);
  });

  test('a 500 is reported as PIA being down, not as a wrong password', async ({ page, boot }) => {
    await boot({ responses: { token: curlStatus(500, 'upstream error') } });

    await page.getByLabel('Username').fill('p1234567');
    await page.getByLabel('Password', { exact: true }).fill('correct');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.locator('#login-error')).toContainText('server error (HTTP 500)');
    await expect(page.locator('#login-error')).not.toContainText('credentials');
  });

  test('an HTML error page becomes a readable message, not a parse error', async ({ page, boot }) => {
    await boot({ responses: { token: curlOk('<!doctype html><html><style>b{x:1}</style>502</html>') } });

    await page.getByLabel('Username').fill('p1234567');
    await page.getByLabel('Password', { exact: true }).fill('correct');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.locator('#login-error')).toContainText('Received a web page');
    await expect(page.locator('#login-error')).not.toContainText('Unexpected token');
  });

  test('a dead network is reported as a network problem', async ({ page, boot }) => {
    await boot({ responses: { token: curlFails(6, 'curl: (6) Could not resolve host') } });

    await page.getByLabel('Username').fill('p1234567');
    await page.getByLabel('Password', { exact: true }).fill('correct');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.locator('#login-error')).toContainText('Could not resolve the server address');
  });
});

test.describe('staying signed in', () => {
  test('is off by default, and no token is written', async ({ page, boot }) => {
    await boot();
    await expect(page.locator('#stay-signed-in')).not.toBeChecked();

    await signIn(page);

    const stored = await page.evaluate(() => Object.fromEntries(window.__STORAGE__));
    expect(stored.authToken).toBeUndefined();
    expect(stored.username).toBe('p1234567');
  });

  test('stores the token with an issue time when it is ticked', async ({ page, boot }) => {
    await boot();
    await page.locator('#stay-signed-in').check();
    await signIn(page);

    const stored = await page.evaluate(() => Object.fromEntries(window.__STORAGE__));
    expect(stored.authToken).toBe('test-token-abc123');
    expect(Number(stored.authTokenIssuedAt)).toBeGreaterThan(0);
  });

  test('a token left on disk by v1 is deleted, with an explanation', async ({ page, boot }) => {
    await boot({ storage: { authToken: 'v1-plaintext-token', username: 'p1234567', selectedRegionIndex: '87' } });

    await expect(page.locator('#login-error')).toContainText('removed the sign-in token');
    await expect(page.locator('#view-login')).toHaveClass(/is-active/);

    const stored = await page.evaluate(() => Object.fromEntries(window.__STORAGE__));
    expect(stored.authToken).toBeUndefined();
    expect(stored.selectedRegionIndex).toBeUndefined();
  });

  test('an expired stored token sends the user back to sign in', async ({ page, boot }) => {
    const longAgo = String(Date.now() - 48 * 60 * 60 * 1000);
    await boot({
      storage: {
        schemaVersion: '2', authToken: 'stale', authTokenIssuedAt: longAgo, staySignedIn: '1',
      },
    });

    await expect(page.locator('#login-error')).toContainText('had expired');
    await expect(page.locator('#view-login')).toHaveClass(/is-active/);
  });

  test('a fresh stored token goes straight to the region picker', async ({ page, boot }) => {
    await boot({
      storage: {
        schemaVersion: '2', authToken: 'fresh', authTokenIssuedAt: String(Date.now()), staySignedIn: '1',
      },
    });

    await expect(page.locator('#view-config')).toHaveClass(/is-active/);
  });
});

test.describe('choosing a region', () => {
  test('lists only regions with a verifiable WireGuard server', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    const options = await page.locator('#region-select option').allTextContents();
    expect(options).toHaveLength(4);
    expect(options.join(' ')).not.toContain('Öland');
    expect(options[0]).toContain('Germany Berlin');
    expect(options[0]).toContain('port forwarding');
  });

  test('Generate stays disabled until something is really selected', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await expect(page.locator('#generate-btn')).toBeDisabled();

    await page.locator('#region-select').selectOption('nl-amsterdam');
    await expect(page.locator('#generate-btn')).toBeEnabled();
  });

  test('filtering narrows the list and drops a selection that scrolled out of view', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await page.locator('#region-select').selectOption('us-chicago');
    await expect(page.locator('#generate-btn')).toBeEnabled();

    await page.locator('#region-filter').fill('switz');
    await expect(page.locator('#region-select option')).toHaveCount(1);
    await expect(page.locator('#generate-btn')).toBeDisabled();

    await page.locator('#region-filter').fill('');
    await expect(page.locator('#region-select option')).toHaveCount(4);
  });

  test('a filter that matches nothing says so instead of showing an empty box', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await page.locator('#region-filter').fill('atlantis');
    await expect(page.locator('#region-select')).toContainText('No region matches "atlantis"');
    await expect(page.locator('#generate-btn')).toBeDisabled();
  });

  test('pinned regions move to the top and persist', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await page.locator('#region-select').selectOption('us-chicago');
    await page.locator('#favourite-btn').click();

    await expect(page.locator('#region-select optgroup').first()).toHaveAttribute('label', 'Pinned');
    await expect(page.locator('#region-select optgroup').first().locator('option')).toHaveText([/US Chicago/]);

    const stored = await page.evaluate(() => Object.fromEntries(window.__STORAGE__));
    expect(JSON.parse(stored.favouriteRegionIds)).toEqual(['us-chicago']);
  });

  test('the saved region is restored by id', async ({ page, boot }) => {
    await boot({
      storage: {
        schemaVersion: '2',
        authToken: 'fresh',
        authTokenIssuedAt: String(Date.now()),
        staySignedIn: '1',
        regionId: 'ch-zurich',
      },
    });

    await expect(page.locator('#region-select')).toHaveValue('ch-zurich');
    await expect(page.locator('#generate-btn')).toBeEnabled();
  });

  test('a saved region PIA no longer offers is explained, not silently swapped', async ({ page, boot }) => {
    await boot({
      storage: {
        schemaVersion: '2',
        authToken: 'fresh',
        authTokenIssuedAt: String(Date.now()),
        staySignedIn: '1',
        regionId: 'jp-tokyo',
      },
    });

    await expect(page.locator('#config-notice')).toContainText('no longer offered');
    await expect(page.locator('#config-notice')).toContainText('jp-tokyo');
    await expect(page.locator('#generate-btn')).toBeDisabled();
  });

  test('a server list that cannot be read leaves an error, not a stuck spinner', async ({ page, boot }) => {
    await boot({ responses: { serverList: curlOk(serverListBody({ error: 'schema changed' })) } });
    await signIn(page);

    await expect(page.locator('#config-error')).toContainText('unexpected shape');
    await expect(page.locator('#region-select')).not.toContainText('Loading regions');
    await expect(page.locator('#generate-btn')).toBeDisabled();
  });
});

test.describe('generating', () => {
  test('produces a config, masks the private key, and reveals on request', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();

    await expect(page.locator('#view-success')).toHaveClass(/is-active/);
    await expect(page.locator('#preview-filename')).toHaveText('PIA-de-berlin.conf');
    await expect(page.locator('#success-subtitle')).toContainText('Germany Berlin');

    const masked = await page.locator('#config-preview').textContent();
    expect(masked).toContain('•••');
    expect(masked).toContain(`PublicKey = ${ADD_KEY_OK.server_key}`);
    expect(masked).toContain('Endpoint = 193.176.86.1:1337');
    expect(masked).not.toContain('undefined');

    await page.getByRole('button', { name: 'Reveal private key' }).click();
    const revealed = await page.locator('#config-preview').textContent();
    expect(revealed).not.toContain('•••');
    expect(revealed).toMatch(/PrivateKey = [A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=/);
  });

  test('the registration request pins the certificate and never uses -k', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();
    await expect(page.locator('#view-success')).toHaveClass(/is-active/);

    const calls = await page.evaluate(() => window.__CALLS__.exec);
    const addKey = calls.find((call) => call.stdIn && call.stdIn.includes('/addKey'));

    expect(addKey.command).toBe('curl -q --config -');
    expect(addKey.stdIn).toContain('cacert = ');
    expect(addKey.stdIn).toContain('connect-to = "de-berlin-401:1337:193.176.86.1:1337"');
    expect(addKey.stdIn).toContain('url = "https://de-berlin-401:1337/addKey"');
    expect(addKey.stdIn).not.toMatch(/insecure/);
  });

  test('an incomplete reply is refused instead of writing "undefined" to a file', async ({ page, boot }) => {
    const { server_key: _dropped, ...incomplete } = ADD_KEY_OK;
    await boot({ responses: { addKey: curlOk(incomplete) } });
    await signIn(page);

    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();

    await expect(page.locator('#config-error')).toContainText('incomplete configuration');
    await expect(page.locator('#view-config')).toHaveClass(/is-active/);
    await expect(page.locator('#view-success')).not.toHaveClass(/is-active/);
  });

  test('a certificate failure names interception and creates nothing', async ({ page, boot }) => {
    await boot({ responses: { addKey: curlFails(60, 'curl: (60) SSL certificate problem') } });
    await signIn(page);

    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();

    await expect(page.locator('#config-error')).toContainText('being intercepted');
    await expect(page.locator('#config-error')).toContainText('No key was registered');
    await expect(page.locator('#view-config')).toHaveClass(/is-active/);
  });

  test('an expired token during generation returns the user to sign in', async ({ page, boot }) => {
    await boot({ responses: { addKey: curlStatus(401, '{"message":"expired"}') } });
    await signIn(page);

    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();

    await expect(page.locator('#view-login')).toHaveClass(/is-active/);
    await expect(page.locator('#login-error')).toContainText('sign in again');
  });

  test('a custom DNS value is validated before anything is generated', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    await page.locator('#region-select').selectOption('de-berlin');
    await page.locator('#dns-preset').selectOption('custom');
    await page.locator('#custom-dns').fill('not-an-ip');
    await page.getByRole('button', { name: /Generate keys/ }).click();

    await expect(page.locator('#config-error')).toContainText('not a valid IPv4 address');

    await page.locator('#custom-dns').fill('9.9.9.9, 1.1.1.1');
    await page.getByRole('button', { name: /Generate keys/ }).click();

    await expect(page.locator('#config-preview')).toContainText('DNS = 9.9.9.9, 1.1.1.1');
  });
});

test.describe('the result', () => {
  test.beforeEach(async ({ page, boot }) => {
    await boot();
    await signIn(page);
    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();
    await expect(page.locator('#view-success')).toHaveClass(/is-active/);
  });

  test('renders a QR code behind an explicit warning', async ({ page }) => {
    await expect(page.locator('#qr-panel')).toBeHidden();

    await page.getByRole('button', { name: 'Show QR' }).click();

    await expect(page.locator('#qr-panel')).toBeVisible();
    await expect(page.locator('#qr-panel')).toContainText('contains your private key');

    const image = page.locator('#qr-target img');
    await expect(image).toBeVisible();
    await expect(image).toHaveAttribute('src', /^data:image\/gif;base64,/);
  });

  test('copies the configuration and warns that the clipboard now holds a key', async ({ page }) => {
    await page.getByRole('button', { name: 'Copy' }).click();

    await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();
    await expect(page.locator('#save-status')).toContainText('on your clipboard');

    const clipboard = await page.evaluate(() => window.__CALLS__.clipboard);
    expect(clipboard[0]).toContain('[Interface]');
    expect(clipboard[0]).toContain('PrivateKey = ');
  });

  test('saving restricts the file to the owner', async ({ page }) => {
    await page.getByRole('button', { name: 'Save .conf file' }).click();

    await expect(page.locator('#save-status')).toContainText('readable only by your account');

    const { files, permissions } = await page.evaluate(() => window.__CALLS__);
    const written = files.find((file) => file.path === '/tmp/saved/PIA.conf');

    expect(written.data).toContain('[Interface]');
    expect(permissions.at(-1)).toMatchObject({
      path: '/tmp/saved/PIA.conf',
      mode: 'REPLACE',
      permissions: { ownerRead: true, ownerWrite: true, groupRead: false, othersRead: false },
    });
  });

  test('a platform that refuses permissions warns rather than pretending', async ({ page, boot }) => {
    await boot({ permissionsFail: true });
    await signIn(page);
    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();
    await page.getByRole('button', { name: 'Save .conf file' }).click();

    await expect(page.locator('#save-status')).toContainText('would not let the app restrict');
    await expect(page.locator('#save-status')).toContainText('contains your private key');
  });

  test('cancelling the save dialog does nothing at all', async ({ page, boot }) => {
    await boot({ savePath: '' });
    await signIn(page);
    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();
    await page.getByRole('button', { name: 'Save .conf file' }).click();

    await expect(page.locator('#save-status')).toBeHidden();
    const files = await page.evaluate(() => window.__CALLS__.files.filter((f) => !f.removed));
    expect(files.filter((file) => file.path.endsWith('.conf'))).toHaveLength(0);
  });

  test('"Generate another" returns to the picker with the selection intact', async ({ page }) => {
    await page.getByRole('button', { name: 'Generate another' }).click();

    await expect(page.locator('#view-config')).toHaveClass(/is-active/);
    await expect(page.locator('#region-select')).toHaveValue('de-berlin');
    await expect(page.locator('#generate-btn')).toBeEnabled();
  });
});

test.describe('signing out', () => {
  test('clears the token and resets the picker', async ({ page, boot }) => {
    await boot();
    await page.locator('#stay-signed-in').check();
    await signIn(page);
    await page.locator('#region-select').selectOption('de-berlin');

    await page.getByRole('button', { name: 'Sign out' }).click();

    await expect(page.locator('#view-login')).toHaveClass(/is-active/);
    await expect(page.locator('#password')).toHaveValue('');

    const stored = await page.evaluate(() => Object.fromEntries(window.__STORAGE__));
    expect(stored.authToken).toBeUndefined();
    expect(stored.staySignedIn).toBe('0');
    expect(stored.username).toBe('p1234567');
  });
});

test.describe('an unusable machine', () => {
  test('missing curl blocks the app with an actionable message', async ({ page, boot }) => {
    await boot({ curlVersion: { exitCode: 127, stdOut: '', stdErr: 'sh: 1: curl: not found' } });

    await expect(page.locator('#view-blocked')).toHaveClass(/is-active/);
    await expect(page.locator('#blocked-message')).toContainText('curl was not found');
    await expect(page.locator('#view-login')).not.toHaveClass(/is-active/);
  });

  test('a curl too old for certificate pinning is refused, not worked around', async ({ page, boot }) => {
    await boot({ curlVersion: { exitCode: 0, stdOut: 'curl 7.29.0 (x86_64) libcurl/7.29.0', stdErr: '' } });

    await expect(page.locator('#view-blocked')).toHaveClass(/is-active/);
    await expect(page.locator('#blocked-message')).toContainText('7.29.0 is too old');
  });
});

test.describe('the page itself', () => {
  test('makes no network request of its own', async ({ page, boot }) => {
    const external = [];
    page.on('request', (request) => {
      if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url());
    });

    await boot();
    await signIn(page);

    expect(external).toEqual([]);
  });

  test('reports no console errors during a full run', async ({ page, boot }) => {
    const errors = [];
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
    page.on('pageerror', (error) => errors.push(String(error)));

    await boot();
    await signIn(page);
    await page.locator('#region-select').selectOption('de-berlin');
    await page.getByRole('button', { name: /Generate keys/ }).click();
    await expect(page.locator('#view-success')).toHaveClass(/is-active/);
    await page.getByRole('button', { name: 'Show QR' }).click();
    await expect(page.locator('#qr-target img')).toBeVisible();

    expect(errors).toEqual([]);
  });

  test('every region in the fixture round-trips through the picker', async ({ page, boot }) => {
    await boot();
    await signIn(page);

    for (const region of SERVER_LIST.regions.filter((r) => r.servers.wg)) {
      await page.locator('#region-select').selectOption(region.id);
      await expect(page.locator('#generate-btn')).toBeEnabled();
    }
  });
});
