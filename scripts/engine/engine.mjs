/**
 * The Workbench engine: everything the local UI can ask of the machine, behind
 * the interface in scripts/workbench/CONTRACT.md.
 *
 * Nothing secret leaves this module. Credentials come back only as "stored or
 * not"; console answers pass through {@link redact}; every error is an
 * `AppError` whose message, hint and detail were written here.
 */

import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { createConsoleClient } from './console.mjs';
import { EngineErrorCode, engineError } from './errors.mjs';
import { redact } from './redact.mjs';
import { createSecretStore } from './secrets.mjs';
import { inspectCertificate, normalizeConsoleUrl, normalizeFingerprint } from './trust.mjs';

const MAX_EXPLORE_PATH = 2048;
const MAX_SECRET_LENGTH = 1024;

/** @returns {string} */
function defaultStoreDir() {
  const base = process.env.LOCALAPPDATA;
  if (!base) {
    throw engineError(EngineErrorCode.STORAGE, 'LOCALAPPDATA is not set, so there is nowhere to keep the settings.', {
      hint: 'The Workbench runs on Windows.',
    });
  }
  return join(base, 'pia-unifi-sync');
}

/**
 * The contract's rule for explorer paths: under `/proxy/network/`, and nothing
 * that could climb out of it or leave the console.
 *
 * @param {unknown} path
 * @returns {string}
 */
export function validateExplorePath(path) {
  const invalid = (message) => engineError(EngineErrorCode.INVALID_INPUT, message, {
    hint: 'Paths start with /proxy/network/, for example /proxy/network/integration/v1/info.',
  });

  if (typeof path !== 'string' || !path) throw invalid('Enter a path to read.');
  if (path.length > MAX_EXPLORE_PATH) throw invalid('That path is too long.');
  if (!path.startsWith('/proxy/network/')) throw invalid('Only paths under /proxy/network/ can be read.');
  // Control characters, whitespace and backslashes have no place in a path and
  // are how request lines get split or normalised into something else.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000- \u007f\\#]/.test(path)) throw invalid('That path contains characters a path does not have.');
  if (path.includes('..') || path.includes('//')) throw invalid('That path is not allowed.');
  if (/%(2e|2f|5c|00)/i.test(path)) throw invalid('That path is not allowed.');
  if (/^[a-z][a-z0-9+.-]*:/i.test(path)) throw invalid('That path is not allowed.');

  // Belt and braces: however a URL parser reads it, it must stay put.
  const resolved = new URL(path, 'https://console.invalid');
  if (resolved.origin !== 'https://console.invalid' || !resolved.pathname.startsWith('/proxy/network/')) {
    throw invalid('That path is not allowed.');
  }
  return path;
}

/**
 * @param {object} row a networkconf row
 * @param {Map<string, object>} statuses network_id → connection
 * @returns {{id: string, name: string, mode: 'file'|'manual'|'unknown', enabled: boolean, status: string|null, notes: string[]}}
 */
export function toTunnel(row, statuses) {
  const id = typeof row._id === 'string' ? row._id : '';
  const connection = statuses.get(id);
  const mode = row.wireguard_client_mode === 'file' || row.wireguard_client_mode === 'manual'
    ? row.wireguard_client_mode
    : 'unknown';
  return {
    id,
    name: typeof row.name === 'string' ? row.name : '',
    mode,
    enabled: row.enabled !== false,
    status: connection && typeof connection.status === 'string' ? connection.status : null,
    notes: connection && Array.isArray(connection.notes) ? connection.notes.filter((note) => typeof note === 'string') : [],
  };
}

/**
 * @param {object} [options]
 * @param {string} [options.storeDir] defaults to %LOCALAPPDATA%\pia-unifi-sync
 * @param {ReturnType<typeof createSecretStore>} [options.secrets]
 * @param {Function} [options.connect] `tls.connect` stand-in
 * @param {Function} [options.request] `https.request` stand-in
 * @param {() => Date} [options.now]
 * @param {number} [options.timeoutMs]
 */
export function createEngine(options = {}) {
  const storeDir = options.storeDir || defaultStoreDir();
  const secrets = options.secrets || createSecretStore({ storeDir });
  const { connect, request, timeoutMs } = options;
  const now = options.now || (() => new Date());
  const consoleFile = join(storeDir, 'console.json');

  /** @returns {Promise<null | {url: string, site: string, fingerprint256: string, pem: string, connectName: string}>} */
  async function readConsole() {
    let text;
    try {
      text = await readFile(consoleFile, 'utf8');
    } catch (err) {
      if (err && err.code === 'ENOENT') return null;
      throw engineError(EngineErrorCode.STORAGE, 'The console settings could not be read.', { detail: String(err && err.code) });
    }
    try {
      const saved = JSON.parse(text);
      if (!saved || typeof saved !== 'object' || typeof saved.url !== 'string') return null;
      return {
        url: saved.url,
        site: typeof saved.site === 'string' && saved.site ? saved.site : 'default',
        fingerprint256: typeof saved.fingerprint256 === 'string' ? saved.fingerprint256 : '',
        pem: typeof saved.pem === 'string' ? saved.pem : '',
        connectName: typeof saved.connectName === 'string' ? saved.connectName : '',
      };
    } catch {
      return null;
    }
  }

  async function writeConsole(record) {
    let existed = true;
    try {
      await stat(storeDir);
    } catch {
      existed = false;
    }
    try {
      await mkdir(storeDir, { recursive: true });
    } catch (err) {
      throw engineError(EngineErrorCode.STORAGE, 'The settings folder could not be created.', { detail: String(err && err.code) });
    }
    // A folder this engine had to create gets the launcher's ACL too.
    if (!existed && typeof secrets.protectDirectory === 'function') await secrets.protectDirectory();

    const temporary = `${consoleFile}.${process.pid}.${Date.now()}.tmp`;
    try {
      await writeFile(temporary, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
      await rename(temporary, consoleFile);
    } catch (err) {
      throw engineError(EngineErrorCode.STORAGE, 'The console settings could not be saved.', { detail: String(err && err.code) });
    }
  }

  function isTrusted(saved) {
    return Boolean(saved && saved.fingerprint256 && saved.pem);
  }

  async function requireConsole() {
    const saved = await readConsole();
    if (!isTrusted(saved)) {
      throw engineError(EngineErrorCode.NOT_CONFIGURED, 'No console has been trusted yet.', {
        hint: 'Enter the console address and confirm its certificate first.',
      });
    }
    return saved;
  }

  async function requireKey() {
    const status = await secrets.status();
    if (!status.unifiApiKey) {
      throw engineError(EngineErrorCode.NOT_CONFIGURED, 'No UniFi API key is stored yet.', {
        hint: 'Create a key on the console under Settings → Control Plane → Integrations and enter it.',
      });
    }
    const { unifiApiKey } = await secrets.read();
    if (!unifiApiKey) {
      throw engineError(EngineErrorCode.NOT_CONFIGURED, 'No UniFi API key is stored yet.');
    }
    return unifiApiKey;
  }

  function client(saved, apiKey) {
    return createConsoleClient({
      url: saved.url, pem: saved.pem, fingerprint256: saved.fingerprint256, apiKey, request, connect, timeoutMs,
    });
  }

  async function getState() {
    const [saved, status] = await Promise.all([readConsole(), secrets.status()]);
    return {
      console: saved
        ? {
          url: saved.url,
          site: saved.site,
          fingerprint256: saved.fingerprint256,
          connectName: saved.connectName,
          trusted: isTrusted(saved),
        }
        : null,
      unifiKey: { stored: Boolean(status.unifiApiKey) },
      pia: { stored: Boolean(status.piaUsername && status.piaPassword) },
    };
  }

  return {
    getState,

    async inspectConsole(url) {
      const origin = normalizeConsoleUrl(url);
      const certificate = await inspectCertificate(origin, { connect, timeoutMs });
      return { url: origin, certificate };
    },

    async trustConsole(url, fingerprint256) {
      const origin = normalizeConsoleUrl(url);
      const expected = normalizeFingerprint(fingerprint256);
      const certificate = await inspectCertificate(origin, { connect, timeoutMs });
      if (certificate.fingerprint256 !== expected) {
        throw engineError(EngineErrorCode.CERT_CHANGED,
          'The console now presents a different certificate from the one you confirmed. Nothing was trusted.', {
            hint: 'Inspect the console again and compare the new fingerprint with the one shown on the console itself.',
            detail: `expected ${expected}, got ${certificate.fingerprint256}`,
          });
      }

      const previous = await readConsole();
      await writeConsole({
        url: origin,
        site: previous && previous.url === origin ? previous.site : 'default',
        fingerprint256: certificate.fingerprint256,
        pem: certificate.pem,
        connectName: certificate.connectName,
        trustedAt: now().toISOString(),
      });
      return getState();
    },

    async setUnifiKey(apiKey) {
      // The launcher's rule: printable ASCII without a double quote. The value
      // itself never appears in a message.
      if (typeof apiKey !== 'string' || !apiKey.trim()) {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'Enter the UniFi API key.');
      }
      const key = apiKey.trim();
      if (key.length > MAX_SECRET_LENGTH || !/^[\x21\x23-\x7E]+$/.test(key)) {
        throw engineError(EngineErrorCode.INVALID_INPUT,
          'That UniFi API key contains characters an API key does not have (a space or line break from pasting?).');
      }

      const saved = await requireConsole();
      const { applicationVersion } = await client(saved, key).info();
      await secrets.write({ unifiApiKey: key });
      return { verified: true, applicationVersion };
    },

    async setPiaCredentials(username, password) {
      if (typeof username !== 'string' || !username.trim()) {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'Enter the PIA username.');
      }
      if (typeof password !== 'string' || !password) {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'Enter the PIA password.');
      }
      const user = username.trim();
      // eslint-disable-next-line no-control-regex
      if (user.length > 128 || /[\s\u0000-\u001f\u007f]/.test(user)) {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'That PIA username contains characters a username does not have.');
      }
      // eslint-disable-next-line no-control-regex
      if (password.length > MAX_SECRET_LENGTH || /[\u0000-\u001f\u007f]/.test(password)) {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'That PIA password contains characters it cannot contain (a line break from pasting?).');
      }
      await secrets.write({ piaUsername: user, piaPassword: password });
      return getState();
    },

    async forgetCredentials() {
      await secrets.clear();
      return getState();
    },

    async explore(path) {
      const checked = validateExplorePath(path);
      const saved = await requireConsole();
      const apiKey = await requireKey();
      const { status, text } = await client(saved, apiKey).get(checked);
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
      return { status, body: redact(parsed) };
    },

    async listTunnels() {
      const saved = await requireConsole();
      const apiKey = await requireKey();
      const unifi = client(saved, apiKey);
      const [rows, connections] = await Promise.all([
        unifi.listVpnClients(saved.site),
        // Status is a nicety; the list is still worth showing without it.
        unifi.vpnStatus(saved.site).catch((err) => {
          if (err && err.code === EngineErrorCode.HTTP) return [];
          throw err;
        }),
      ]);
      const statuses = new Map();
      for (const connection of connections) {
        if (connection && typeof connection.network_id === 'string') statuses.set(connection.network_id, connection);
      }
      return { tunnels: rows.map((row) => toTunnel(row, statuses)) };
    },
  };
}
