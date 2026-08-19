/**
 * Everything that touches the host machine.
 *
 * Keeping the Neutralino calls behind this adapter is what lets the rest of the
 * app be plain modules that Node and a headless browser can both exercise.
 */

import { AppError, ErrorCode } from '../core/errors.js';
import { PIA_CA_PEM } from '../core/pia-ca.js';

/** 0700 — a directory only its owner may enter. */
const OWNER_ONLY_DIRECTORY = Object.freeze({
  all: false,
  ownerAll: true,
  ownerRead: true,
  ownerWrite: true,
  ownerExec: true,
  groupAll: false,
  groupRead: false,
  groupWrite: false,
  groupExec: false,
  othersAll: false,
  othersRead: false,
  othersWrite: false,
  othersExec: false,
});

/** 0600 — owner read/write, nobody else. */
const OWNER_ONLY = Object.freeze({
  all: false,
  ownerAll: false,
  ownerRead: true,
  ownerWrite: true,
  ownerExec: false,
  groupAll: false,
  groupRead: false,
  groupWrite: false,
  groupExec: false,
  othersAll: false,
  othersRead: false,
  othersWrite: false,
  othersExec: false,
});

/**
 * Run a command. The only command this app ever runs is curl, and the only
 * variable part travels on stdin.
 *
 * @param {string} command
 * @param {{stdIn?: string}} [options]
 * @returns {Promise<{exitCode: number, stdOut: string, stdErr: string}>}
 */
export async function exec(command, options = {}) {
  const result = await Neutralino.os.execCommand(command, options);
  return {
    exitCode: typeof result.exitCode === 'number' ? result.exitCode : -1,
    stdOut: result.stdOut || '',
    stdErr: result.stdErr || '',
  };
}

/**
 * Neutralino's key/value store, shaped like the adapter `Prefs` expects.
 *
 * Reading a key that was never written throws, which is not an error condition
 * for us — a missing preference is just a missing preference.
 *
 * @type {import('../core/prefs.js').StorageAdapter}
 */
export const storage = {
  async getItem(key) {
    try {
      const value = await Neutralino.storage.getData(key);
      return value === '' ? null : value;
    } catch {
      return null;
    }
  },
  async setItem(key, value) {
    try {
      await Neutralino.storage.setData(key, value);
    } catch (err) {
      throw new AppError(ErrorCode.STORAGE, 'Could not save your preferences.', { cause: err });
    }
    await ensureStorageIsPrivate();
  },
  async removeItem(key) {
    try {
      await Neutralino.storage.removeData(key);
    } catch {
      // Removing a key that is not there is a success as far as we care.
    }
  },
};

/**
 * Keep Neutralino's key/value store readable only by its owner.
 *
 * The framework writes `<app directory>/.storage/<key>.neustorage` with default
 * permissions — 0644 on a typical system, and the directory 0755. When the user
 * has opted into "Stay signed in", one of those files is a bearer token for
 * their VPN account, so on a shared machine every other local account could read
 * it. Restricting the directory denies the whole tree in one call, and matches
 * the treatment the saved configuration already gets.
 *
 * Done once per session, after the first write, since that is when the directory
 * is guaranteed to exist.
 */
let storageSecured = false;

async function ensureStorageIsPrivate() {
  if (storageSecured) return;
  storageSecured = true; // Even on failure: retrying every write would be pointless noise.

  try {
    const directory = await Neutralino.filesystem.getJoinedPath(NL_PATH, '.storage');
    await Neutralino.filesystem.setPermissions(directory, OWNER_ONLY_DIRECTORY, 'REPLACE');
  } catch {
    // Windows maps POSIX modes loosely and may refuse. The token is still only
    // written when the user asked for it, and signing out removes it.
  }
}

/**
 * Write PIA's CA to a private temporary file so `curl --cacert` can read it.
 *
 * The name is randomised: a predictable path in a shared temp directory would
 * let another local user pre-place or swap the file between our write and
 * curl's read, which would quietly defeat the certificate pinning it exists to
 * provide.
 */
export class CaCertFile {
  constructor() {
    /** @type {string} */
    this.path = '';
  }

  /** @returns {Promise<string>} the path written */
  async materialise() {
    if (this.path) return this.path;

    const suffix = randomHex(16);
    const directory = await Neutralino.os.getPath('temp');
    const path = await Neutralino.filesystem.getJoinedPath(directory, `pia-ca-${suffix}.pem`);

    try {
      await Neutralino.filesystem.writeFile(path, PIA_CA_PEM);
    } catch (err) {
      throw new AppError(
        ErrorCode.FILESYSTEM,
        "Could not write Private Internet Access's certificate to a temporary file, " +
        'so the connection could not be verified.',
        { cause: err },
      );
    }

    await restrictPermissions(path);
    this.path = path;
    return path;
  }

  async cleanUp() {
    if (!this.path) return;
    try {
      await Neutralino.filesystem.remove(this.path);
    } catch {
      // A leftover copy of a public CA certificate in the temp directory is harmless.
    }
    this.path = '';
  }
}

/**
 * Ask for a location and write the configuration there with owner-only
 * permissions — the file contains a private key.
 *
 * @param {object} input
 * @param {string} input.defaultName
 * @param {string} input.contents
 * @returns {Promise<{path: string, restricted: boolean} | null>} null if the user cancelled
 */
export async function saveConfigFile({ defaultName, contents }) {
  const path = await Neutralino.os.showSaveDialog('Save WireGuard configuration', {
    defaultPath: defaultName,
    filters: [
      { name: 'WireGuard configuration', extensions: ['conf'] },
      { name: 'All files', extensions: ['*'] },
    ],
  });

  if (!path) return null;

  try {
    await Neutralino.filesystem.writeFile(path, contents);
  } catch (err) {
    throw new AppError(ErrorCode.FILESYSTEM, `Could not write the file: ${describe(err)}`, { cause: err });
  }

  const restricted = await restrictPermissions(path);
  return { path, restricted };
}

/**
 * @param {string} path
 * @returns {Promise<boolean>} false when the platform would not apply them
 */
export async function restrictPermissions(path) {
  try {
    await Neutralino.filesystem.setPermissions(path, OWNER_ONLY, 'REPLACE');
    return true;
  } catch {
    // Windows maps POSIX modes loosely and may refuse outright. The caller
    // tells the user rather than pretending the file is protected.
    return false;
  }
}

/**
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  try {
    await Neutralino.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** @returns {Promise<void>} */
export async function exit() {
  await Neutralino.app.exit();
}

function randomHex(bytes) {
  const buffer = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buffer);
  return Array.from(buffer, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function describe(err) {
  if (err && typeof err === 'object' && 'message' in err) return String(err.message);
  return String(err);
}
