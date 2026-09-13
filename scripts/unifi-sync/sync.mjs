/**
 * The command-line half of the UniFi sync.
 *
 * The sync itself lives in `resources/js/core/unifi-sync.js`, in the
 * application's own tree, because none of it is specific to a command line: it
 * takes a parsed configuration and two injected clients and returns a report.
 * The desktop app needs exactly that, and a second copy of it would drift.
 *
 * What stays here is the one piece that is genuinely CLI vocabulary — reading
 * credentials out of the environment, including the `*_FILE` indirection that
 * Docker secrets and systemd `LoadCredential=` hand out. The app has no
 * environment to read and a different place to keep secrets.
 *
 * Everything else is re-exported, so existing importers do not have to care
 * where it moved to.
 */

import { AppError, ErrorCode } from '../../resources/js/core/errors.js';

export {
  REQUIRED_FIELDS,
  loadSyncConfig,
  findWireGuardClient,
  patchWireGuardClient,
  describeChanges,
  inspectTunnels,
  prepareTunnel,
  applyTunnel,
  syncTunnels,
} from '../../resources/js/core/unifi-sync.js';

/**
 * Credentials come from the environment, or from files the environment names —
 * the `*_FILE` form is what Docker and systemd `LoadCredential=` hand out — and
 * never from the configuration file, which is safe to commit.
 *
 * @param {NodeJS.ProcessEnv} env
 * @param {(path: string) => string} readFile
 */
export function readCredentials(env, readFile) {
  const read = (name) => {
    if (typeof env[name] === 'string' && env[name] !== '') return env[name];
    const file = env[`${name}_FILE`];
    if (typeof file === 'string' && file !== '') {
      try {
        return readFile(file).replace(/\r?\n$/, '');
      } catch (err) {
        throw new AppError(ErrorCode.FILESYSTEM, `Could not read ${name}_FILE (${file}).`, {
          cause: err, detail: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return '';
  };

  const credentials = {
    piaUsername: read('PIA_USERNAME'),
    piaPassword: read('PIA_PASSWORD'),
    unifiApiKey: read('UNIFI_API_KEY'),
    unifiUsername: read('UNIFI_USERNAME'),
    unifiPassword: read('UNIFI_PASSWORD'),
  };

  if (!credentials.piaUsername || !credentials.piaPassword) {
    throw new AppError(ErrorCode.INVALID_INPUT, 'Set PIA_USERNAME and PIA_PASSWORD (or PIA_USERNAME_FILE / PIA_PASSWORD_FILE).');
  }
  if (!credentials.unifiApiKey && !(credentials.unifiUsername && credentials.unifiPassword)) {
    throw new AppError(ErrorCode.INVALID_INPUT,
      'Set UNIFI_API_KEY, or UNIFI_USERNAME and UNIFI_PASSWORD (the *_FILE forms work too).');
  }

  return credentials;
}
