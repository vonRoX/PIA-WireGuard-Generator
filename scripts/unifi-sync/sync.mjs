/**
 * Keeping UniFi WireGuard VPN Clients registered with Private Internet Access.
 *
 * Why this exists: PIA's WireGuard servers keep a registered key only while the
 * peer keeps talking to them. Let the tunnel drop for a few hours — a gateway
 * reboot, a firmware update, a WAN blip that outlasts the keepalive — and the
 * server forgets the key, so the tunnel comes back as "Not Established" until
 * someone regenerates a configuration and pastes it into the console again.
 * This module does that round trip unattended: fresh token, fresh key pair,
 * register with a server in the chosen region, rewrite the VPN Client row.
 *
 * Nothing here talks to the network itself. The PIA and UniFi clients come in
 * through injection, so the whole flow runs against fakes in the test suite.
 */

import { AppError, ErrorCode } from '../../resources/js/core/errors.js';
import { generateKeyPair, buildConfig, configFileName } from '../../resources/js/core/wireguard.js';
import { findRegionById, pickServer } from '../../resources/js/core/serverlist.js';
import { resolveDns, CUSTOM_DNS, DEFAULT_DNS } from '../../resources/js/core/dns.js';

/**
 * The fields a WireGuard VPN Client row must carry for the update to mean
 * anything. Their absence says the Network application changed its schema, and
 * the right response is to stop, not to add fields the gateway will ignore.
 */
export const REQUIRED_FIELDS = Object.freeze([
  'wireguard_client_peer_public_key',
  'wireguard_client_peer_ip',
  'wireguard_client_peer_port',
  'ip_subnet',
]);

/** Fields whose values must never be printed. */
const SECRET_FIELDS = new Set(['x_wireguard_private_key', 'wireguard_client_preshared_key', 'wireguard_client_configuration_file']);

/**
 * @typedef {object} TunnelSpec
 * @property {string} network name of the VPN Client in the UniFi console, exactly as shown
 * @property {string} region  PIA region id, e.g. `czech` or `us_east`
 * @property {string} dns     comma-separated resolvers for the generated configuration
 */

/**
 * @typedef {object} SyncConfig
 * @property {{url: string, site: string, selfHosted: boolean, certificate: string|null}} unifi
 * @property {TunnelSpec[]} tunnels
 */

/**
 * Validate a parsed configuration file.
 *
 * @param {any} raw
 * @param {(relative: string) => string} resolvePath turns a relative path in the file into an absolute one
 * @returns {SyncConfig}
 */
export function loadSyncConfig(raw, resolvePath = (p) => p) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new AppError(ErrorCode.INVALID_INPUT, 'The configuration file must contain a JSON object.');
  }

  const unifi = raw.unifi;
  if (!unifi || typeof unifi !== 'object' || typeof unifi.url !== 'string' || !unifi.url.startsWith('https://')) {
    throw new AppError(ErrorCode.INVALID_INPUT,
      'The configuration needs "unifi": { "url": "https://<console address>" }.');
  }
  try {
    new URL(unifi.url);
  } catch {
    throw new AppError(ErrorCode.INVALID_INPUT, `"${unifi.url}" is not a valid URL.`);
  }

  const defaultDns = raw.dns === undefined ? DEFAULT_DNS : resolveDns(CUSTOM_DNS, String(raw.dns));

  if (!Array.isArray(raw.tunnels) || raw.tunnels.length === 0) {
    throw new AppError(ErrorCode.INVALID_INPUT,
      'The configuration needs a non-empty "tunnels" list, each entry naming a UniFi VPN Client and a PIA region.');
  }

  const tunnels = raw.tunnels.map((tunnel, index) => {
    if (!tunnel || typeof tunnel.network !== 'string' || tunnel.network.trim() === '' ||
        typeof tunnel.region !== 'string' || tunnel.region.trim() === '') {
      throw new AppError(ErrorCode.INVALID_INPUT,
        `Tunnel #${index + 1} needs both "network" (the VPN Client name in UniFi) and "region" (a PIA region id).`);
    }
    return {
      network: tunnel.network.trim(),
      region: tunnel.region.trim(),
      dns: tunnel.dns === undefined ? defaultDns : resolveDns(CUSTOM_DNS, String(tunnel.dns)),
    };
  });

  const names = new Set();
  for (const { network } of tunnels) {
    if (names.has(network)) {
      throw new AppError(ErrorCode.INVALID_INPUT, `"${network}" is listed twice in "tunnels".`);
    }
    names.add(network);
  }

  return {
    unifi: {
      url: unifi.url,
      site: typeof unifi.site === 'string' && unifi.site ? unifi.site : 'default',
      selfHosted: Boolean(unifi.selfHosted),
      certificate: typeof unifi.certificate === 'string' && unifi.certificate ? resolvePath(unifi.certificate) : null,
    },
    tunnels,
  };
}

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

/**
 * Locate the VPN Client row for a tunnel, by the name shown in the console.
 *
 * @param {object[]} networks every `networkconf` row on the site
 * @param {string} name
 * @returns {object}
 */
export function findWireGuardClient(networks, name) {
  const wireguardClients = networks.filter((row) =>
    row && row.purpose === 'vpn-client' && row.vpn_type === 'wireguard-client');

  const match = wireguardClients.find((row) => row.name === name);
  if (match) return match;

  const sameName = networks.find((row) => row && row.name === name);
  if (sameName) {
    throw new AppError(ErrorCode.INVALID_INPUT,
      `"${name}" exists in UniFi but is not a WireGuard VPN Client (it is ${describeRow(sameName)}). ` +
      'Only WireGuard VPN Clients can be refreshed.');
  }

  const available = wireguardClients.map((row) => `"${row.name}"`).join(', ') || 'none';
  throw new AppError(ErrorCode.INVALID_INPUT,
    `No WireGuard VPN Client named "${name}" was found on this site. Create it once in the console ` +
    `(Settings → VPN → VPN Client), then run this again. WireGuard VPN Clients present: ${available}.`);
}

/**
 * Produce the updated row for one registration. Everything the user configured
 * in the console — routing, DNS pulling, which devices use the tunnel — is left
 * exactly as it was; only the fields that a registration changes are touched.
 *
 * @param {object} entry the existing row
 * @param {object} input
 * @param {import('../../resources/js/core/wireguard.js').KeyPair} input.keys
 * @param {{peerIp: string, serverKey: string, serverIp: string, serverPort: number}} input.peer
 * @param {string} input.config the rendered `.conf`, for rows created by file upload
 * @param {string} input.regionId
 * @returns {object}
 */
export function patchWireGuardClient(entry, { keys, peer, config, regionId }) {
  if (!entry || typeof entry !== 'object' || typeof entry._id !== 'string') {
    throw new AppError(ErrorCode.PROTOCOL, 'The VPN Client row from UniFi has no id.');
  }

  const missing = REQUIRED_FIELDS.filter((field) => !(field in entry));
  if (missing.length > 0) {
    throw new AppError(ErrorCode.PROTOCOL,
      'The VPN Client row from UniFi does not carry the WireGuard fields this script knows how to update, ' +
      'so it was left untouched. The Network application may have changed its schema.',
      { detail: `missing: ${missing.join(', ')}; present: ${Object.keys(entry).sort().join(', ')}` });
  }

  const next = {
    ...entry,
    x_wireguard_private_key: keys.privateKey,
    wireguard_client_peer_public_key: peer.serverKey,
    wireguard_client_peer_ip: peer.serverIp,
    wireguard_client_peer_port: peer.serverPort,
    ip_subnet: `${peer.peerIp}/32`,
  };

  // The console derives the public key itself, but some builds store it too;
  // keep whatever is there consistent with the new private key.
  if ('wireguard_public_key' in entry) next.wireguard_public_key = keys.publicKey;

  // Rows created by uploading a `.conf` keep the file alongside the parsed
  // fields. Replace it so the UI never shows a file that disagrees with the
  // tunnel it describes.
  if ('wireguard_client_configuration_file' in entry || entry.wireguard_client_mode === 'file') {
    next.wireguard_client_configuration_file = config;
    if (!next.wireguard_client_configuration_filename) {
      next.wireguard_client_configuration_filename = configFileName(regionId);
    }
  }

  return next;
}

/**
 * Which fields an update changes, for the report — secrets reported by name only.
 *
 * @param {object} before
 * @param {object} after
 * @returns {string[]}
 */
export function describeChanges(before, after) {
  return Object.keys(after)
    .filter((key) => JSON.stringify(before[key]) !== JSON.stringify(after[key]))
    .sort()
    .map((key) => (SECRET_FIELDS.has(key) ? `${key} (redacted)` : `${key}: ${JSON.stringify(before[key])} → ${JSON.stringify(after[key])}`));
}

/**
 * @typedef {object} TunnelResult
 * @property {string} network
 * @property {string} region
 * @property {boolean} ok
 * @property {string} [server] common name of the PIA server registered with
 * @property {string} [endpoint]
 * @property {string[]} [changes]
 * @property {AppError} [error]
 */

/**
 * Register every configured tunnel and write the result to UniFi.
 *
 * One tunnel failing does not stop the others: the CZ tunnel should not stay
 * broken because the US region was renamed.
 *
 * @param {object} deps
 * @param {import('../../resources/js/core/pia.js').PiaClient} deps.pia
 * @param {{listNetworks: () => Promise<object[]>, updateNetwork: (id: string, entry: object) => Promise<object>}} deps.unifi
 * @param {import('../../resources/js/core/wireguard.js').CryptoProvider} deps.crypto
 * @param {SyncConfig} deps.config
 * @param {{piaUsername: string, piaPassword: string}} deps.credentials
 * @param {boolean} [deps.dryRun] register with PIA and compute the update, but write nothing to UniFi
 * @param {(line: string) => void} [deps.log]
 * @param {() => number} [deps.random]
 * @returns {Promise<TunnelResult[]>}
 */
export async function syncTunnels({ pia, unifi, crypto, config, credentials, dryRun = false, log = () => {}, random }) {
  log('Signing in to Private Internet Access…');
  const token = await pia.login(credentials.piaUsername, credentials.piaPassword);

  log('Fetching the PIA server list…');
  const regions = await pia.fetchRegions();

  log(`Reading VPN Clients from ${config.unifi.url}…`);
  const networks = await unifi.listNetworks();

  /** @type {TunnelResult[]} */
  const results = [];

  for (const tunnel of config.tunnels) {
    const result = { network: tunnel.network, region: tunnel.region, ok: false };
    results.push(result);

    try {
      const entry = findWireGuardClient(networks, tunnel.network);

      const region = findRegionById(regions, tunnel.region);
      if (!region) {
        throw new AppError(ErrorCode.INVALID_INPUT,
          `PIA has no WireGuard region with id "${tunnel.region}". Run with --list-regions to see the ids.`);
      }

      const server = pickServer(region, random);
      const keys = generateKeyPair(crypto);

      log(`${tunnel.network}: registering a new key with ${server.cn} (${region.name})…`);
      const peer = await pia.addKey({ token, publicKey: keys.publicKey, server });

      const rendered = buildConfig({ keys, peer, dns: tunnel.dns, regionName: region.name });
      const next = patchWireGuardClient(entry, { keys, peer, config: rendered, regionId: region.id });

      result.server = server.cn;
      result.endpoint = `${peer.serverIp}:${peer.serverPort}`;
      result.changes = describeChanges(entry, next);

      if (dryRun) {
        log(`${tunnel.network}: dry run — UniFi not updated.`);
      } else {
        log(`${tunnel.network}: updating the VPN Client in UniFi…`);
        await unifi.updateNetwork(entry._id, next);
      }

      result.ok = true;
    } catch (err) {
      result.error = err instanceof AppError
        ? err
        : new AppError(ErrorCode.NETWORK, 'The tunnel could not be refreshed.', {
          cause: err, detail: err instanceof Error ? err.message : String(err),
        });
      log(`${tunnel.network}: FAILED — ${result.error.message}`);
    }
  }

  return results;
}

function describeRow(row) {
  if (row.purpose === 'vpn-client') return `a ${row.vpn_type || 'different'} VPN client`;
  return `a "${row.purpose || 'unknown'}" network`;
}
