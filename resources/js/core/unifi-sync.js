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
 * Nothing here talks to the network itself, or to a filesystem, or to a shell.
 * The PIA and UniFi clients come in through injection, which is what lets the
 * whole flow run against fakes in the test suite — and what lets it live here,
 * in the application's own tree, rather than beside the command-line script it
 * was written for. `scripts/unifi-sync/sync.mjs` re-exports all of it; the only
 * thing that stayed behind is `readCredentials`, which speaks in environment
 * variables and so belongs to the CLI alone.
 */

import { AppError, ErrorCode } from './errors.js';
import { generateKeyPair, buildConfig, configFileName, isBase64Key, parseConfig } from './wireguard.js';
import { findRegionById, pickServer } from './serverlist.js';
import { resolveDns, CUSTOM_DNS, DEFAULT_DNS } from './dns.js';

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
 * A value that is a mask rather than a secret.
 *
 * Some Network builds return a fixed run of asterisks where a stored secret
 * belongs, so that reading a row does not disclose it. That is good practice
 * and a trap for anything that round-trips the row: send the mask back and the
 * controller stores the mask, which for a preshared key means the tunnel stops
 * handshaking, with nothing in the reply to say so. Reported upstream against
 * another tool as ubiquiti-community/terraform-provider-unifi#490.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function looksRedacted(value) {
  return typeof value === 'string' && value !== '' && /^[*\u2022.\s]+$/.test(value);
}

/**
 * @typedef {object} TunnelSpec
 * @property {string} network name of the VPN Client in the UniFi console, exactly as shown
 * @property {string} region  PIA region id, e.g. `czech` or `us_east`
 * @property {string} dns     comma-separated resolvers for the generated configuration
 * @property {boolean} [dnsExplicit] whether the configuration file chose `dns`, rather than the
 *           default filling it in — a file-mode tunnel keeps its own resolver unless told otherwise
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
      dnsExplicit: tunnel.dns !== undefined || raw.dns !== undefined,
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
 * @param {import('./wireguard.js').KeyPair} input.keys
 * @param {{peerIp: string, serverKey: string, serverIp: string, serverPort: number}} input.peer
 * @param {string} input.config the rendered `.conf`, for rows created by file upload
 * @param {string} input.regionId
 * @returns {object}
 */
export function patchWireGuardClient(entry, { keys, peer, config, regionId }) {
  assessTunnel(entry);

  // A row created by uploading a `.conf` is described by that file and nothing
  // else: it has no key or peer fields, and adding them would leave two
  // descriptions of one tunnel for the gateway to choose between. Replace the
  // file, and the address the console derived from it — the two must move
  // together, or the handshake succeeds with a source address PIA drops.
  if (isFileMode(entry)) {
    const next = {
      ...entry,
      ip_subnet: `${peer.peerIp}/32`,
      wireguard_client_configuration_file: config,
    };
    if (!next.wireguard_client_configuration_filename) {
      next.wireguard_client_configuration_filename = configFileName(regionId);
    }
    return next;
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
  if ('wireguard_client_configuration_file' in entry) {
    next.wireguard_client_configuration_file = config;
    if (!next.wireguard_client_configuration_filename) {
      next.wireguard_client_configuration_filename = configFileName(regionId);
    }
  }

  return next;
}

/** @param {object} entry */
function isFileMode(entry) {
  return Boolean(entry && entry.wireguard_client_mode === 'file');
}

/**
 * Refuse, before anything is spent, a row this module cannot refresh safely.
 *
 * Every check that depends only on the row as read belongs here rather than
 * after the PIA registration: a refusal discovered once a key has been issued
 * has already cost a registration and achieved nothing.
 *
 * @param {object} entry a WireGuard VPN Client row as read
 * @returns {{mode: 'file'|'manual', existingDns: string|null}}
 * @throws {AppError}
 */
export function assessTunnel(entry) {
  if (!entry || typeof entry !== 'object' || typeof entry._id !== 'string') {
    throw new AppError(ErrorCode.PROTOCOL, 'The VPN Client row from UniFi has no id.');
  }

  if (isFileMode(entry)) return assessFileModeRow(entry);

  const missing = REQUIRED_FIELDS.filter((field) => !(field in entry));
  if (missing.length > 0) {
    throw new AppError(ErrorCode.PROTOCOL,
      'The VPN Client row from UniFi does not carry the WireGuard fields this script knows how to update, ' +
      'so it was left untouched. The Network application may have changed its schema.',
      { detail: `missing: ${missing.join(', ')}; present: ${Object.keys(entry).sort().join(', ')}` });
  }

  // Everything a refresh does not replace is carried over from the row as it
  // was read. That is only safe while the row holds real values: a secret the
  // console masked on read would be written back as the mask, replacing the
  // real one. The private key is exempt because a refresh replaces it outright.
  const masked = [...SECRET_FIELDS]
    .filter((field) => field !== 'x_wireguard_private_key' && looksRedacted(entry[field]));

  if (masked.length > 0) {
    throw new AppError(ErrorCode.PROTOCOL,
      `The console returned ${masked.join(', ')} masked rather than in full, so this row cannot be written ` +
      'back without replacing the real value with the mask. The tunnel was left untouched. Clear the ' +
      'setting in the console, or configure the tunnel without it.',
      { detail: `masked on read: ${masked.join(', ')}` });
  }

  // A row that says it uses a preshared key but does not carry one is the same
  // hazard wearing different clothes: writing it back drops the key. "Carry"
  // means a real key — a console that hides the value by blanking it, or by
  // substituting a placeholder the mask check above does not recognise, is
  // caught here, because neither is shaped like a WireGuard key.
  if (entry.wireguard_client_preshared_key_enabled === true &&
      !isBase64Key(entry.wireguard_client_preshared_key)) {
    throw new AppError(ErrorCode.PROTOCOL,
      'This VPN Client uses a preshared key, but the console did not return one, so writing the row back ' +
      'would remove it and the tunnel would stop connecting. The tunnel was left untouched.',
      { detail: 'wireguard_client_preshared_key_enabled is true with no valid wireguard_client_preshared_key' });
  }

  return { mode: 'manual', existingDns: null };
}

/**
 * A file-mode row is refreshed by replacing its file with one {@link buildConfig}
 * renders, so it is only safe when the stored file is that same single-peer
 * shape: anything a regenerated file would silently drop — a second peer, a
 * preshared key, an unknown section — stops the refresh instead.
 *
 * @param {object} entry
 * @returns {{mode: 'file', existingDns: string|null}}
 */
function assessFileModeRow(entry) {
  const refuse = (reason) => new AppError(ErrorCode.PROTOCOL,
    `This VPN Client was created from an uploaded configuration file, and ${reason}, so it was left untouched.`,
    { detail: `file-mode row: ${reason}` });

  const file = entry.wireguard_client_configuration_file;
  if (typeof file !== 'string' || file.trim() === '') {
    throw refuse('the console returned no configuration file for it');
  }

  const parsed = parseConfig(file);
  if (!parsed.interface) throw refuse('its configuration file has no [Interface] section');

  const privateKey = parsed.interface.privatekey;
  if (looksRedacted(privateKey)) throw refuse('the console returned the key inside its configuration file masked');
  if (!isBase64Key(privateKey)) throw refuse('the key inside its configuration file is not a WireGuard key');

  if (parsed.peers.length !== 1) {
    throw refuse(`its configuration file has ${parsed.peers.length} [Peer] sections where a refresh writes exactly one`);
  }
  if (parsed.peers[0].presharedkey !== undefined) {
    throw refuse('its configuration file uses a preshared key, which a refresh would not carry over');
  }
  if (parsed.unknownSections.length > 0) {
    throw refuse(`its configuration file has sections a refresh would drop (${parsed.unknownSections.join(', ')})`);
  }

  let existingDns = null;
  if (parsed.interface.dns) {
    try {
      existingDns = resolveDns(CUSTOM_DNS, parsed.interface.dns);
    } catch {
      // A resolver given by name, or an IPv6 one, is not something the
      // generator can write back; the configured DNS is used instead.
      existingDns = null;
    }
  }

  return { mode: 'file', existingDns };
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
 * @typedef {object} InspectedTunnel
 * @property {TunnelSpec} tunnel
 * @property {object} [entry] the VPN Client row this tunnel refers to
 * @property {AppError} [error] why no row could be resolved
 */

/**
 * Match every configured tunnel to the row it refers to, without touching the
 * network and without spending anything.
 *
 * This is the half of the work that can be shown to somebody before they commit
 * to it: which rows exist, which names no longer match, which row is the wrong
 * kind of VPN client. One tunnel failing to resolve is recorded rather than
 * thrown, because a renamed CZ tunnel is no reason to leave the US one broken.
 *
 * @param {object} input
 * @param {SyncConfig} input.config
 * @param {object[]} input.networks every `networkconf` row on the site
 * @returns {InspectedTunnel[]} one entry per configured tunnel, in order
 */
export function inspectTunnels({ config, networks }) {
  return config.tunnels.map((tunnel) => {
    try {
      const entry = findWireGuardClient(networks, tunnel.network);
      assessTunnel(entry);
      return { tunnel, entry };
    } catch (err) {
      return { tunnel, error: asAppError(err) };
    }
  });
}

/**
 * @typedef {object} PreparedTunnel
 * @property {{cn: string, ip: string}} server the PIA server the key was registered with
 * @property {{id: string, name: string}} region
 * @property {{peerIp: string, serverKey: string, serverIp: string, serverPort: number}} peer
 * @property {object} next the row as it should be written back
 * @property {string[]} changes
 */

/**
 * Register one fresh key pair with PIA and work out the row that follows from
 * it. This is the step that costs something: it spends an account token on a
 * registration that is worthless until the row is written.
 *
 * @param {object} input
 * @param {import('./pia.js').PiaClient} input.pia
 * @param {string} input.token
 * @param {object[]} input.regions the parsed PIA server list
 * @param {import('./wireguard.js').CryptoProvider} input.crypto
 * @param {TunnelSpec} input.tunnel
 * @param {object} input.entry the existing row, from `inspectTunnels`
 * @param {() => number} [input.random]
 * @param {(line: string) => void} [input.log]
 * @returns {Promise<PreparedTunnel>}
 */
export async function prepareTunnel({ pia, token, regions, crypto, tunnel, entry, random, log = () => {} }) {
  const region = findRegionById(regions, tunnel.region);
  if (!region) {
    throw new AppError(ErrorCode.INVALID_INPUT,
      `PIA has no WireGuard region with id "${tunnel.region}". Run with --list-regions to see the ids.`);
  }

  // Checked again here, not only in inspectTunnels, because this is the last
  // moment a refusal costs nothing.
  const { existingDns } = assessTunnel(entry);

  // A file-mode tunnel already names the resolver its owner chose. Unless the
  // configuration asks for a different one, a refresh keeps it.
  const dns = !tunnel.dnsExplicit && existingDns ? existingDns : tunnel.dns;

  const server = pickServer(region, random);
  const keys = generateKeyPair(crypto);

  log(`${tunnel.network}: registering a new key with ${server.cn} (${region.name})…`);
  const peer = await pia.addKey({ token, publicKey: keys.publicKey, server });

  const rendered = buildConfig({ keys, peer, dns, regionName: region.name });
  const next = patchWireGuardClient(entry, { keys, peer, config: rendered, regionId: region.id });

  return { server, region, peer, next, changes: describeChanges(entry, next) };
}

/**
 * Write one prepared row back to the console.
 *
 * @param {object} input
 * @param {{updateNetwork: (id: string, entry: object) => Promise<object>}} input.unifi
 * @param {object} input.entry the row as it was read
 * @param {object} input.next the row as prepared
 * @returns {Promise<object>} the row the console echoed back
 */
export async function applyTunnel({ unifi, entry, next }) {
  const stored = await unifi.updateNetwork(entry._id, next);

  // A 200 says the console accepted the request, not that it kept what was
  // sent. Where the echo carries the fields that make the tunnel work, they
  // must be the ones written — otherwise the new key is registered with PIA and
  // the gateway is running something else.
  if (stored && typeof stored === 'object') {
    const differs = ['ip_subnet', 'wireguard_client_configuration_file', 'wireguard_client_peer_public_key', 'wireguard_client_peer_ip']
      .filter((field) => field in stored && field in next && JSON.stringify(stored[field]) !== JSON.stringify(next[field]));
    if (differs.length > 0) {
      throw new AppError(ErrorCode.PROTOCOL,
        'The console accepted the update but stored something different from what was sent; check the tunnel in UniFi.',
        { detail: `differs in the echo: ${differs.join(', ')}` });
    }
  }

  return stored;
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
 * Each tunnel is registered and then written before the next is registered.
 * That ordering is deliberate and `test/unifi-sync.test.js` asserts it: a key
 * PIA has issued does nothing until the gateway is using it, so the gap between
 * the two is kept as small as it can be.
 *
 * @param {object} deps
 * @param {import('./pia.js').PiaClient} deps.pia
 * @param {{listNetworks: () => Promise<object[]>, updateNetwork: (id: string, entry: object) => Promise<object>}} deps.unifi
 * @param {import('./wireguard.js').CryptoProvider} deps.crypto
 * @param {SyncConfig} deps.config
 * @param {{piaUsername: string, piaPassword: string}} [deps.credentials]
 * @param {string} [deps.token] an account token already in hand; when given, no sign-in is made
 * @param {boolean} [deps.dryRun] register with PIA and compute the update, but write nothing to UniFi
 * @param {(line: string) => void} [deps.log]
 * @param {() => number} [deps.random]
 * @returns {Promise<TunnelResult[]>}
 */
export async function syncTunnels({ pia, unifi, crypto, config, credentials, token: existingToken, dryRun = false, log = () => {}, random }) {
  // The app signs in for its own reasons and holds the token already; asking
  // PIA for a second one would be a wasted round trip against an endpoint that
  // rate-limits. The CLI has no token and passes credentials instead.
  let token = existingToken;
  if (!token) {
    log('Signing in to Private Internet Access…');
    token = await pia.login(credentials.piaUsername, credentials.piaPassword);
  }

  log('Fetching the PIA server list…');
  const regions = await pia.fetchRegions();

  log(`Reading VPN Clients from ${config.unifi.url}…`);
  const networks = await unifi.listNetworks();

  /** @type {TunnelResult[]} */
  const results = [];

  for (const { tunnel, entry, error } of inspectTunnels({ config, networks })) {
    const result = { network: tunnel.network, region: tunnel.region, ok: false };
    results.push(result);

    try {
      if (error) throw error;

      const prepared = await prepareTunnel({ pia, token, regions, crypto, tunnel, entry, random, log });

      result.server = prepared.server.cn;
      result.endpoint = `${prepared.peer.serverIp}:${prepared.peer.serverPort}`;
      result.changes = prepared.changes;

      if (dryRun) {
        log(`${tunnel.network}: dry run — UniFi not updated.`);
      } else {
        log(`${tunnel.network}: updating the VPN Client in UniFi…`);
        await applyTunnel({ unifi, entry, next: prepared.next });
      }

      result.ok = true;
    } catch (err) {
      result.error = asAppError(err);
      log(`${tunnel.network}: FAILED — ${result.error.message}`);
    }
  }

  return results;
}

/**
 * @param {unknown} err
 * @returns {AppError}
 */
function asAppError(err) {
  return err instanceof AppError
    ? err
    : new AppError(ErrorCode.NETWORK, 'The tunnel could not be refreshed.', {
      cause: err, detail: err instanceof Error ? err.message : String(err),
    });
}

function describeRow(row) {
  if (row.purpose === 'vpn-client') return `a ${row.vpn_type || 'different'} VPN client`;
  return `a "${row.purpose || 'unknown'}" network`;
}
