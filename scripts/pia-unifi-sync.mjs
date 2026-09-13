#!/usr/bin/env node
/**
 * Refresh the WireGuard VPN Clients on a UniFi gateway with fresh Private
 * Internet Access registrations — the same round trip the desktop app does,
 * minus the pasting.
 *
 * Usage:
 *   node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json [--dry-run]
 *   node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json --list-regions
 *   node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json --list-networks
 *
 * Credentials come from the environment (PIA_USERNAME, PIA_PASSWORD, and either
 * UNIFI_API_KEY or UNIFI_USERNAME + UNIFI_PASSWORD); each also accepts a
 * `*_FILE` variant naming a file to read. See docs/wiki/features/UniFi_Automation.md.
 */

import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';

import { HttpClient } from '../resources/js/core/http.js';
import { PiaClient } from '../resources/js/core/pia.js';
import { PIA_CA_PEM } from '../resources/js/core/pia-ca.js';
import { AppError } from '../resources/js/core/errors.js';

import { curlExec } from './unifi-sync/exec.mjs';
import { nodeCrypto } from './unifi-sync/crypto.mjs';
import { UnifiClient, trustFromPem } from './unifi-sync/unifi.mjs';
import { loadSyncConfig, readCredentials, syncTunnels } from './unifi-sync/sync.mjs';

const USAGE = `Usage: node scripts/pia-unifi-sync.mjs --config <file> [--dry-run | --list-regions | --list-networks]

  --config <file>    JSON file naming the UniFi console and the tunnels to refresh
  --dry-run          register new keys with PIA and show what would change, but do not write to UniFi
  --list-regions     print PIA's WireGuard region ids and exit
  --list-networks    print the VPN Clients found in UniFi and exit
  --quiet            only print failures

Environment: PIA_USERNAME, PIA_PASSWORD, and UNIFI_API_KEY or UNIFI_USERNAME + UNIFI_PASSWORD.
Any of them may instead be given as <NAME>_FILE, naming a file that holds the value.
`;

function parseArgs(argv) {
  const options = { config: '', dryRun: false, listRegions: false, listNetworks: false, quiet: false, help: false };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--config') options.config = argv[++i] || '';
    else if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--list-regions') options.listRegions = true;
    else if (arg === '--list-networks') options.listNetworks = true;
    else if (arg === '--quiet' || arg === '-q') options.quiet = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new AppError('INVALID_INPUT', `Unknown argument: ${arg}`);
  }
  return options;
}

/**
 * `curl --cacert` needs a path, so PIA's bundled CA is written to a private
 * temporary directory for the duration of the run — the same thing the desktop
 * app does at startup.
 */
function materialiseCa() {
  const dir = mkdtempSync(join(tmpdir(), 'pia-unifi-sync-'));
  const path = join(dir, 'pia-ca.crt');
  writeFileSync(path, PIA_CA_PEM, { mode: 0o600 });
  return { path, remove: () => rmSync(dir, { recursive: true, force: true }) };
}

function printError(err) {
  const message = err instanceof AppError ? err.message : `Unexpected error: ${err instanceof Error ? err.message : String(err)}`;
  process.stderr.write(`\nerror: ${message}\n`);
  if (err instanceof AppError && err.detail) process.stderr.write(`  ${err.detail}\n`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help || !options.config) {
    process.stdout.write(USAGE);
    return options.help ? 0 : 2;
  }

  const log = options.quiet ? () => {} : (line) => process.stderr.write(`${line}\n`);

  const configPath = resolve(options.config);
  const config = loadSyncConfig(
    JSON.parse(readFileSync(configPath, 'utf8')),
    (relative) => resolve(dirname(configPath), relative),
  );
  const http = new HttpClient(curlExec, { tolerateUnknownRevocation: process.platform === 'win32' });
  await http.preflight();

  const ca = materialiseCa();
  try {
    const pia = new PiaClient(http, () => ca.path);

    // The region list is public; no credentials are needed to print it.
    if (options.listRegions) {
      const regions = await pia.fetchRegions();
      for (const region of regions) {
        process.stdout.write(`${region.id.padEnd(24)} ${region.name}${region.geo ? '  (geo)' : ''}\n`);
      }
      return 0;
    }

    const credentials = readCredentials(process.env, (path) => readFileSync(path, 'utf8'));

    const unifi = new UnifiClient({
      url: config.unifi.url,
      site: config.unifi.site,
      selfHosted: config.unifi.selfHosted,
      trust: config.unifi.certificate ? trustFromPem(readFileSync(config.unifi.certificate, 'utf8')) : null,
      apiKey: credentials.unifiApiKey,
    });

    if (!credentials.unifiApiKey) {
      log(`Signing in to ${config.unifi.url}…`);
      await unifi.login(credentials.unifiUsername, credentials.unifiPassword);
    }

    if (options.listNetworks) {
      const rows = (await unifi.listNetworks()).filter((row) => row && row.purpose === 'vpn-client');
      if (rows.length === 0) process.stdout.write('No VPN Clients on this site.\n');
      for (const row of rows) {
        const endpoint = row.wireguard_client_peer_ip ? `${row.wireguard_client_peer_ip}:${row.wireguard_client_peer_port}` : '';
        process.stdout.write(`${String(row.name).padEnd(32)} ${String(row.vpn_type).padEnd(18)} ${row.enabled === false ? 'disabled' : 'enabled '}  ${endpoint}\n`);
      }
      return 0;
    }

    const results = await syncTunnels({
      pia, unifi, crypto: nodeCrypto, config, credentials, dryRun: options.dryRun, log,
    });

    let failed = 0;
    for (const result of results) {
      if (result.ok) {
        if (!options.quiet) {
          process.stdout.write(`${options.dryRun ? 'would update' : 'updated'}: ${result.network} ← ${result.server} (${result.endpoint})\n`);
          for (const change of result.changes) process.stdout.write(`    ${change}\n`);
        }
      } else {
        failed++;
        process.stderr.write(`failed: ${result.network} — ${result.error.message}\n`);
        if (result.error.detail) process.stderr.write(`    ${result.error.detail}\n`);
      }
    }

    return failed === 0 ? 0 : 1;
  } finally {
    ca.remove();
  }
}

main().then(
  (code) => { process.exitCode = code; },
  (err) => { printError(err); process.exitCode = 1; },
);
