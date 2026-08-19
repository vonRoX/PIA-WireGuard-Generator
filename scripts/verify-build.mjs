#!/usr/bin/env node
/**
 * Fail the build when the build produced nothing.
 *
 * `neu build` prints "Application package was generated at the dist directory!"
 * and exits 0 even when it wrote no files at all — for instance when the client
 * library has not been downloaded, which is the state of every fresh clone. A
 * release pipeline gated on that exit code ships an empty release and says
 * nothing. This script is the gate instead.
 *
 * Usage: node scripts/verify-build.mjs [--dist <path>] [--json]
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Anything smaller than this is a stub, not an application. */
const MIN_BINARY_BYTES = 256 * 1024;

const EXECUTABLE_PATTERN = /(?:\.exe|_x64|_arm64|_armhf|-x64|-arm64)$|\.exe$/i;

function parseArgs(argv) {
  const options = { dist: join(ROOT, 'dist'), json: false };

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dist') options.dist = resolve(argv[++i]);
    else if (argv[i] === '--json') options.json = true;
  }
  return options;
}

function binaryName() {
  try {
    const config = JSON.parse(readFileSync(join(ROOT, 'neutralino.config.json'), 'utf8'));
    return config?.cli?.binaryName || 'app';
  } catch {
    return 'app';
  }
}

/** @returns {{path: string, name: string, bytes: number, sha256: string}[]} */
function collectArtefacts(directory) {
  const found = [];

  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile()) {
        const bytes = statSync(path).size;
        found.push({
          path,
          name: entry.name,
          bytes,
          sha256: createHash('sha256').update(readFileSync(path)).digest('hex'),
        });
      }
    }
  };

  walk(directory);
  return found;
}

function fail(message, hint) {
  process.stderr.write(`\nBuild verification failed: ${message}\n`);
  if (hint) process.stderr.write(`\n  ${hint}\n`);
  process.stderr.write('\n');
  process.exit(1);
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const name = binaryName();

  if (!existsSync(options.dist)) {
    fail(
      `no dist directory at ${options.dist}.`,
      'Run `npm run build`. If that appeared to succeed, the Neutralino binaries were probably never\n' +
      '  downloaded — `neu update` must run first, and it needs network access to GitHub releases.',
    );
  }

  const artefacts = collectArtefacts(options.dist);
  if (artefacts.length === 0) {
    fail(`${options.dist} exists but is empty.`, 'This is the failure `neu build` reports as success.');
  }

  const executables = artefacts.filter(
    (artefact) => EXECUTABLE_PATTERN.test(artefact.name) || artefact.name.startsWith(name),
  );
  const substantial = executables.filter((artefact) => artefact.bytes >= MIN_BINARY_BYTES);

  if (substantial.length === 0) {
    fail(
      `no application binary of at least ${(MIN_BINARY_BYTES / 1024).toFixed(0)} KiB was produced.`,
      `Found ${artefacts.length} file(s): ${artefacts.map((a) => `${a.name} (${a.bytes} B)`).join(', ')}`,
    );
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify({ dist: options.dist, artefacts: substantial }, null, 2)}\n`);
    return;
  }

  process.stdout.write(`\nBuild verified — ${substantial.length} binaries in ${options.dist}\n\n`);
  for (const artefact of substantial.sort((a, b) => a.name.localeCompare(b.name))) {
    const size = `${(artefact.bytes / 1024 / 1024).toFixed(1)} MiB`.padStart(9);
    process.stdout.write(`  ${artefact.name.padEnd(38)} ${size}  ${artefact.sha256.slice(0, 16)}…\n`);
  }
  process.stdout.write('\n');
}

main();
