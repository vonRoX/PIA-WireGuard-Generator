/**
 * The DPAPI credential store shared with scripts/pia-unifi-sync.ps1.
 *
 * `credentials.xml` is `Export-Clixml` of a `[pscustomobject]` whose secret
 * properties are `SecureString`s — which Windows PowerShell serialises encrypted
 * with DPAPI for the current account. Node has no DPAPI binding, so every read
 * and write goes through `powershell.exe`, and the rules for that are strict:
 *
 *  - The script is a constant. It is handed over with `-EncodedCommand`, so the
 *    command line holds nothing but that constant.
 *  - The request — operation, directory and any secret values — travels on
 *    stdin as base64 of UTF-8 JSON; the answer comes back on stdout the same way.
 *    (`-Command -` was tried first: PowerShell reads stdin *as commands*, so a
 *    JSON line after the script is executed as code, and the parser error echoes
 *    the secret to stderr. Base64 also sidesteps the console code page.)
 *  - stderr is never read into an error. The script catches everything and
 *    answers with a fixed error code, and only that code reaches `detail`.
 *
 * Format: when all three values are known the file is exactly what the
 * launcher writes, `Version = 1`. A partial set — the Workbench stores the
 * UniFi key before the PIA credentials exist — is written as `Version = 2` with
 * only the properties that are present. The launcher's reader must accept that.
 */

import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

import { EngineErrorCode, engineError } from './errors.mjs';

/** JavaScript name → property name in credentials.xml. */
export const SECRET_PROPERTIES = Object.freeze({
  piaUsername: 'PiaUsername',
  piaPassword: 'PiaPassword',
  unifiApiKey: 'UnifiApiKey',
});

export const POWERSHELL = 'powershell.exe';

/**
 * The one script ever run. It never writes a value to stdout except the
 * decrypted set on `read`, and never writes a value to stderr at all.
 */
export const STORE_SCRIPT = String.raw`
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Send-Result($Result) {
  $json = ConvertTo-Json -InputObject $Result -Compress -Depth 4
  [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
}

try {
  $raw = [Console]::In.ReadToEnd().Trim()
  $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw)) | ConvertFrom-Json
  $dir = [string]$request.dir
  $op = [string]$request.op
} catch {
  Send-Result @{ ok = $false; error = 'BAD_REQUEST' }
  exit 0
}

$names = @('PiaUsername', 'PiaPassword', 'UnifiApiKey')
$file = Join-Path $dir 'credentials.xml'

function Protect-Directory {
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
  }
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $dir /inheritance:r /grant:r ('*' + $sid + ':(OI)(CI)F') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }
}

# SecureStrings as stored, never turned into text. Empty ones count as absent.
function Get-Stored {
  $found = @{}
  if (-not (Test-Path -LiteralPath $file)) { return $found }
  $stored = Import-Clixml -LiteralPath $file
  foreach ($name in $names) {
    $property = $stored.PSObject.Properties[$name]
    if ($null -ne $property -and $property.Value -is [System.Security.SecureString] -and $property.Value.Length -gt 0) {
      $found[$name] = $property.Value
    }
  }
  return $found
}

function Get-Presence($Values) {
  $presence = @{}
  foreach ($name in $names) { $presence[$name] = $Values.ContainsKey($name) }
  return $presence
}

if ($op -eq 'read') {
  try { $stored = Get-Stored } catch { Send-Result @{ ok = $false; error = 'UNREADABLE' }; exit 0 }
  $values = @{}
  foreach ($name in $stored.Keys) {
    $values[$name] = [System.Net.NetworkCredential]::new('', $stored[$name]).Password
  }
  Send-Result @{ ok = $true; values = $values }
  exit 0
}

if ($op -eq 'write') {
  $next = @{}
  foreach ($name in $names) {
    $property = $request.values.PSObject.Properties[$name]
    if ($null -ne $property -and $property.Value -is [string] -and $property.Value.Length -gt 0) {
      $next[$name] = ConvertTo-SecureString -String $property.Value -AsPlainText -Force
    }
  }

  try {
    $stored = Get-Stored
  } catch {
    # Saved by another account or computer. Replacing everything is fine;
    # silently dropping what cannot be read is not.
    if ($next.Count -ne $names.Count) { Send-Result @{ ok = $false; error = 'UNREADABLE' }; exit 0 }
    $stored = @{}
  }
  foreach ($name in $stored.Keys) {
    if (-not $next.ContainsKey($name)) { $next[$name] = $stored[$name] }
  }

  try {
    Protect-Directory
    $record = [ordered]@{}
    if ($next.Count -eq $names.Count) { $record.Version = [int]1 } else { $record.Version = [int]2 }
    foreach ($name in $names) {
      if ($next.ContainsKey($name)) { $record[$name] = $next[$name] }
    }
    $temporary = Join-Path $dir ('credentials.' + [guid]::NewGuid().ToString('N') + '.tmp')
    [pscustomobject]$record | Export-Clixml -LiteralPath $temporary -Force
    Move-Item -LiteralPath $temporary -Destination $file -Force
  } catch {
    Send-Result @{ ok = $false; error = 'WRITE_FAILED' }
    exit 0
  }
  Send-Result @{ ok = $true; stored = (Get-Presence $next) }
  exit 0
}

if ($op -eq 'clear') {
  try {
    if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
  } catch {
    Send-Result @{ ok = $false; error = 'WRITE_FAILED' }
    exit 0
  }
  Send-Result @{ ok = $true }
  exit 0
}

if ($op -eq 'protect') {
  try { Protect-Directory } catch { Send-Result @{ ok = $false; error = 'WRITE_FAILED' }; exit 0 }
  Send-Result @{ ok = $true }
  exit 0
}

Send-Result @{ ok = $false; error = 'BAD_REQUEST' }
`;

export const POWERSHELL_ARGS = Object.freeze([
  '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
  '-EncodedCommand', Buffer.from(STORE_SCRIPT, 'utf16le').toString('base64'),
]);

/**
 * @callback ExecFn
 * @param {string} file
 * @param {readonly string[]} args
 * @param {{stdin: string}} options
 * @returns {Promise<{exitCode: number, stdout: string}>}
 */

/** @type {ExecFn} */
export function powershellExec(file, args, { stdin }) {
  return new Promise((resolve) => {
    const child = execFile(file, args, {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      timeout: 60_000,
    }, (error, stdout) => {
      // stderr is deliberately dropped: it is PowerShell's, not ours.
      if (!error) resolve({ exitCode: 0, stdout });
      else resolve({ exitCode: typeof error.code === 'number' ? error.code : -1, stdout: stdout || '' });
    });
    child.stdin.on('error', () => { /* exited early; the exit code tells the story */ });
    child.stdin.end(stdin);
  });
}

const MESSAGES = {
  UNREADABLE: [
    'The stored credentials could not be decrypted.',
    'They were saved by a different Windows account or on another computer. Forget them and enter them again.',
  ],
  WRITE_FAILED: ['The credentials could not be saved.', 'Check that the folder under %LOCALAPPDATA% is writable by you.'],
  BAD_REQUEST: ['The credential store could not be used.', ''],
};

/**
 * @param {{storeDir: string, exec?: ExecFn}} options
 */
export function createSecretStore({ storeDir, exec = powershellExec }) {
  if (typeof storeDir !== 'string' || !isAbsolute(storeDir)) {
    throw engineError(EngineErrorCode.INVALID_INPUT, 'The credential store needs an absolute directory.');
  }
  const file = join(storeDir, 'credentials.xml');

  async function run(request) {
    const stdin = Buffer.from(JSON.stringify({ dir: storeDir, ...request }), 'utf8').toString('base64');
    let result;
    try {
      result = await exec(POWERSHELL, POWERSHELL_ARGS, { stdin });
    } catch {
      result = { exitCode: -1, stdout: '' };
    }

    let answer = null;
    try {
      answer = JSON.parse(Buffer.from(String(result.stdout || '').trim(), 'base64').toString('utf8'));
    } catch {
      answer = null;
    }

    if (!answer || typeof answer !== 'object') {
      throw engineError(EngineErrorCode.STORAGE, 'Windows PowerShell could not be run to use the credential store.', {
        hint: 'The Workbench keeps credentials with Windows DPAPI and needs powershell.exe.',
        detail: `powershell.exe exit code ${result.exitCode}`,
      });
    }
    if (answer.ok !== true) {
      const code = typeof answer.error === 'string' && answer.error in MESSAGES ? answer.error : 'BAD_REQUEST';
      const [message, hint] = MESSAGES[code];
      throw engineError(EngineErrorCode.STORAGE, message, { hint: hint || undefined, detail: code });
    }
    return answer;
  }

  return {
    storeDir,
    file,

    /** @returns {Promise<{piaUsername: string, piaPassword: string, unifiApiKey: string}>} */
    async read() {
      const { values } = await run({ op: 'read' });
      const out = {};
      for (const [jsName, property] of Object.entries(SECRET_PROPERTIES)) {
        const value = values && typeof values === 'object' ? values[property] : undefined;
        out[jsName] = typeof value === 'string' ? value : '';
      }
      return out;
    },

    /**
     * Merge `partial` into what is stored. Absent or empty values leave the
     * stored ones alone; use {@link clear} to remove.
     *
     * @param {{piaUsername?: string, piaPassword?: string, unifiApiKey?: string}} partial
     * @returns {Promise<{piaUsername: boolean, piaPassword: boolean, unifiApiKey: boolean}>}
     */
    async write(partial) {
      if (!partial || typeof partial !== 'object') {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'Nothing to store.');
      }
      const values = {};
      for (const [jsName, property] of Object.entries(SECRET_PROPERTIES)) {
        const value = partial[jsName];
        if (value === undefined || value === null || value === '') continue;
        if (typeof value !== 'string') {
          throw engineError(EngineErrorCode.INVALID_INPUT, 'Credentials must be text.');
        }
        values[property] = value;
      }
      for (const jsName of Object.keys(partial)) {
        if (!(jsName in SECRET_PROPERTIES)) {
          throw engineError(EngineErrorCode.INVALID_INPUT, 'Unknown credential.');
        }
      }
      if (Object.keys(values).length === 0) {
        throw engineError(EngineErrorCode.INVALID_INPUT, 'Nothing to store.');
      }

      const { stored } = await run({ op: 'write', values });
      return presence(stored);
    },

    /** Delete credentials.xml. Nothing else in the folder is touched. */
    async clear() {
      await run({ op: 'clear' });
    },

    /** Create the folder if needed and restrict it to this account, as the launcher does. */
    async protectDirectory() {
      await run({ op: 'protect' });
    },

    /**
     * Which values are stored, read from the XML without decrypting anything:
     * a `SecureString` serialises as `<SS N="Name">hex</SS>`.
     *
     * @returns {Promise<{piaUsername: boolean, piaPassword: boolean, unifiApiKey: boolean, version: number|null}>}
     */
    async status() {
      let xml;
      try {
        xml = decodeXml(await readFile(file));
      } catch (err) {
        if (err && err.code === 'ENOENT') return { ...presence({}), version: null };
        throw engineError(EngineErrorCode.STORAGE, 'The credential store could not be read.', {
          detail: err && err.code ? String(err.code) : '',
        });
      }
      return parseStoreStatus(xml);
    },
  };
}

/**
 * Windows PowerShell's `Export-Clixml` writes UTF-16 LE with a byte-order mark;
 * PowerShell 7 writes UTF-8. Either may turn up.
 *
 * @param {Buffer} bytes
 * @returns {string}
 */
export function decodeXml(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return bytes.subarray(2).toString('utf16le');
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return bytes.subarray(3).toString('utf8');
  return bytes.toString('utf8');
}

/**
 * @param {string} xml credentials.xml
 * @returns {{piaUsername: boolean, piaPassword: boolean, unifiApiKey: boolean, version: number|null}}
 */
export function parseStoreStatus(xml) {
  const stored = {};
  for (const property of Object.values(SECRET_PROPERTIES)) {
    stored[property] = new RegExp(`<SS N="${property}">[0-9a-fA-F]+</SS>`).test(xml);
  }
  const version = /<I32 N="Version">(\d+)<\/I32>/.exec(xml);
  return { ...presence(stored), version: version ? Number(version[1]) : null };
}

/** @param {Record<string, boolean>|undefined} byProperty */
function presence(byProperty) {
  const out = {};
  for (const [jsName, property] of Object.entries(SECRET_PROPERTIES)) {
    out[jsName] = Boolean(byProperty && byProperty[property]);
  }
  return out;
}
