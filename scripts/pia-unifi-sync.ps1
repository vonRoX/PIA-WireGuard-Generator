<#
.SYNOPSIS
  Refresh the UniFi WireGuard tunnels from Windows, with the credentials kept
  encrypted for your Windows account instead of in a text file.

.DESCRIPTION
  Credentials live in %LOCALAPPDATA%\pia-unifi-sync\credentials.xml, encrypted
  with DPAPI: only this Windows account, on this computer, can decrypt them. A
  copied file, a backup, another account, or a disk pulled from the machine
  gets nothing. They are never in the repository, so there is nothing to commit
  by accident and nothing lost when a checkout is deleted.

  What DPAPI does not stop: a program already running as you can decrypt them,
  exactly as it could read a plaintext file you own. The UniFi API key is a
  site-admin credential either way — revoke it in the console when you no
  longer need it.

  On each run the secrets are decrypted into this process's environment, which
  is where scripts/pia-unifi-sync.mjs already reads them, and removed again when
  the run ends. Nothing is passed on a command line, so nothing appears in a
  process listing.

  With no arguments this performs a DRY RUN. Pass --apply to write to the
  console. Anything else is passed through, so --list-networks, --list-regions
  and --diagnose --probe-write work as documented.

.EXAMPLE
  powershell -File scripts\pia-unifi-sync.ps1 -SetCredentials

.EXAMPLE
  powershell -File scripts\pia-unifi-sync.ps1 --diagnose --probe-write

.EXAMPLE
  powershell -File scripts\pia-unifi-sync.ps1 -ForgetCredentials
#>
[CmdletBinding(PositionalBinding = $false)]
param(
  # Prompt for the credentials and store them, encrypted, replacing any stored before.
  [switch]$SetCredentials,
  # Delete the stored credentials.
  [switch]$ForgetCredentials,
  # Everything else goes to the sync script untouched.
  [Parameter(ValueFromRemainingArguments)][string[]]$SyncArguments
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Entry = Join-Path $RepoRoot 'scripts\pia-unifi-sync.mjs'
$ConfigFile = Join-Path $RepoRoot 'pia-unifi-sync.json'
$StoreDir = Join-Path $env:LOCALAPPDATA 'pia-unifi-sync'
$StoreFile = Join-Path $StoreDir 'credentials.xml'

# The environment variables the sync script reads. Nothing else is set.
$CredentialVariables = @('PIA_USERNAME', 'PIA_PASSWORD', 'UNIFI_API_KEY')

function Fail([string]$Message) {
  Write-Host ''
  Write-Host "  $Message" -ForegroundColor Red
  Write-Host ''
  exit 1
}

# Export-Clixml encrypts a SecureString with DPAPI only on Windows; elsewhere it
# would write the secret in a reversible form. Refuse rather than pretend.
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
  Fail 'This launcher relies on Windows DPAPI and runs only on Windows. Elsewhere, use the *_FILE variables described in docs/wiki/features/UniFi_Automation.md.'
}

function Read-Secret([string]$Prompt) {
  $secure = Read-Host -Prompt $Prompt -AsSecureString
  if ($secure.Length -eq 0) { Fail "$Prompt was left empty. Nothing was stored." }
  return $secure
}

function ConvertFrom-Secret([System.Security.SecureString]$Secure) {
  return [System.Net.NetworkCredential]::new('', $Secure).Password
}

function Protect-StoreDirectory {
  if (-not (Test-Path -LiteralPath $StoreDir)) {
    New-Item -ItemType Directory -Path $StoreDir | Out-Null
  }
  # DPAPI already makes the file useless to anyone else; the ACL keeps other
  # accounts from even listing or deleting it. Granted by SID, so a renamed
  # account or a localised "Administrators" does not break it.
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $StoreDir /inheritance:r /grant:r "*${sid}:(OI)(CI)F" | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "Could not restrict access to $StoreDir." }
}

if ($SetCredentials -and $ForgetCredentials) {
  Fail 'Use -SetCredentials or -ForgetCredentials, not both.'
}

if ($ForgetCredentials) {
  if (Test-Path -LiteralPath $StoreFile) {
    Remove-Item -LiteralPath $StoreFile -Force
    Write-Host "  Stored credentials deleted. Consider revoking the UniFi API key in the console as well."
  } else {
    Write-Host '  No credentials were stored.'
  }
  exit 0
}

if ($SetCredentials) {
  Write-Host ''
  Write-Host '  Credentials are encrypted for this Windows account and stored in'
  Write-Host "    $StoreFile"
  Write-Host '  Nothing you type is shown or written anywhere else.'
  Write-Host ''

  $piaUsername = Read-Host -Prompt 'PIA username (p1234567)'
  if ([string]::IsNullOrWhiteSpace($piaUsername)) { Fail 'The PIA username was left empty. Nothing was stored.' }
  $piaPassword = Read-Secret 'PIA password'
  $unifiApiKey = Read-Secret 'UniFi API key (Settings > Control Plane > Integrations)'

  # The key travels in an HTTP header, so a stray space, newline or quote from
  # a clumsy paste would corrupt the request. Only printable ASCII other than a
  # double quote is accepted — Ubiquiti documents no stricter alphabet. Checked here, where it can be
  # retyped, rather than failing on the console later. The value is never shown.
  if ((ConvertFrom-Secret $unifiApiKey) -cnotmatch '^[\x21\x23-\x7E]+$') {
    Fail 'That UniFi API key contains characters an API key does not have (a space or line break from pasting?). Nothing was stored.'
  }

  Protect-StoreDirectory
  [pscustomobject]@{
    Version     = 1
    PiaUsername = ConvertTo-SecureString -String $piaUsername.Trim() -AsPlainText -Force
    PiaPassword = $piaPassword
    UnifiApiKey = $unifiApiKey
  } | Export-Clixml -LiteralPath $StoreFile -Force

  Write-Host ''
  Write-Host '  Stored. Run this script again without -SetCredentials to use them.'
  exit 0
}

# --- A run --------------------------------------------------------------------

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Fail 'Node.js was not found. Install the LTS build from https://nodejs.org/ (Node 20 or newer), then run this again.'
}
if (-not (Test-Path -LiteralPath $ConfigFile)) {
  Fail "No configuration file at $ConfigFile. Copy examples\pia-unifi-sync.example.json there and edit it."
}
if (-not (Test-Path -LiteralPath $StoreFile)) {
  Fail "No stored credentials. Run: powershell -File `"$PSCommandPath`" -SetCredentials"
}

try {
  $stored = Import-Clixml -LiteralPath $StoreFile
  $values = @{
    PIA_USERNAME  = ConvertFrom-Secret $stored.PiaUsername
    PIA_PASSWORD  = ConvertFrom-Secret $stored.PiaPassword
    UNIFI_API_KEY = ConvertFrom-Secret $stored.UnifiApiKey
  }
} catch {
  # DPAPI refuses to decrypt for a different account or computer. Say that,
  # rather than surfacing a cryptographic exception.
  Fail 'The stored credentials could not be decrypted. They were saved by a different Windows account or on another computer. Run with -SetCredentials to store them again.'
}

# A refresh is a dry run unless --apply is given — including one narrowed with
# --only, which would otherwise write simply because it had an argument.
# Commands that never write (listing, diagnosing, help) pass through untouched.
$given = @($SyncArguments | Where-Object { $_ })
$readOnly = @('--list-networks', '--list-regions', '--diagnose', '--help', '-h', '--dry-run')
if ($given -contains '--apply') {
  $nodeArguments = @($given | Where-Object { $_ -ne '--apply' })
} elseif (@($given | Where-Object { $readOnly -contains $_ }).Count -gt 0) {
  $nodeArguments = $given
} else {
  $nodeArguments = @('--dry-run') + $given
}

Write-Host ''
if ($nodeArguments.Count -gt 0) {
  Write-Host "  Running: pia-unifi-sync $($nodeArguments -join ' ')"
} else {
  Write-Host '  Running: pia-unifi-sync (applying changes to the console)'
}
Write-Host ''

# Anything already in the environment under these names would be overwritten
# anyway; putting it back afterwards keeps an interactive session as it was.
$previous = @{}
foreach ($name in $CredentialVariables) {
  $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$exitCode = 1
try {
  foreach ($name in $CredentialVariables) {
    [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process')
  }
  & node $Entry --config $ConfigFile @nodeArguments
  $exitCode = $LASTEXITCODE
} finally {
  foreach ($name in $CredentialVariables) {
    [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
  }
  $values.Clear()
}

Write-Host ''
if ($exitCode -eq 0) {
  Write-Host '  Finished.'
} else {
  Write-Host "  Finished with errors (exit code $exitCode)."
}
exit $exitCode
