# --- PIA WireGuard Config Generator (API Mode) v7 ---
# Fixes: 'param' block moved to top of script (Syntax Requirement)

param (
    [string]$Username = "",
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"

try {
    $WgExe = "C:\Program Files\WireGuard\wg.exe"

    # --- Setup ---
    if (-not (Test-Path $WgExe)) {
        Write-Error "CRITICAL: wg.exe not found at $WgExe. Please install WireGuard."
        throw "WireGuard missing"
    }

    Write-Host "--- PIA WireGuard Generator v7 ---" -ForegroundColor Cyan
    Write-Host "Using Username: $Username" -ForegroundColor DarkGray

    # 1. Generate Keys
    Write-Host "`n[1/5] Generating WireGuard Keys..." -ForegroundColor Cyan
    $PrivateKey = (& $WgExe genkey).Trim()
    $PublicKey = ($PrivateKey | & $WgExe pubkey).Trim()
    Write-Host "    > Public Key:  $PublicKey" -ForegroundColor Gray

    # 2. Authenticate (Loop)
    $Token = $null
    while (-not $Token) {
        Write-Host "`n[2/5] Authenticating with PIA..." -ForegroundColor Cyan
        
        if ([string]::IsNullOrWhiteSpace($Username)) {
            $Username = Read-Host "Enter your PIA Username"
        }

        if ([string]::IsNullOrWhiteSpace($Password)) {
            $SecurePass = Read-Host "Enter your PIA Password for $Username" -AsSecureString
            $Password = [System.Net.NetworkCredential]::new("", $SecurePass).Password
        }
        
        $TokenAuthUrl = "https://www.privateinternetaccess.com/api/client/v2/token"
        $AuthBody = @{
            username = $Username
            password = $Password
        }

        try {
            Write-Host "    > Sending authentication request..." -ForegroundColor DarkGray
            $AuthResponse = Invoke-RestMethod -Uri $TokenAuthUrl -Method Post -Body $AuthBody
            $Token = $AuthResponse.token
            Write-Host "    > Success! Token retrieved." -ForegroundColor Green
        } catch {
            Write-Warning "Authentication Failed."
            if ($_.Exception.Response) {
                $Reader = New-Object System.IO.StreamReader $_.Exception.Response.GetResponseStream()
                $RespBody = $Reader.ReadToEnd()
                Write-Host "    > Server Message: $RespBody" -ForegroundColor Red
            } else {
                Write-Host "    > Error: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            $Retry = Read-Host "    Retry? (y/n)"
            if ($Retry -ne 'y') { exit }
            $Password = $null # Clear password so it prompts again on retry
        }
    }

    # 3. Fetch Server List & Select Region
    Write-Host "`n[3/5] Fetching Server List..." -ForegroundColor Cyan
    
    $RawResponse = $null
    try {
        Write-Host "    > Downloading latest list from PIA API..." -ForegroundColor DarkGray
        $RawResponse = Invoke-RestMethod -Uri "https://serverlist.piaservers.net/vpninfo/servers/v6" -Method Get
    } catch {
        if (Test-Path "$PSScriptRoot\v6.json") {
            Write-Warning "Web fetch failed. Falling back to local v6.json..."
            $RawResponse = Get-Content -Path "$PSScriptRoot\v6.json" -Raw
        } else {
            throw "Failed to download server list and no local fallback found."
        }
    }

    # Clean the response: Strip the signature block (Keep everything up to the LAST '}')
    if ($RawResponse -is [string]) {
        $LastIdx = $RawResponse.LastIndexOf('}')
        if ($LastIdx -ge 0) {
            $JsonOnly = $RawResponse.Substring(0, $LastIdx + 1)
            $Servers = $JsonOnly | ConvertFrom-Json
        } else {
            throw "Invalid JSON response (no closing brace found)."
        }
    } else {
        # If Invoke-RestMethod already parsed it as an object
        $Servers = $RawResponse
    }
    
    Write-Host "    > Server list processed ($($Servers.regions.Count) regions found)." -ForegroundColor Gray

    # Filter for WireGuard enabled regions
    $WgRegions = $Servers.regions | Where-Object { $_.servers.wg } | Sort-Object name
    if ($WgRegions.Count -eq 0) {
        throw "No WireGuard-enabled regions found in the server list!"
    }

    # Region Selection Loop
    $SelectedRegion = $null
    while (-not $SelectedRegion) {
        Write-Host "`nAvailable Regions:" -ForegroundColor Yellow
        $i = 1
        foreach ($region in $WgRegions) {
            # Format: [ 1] Czech Republic (czech)
            # Pre-format string to avoid Write-Host parameter binding issues
            $Line = " [{0,2}] {1,-35} ({2})" -f $i, $region.name, $region.id
            Write-Host $Line
            $i++
        }

        $Selection = Read-Host "`nEnter the NUMBER of your desired region (1-$($WgRegions.Count))"
        
        if ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $WgRegions.Count) {
            $SelectedRegion = $WgRegions[[int]$Selection - 1]
            Write-Host "    > Selected: $($SelectedRegion.name)" -ForegroundColor Green
        } else {
            Write-Warning "Invalid selection. Please enter a number between 1 and $($WgRegions.Count)."
            Start-Sleep -Milliseconds 500
        }
    }

    # 4. Register Key (Retry Loop)
    Write-Host "`n[4/5] Registering Key with Server..." -ForegroundColor Cyan

    # SSL Bypass Setup
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    $KeyRegistered = $false
    $Attempt = 0
    $MaxAttempts = 3

    while (-not $KeyRegistered -and $Attempt -lt $MaxAttempts) {
        $Attempt++
        $WgServer = $SelectedRegion.servers.wg | Get-Random
        $WgIP = $WgServer.ip
        $WgCN = $WgServer.cn
        $WgPort = "1337"

        Write-Host "    > Attempt $Attempt/${MaxAttempts}: Connecting to $WgCN ($WgIP)..." -ForegroundColor DarkGray

        # Try IP first, then CN
        $AddKeyUrl = "https://${WgIP}:${WgPort}/addKey?pt=${Token}&pubkey=$([Uri]::EscapeDataString($PublicKey))"
        
        try {
            $KeyResponse = Invoke-RestMethod -Uri $AddKeyUrl -Method Get
            if ($KeyResponse.status -eq "OK") {
                $KeyRegistered = $true
                Write-Host "    > Success! Key registered." -ForegroundColor Green
            } else {
                Write-Warning "    > Server returned status: $($KeyResponse.status) - $($KeyResponse.message)"
            }
        } catch {
            Write-Host "    > IP connection failed ($($_.Exception.Message)). Trying Hostname..." -ForegroundColor DarkGray
            $AddKeyUrl = "https://${WgCN}:${WgPort}/addKey?pt=${Token}&pubkey=$([Uri]::EscapeDataString($PublicKey))"
            try {
                $KeyResponse = Invoke-RestMethod -Uri $AddKeyUrl -Method Get
                if ($KeyResponse.status -eq "OK") {
                    $KeyRegistered = $true
                    Write-Host "    > Success! Key registered." -ForegroundColor Green
                }
            } catch {
                Write-Host "    > Hostname connection failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    if (-not $KeyRegistered) {
        throw "Failed to register key after $MaxAttempts attempts. Try selecting a different region."
    }

    # 5. Save Config
    Write-Host "`n[5/5] Saving Configuration..." -ForegroundColor Cyan

    $ServerPub = $KeyResponse.server_key
    $ServerPort = $KeyResponse.server_port
    $ServerIp = $KeyResponse.server_ip
    $ClientIp = $KeyResponse.peer_ip
    $DNS = "10.0.0.243"

    $ConfigContent = @"
[Interface]
Address = ${ClientIp}/32
PrivateKey = ${PrivateKey}
DNS = ${DNS}

[Peer]
PublicKey = ${ServerPub}
Endpoint = ${ServerIp}:${ServerPort}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"@

    $OutFile = Join-Path $PSScriptRoot "PIA-$($SelectedRegion.id).conf"
    $ConfigContent | Out-File -FilePath $OutFile -Encoding ascii

    Write-Host "`nDONE! Config saved to: $OutFile" -ForegroundColor Green

} catch {
    Write-Host "`n[!] FATAL ERROR OCCURRED:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}

Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray
Read-Host "Press Enter to exit..."
