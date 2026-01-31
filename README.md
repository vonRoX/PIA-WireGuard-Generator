# PIA WireGuard Generator (PowerShell)

A PowerShell script that automates the creation of WireGuard configuration files for **Private Internet Access (PIA)** using their official API.

## Features

- **Automated Key Generation**: Uses the local `wg.exe` to generate secure private/public keys.
- **Region Selection**: Fetches the latest server list from PIA and lets you interactively select your desired region.
- **Port Forwarding Support**: Connects to PIA's API to register your public key.
- **Config Generation**: Outputs a standard `.conf` file ready for import into the WireGuard client.
- **Secure**: Credentials are not hardcoded. You are prompted at runtime, and they are only used in memory for the session.

## Prerequisites

1.  **Windows**: This script is designed for Windows PowerShell.
2.  **WireGuard for Windows**: You must have the official WireGuard client installed.
    - Default path expected: `C:\Program Files\WireGuard\wg.exe`
3.  **PIA Account**: A valid Private Internet Access subscription.

## Usage

1.  Clone this repository or download the script.
2.  Open PowerShell.
3.  Run the script:
    ```powershell
    .\PIA-WireGuard-Generator.ps1
    ```
4.  Follow the interactive prompts:
    - Enter your PIA Username (e.g., `p1234567`) and Password.
    - Select a region from the list.
5.  The script will generate a `.conf` file in the same directory (e.g., `PIA-czech_republic.conf`).
6.  Import this file into your WireGuard client.

### Non-Interactive Mode (Optional)

You can pass credentials as parameters if you are automating this process (use with caution):

```powershell
.\PIA-WireGuard-Generator.ps1 -Username "p1234567" -Password "YourPassword"
```

## Security & Privacy

- **.gitignore**: This repository includes a `.gitignore` file that prevents `*.conf` (WireGuard configs) and `*.json` (server lists) from being committed to version control.
- **Credentials**: Your password is handled as a `SecureString` during input and is passed to the PIA API over HTTPS.

## Disclaimer

This is a community-created script and is not officially supported by Private Internet Access. Use at your own risk.
