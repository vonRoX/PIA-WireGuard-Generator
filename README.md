# PIA WireGuard Generator

A lightweight, premium desktop application for generating and registering WireGuard configurations for Private Internet Access (PIA). 

Built using **Node.js** and **Neutralinojs**, this application uses your operating system's native WebView engine instead of embedding a heavy Chromium browser (like Electron). This results in a lightning-fast `< 5MB` executable size and instantaneous startup time.

<p align="center">
  <img src="resources/icons/appIcon.png" width="128" />
</p>

## Features

- **No WireGuard Installation Required:** This application natively generates secure Curve25519 UDP private/public WireGuard keypairs using a purely JavaScript implementation (`tweetnacl-js`). You don't need `wg.exe` or any other dependencies installed!
- **Auto Server Registration:** Simply login and the app connects to the PIA API to retrieve a token, fetches the latest v6 server list across the globe, and securely registers your public key.
- **Advanced DNS Control:** 
  - PIA Standard (`10.0.0.242`)
  - PIA Streaming Optimized (`10.0.0.243`)
  - PIA MACE (Ad-blocking) (`10.0.0.244`)
  - Streaming + MACE (`10.0.0.241`)
  - Or specify any custom IP!
- **State Persistence:** Securely remembers your credentials, desired target region, and advanced DNS preferences across application restarts so you don't have to constantly log in.
- **Cross-Platform:** Works on Windows, macOS, and Linux.

## How to Build
To bundle the frontend into standalone executables:
```bash
npm install
npm run build
```
This will generate binaries for `win`, `mac`, and `linux` inside the `/dist` directory.

## Licenses
This project uses the `tweetnacl` library which is released under the **MIT License** and embedded locally within the resources. Neutralinojs is also licensed under the MIT License.
