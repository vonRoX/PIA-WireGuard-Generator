---
title: Project Architecture Overview
aliases: [Architecture, Overview]
tags: [architecture, reference]
created: "2026-04-18"
updated: "2026-04-18"
sources: []
status: active
confidence: high
---
# PIA WireGuard Generator Architecture

## System Design
The application generates WireGuard `.conf` files for Private Internet Access (PIA) locally. It replaced an Electron foundation with Neutralinojs to reduce package size from 80MB to under 5MB. 

The architecture consists of a Neutralinojs backend wrapper and a Vanilla JS frontend. It requires no external dependencies or binaries like `wg.exe`.

## Neutralinojs Backend Wrapper
Neutralinojs provides native OS capabilities to the web frontend via its API. Key configurations reside in `neutralino.config.json`. The application requires `os.execCommand` to execute `curl` requests. This bypasses CORS restrictions that standard `fetch()` API calls encounter when connecting to PIA servers. It also uses the `storage` API to persist user credentials and preferences.

## Vanilla JS Frontend
The frontend is contained entirely within `resources/`. It uses HTML, CSS, and vanilla JS. 

- `index.html`: Defines the three-step flow: Authentication, Configuration, Success.
- `style.css`: Uses CSS variables to mimic a Tailwind-style dark theme without the framework overhead.
- `renderer.js`: Manages DOM interactions, API handshakes, cryptographic generation, and file saving.

## Application Flows

### PIA Authentication Flow
Authentication uses `username` and `password` payload sent to PIA via a `curl` POST request to `/api/client/v2/token`. Upon success, the API returns a token. This token allows access to the WireGuard configuration endpoints.

### Key Generation & Registration Flow
1. **Region Fetch**: Retrieves the server list via a GET request to `/vpninfo/servers/v6`.
2. **Local Key Generation**: Uses `tweetnacl.js` to locally generate an ed25519 keypair. The private key never leaves the client machine.
3. **Public Key Registration**: Sends the generated public key and the authentication token to a selected PIA server via `curl`. The endpoint assigns an internal IP and provides the server's public key.
4. **Configuration Export**: Combines the local private key, assigned IP, server endpoint, and chosen DNS into a `.conf` string, exporting it via the Neutralino save dialog.
