---
title: WireGuard Generation
aliases: [Generation, Keypair]
tags: [features, wireguard]
created: "2026-04-18"
updated: "2026-04-18"
sources: ["[[2026-04-18_project_overview]]"]
status: active
confidence: high
---
# WireGuard Generation

This feature orchestrates the creation of a standalone WireGuard `.conf` file without relying on external system binaries like `wg.exe`.

## Key Sequence
1. **Region Retrieval**: The application fetches the latest v6 server list via `https://serverlist.piaservers.net/vpninfo/servers/v6`.
2. **Local Cryptography**: A local ed25519 keypair is generated using the `tweetnacl.js` library. The private key remains on the client device.
3. **API Registration**: The application uses the authentication token from the [[Authentication_Flow]] and the generated public key to register with the selected PIA server endpoint. The request is made via a `curl` call configured with the `-k` flag to bypass internal SSL certificate warnings.
4. **Config Composition**: Upon successful registration, the API returns the peer IP, the server's public key, and the endpoint address. The application composes these details along with the user's preferred DNS into a standard `.conf` format.
5. **Export**: The resulting text is saved to the local filesystem using the Neutralino `filesystem.writeFile` API.

## External Connections
- [[Frontend_Stack]]
- [[Authentication_Flow]]
- [[Neutralinojs_Integration]]
