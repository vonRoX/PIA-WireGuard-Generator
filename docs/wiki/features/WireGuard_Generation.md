---
title: WireGuard Generation
aliases: [Config Generation, Key Generation]
tags: [features, wireguard]
created: "2026-04-18"
updated: "2026-08-19"
sources: ["[[2026-04-18_project_overview]]"]
status: active
confidence: high
---
# WireGuard Generation

Producing a `.conf` file requires a key pair, a server to register it with, and a response that can
be trusted enough to write into a tunnel configuration.

## Region selection
`https://serverlist.piaservers.net/vpninfo/servers/v6` returns a JSON document on its first line
followed by a signature, so the first line is taken rather than the body being parsed whole. Regions
are kept only if they offer a WireGuard server carrying both an address and a certificate common
name — without the `cn` there is nothing to verify against, and this app will not connect
unverified.

The chosen region is remembered by its **id**. Version 1 stored its index in a network-fetched list,
so the saved position pointed at a different country whenever PIA added or removed a region.

## Key generation
`generateKeyPair` draws 32 bytes from the platform CSPRNG, clamps them per RFC 7748, and derives the
public key with tweetnacl. The private key never leaves the machine; only the public key is sent.
The test suite checks the derivation against Node's own X25519 implementation rather than trusting a
single library.

## Registration
`GET https://<cn>:1337/addKey?pt=<token>&pubkey=<key>`, with the certificate verified against PIA's
bundled authority and the connection directed at the server's address — see [[Security_Model]]. The
port comes from the server list rather than being hard-coded. Both parameters are URL-encoded by
curl, so a token containing `&` cannot introduce a second parameter.

## Validation
Every field used in the configuration is checked before the template is filled: `peer_ip` and
`server_ip` must be IPv4 addresses, `server_key` a 32-byte base64 key, `server_port` a valid port. A
reply of `{"status": "OK"}` missing a field is an error, not a file containing `undefined`.

## Output
```
# Private Internet Access - <region>
[Interface]
Address = <peer_ip>/32
PrivateKey = <generated>
DNS = <chosen resolver>

[Peer]
PublicKey = <server_key>
Endpoint = <server_ip>:<server_port>
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

The result is shown with the private key masked, and can be revealed, copied, exported as a QR code
for a phone, or saved. Saved files are written with owner-only permissions.

## External Connections
- [[Authentication_Flow]]
- [[Frontend_Stack]]
- [[Security_Model]]
