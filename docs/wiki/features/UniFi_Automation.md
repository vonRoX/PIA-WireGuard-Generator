---
title: UniFi Automation
aliases: [UniFi Sync, Automation, Headless]
tags: [features, automation, unifi]
created: "2026-09-02"
updated: "2026-09-02"
sources: []
status: active
confidence: medium
---
# UniFi Automation

`scripts/pia-unifi-sync.mjs` does the desktop app's round trip without the desktop: sign in to
Private Internet Access, generate a key pair, register it with a server in a chosen region, and
write the result straight into a WireGuard **VPN Client** on a UniFi gateway (UCG Ultra, UDM, UDR,
or a self-hosted Network application). Run it from a timer and the tunnels stop needing you.

## Why the tunnels keep dying

A PIA WireGuard registration is not a credential you hold; it is a row in a server's peer table
that exists only while the peer keeps talking. Community operators of PIA's own scripts report
that a registered key is dropped after some hours without a handshake, and that registering a
second key against the same server with the same account token can invalidate the first. So a
gateway reboot, a firmware update, or a WAN outage that outlasts `PersistentKeepalive` leaves the
console showing **Not Established** until someone generates a new configuration and pastes it in.
The account token itself lasts about a day, which is why the generator has to sign in again
rather than reuse one.

Nothing about that changes; the script just makes the round trip cheap enough to run on a
schedule.

## What it touches in UniFi

A VPN Client is a `networkconf` row with `purpose: "vpn-client"` and `vpn_type:
"wireguard-client"`. The script reads the row by the name shown in the console, and replaces
exactly the fields a registration changes:

| Field | New value |
|---|---|
| `x_wireguard_private_key` | the freshly generated private key |
| `wireguard_public_key` (when present) | its public half |
| `wireguard_client_peer_public_key` | the server key `addKey` returned |
| `wireguard_client_peer_ip`, `wireguard_client_peer_port` | the endpoint |
| `ip_subnet` | the peer address, `/32` |
| `wireguard_client_configuration_file` (rows created by upload) | a rendered `.conf` matching the above |

Routing, DNS pulling, which networks use the tunnel, and every other setting are sent back
unchanged. The row is then `PUT` to `rest/networkconf/<id>`, which is what the console's own UI
does on **Apply**, and the gateway re-provisions the tunnel — expect a few seconds of interruption
per tunnel, so schedule the run for a quiet hour.

If a row lacks the fields above the script refuses to write it and prints the fields it did find;
Ubiquiti publishes no schema for this API, and guessing at one is how a tunnel ends up silently
misconfigured.

## Setting it up

1. **Create the VPN Clients once in the console** (Settings → VPN → VPN Client → WireGuard), by
   uploading a configuration from the app. Give each a name you will refer to.

2. **Choose how the script signs in.** Either:
   - an **API key** — Settings → Control Plane → Integrations on UniFi Network 9 and later, set as
     `UNIFI_API_KEY`; or
   - a **dedicated local admin without multi-factor authentication**, set as `UNIFI_USERNAME` and
     `UNIFI_PASSWORD`. A UniFi account with MFA cannot be used unattended.

   The API key is preferred: it can be revoked on its own, and a leak does not expose a password.
   Whether a key is accepted on the `networkconf` route depends on the Network version; `--dry-run`
   will tell you immediately.

3. **Trust the console's certificate.** A console ships with a self-signed certificate, and the
   script never disables verification. Export the certificate from your browser (the padlock →
   certificate → export as Base64/PEM) and point `unifi.certificate` at the file. The script then
   accepts *that certificate and no other*, regardless of the name it carries, which is stricter
   than what a browser does after you click through the warning. If your console has a real
   certificate for the name you reach it by, omit the setting.

4. **Write the configuration** — copy `examples/pia-unifi-sync.example.json`:

   ```json
   {
     "unifi": { "url": "https://192.168.1.1", "certificate": "unifi-console.pem" },
     "dns": "10.0.0.243",
     "tunnels": [
       { "network": "WireGuard PIA CZ", "region": "czech" },
       { "network": "WireGuard US East", "region": "us_east" }
     ]
   }
   ```

   `network` is the VPN Client name exactly as the console shows it; `region` is a PIA region id
   (`--list-regions` prints them). `dns` takes the same values as the app, and a tunnel may override
   it. The file holds no secrets. Add `"site"` if the site was renamed, and `"selfHosted": true` for a
   Network application that is not on a UniFi OS console.

5. **Put the credentials in the environment**, or in files named by `PIA_USERNAME_FILE` and
   friends — the form Docker secrets and systemd `LoadCredential=` use.

6. **Rehearse**:

   ```bash
   node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json --list-networks
   node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json --dry-run
   ```

   A dry run signs in everywhere, registers a real key with PIA, and prints the fields it would
   change — private keys named but never shown — without writing to the console.

7. **Schedule it.** `examples/systemd/` has a service and a timer for twice a day; the equivalent
   cron line is

   ```
   0 4,16 * * *  cd /opt/PIA-WireGuard-Generator && node scripts/pia-unifi-sync.mjs --config /etc/pia-unifi-sync.json --quiet
   ```

   Twice daily is a comfortable margin against both the token's day and the registration's idle
   timeout. Every run rotates the key pair, which is what the app does too.

## Where it runs

Anywhere with Node 20+ and curl that can reach both the internet and the console: a NAS, a
Raspberry Pi, the machine that already runs Home Assistant. It cannot run *on* the gateway, which
has no Node, and a script placed on UniFi OS does not survive a firmware update in any case.

## How the pieces fit

```
scripts/pia-unifi-sync.mjs      argument parsing, credentials, exit codes
scripts/unifi-sync/sync.mjs     config validation, row patching, the per-tunnel loop
scripts/unifi-sync/unifi.mjs    the console client: sign-in, CSRF, networkconf GET/PUT, certificate pinning
scripts/unifi-sync/exec.mjs     runs `curl -q --config -` through execFile — no shell at all
scripts/unifi-sync/crypto.mjs   X25519 from node:crypto, the reference the test suite already trusts
```

The PIA side is the app's own `HttpClient` and `PiaClient`, so PIA requests are pinned to the
bundled CA and `addKey` replies are validated before anything is written, exactly as in the app.
The UniFi side uses `node:https` directly: it needs cookies and `PUT`, which the curl config path
was never built for, and a LAN request should not go through whatever proxy curl finds in the
environment.

`test/unifi-sync.test.js` runs the whole flow against a fake console over TLS, including the
pinning cases: the pinned self-signed certificate is accepted whatever it is called, a different
self-signed certificate is refused before a byte is sent, and a leaf from a private CA is accepted
only when its issuer is in the file.

## External Connections
- [[WireGuard_Generation]]
- [[Authentication_Flow]]
- [[Security_Model]]
