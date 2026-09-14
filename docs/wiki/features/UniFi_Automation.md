---
title: UniFi Automation
aliases: [UniFi Sync, Automation, Headless]
tags: [features, automation, unifi]
created: "2026-09-02"
updated: "2026-09-13"
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
that exists only while the peer keeps talking. **PIA documents none of this.** Their own
[`manual-connections`](https://github.com/pia-foss/manual-connections) scripts document the auth
token's expiry and the port-forward signature's two months, and say nothing at all about how long
a key registration lives.

What is known comes from community operators, and is worth quoting accurately rather than in the
form it usually gets repeated:

- **Idle expiry.** [`thrnz/docker-wireguard-pia`](https://github.com/thrnz/docker-wireguard-pia),
  the most widely used PIA WireGuard container, reports that keys "seem to expire at PIA's end
  after several hours of inactivity" and that setting `PersistentKeepalive` "may be enough to
  prevent this from happening". Note the hedging — this is observed behaviour, not a specification.
- **A second key displacing the first.** This one is usually repeated as a flat rule, and it is
  not. The source scopes it to a three-way coincidence: a second key registered *to the same
  endpoint address* *using the same auth token*, which "in practice is probably only an issue if
  multiple containers share the same auth token, and if they also happen to pick the same vpn
  endpoint". Two tunnels in different regions do not meet that condition.

So a gateway reboot, a firmware update, or a WAN outage that outlasts the keepalive leaves the
console showing **Not Established** until someone generates a new configuration and pastes it in.
The account token itself lasts about a day, which is why the generator has to sign in again
rather than reuse one.

### Try a keepalive before you automate anything

Since the documented cause is *inactivity*, the cheapest fix is to stop the tunnel going idle.
If your VPN Client was created by uploading a `.conf`, check that it carries
`PersistentKeepalive = 25` under `[Peer]`. That costs nothing, needs no script, and every refresh
it avoids is a refresh that cannot go wrong.

It may not be available: the `networkconf` row a console returns has no keepalive field of its
own, so on a tunnel configured by hand in the UI there may be nothing to set. `--diagnose` lists
the fields your console actually returns, which will tell you either way.

## This API is not supported by Ubiquiti, and there is no alternative

Worth stating plainly before anything else. The script drives
`/proxy/network/api/s/<site>/rest/networkconf` — the console's **private** API, the one its own
web UI calls. Ubiquiti publishes no schema for it, does not version it, and promises nothing
about it. The maintainers of the longest-running client for it
([`Art-of-WiFi/UniFi-API-client`](https://github.com/Art-of-WiFi/UniFi-API-client)) put a
disclaimer at the top of their README saying exactly that.

This is not a shortcut around a supported path. There isn't one:

- **The official UniFi Network Integration API** (`/proxy/network/integration/v1`) cannot do it.
  From Network 10.0 it gained real CRUD for networks, firewall policies, DNS and ACLs — but its
  "network" object is a VLAN: name, `vlanId`, subnet, DHCP. No `purpose`, no `vpn_type`, no
  WireGuard field. Its only VPN surface is read-only, and lists VPN *servers*, not clients. On
  Network 9.x it cannot touch network configuration at all.
- **The Site Manager API** (`api.ui.com`) is read-only — inventory, sites, ISP metrics.
- **There is no official CLI, config file, Ansible collection or Terraform provider.**
- Every community tool that *can* configure WireGuard on a UniFi gateway — the Terraform
  providers, the PHP clients — uses this same private endpoint. The providers built on the
  official API are structurally incapable of it.

**What this means in practice.** The path itself has been stable for years. What breaks is
payload validation: a firmware update changes a field's name or type, and writes start failing
with `400 api.err.*`. That is a loud failure, not a silent one, and this tool is built to stop
rather than guess — it refuses to write a row missing the fields it knows, and prints what it
found instead. If a Network update ever breaks it, expect a clear refusal and an unchanged
gateway, not a mangled tunnel.

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

It also refuses when the console returns a **masked** secret — a run of asterisks where a stored
key belongs. Some builds do that so reading a row does not disclose it, which is good practice and
a trap for anything that reads a row and writes it back: send the mask and the console stores the
mask. For a preshared key that means the tunnel stops handshaking and nothing in the reply says
so. The same bug was reported against a Terraform provider as
[`ubiquiti-community/terraform-provider-unifi#490`](https://github.com/ubiquiti-community/terraform-provider-unifi/issues/490).
The private key is exempt, because a refresh replaces it outright.

## Setting it up

1. **Create the VPN Clients once in the console** (Settings → VPN → VPN Client → WireGuard), by
   uploading a configuration from the app. Give each a name you will refer to.

2. **Choose how the script signs in.** Either:
   - an **API key** — Settings → Control Plane → Integrations on UniFi Network 9 and later, set as
     `UNIFI_API_KEY`; or
   - a **dedicated local admin without multi-factor authentication**, set as `UNIFI_USERNAME` and
     `UNIFI_PASSWORD`. A UniFi account with MFA cannot be used unattended.

   The API key is preferred: it can be revoked on its own, and a leak does not expose a password.
   Whether a key is accepted on the `networkconf` route depends on the Network version. `--dry-run`
   does **not** answer that — it registers keys with PIA and then stops, without ever issuing the
   write (`syncTunnels` skips `updateNetwork` entirely when `dryRun` is set). Use
   `--diagnose --probe-write`, which writes one row back unchanged and reports whether the console
   accepted it.

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

### From Windows, by double-click

With no always-on host, a timer is beside the point — you want to fix the tunnels when you notice
they are down. `scripts\pia-unifi-sync.cmd` does that:

1. Put `pia-unifi-sync.json` and `pia-unifi-sync.env` in the repository root (copy them from
   `examples\`). Both are already in `.gitignore`.
2. Double-click `scripts\pia-unifi-sync.cmd`. With no arguments it performs a **dry run** — it
   registers fresh keys with PIA and prints what it would change, without writing to the console.
3. When the output looks right, run it again with `--apply`.

Credentials travel in the environment, never on the command line, so they do not appear in the
window title, the scroll buffer, or another user's process list. The launcher refuses to start
with a clear message if Node is missing or either file is absent.

### Finding out what your console actually does

`--diagnose` reports the three facts that decide whether this can work, and how:

```
node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json --diagnose
```

It reads the console's certificate — whether it is self-signed, whether it is a CA or a leaf, and
what names it carries — then performs the same read the sync performs and reports what came back
that a curl-based client would not be able to see: response header names, whether a session cookie
was set, and whether a CSRF token was picked up. Header *names* only; no value is ever printed.

It then describes each VPN Client the configuration names, **field by field** — which is the only
way to learn what your particular console puts in a row, since no schema is published. Field names
are always listed; values only for the few short flags that decide how a row must be written
(`wireguard_client_mode`, whether a preshared key is enabled, DNS pulling, default route). Every
secret is reported as `present`, `absent` or `looks redacted`, never shown.

Add `--probe-write` to also write each configured row back **unchanged**. That is the only honest
way to learn whether your credential authorises a write without changing anything: the body is
byte-identical to what the console just sent, so the gateway re-provisions the tunnel briefly but
its configuration does not change.

Unless a secret came back masked — then "byte-identical" would be a lie, and writing the row back
would store the mask over the real key. The probe checks first and refuses, reporting why. That
refusal is itself the finding: it means no tool can safely round-trip that row.

## How the pieces fit

```
scripts/pia-unifi-sync.mjs      argument parsing, credentials, exit codes
scripts/unifi-sync/sync.mjs     reads credentials from the environment; re-exports the rest
resources/js/core/unifi-sync.js config validation, row patching, the per-tunnel loop
scripts/unifi-sync/unifi.mjs    the console client: sign-in, CSRF, networkconf GET/PUT, certificate pinning
scripts/unifi-sync/exec.mjs     runs `curl -q --config -` through execFile — no shell at all
scripts/unifi-sync/crypto.mjs   X25519 from node:crypto, the reference the test suite already trusts
```

The sync itself lives in the application's tree rather than beside the script,
because none of it is specific to a command line: it takes a parsed
configuration and two injected clients and returns a report. It is built from
three steps the desktop app can use separately — `inspectTunnels` matches each
configured tunnel to its row and costs nothing, `prepareTunnel` registers one
key with PIA, and `applyTunnel` writes one row back. `syncTunnels` is those
three composed, and it registers and writes one tunnel at a time rather than
batching every registration ahead of every write: a key PIA has issued does
nothing until the gateway is using it, so the gap between the two is kept
small. `test/unifi-sync.test.js` asserts that ordering.

The PIA side is the app's own `HttpClient` and `PiaClient`, so PIA requests are pinned to the
bundled CA and `addKey` replies are validated before anything is written, exactly as in the app.
The UniFi side uses `node:https` directly, because it may need to read response headers — a
console that sets a session cookie on an API-key request has to be followed, and the curl config
path cannot see a header at all. Whether any console actually does that is the open question
`--diagnose` exists to answer.

`test/unifi-sync.test.js` runs the whole flow against a fake console over TLS, including the
pinning cases: the pinned self-signed certificate is accepted whatever it is called, a different
self-signed certificate is refused before a byte is sent, and a leaf from a private CA is accepted
only when its issuer is in the file.

## External Connections
- [[WireGuard_Generation]]
- [[Authentication_Flow]]
- [[Security_Model]]
