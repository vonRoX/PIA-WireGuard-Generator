<div align="center">

<img src="resources/icons/appIcon.png" width="96" alt="">

# PIA WireGuard Generator

**Generate standalone WireGuard® configuration files for Private Internet Access — without installing their app.**

[![CI](https://github.com/vonRoX/PIA-WireGuard-Generator/actions/workflows/ci.yml/badge.svg)](https://github.com/vonRoX/PIA-WireGuard-Generator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

</div>

---

PIA hands out OpenVPN profiles, but getting a **WireGuard** config out of them means running their
desktop app. That leaves out routers, a Raspberry Pi, pfSense, OPNsense, a NAS, or anything else that
speaks WireGuard and nothing else.

This tool does what their app does at the protocol level: generate a Curve25519 key pair on your
machine, register the public half with a PIA server, and write out a `.conf` you can import anywhere.
The private key never leaves the computer you ran it on.

<div align="center">

<img src="docs/images/02-choose-region.png" width="700" alt="Choosing a server region">

</div>

## What it does

- **Real WireGuard configs.** Plain `.conf` files that any WireGuard client will import — routers,
  phones, servers, containers.
- **Keys generated locally.** Curve25519 in the app itself. You do not need WireGuard, `wg`, or Go
  installed to produce a configuration.
- **Every PIA region, live.** Fetched from PIA's server list at launch, filtered to regions that
  actually offer WireGuard. Pin the ones you use.
- **DNS you choose.** PIA's in-tunnel resolvers — standard, streaming-optimised, or MACE ad-blocking
  — or any resolver of your own.
- **Import by QR.** Scan straight into the WireGuard app on a phone.
- **Nothing phones home.** No analytics, no update checks, no fonts from a CDN. The only hosts it
  ever contacts are Private Internet Access's own.

<div align="center">

<img src="docs/images/03-configuration-ready.png" width="700" alt="The generated configuration, with the private key masked">

</div>

## Running it

Download **one file** for your platform from [Releases](../../releases) — each is 2–4 MB, there is no
installer, and nothing is written outside the folder you put it in. There is no `.app` bundle, `.msi`
or `.deb`: it is a single executable.

<details open>
<summary><b>Windows</b> — <code>pia-wireguard-generator-win_x64.exe</code></summary>

Double-click it.

Windows SmartScreen will warn that the publisher is unknown, because the binary is not code-signed —
signing certificates cost money this project does not have. Choose **More info → Run anyway**, or
verify the SHA-256 against `SHA256SUMS` on the release first:

```powershell
Get-FileHash .\pia-wireguard-generator-win_x64.exe -Algorithm SHA256
```

Requires the WebView2 runtime, which Windows 11 includes and Windows 10 gets with Microsoft Edge —
in practice it is already there.
</details>

<details>
<summary><b>macOS</b> — <code>pia-wireguard-generator-mac_universal</code> (Intel and Apple Silicon)</summary>

It is a plain binary rather than an app bundle, so it needs the executable bit, and macOS will
quarantine anything downloaded from the internet that is not notarized:

```bash
chmod +x pia-wireguard-generator-mac_universal
xattr -d com.apple.quarantine pia-wireguard-generator-mac_universal
./pia-wireguard-generator-mac_universal
```

Without the `xattr` line you get *"cannot be opened because the developer cannot be verified"*.
Nothing else is needed — macOS provides the webview and curl.
</details>

<details>
<summary><b>Linux</b> — <code>pia-wireguard-generator-linux_x64</code> (also arm64, armhf)</summary>

```bash
chmod +x pia-wireguard-generator-linux_x64
./pia-wireguard-generator-linux_x64
```

Needs a GTK webview, which most desktop installs already have. If the app exits telling you so:

```bash
sudo apt install libwebkit2gtk-4.1-0     # Debian/Ubuntu — or libwebkit2gtk-4.0-37 on older releases
sudo dnf install webkit2gtk4.1           # Fedora
sudo pacman -S webkit2gtk-4.1            # Arch
```
</details>

Then: sign in with your PIA username (it starts with `p`), pick a region and a DNS resolver, hit
**Generate**, and either **Save .conf file** or scan the QR code from the WireGuard app on your
phone. Import the file into your router or client and you are done.

> [!TIP]
> `PersistentKeepalive = 25` is already set, which is what you want behind NAT. If your client
> expects the interface address without a prefix, drop the `/32`.

> [!NOTE]
> Preferences live in a `.storage` folder created next to the executable, so keep it somewhere you
> can write — your home directory or a USB stick is fine, `C:\Program Files` is not. Deleting that
> folder resets the app completely.

> [!IMPORTANT]
> The app uses **curl** for every network request. Windows 10 1803+, macOS, and most Linux
> distributions ship it. If it is missing the app tells you on startup rather than failing later.

## Keeping a UniFi gateway registered automatically

PIA's servers drop a WireGuard registration after some hours without a handshake, and the account
token lasts a day, so a tunnel on a router that reboots or loses its WAN for a while comes back as
**Not Established** until a fresh configuration is pasted in. For UniFi gateways (UCG Ultra, UDM,
UDR) there is a headless companion that does the whole round trip on a timer:

```bash
cp examples/pia-unifi-sync.example.json pia-unifi-sync.json   # name your VPN Clients and regions
export PIA_USERNAME=p1234567 PIA_PASSWORD=… UNIFI_API_KEY=…      # or UNIFI_USERNAME + UNIFI_PASSWORD
node scripts/pia-unifi-sync.mjs --config pia-unifi-sync.json --dry-run
```

It signs in to PIA with the same pinned, validated code path as the app, registers a new key pair
for each tunnel, and rewrites only the key, endpoint and address fields of the matching WireGuard
**VPN Client** in the console — routing and everything else you set up stay as they are. The
console's self-signed certificate is pinned from a file you export, never ignored. Needs Node 20+
and curl on any always-on machine that can reach both the internet and the gateway; systemd units
are in [`examples/systemd/`](examples/systemd/), and the details are in
[`docs/wiki/features/UniFi_Automation.md`](docs/wiki/features/UniFi_Automation.md).

## Security

This tool handles a VPN credential and writes a private key to disk, so it is worth being precise
about what it does.

**Your password never touches a command line.** Requests are made with curl, because the webview
cannot call PIA's API directly — their endpoints send no CORS headers. But the command executed is
always the fixed string `curl -q --config -`, and the entire request travels to it on standard
input as a curl configuration file. Nothing you type is ever parsed by a shell, so a password
containing `` ` ``, `$( )`, `&`, `%VAR%` or a quote is just a password. It is also never visible in
`ps` output, in shell history, or to process-monitoring software.

**Certificates are verified, including PIA's internal ones.** The key-registration endpoint runs on
PIA's own certificate authority rather than a public one. This app bundles that CA and pins to it,
completing the handshake against the server's certificate name — the same approach PIA's published
`manual-connections` scripts use. If verification fails, the request fails: no key is registered and
no configuration is written. Earlier versions of this tool passed `-k` here, which accepted any
certificate at all.

On Windows, where curl verifies through Schannel, pinned requests additionally pass
`--ssl-revoke-best-effort`, because PIA's authority publishes no revocation endpoint for Schannel to
consult. That tolerates revocation data being missing; it does not skip verification, and a revoked
certificate is still rejected.

**Your session token is not stored unless you ask.** "Stay signed in" is off by default. When it is
off the token lives in memory and is gone when you quit. When it is on, it is stored with a recorded
expiry and revalidated on the next launch. Signing out erases it.

**Saved configurations are owner-only.** The `.conf` contains your private key, so it is written with
`0600` permissions. If the platform refuses, the app tells you rather than assuming.

**Nothing is sent anywhere else.** A `Content-Security-Policy` of `default-src 'none'` means the app
window cannot load a remote script, style, font, or image even if one were added by mistake. A test
in the suite fails the build if any non-PIA URL appears in the source.

Found a problem? See [SECURITY.md](SECURITY.md). Please do not open a public issue for it.

## Building from source

```bash
git clone https://github.com/vonRoX/PIA-WireGuard-Generator.git
cd PIA-WireGuard-Generator

npm install
npm run build        # binaries for every platform, in dist/
```

`npm run build` runs `neu update` first — without it the Neutralino client library is missing and
`neu build` writes nothing while still reporting success. The build ends in
`scripts/verify-build.mjs`, which fails loudly if no real binary was produced.

To run it during development:

```bash
npm start            # launches the app
npm test             # unit and integration tests
npm run test:e2e     # browser tests (needs: npx playwright install chromium)
npm run lint
```

The test suite runs entirely offline. Command-injection payloads are pushed through a real shell and
a real curl; certificate pinning is checked against a local TLS server with a throwaway CA, including
that a certificate from the wrong authority is rejected.

## How it works

```
 you ──▶ sign in ──▶ POST /api/client/v2/token          ▶ session token
             │
             ├─▶ GET serverlist.piaservers.net/…/v6     ▶ regions with WireGuard
             │
             └─▶ generate X25519 keypair (locally)
                        │
                        └─▶ GET https://<cn>:1337/addKey   ▶ peer IP, server key, endpoint
                              --cacert <PIA CA>             │
                              --connect-to <cn>:1337:<ip>:1337
                                                            └─▶ .conf written to disk
```

The application is Neutralinojs, so a release binary is a few megabytes rather than a bundled
browser. More detail lives in [`docs/wiki/`](docs/wiki/), including the
[security model](docs/wiki/architecture/Security_Model.md).

## Disclaimers

- **Not affiliated with Private Internet Access.** This is a community tool. It is not endorsed by,
  associated with, or supported by PIA.
- **WireGuard** is a registered trademark of Jason A. Donenfeld.
- Your credentials go to `privateinternetaccess.com` and nowhere else. That is a design property with
  tests behind it, not just a promise — but you are welcome to read the source and check.

## Licence

[MIT](LICENSE). Bundled third-party components keep their own licences — see the end of that file.
