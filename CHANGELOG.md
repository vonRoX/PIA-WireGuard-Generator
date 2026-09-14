# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scripts/pia-unifi-sync.mjs`, a headless companion for UniFi gateways. It signs in to PIA,
  registers a fresh key pair with a server in each configured region, and rewrites the matching
  WireGuard **VPN Client** rows on the console through its local API, so a timer can keep the
  tunnels registered instead of a person pasting configurations. Credentials come from the
  environment or `*_FILE` secrets; the console's self-signed certificate is pinned from an exported
  file rather than verification being switched off. Documented in
  `docs/wiki/features/UniFi_Automation.md`, with systemd units under `examples/`.
- `scripts/pia-unifi-sync.cmd`, a double-clickable launcher for Windows. With no always-on host to
  run a timer on, this is the one-click form of the same chore: dry run by default, `--apply` to
  write. Credentials are read from `pia-unifi-sync.env` into the environment and never appear on a
  command line.
- `--diagnose` on the sync script, reporting what the console's certificate carries and what its
  responses contain that a curl-based client could not see — response header names, whether a
  session cookie was set, whether a CSRF token was derived. Header names only; never a value.
  `--probe-write` additionally writes one row back byte-identical, which is the only way to learn
  whether a credential authorises a write without changing anything.
- `scripts/pia-unifi-sync.ps1`, a Windows launcher that keeps the credentials encrypted with DPAPI
  in `%LOCALAPPDATA%` instead of a plaintext `pia-unifi-sync.env` in the repository.
  `-SetCredentials` prompts for them without echoing, `-ForgetCredentials` deletes them, and every
  other argument behaves as it does for the `.cmd`. Values are placed in the environment for the
  run and removed afterwards; none appears on a command line.
- `docs/HANDOVER.md`, a one-page brief for a session started on the machine that can actually
  reach the console: what is settled, the single run that answers what is not, how to read its
  verdict, and the constraints that hold whatever it says.

### Changed

- **The sync refreshes file-mode VPN Clients** — the kind UniFi creates when a `.conf` is uploaded,
  and the kind both tunnels on the first real console turned out to be. Such a row has no key or
  peer fields; its whole tunnel lives in `wireguard_client_configuration_file`. A refresh now
  replaces that file and `ip_subnet` together (the address must move with the key, or the handshake
  succeeds and PIA drops the traffic), adds no manual-mode fields, and keeps the resolver the
  existing file names unless the configuration sets `dns`. A file that is not the single-peer shape
  a refresh writes — a second peer, a preshared key, an unknown section, a masked key — is refused.
  Verified on a UCG Ultra: both tunnels went from `CONNECTING` to `CONNECTED`.
- **Every check that depends only on the row runs before a PIA key is registered.** Previously a row
  the sync would refuse was refused after `addKey`, spending a registration on nothing.
- After a write, the console's echo is compared with what was sent, and a difference in the fields
  that make the tunnel work is reported as a failure rather than a success.
- `--only <name>` refreshes a single tunnel, and after writing the CLI watches
  `v2/api/site/<site>/vpn/connections` until each tunnel reports connected (`--no-wait` to skip).
  `scripts/pia-unifi-sync.ps1` treats a refresh narrowed with `--only` as a dry run unless `--apply`
  is also given.
- **`--probe-write` now tells a cookie the console sets from one a write needs.** It used to write
  from the client that had just performed the read, which replays any cookie and CSRF token it was
  handed — so an accepted write said nothing about a client that cannot see response headers, and
  a cookie that was merely set was reported as blocking the desktop app. The first write now comes
  from a client that has sent nothing; the session is tried only if that is refused on
  authorisation and the read actually left one. Each tunnel is still written once when the bare
  write succeeds.
- **`--probe-write` resolves rows by type as well as name**, so a configuration naming the LAN by
  mistake reports that instead of writing the LAN back to the gateway. It also refuses a row that
  lacks the fields the sync needs, a private key that is not shaped like a WireGuard key, and any
  `x_` field that came back masked or blank — not only a run of asterisks.
- The sync refuses a row whose preshared key is in use but is not a real key. A console that hides
  the value by blanking it, or with a placeholder like `xxxx`, previously passed the check and would
  have had the blank written over the real key.
- `--diagnose` now describes each configured VPN Client **field by field** — names always, values
  only for the few short flags that decide how a row must be written, and every secret as
  `present`, `absent` or `looks redacted`. Ubiquiti publishes no schema for `networkconf`, so
  looking at a real row is the only way to know what a given console returns.
- **The sync refuses to write a row carrying a masked secret, and so does `--probe-write`.** Some
  Network builds return a run of asterisks where a stored key belongs, so that reading a row does
  not disclose it. Anything that reads a row and writes it back then stores the mask over the real
  key; for a preshared key the tunnel stops handshaking and the reply says the write succeeded.
  (Reported against another tool as `ubiquiti-community/terraform-provider-unifi#490`.) A row that
  declares a preshared key but carries none is refused for the same reason. The private key is
  exempt — a refresh replaces it outright.
- The UniFi sync moved from `scripts/unifi-sync/sync.mjs` to `resources/js/core/unifi-sync.js`, so
  the desktop app can use the same code rather than growing a second copy of it. Only
  `readCredentials`, which speaks in environment variables, stayed with the script; everything else
  is re-exported, so nothing that imported it has to change. The loop is now built from three steps
  the app can call separately — `inspectTunnels` (matches configured tunnels to console rows and
  costs nothing), `prepareTunnel` (registers one key with PIA), `applyTunnel` (writes one row) —
  and `syncTunnels` accepts an account token it is given instead of always signing in again.
  Registration and write still interleave one tunnel at a time, and the test suite now asserts that
  order rather than merely not noticing it.
- The curl layer can write: `PUT` is emitted as its own fixed line, an unrecognised method is
  refused rather than silently becoming a `GET`, and a `PUT` sends no `Expect: 100-continue` for a
  middlebox to stall on. `noproxy` is available for a console on the LAN, but only when the URL's
  host is genuinely in a private range — a console reached through a corporate proxy keeps using
  it, and a mistyped address cannot carry an API key past the proxy that would have refused it.
- `HttpClient.send()` is now built on `sendExpectingAnyStatus()`, which returns a non-2xx response
  instead of throwing. A UniFi console explains its refusals in the body of a 401, and `send()`
  discarded exactly that. Callers must inspect `status` first, and a guard test keeps the list of
  them short.

### Fixed

- `--diagnose` no longer reports a self-signed **leaf** certificate as something that blocks the
  desktop app. It was written before the question was settled; the `windows-latest` CI leg has
  since proven that genuine Schannel accepts a `CA:FALSE` leaf as its own trust anchor when it is
  the whole `cacert` store. A factory console presents exactly that, so the report would have
  raised a false blocker on the one machine the report exists to run on.

- `docs/wiki/features/UniFi_Automation.md` stated as fact that "registering a second key against
  the same server with the same account token can invalidate the first". The source scopes that
  far more narrowly — same endpoint **and** same token **and** concurrent registration, hedged as
  "probably only an issue if" — and PIA documents nothing about key lifetime at all. The page now
  quotes what the source actually says, names it, and says plainly that PIA is silent. It also now
  states outright that the `networkconf` endpoint is unsupported by Ubiquiti and that no supported
  alternative exists, and suggests trying `PersistentKeepalive` before automating anything.
- `docs/wiki/features/UniFi_Automation.md` claimed `--dry-run` would show immediately whether an
  API key is accepted on the `networkconf` route. It cannot: a dry run never issues the write.
  The page now points at `--diagnose --probe-write`, which does.

## [2.0.0] - 2026-08-20

A security and correctness release. Everything below came out of a review of v1.1.0.

### Security

- **Fixed a command-injection vulnerability in sign-in.** The login payload was interpolated into a
  string executed by the platform shell, escaped only by replacing double quotes. A password
  containing `` ` `` or `$( )` executed arbitrary commands. Requests now run as the fixed command
  `curl -q --config -` with the whole request supplied on standard input, so nothing typed into the
  app is ever parsed by a shell — on any platform.
- **Restored TLS certificate verification on key registration.** That request carries the account
  token and returns the server key and endpoint written into the tunnel, and it was made with `-k`,
  which accepts any certificate. It now pins Private Internet Access's own RSA-4096 certificate
  authority and completes the handshake against the server's certificate name. Verification failure
  aborts the request; there is no fallback.
- **Credentials no longer appear in process arguments.** The password and token were passed on the
  curl command line, visible to any local user through `ps` or `/proc`.
- **The preferences store is restricted to your account.** Neutralino writes
  `<app folder>/.storage/*.neustorage` at `0644` inside a `0755` directory; with "Stay signed in"
  enabled one of those files is a bearer token, so every local user could read it. The app now
  restricts that directory the first time it writes.
- **Saved configurations are written owner-only** (`0600`) instead of with default permissions. The
  file contains a private key.
- **The session token is no longer stored unless requested.** "Stay signed in" is off by default;
  when enabled the token is stored with a recorded expiry and revalidated at startup.
- **Removed the Google Fonts request made on every launch**, which disclosed the user's IP address
  and launch time to a third party in a tool whose stated purpose is privacy. The font is vendored.
- On Windows, pinned requests set `--ssl-revoke-best-effort`. Windows curl uses Schannel, which
  fails a certificate authority that publishes no revocation endpoint — which PIA's root does not —
  so without this the app could not verify anything on Windows at all. Revocation data being absent
  is tolerated; a revoked certificate is still rejected and the chain is still pinned.
- Server-list entries are validated at the parse boundary: a common name must be a syntactically
  valid host name and an address a valid IPv4 address before either reaches URL construction.
- Added a `Content-Security-Policy` of `default-src 'none'`, so remote content cannot be loaded even
  by mistake, and `-q` to curl so a hostile `~/.curlrc` cannot inject options.

### Fixed

- Registration responses are validated before a configuration is rendered. A reply missing a field
  used to produce `Endpoint = undefined:undefined` in a file the user was told was ready.
- Network and HTTP failures are reported accurately. A PIA outage said "check your credentials", and
  an HTML error page surfaced as `Unexpected token <`.
- A server list without a `regions` array now reports an error instead of leaving the window on a
  "Loading regions…" placeholder that never resolved.
- The chosen region is remembered by its stable id rather than by its position in a list fetched from
  the network — the old behaviour silently selected a different country whenever PIA's region set
  changed.
- **Generate** is enabled only when a region is genuinely selected, including after a filter hides
  the current selection.
- Signing out clears stored credentials rather than blanking a value, and resets the picker.
- Keys ending in `0`, `4` or `8` are no longer rejected as malformed.
- `npm run build` no longer exits 0 after producing nothing: it runs `neu update` first and verifies
  that real binaries exist afterwards.

### Added

- Region filtering, and pinned regions that stay at the top of the list.
- A configuration preview with the private key masked behind a reveal toggle, and copy to clipboard.
- QR code export for importing on a phone.
- A startup check for curl, with an actionable message.
- 107 offline unit and integration tests, 37 browser tests, and CI across Linux, macOS and Windows.
- A release workflow that builds, verifies, and publishes binaries with checksums.

### Changed

- The application is restructured into testable modules; `resources/js/renderer.js` is gone.
- Licence is now MIT throughout — the file previously carried the Neutralinojs template's copyright
  while `package.json` declared ISC.
- Removed unreferenced template files that were being embedded into every release binary, and a
  `FUNDING.yml` that pointed sponsorships at the Neutralinojs author.

### Migration

Storage moves to schema v2. Any token written by v1 is deleted on first launch and the saved region
index is discarded, so the first start after upgrading asks for a sign-in and a region. Nothing else
is affected, and previously generated `.conf` files keep working.

## [1.1.0] - 2026-04-18

- Replaced the original PowerShell script with a Neutralinojs desktop application.
