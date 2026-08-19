# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-19

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
- **Saved configurations are written owner-only** (`0600`) instead of with default permissions. The
  file contains a private key.
- **The session token is no longer stored unless requested.** "Stay signed in" is off by default;
  when enabled the token is stored with a recorded expiry and revalidated at startup.
- **Removed the Google Fonts request made on every launch**, which disclosed the user's IP address
  and launch time to a third party in a tool whose stated purpose is privacy. The font is vendored.
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
