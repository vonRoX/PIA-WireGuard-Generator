# Security policy

## Reporting a vulnerability

Please report privately through
[GitHub Security Advisories](https://github.com/vonRoX/PIA-WireGuard-Generator/security/advisories/new)
rather than opening a public issue.

Useful things to include: what an attacker can do, how to reproduce it, and the version you tested.
A proof of concept helps but is not required.

This is a small project maintained in spare time. Expect an initial response within a week, and
please give a fix a reasonable window before disclosing.

**Never include a real password, session token, or unredacted `.conf` file in a report.** Redact
everything after `PrivateKey =`.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.x     | Yes       |
| 1.x     | No — upgrade; 1.x contains a command-injection vulnerability and disables TLS verification on one request |

## What this app does with your data

- **Password** — sent once, over TLS, to `privateinternetaccess.com` in exchange for a session token.
  It is never written to disk, never placed on a command line, and is cleared from the window after
  sign-in.
- **Session token** — kept in memory. Written to local storage only if you tick "Stay signed in",
  which is off by default, and then with a recorded expiry. Signing out deletes it. That storage is
  a `.storage` folder beside the executable; the app restricts it to your account (`0700`) the first
  time it writes, because the framework's default would leave it readable by every local user.
- **Private key** — generated on your machine and never transmitted. Only the corresponding public
  key is sent to PIA, which is what makes the tunnel work. Saved configurations are written with
  owner-only permissions.
- **Everything else** — nothing. No analytics, no crash reporting, no update checks. The only hosts
  the app contacts are `privateinternetaccess.com` and `serverlist.piaservers.net`; a test fails the
  build if any other URL appears in the source, and the window's Content-Security-Policy blocks
  remote content at runtime.

## Threat model, briefly

The app defends against a network attacker who can intercept its traffic (certificates are verified
against PIA's own CA, and failure aborts the operation), against another local user reading
credentials from process arguments or from the saved configuration file, and against hostile input
in your own password reaching a shell.

It does not defend against malware already running as your user, a compromised PIA account, or a
compromised Private Internet Access. It also cannot protect a `.conf` file after you have copied it
somewhere else — treat that file as the credential it is.
