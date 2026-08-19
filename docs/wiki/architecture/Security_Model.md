---
title: Security Model
aliases: [Security, Threat Model]
tags: [architecture, security]
created: "2026-08-19"
updated: "2026-08-19"
sources: []
status: active
confidence: high
---
# Security Model

This application holds a VPN account credential and writes a private key to disk. Two properties
carry most of the weight, and both have tests that fail if they are weakened.

## 1. The shell never receives user data

Requests are made with `curl` because the webview cannot call the Private Internet Access API
directly — the endpoints send no CORS headers. `Neutralino.os.execCommand` runs its argument through
the platform shell (`/bin/sh -c`, or `cmd.exe /c` on Windows), so any value interpolated into that
string is code.

Version 1 interpolated the login payload after escaping only double quotes, which made a password
containing `` ` `` or `$( )` execute. No portable quoting scheme fixes this: POSIX shells and
`cmd.exe` disagree about nearly everything, and `cmd.exe` expands `%VAR%` inside double quotes.

So the shell is given nothing to parse. The command is always the constant string

```
curl -q --config -
```

and the entire request — URL, headers, body, token — is written to curl's standard input as a
[configuration file](https://curl.se/docs/manpage.html#-K). Escaping reduces to curl's own small
grammar: `\\`, `\"`, `\t`, `\n`, `\r`, `\v`, with any other control character rejected outright.

`-q` must remain the first argument. It stops curl reading `~/.curlrc` (or `%APPDATA%\_curlrc`),
which could otherwise inject `--insecure` or a proxy without the app's knowledge.

Enforced by `test/curl.test.js`, which also reproduces the v1 escaping and asserts that it *does*
execute an injected command — a guard that cannot detect the original bug is not a guard.

## 2. Certificates are verified, and failure is fatal

The key-registration endpoint (`https://<cn>:1337/addKey`) presents a certificate signed by PIA's own
RSA-4096 authority, not a public one. Version 1 handled that with `-k`, which accepts any
certificate — on the single request that both carries the account token and returns the server key
and endpoint written into the tunnel configuration. An attacker on the same network could take the
token and return an endpoint that `AllowedIPs = 0.0.0.0/0` then routes all traffic to.

The CA is now bundled (`resources/js/core/pia-ca.js`, with its SHA-256 fingerprint recorded and
asserted) and pinned:

```
--cacert <the PIA CA>
--connect-to "<cn>::<ip>:"
```

which connects to the server's address while validating the certificate against its common name —
the approach PIA's own `manual-connections` scripts use. Because `--embed-resources` packs resources
into the binary and `--cacert` needs a real path, the certificate is written to a randomly named
temporary file at startup and removed on exit. The name is randomised so another local user cannot
pre-place a file at a predictable path and substitute their own authority.

A server entry without a common name is refused rather than contacted unverified. The common name
and address are also validated as a host name and an IPv4 address at the point the server list is
parsed, before either can be interpolated into the request URL or into curl's colon-separated
`--connect-to` field — pinning already makes a tampered value fail the handshake, but the check
belongs at the boundary rather than relying on that.

### One platform caveat

Windows curl uses Schannel, which performs revocation checking and treats "cannot determine" as
failure. PIA's root publishes neither a CRL nor an OCSP responder — normal for a private CA — so
every pinned request on Windows would otherwise fail with `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`.

The app therefore sets `--ssl-revoke-best-effort` on Windows, and only on the pinned requests. That
option tolerates revocation data being *absent or unreachable*; a certificate that is actually
revoked is still rejected, and the chain is still verified against the pinned authority. It is not
`--ssl-no-revoke`, which would skip the check entirely, and it is not `--insecure`. Because the
option requires curl 7.70, the startup check demands that version on Windows rather than 7.49.

This was caught by the Windows CI job, not by reasoning — which is why that job exists.

Enforced by `test/network.test.js` against a local TLS server with a per-run throwaway CA, including
the negative case, and by `test/guards.test.js`, which fails if `-k` or `--insecure` appears anywhere
in the sources.

## Credentials

| | |
|---|---|
| Password | Sent once over TLS in a request body. Never on a command line, never written to disk, cleared from the window after sign-in. |
| Session token | In memory by default. Written to storage only behind the "Stay signed in" opt-in, with a recorded issue time; treated as expired after 23 hours and revalidated at startup. Deleted on sign-out. |
| Private key | Generated locally, never transmitted. Only the public key is sent. |
| Saved `.conf` | Written with owner-only permissions. If the platform refuses, the user is told rather than reassured. |

Upgrading from v1 deletes the token that version stored unconditionally — a one-time sign-out, and
the right trade for a tool whose purpose is minding credentials.

## Containment

The window ships a `Content-Security-Policy` of `default-src 'none'` with `'self'` for scripts,
styles, fonts and connections, so remote content cannot load even if a reference were added by
mistake. `test/guards.test.js` additionally fails the build if any URL outside PIA's two endpoints
appears in the sources, if a source writes to the console, or if the bundled CA drifts from its
recorded fingerprint.

`neutralino.config.json` enumerates the native methods the app may call rather than granting
`os.*` and `filesystem.*` wholesale.

## Out of scope

Malware already running as the user, a compromised PIA account, a compromised Private Internet
Access, and anything that happens to a `.conf` file after it leaves this app.

## External Connections
- [[Neutralinojs_Integration]]
- [[Authentication_Flow]]
- [[WireGuard_Generation]]
