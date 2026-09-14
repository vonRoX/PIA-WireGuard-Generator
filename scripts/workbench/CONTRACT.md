# Workbench contract

The Workbench is a local web UI for setting up and exercising the UniFi refresh: onboarding (console
address → certificate fingerprint → UniFi API key → PIA credentials), a read-only API explorer, and a
tunnels page. It is three separately built pieces that meet at this contract. Change it only by
agreement; everything below is binding for the first milestone.

```
scripts/workbench/server.mjs        HTTP server + security          (server agent)
scripts/workbench/public/           browser UI: index.html, app.js, styles.css   (UI agent)
scripts/workbench/fake-engine.mjs   in-memory engine for UI work and server tests (UI agent)
scripts/engine/                     the real engine: secrets, trust, redaction, console calls (engine agent)
```

## Facts the engine must respect (measured on a real UCG Ultra, UniFi Network 10.x)

- The UniFi API key is a **local** key created on the console (Settings → Control Plane →
  Integrations). A Site Manager key from unifi.ui.com returns `401 {"error":{"code":401,"message":"Unauthorized"}}`
  on every local path — indistinguishable from no key. Say so in the error hint.
- Header `X-API-KEY`. No cookie or CSRF token is set on an authenticated request, and none is needed
  for a write. Do not implement cookie handling.
- Base paths: private `/proxy/network/api/s/{site}/...`, v2 `/proxy/network/v2/api/site/{site}/...`,
  official `/proxy/network/integration/v1/...` (`GET /v1/info` → `{applicationVersion}` is the cheapest
  key check).
- The console certificate is a self-signed `CA:FALSE` leaf whose names do **not** include the LAN IP.
  Trust is by SHA-256 fingerprint of that exact certificate (see `trustFromPem` / `checkServerIdentity`
  in `scripts/unifi-sync/unifi.mjs`). Never `rejectUnauthorized: false` on a request that carries a
  credential; reading the certificate before trust is the only unverified connection allowed, and it
  sends nothing.
- VPN Client rows: `GET /proxy/network/api/s/{site}/rest/networkconf`, `purpose: "vpn-client"`,
  `vpn_type: "wireguard-client"`, `wireguard_client_mode: "file" | "manual"`. File-mode rows carry the
  whole `.conf` — **with a real PrivateKey** — in `wireguard_client_configuration_file`.
- Tunnel status: `GET /proxy/network/v2/api/site/{site}/vpn/connections` →
  `{connections:[{network_id, status, type, notes?:string[]}]}`; `network_id` is the row `_id`;
  observed statuses include `CONNECTING` with note `CONNECTING_LONGER_THAN_USUAL`.

## Storage

Everything under `%LOCALAPPDATA%\pia-unifi-sync\` (the folder `scripts/pia-unifi-sync.ps1` already
creates and ACLs to the current user).

- `credentials.xml` — **existing format, must stay compatible with `scripts/pia-unifi-sync.ps1`**:
  `Export-Clixml` of `[pscustomobject]@{ Version = 1; PiaUsername; PiaPassword; UnifiApiKey }`, each a
  DPAPI `SecureString`. A missing value is stored as an empty-string SecureString is NOT allowed by the
  launcher's reader — store only when all three are known, or extend the format with `Version = 2`
  whose reader tolerates absent properties and keep `pia-unifi-sync.ps1` reading both.
- `console.json` — non-secret: `{ "url", "site", "fingerprint256", "pem", "connectName" }`.

Secrets travel between Node and PowerShell **on stdin only**, never argv or environment of a long-lived
process, and are never logged, never returned to the browser, never written to disk outside DPAPI.

## Engine interface (JavaScript)

`createEngine(options)` returns an object with these async methods. Errors are `AppError`
(`resources/js/core/errors.js`) with a `code` string and optional `hint`.

```js
getState()                       // → State
inspectConsole(url)              // → { url, certificate: Certificate }   (no trust stored)
trustConsole(url, fingerprint256)// → State; re-reads the cert and refuses if the fingerprint changed
setUnifiKey(apiKey)              // → { verified: true, applicationVersion } ; stores only if verified
setPiaCredentials(user, pass)    // → State (stores; verification is not required in this milestone)
forgetCredentials()              // → State
explore(path)                    // → { status, body }   GET only, redacted
listTunnels()                    // → { tunnels: Tunnel[] }
```

```ts
State = {
  console: null | { url, site, fingerprint256, connectName, trusted: boolean },
  unifiKey: { stored: boolean },
  pia: { stored: boolean },
}
Certificate = { subject, issuer, selfSigned, ca, names: string[], fingerprint256, validFrom, validTo, connectName }
// connectName: the first DNS name in the certificate (e.g. "unifi.local"), used to connect to the IP
Tunnel = { id, name, mode: "file"|"manual"|"unknown", enabled, status: string|null, notes: string[] }
```

Error codes the UI must handle: `INVALID_INPUT`, `NETWORK`, `TLS`, `CERT_CHANGED`,
`UNIFI_KEY_REJECTED` (hint names the Site Manager mistake), `NOT_CONFIGURED`, `HTTP`.

`explore(path)` accepts only paths starting with `/proxy/network/` and no `..`, `//`, scheme or host.
Redaction (engine, before anything leaves Node): any object key matching
`/key|secret|password|passphrase|token|psk|x_/i` → `"<redacted>"`; inside every string, a line
`PrivateKey = …` or `PresharedKey = …` → `PrivateKey = <redacted>`.

## HTTP API (server ↔ UI)

JSON in and out. Errors: `{ "error": { "code", "message", "hint"? } }` with a 4xx/5xx status.

| Method | Path | Body | Engine call |
| --- | --- | --- | --- |
| GET | `/api/state` | | `getState()` |
| POST | `/api/console/inspect` | `{url}` | `inspectConsole` |
| POST | `/api/console/trust` | `{url, fingerprint256}` | `trustConsole` |
| POST | `/api/unifi-key` | `{apiKey}` | `setUnifiKey` |
| POST | `/api/pia` | `{username, password}` | `setPiaCredentials` |
| DELETE | `/api/credentials` | | `forgetCredentials` |
| GET | `/api/explore?path=…` | | `explore` |
| GET | `/api/tunnels` | | `listTunnels` |

## Server security (binding)

- Listen on `127.0.0.1` only, random free port. Print one URL `http://127.0.0.1:<port>/?token=<32 random bytes, base64url>`.
- The token is exchanged once for an `HttpOnly; SameSite=Strict; Path=/` session cookie, then the
  server redirects to `/` without the query. Every other request needs that cookie.
- Reject any request whose `Host` is not exactly `127.0.0.1:<port>` (DNS rebinding) and any `/api/*`
  request with an `Origin` other than `http://127.0.0.1:<port>`.
- Every `/api/*` request must carry `X-Workbench: 1` (a CSRF-proof custom header).
- Response headers: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- Request bodies capped at 64 KB. Static files served only from `public/`, no directory listing, no
  path traversal.
- Never log request bodies. Log method, path (without query), status.
- `node scripts/workbench/server.mjs [--fake] [--port N] [--no-open]`; `--fake` uses
  `fake-engine.mjs`. `npm run workbench` runs it.
