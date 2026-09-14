# Handover: finishing the UniFi refresh button

This file exists so a Claude Code session started **on the Windows PC that can reach the UniFi
console** can pick the work up without a wall of pasted context. Read it, then do the run in
[One run settles it](#one-run-settles-it).

## What we are building, and why it is stuck

PIA's WireGuard servers forget a registered key after some hours without a handshake. A UCG Ultra
that reboots or loses its WAN comes back with both tunnels **Not Established**, and the fix today
is manual: generate a configuration in the desktop app, paste it into the UniFi console, twice,
every few days.

The goal is to make that **one button in the desktop app**. The settled shape: Windows, a UniFi
**local API key** (no username/password), all tunnels refreshed in one action, settings in an
in-app panel, preview → apply, plain TLS attempted first and the certificate asked for only if
that fails.

The command-line half already works end to end and is merged. What is not settled is whether the
**desktop app** can do the same thing, because the app is a Neutralino webview that reaches the
network only through `curl -q --config -`, and `resources/js/core/http.js` reduces every response
to a **body and a status code**. Response headers are invisible to it.

That is fine *only* if the console never requires a header the app cannot see. `UnifiClient`
(`scripts/unifi-sync/unifi.mjs`) harvests `set-cookie` and a CSRF token from every response and
replays them on the next write. The CLI can do that; a curl-based client cannot. Nobody has ever
checked whether a real console actually sets that cookie on an API-key request — the machine that
wrote this code could not reach one, so the only evidence was a fake console it also wrote.

**That is the whole remaining blocker.** Everything else is answered.

## One run settles it

### Set up two files (once)

Both are already in `.gitignore`. **Never commit them, never print their contents, never paste
them into a chat.**

`pia-unifi-sync.json` — copy from `examples\pia-unifi-sync.example.json`:

- `unifi.url` — the console address, e.g. `https://192.168.1.1`
- **Delete the `certificate` line for now.** Plain TLS is tried first by design; add a pinned PEM
  only if that fails.
- `dns` — optional, defaults to PIA's own resolver
- `tunnels[].network` — each VPN Client's name **exactly as the console shows it**
- `tunnels[].region` — a PIA region id; `--list-regions` prints them (no credentials needed)

`pia-unifi-sync.env` — copy from `examples\pia-unifi-sync.env.example`:

- `PIA_USERNAME`, `PIA_PASSWORD`
- `UNIFI_API_KEY` — UniFi console → Settings → Control Plane → Integrations
- **Delete the `UNIFI_USERNAME` / `UNIFI_PASSWORD` lines.** An API key is the chosen path.

Note: `--diagnose` and `--list-networks` require the PIA variables to be set even though they
never use them (`scripts/pia-unifi-sync.mjs` reads credentials before branching). Set them; they
are needed for the real run anyway.

### Then run

```
node scripts\pia-unifi-sync.mjs --config pia-unifi-sync.json --list-networks
node scripts\pia-unifi-sync.mjs --config pia-unifi-sync.json --diagnose --probe-write
```

`--list-networks` confirms the names match. `--diagnose --probe-write` answers everything else: it
reads the certificate, performs the same GET the sync performs, describes each configured row
field by field, and writes each row back **byte-identical** to learn whether the credential
authorises a write at all. It refuses that write if a secret came back masked, because then
"byte-identical" would mean storing the mask over the real key.

No secret is ever printed — header *names* only, and each secret field reported as
`present` / `absent` / `looks redacted`.

### Read the verdict

The report ends with **"What this means for the desktop app"**. The lines that decide it:

| Line | What it means |
| --- | --- |
| `set-cookie present   no` | the app can talk to this console through curl |
| `set-cookie present   yes` | **stop** — an API-key-only curl client structurally cannot carry it |
| Write probe `accepted` | the API key authorises a write, so Apply will not fail after PIA keys are spent |
| Write probe `REFUSED` | read the message; a masked secret and an unauthorised write are different findings |
| `CA:TRUE no` | expected. A factory console presents a self-signed leaf and it pins fine — see below |

**Decision rule.** No cookie **and** every write probe accepted ⇒ the app port is buildable as
specified; start Phase 2 below. A cookie ⇒ stop, say so plainly, and lay out the honest options
rather than building around it.

### One more thing, before the first *real* write

Put a **non-ASCII character** (an em dash, an accented letter) in one VPN Client's description in
the console first. The whole row is echoed back on a write, and the app would send that body
through `cmd.exe` stdin — a path no test covers. A mangled character would be written into the
gateway permanently.

## What is already done

- The CLI refreshes tunnels end to end, from a timer or `scripts\pia-unifi-sync.cmd`.
- The sync brain is shared with the app at `resources/js/core/unifi-sync.js` — the app will not
  get a second copy to drift from. It is built from three separable steps: `inspectTunnels`,
  `prepareTunnel`, `applyTunnel`.
- `curl` can PUT, skips a proxy for private-range hosts only, and is covered by a real curl
  process against a real TLS server (`test/unifi-write.test.js`).
- **The Schannel question is answered: yes.** Windows CI (`test/unifi-pinning.test.js` on the
  `windows-latest` leg, backend verified as `schannel`, not Git's OpenSSL) proves a self-signed
  `CA:FALSE` leaf **is** accepted as its own trust anchor when it is the whole `cacert` store. A
  leaf certificate is not a problem.
- The sync refuses to write a row that would erase a secret the console masked on read.

## If it is buildable: Phase 2 in brief

- `resources/js/core/unifi.js` — `unwrapUnifiEnvelope()` (a 200 can carry `meta.rc: 'error'`),
  `assertNetworkId`, and `class UnifiConsole` on `HttpClient`. Key tunnels on the row `_id`, not
  `name`, so a rename in the console does not silently break the saved config.
- The preview is a **PUT of the row back byte-identical**, not a read-only check — a read-only
  preview proves nothing about whether the write is authorised or the schema accepted.
- Certificate handling: paste the PEM into a textarea and write it to a randomised temp file
  through `restrictPermissions`, exactly as `CaCertFile` does
  (`resources/js/platform/neutralino.js`). Note `materialise()` short-circuits on `this.path`, so
  key the cache on the PEM or `cleanUp()` first, or editing the pasted PEM keeps pinning the old
  one. **No `nativeAllowList` change** — a file picker would mean letting the webview read any
  file for a few KB of PEM. Ladder: system store → pin → pin + `connect-to`, advancing **only** on
  `ErrorCode.TLS`, with a short connect timeout so a mistyped address is not six spinners.
- Storage: `unifiConsole` and `unifiApiKey` as separate keys, deliberately **not** in
  `CREDENTIAL_KEYS` — signing out of PIA should not unconfigure the console. Storage is plaintext;
  say so in the UI, and say that a UniFi local API key is a site-admin credential covering
  firewall rules and port forwards, not a read-only token.
- UI: `#view-unifi` and `#view-refresh`. `switchTo()` already hides the step rail for views outside
  `['login','config','success']`, so they slot in without disturbing it.

## Standing constraints — these are not negotiable

- **`test/guards.test.js` is binding.** It exists because v1 of this project shipped a shell
  injection RCE. It enforces, over `resources/js`: no `--insecure` / `-k` / `ssl-no-revoke`;
  `Neutralino.os.execCommand` in exactly one file; no interpolated or concatenated exec command;
  `CURL_COMMAND` byte-identical; no `console.*` anywhere; every absolute URL literal a PIA origin.
  If a guard fails, the code is wrong — do not weaken the guard.
- **Never disable TLS verification** to get past a certificate problem, in code or on a command
  line, not even temporarily.
- **Never commit or echo** `pia-unifi-sync.json` or `pia-unifi-sync.env`, and never print an API
  key, a PIA password, a private key or a preshared key — not in a log line, not in a commit, not
  in a chat reply.
- `npm test` and `npm run lint` must be green before pushing. Browser tests: `npm run test:e2e`
  (Playwright — it drives a stub, so it cannot validate a curl config).

## Where the reasoning lives

- `docs/wiki/features/UniFi_Automation.md` — the full feature write-up: why the tunnels die, why
  a keepalive is worth trying before automating anything, why this private endpoint is the only
  one that can do the job (the official Integration API's `networks` resource is VLAN-shaped and
  has no WireGuard field), and what a masked secret costs.
- `CHANGELOG.md` — what changed when.
- `scripts/unifi-sync/diagnose.mjs` — the module header states the three facts and why each one
  matters.
