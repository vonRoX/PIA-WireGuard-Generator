---
title: Authentication Flow
aliases: [Auth, Login]
tags: [features, authentication]
created: "2026-04-18"
updated: "2026-08-19"
sources: []
status: active
confidence: high
---
# Authentication Flow

The application exchanges the user's Private Internet Access credentials for a short-lived API token.

## Sequence
1. **Preflight**: before the sign-in form is usable, the app confirms `curl` is present and new
   enough for `--connect-to` (7.49+). A machine without it gets an explanatory screen rather than a
   failure three steps later.
2. **Input**: the user enters their PIA username (typically starting with `p`) and password in the
   [[Frontend_Stack]].
3. **Request**: `PiaClient.login` posts to
   `https://www.privateinternetaccess.com/api/client/v2/token`. The body — and therefore the
   password — travels to curl on standard input, never on a command line. See [[Security_Model]].
4. **Response handling**: the HTTP status is checked before the body is parsed, so a 500 reads as a
   PIA outage and a 401 as bad credentials. A response that is not JSON, such as a captive-portal
   page, produces a message about that rather than a parser error.
5. **Persistence**: the username is remembered. The token is kept in memory unless the user ticks
   "Stay signed in", which is off by default; when ticked it is stored alongside its issue time.
6. **Restore**: on the next launch a stored token is used only if it is under 23 hours old.
   Otherwise it is deleted and the user is asked to sign in, with an explanation.
7. **Expiry mid-session**: a 401 from any later request clears the token and returns to this screen
   rather than surfacing a parse failure.

Signing out deletes the stored token and clears the opt-in; the username survives as a convenience.

## External Connections
- [[Frontend_Stack]]
- [[Neutralinojs_Integration]]
- [[Security_Model]]
- [[WireGuard_Generation]]
