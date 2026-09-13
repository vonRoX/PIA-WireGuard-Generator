---
title: Project Log
aliases: [Changelog, Log]
tags: [project-management, log]
created: "2026-04-18"
updated: "2026-09-02"
sources: []
status: active
confidence: high
---
# Project Log

- **2026-04-18**: Initialized project wiki and logging.
- **2026-04-18**: Completed Electron to Neutralinojs migration and build tests.

## [2026-04-18] ingest | PIA WireGuard Generator Architecture Overview
- Pages created:
  - [[Neutralinojs_Integration]]
  - [[Frontend_Stack]]
  - [[Authentication_Flow]]
  - [[WireGuard_Generation]]

## [2026-08-20] v2.0.0 | Security and correctness release
- Trigger: a code review of v1.1.0 raising 15 findings, three serious.
- Two vulnerabilities fixed: command injection through the sign-in password, and TLS verification
  disabled on the request that carries the account token and returns the tunnel endpoint.
- Network layer rebuilt so the shell never receives user data; PIA's own certificate authority is
  now bundled and pinned.
- `renderer.js` split into testable modules under `core/`, `platform/` and `app.js`.
- Token storage became opt-in and expiring; saved configurations are owner-only.
- 115 offline tests, 38 browser tests, CI on Linux, macOS and Windows, and a release workflow that
  verifies the build actually produced binaries.
- Pages updated: [[Neutralinojs_Integration]], [[Frontend_Stack]], [[Authentication_Flow]],
  [[WireGuard_Generation]]
- Page created: [[Security_Model]]

## [2026-09-02] unifi-sync | Unattended refresh of UniFi VPN Clients
- Trigger: PIA WireGuard registrations lapse after some hours idle and the token after a day, so a
  UCG Ultra running two PIA tunnels needed a fresh `.conf` pasted in every few days.
- Added `scripts/pia-unifi-sync.mjs`: the app's own `PiaClient` under Node, plus a small client for
  the console's `networkconf` API that rewrites only the registration fields of a WireGuard VPN
  Client row. Console certificates are pinned by file, never ignored.
- Offline tests against a fake console over TLS; systemd timer and cron examples.
- Page created: [[UniFi_Automation]]
