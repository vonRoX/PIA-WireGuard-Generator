---
title: Project Log
aliases: [Changelog, Log]
tags: [project-management, log]
created: "2026-04-18"
updated: "2026-08-19"
sources: []
status: active
confidence: high
---
# Project Log

- **2026-04-18**: Initialized project wiki and logging.
- **2026-04-18**: Completed Electron to Neutralinojs migration and build tests.

## [2026-04-18] ingest | PIA WireGuard Generator Architecture Overview
- Source: `[[2026-04-18_project_overview]]`
- Summary: `[[summary_2026-04-18_project_overview]]`
- Pages created: 
  - [[Neutralinojs_Integration]]
  - [[Frontend_Stack]]
  - [[Authentication_Flow]]
  - [[WireGuard_Generation]]

## [2026-08-19] v2.0.0 | Security and correctness release
- Trigger: a code review of v1.1.0 raising 15 findings, three serious.
- Two vulnerabilities fixed: command injection through the sign-in password, and TLS verification
  disabled on the request that carries the account token and returns the tunnel endpoint.
- Network layer rebuilt so the shell never receives user data; PIA's own certificate authority is
  now bundled and pinned.
- `renderer.js` split into testable modules under `core/`, `platform/` and `app.js`.
- Token storage became opt-in and expiring; saved configurations are owner-only.
- 107 offline tests, 37 browser tests, CI on Linux, macOS and Windows, and a release workflow that
  verifies the build actually produced binaries.
- Pages updated: [[Neutralinojs_Integration]], [[Frontend_Stack]], [[Authentication_Flow]],
  [[WireGuard_Generation]]
- Page created: [[Security_Model]]
