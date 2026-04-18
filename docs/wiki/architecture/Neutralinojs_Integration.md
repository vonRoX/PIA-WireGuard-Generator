---
title: Neutralinojs Integration
aliases: [Neutralino, Wrapper]
tags: [architecture, neutralino]
created: "2026-04-18"
updated: "2026-04-18"
sources: ["[[2026-04-18_project_overview]]"]
status: active
confidence: high
---
# Neutralinojs Integration

The PIA WireGuard Generator relies on Neutralinojs as a lightweight desktop framework. This architectural choice replaced Electron, reducing the overall application footprint.

## Configuration
The project is configured via `neutralino.config.json`. The configuration allows the web client to execute specific native capabilities via the `nativeAllowList`. This includes permissions for `app.*`, `os.*`, `storage.*`, and `filesystem.*`.

## Native OS Execution
The application heavily utilizes `Neutralino.os.execCommand`. Standard web `fetch()` calls fail due to Cross-Origin Resource Sharing (CORS) blocks on Private Internet Access (PIA) APIs. By executing `curl` commands natively, the application bypasses these browser-level network restrictions. This mechanism is critical for both the [[Authentication_Flow]] and the [[WireGuard_Generation]] process.

## Storage
The application uses the Neutralino storage API (`Neutralino.storage.setData` and `Neutralino.storage.getData`) to persist user state. This includes:
- Authentication tokens
- Usernames
- Saved region preferences
- Custom DNS settings

## External Connections
- [[Frontend_Stack]]
- [[WireGuard_Generation]]
