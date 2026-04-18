---
title: Authentication Flow
aliases: [Auth, Login]
tags: [features, authentication]
created: "2026-04-18"
updated: "2026-04-18"
sources: ["[[2026-04-18_project_overview]]"]
status: active
confidence: high
---
# Authentication Flow

The application authenticates directly with Private Internet Access (PIA) to obtain a short-lived API token.

## Sequence
1. **Input**: The user enters their PIA username (typically starting with `p`) and password in the [[Frontend_Stack]].
2. **API Request**: The application sends a POST request to `https://www.privateinternetaccess.com/api/client/v2/token` containing the credentials. This is executed natively via [[Neutralinojs_Integration]] using `curl` to bypass browser CORS restrictions.
3. **Response Handling**: If successful, PIA returns an authentication token.
4. **Persistence**: The token and username are stored in local storage using `Neutralino.storage.setData`.
5. **View Transition**: The application transitions to the configuration view, enabling the [[WireGuard_Generation]] process.

## External Connections
- [[Frontend_Stack]]
- [[Neutralinojs_Integration]]
- [[WireGuard_Generation]]
