---
title: Frontend Stack
aliases: [Frontend, UI]
tags: [architecture, frontend]
created: "2026-04-18"
updated: "2026-04-18"
sources: ["[[2026-04-18_project_overview]]"]
status: active
confidence: high
---
# Frontend Stack

The PIA WireGuard Generator uses a pure vanilla web stack for its user interface. It avoids heavy JavaScript frameworks in favor of direct DOM manipulation.

## Core Technologies
- **HTML**: `index.html` structure defining the three main views (login, configuration, success).
- **CSS**: `style.css` uses CSS variables for a dark mode palette similar to Tailwind CSS. The design language incorporates a modern, dark Slate/Sky aesthetic.
- **JavaScript**: `renderer.js` handles state transitions, API integrations, and event listeners.

## View Management
The UI operates as a Single Page Application (SPA). The application defines three distinct `.view` sections. The active view is controlled by toggling the `.active` CSS class.
1. **Login View**: Captures credentials.
2. **Config View**: Selects regions and DNS.
3. **Success View**: Offers the `.conf` save dialog.

## Interaction with Backend
The frontend JavaScript communicates directly with the [[Neutralinojs_Integration]] layer to persist data and execute curl commands. It orchestrates the entire [[WireGuard_Generation]] sequence based on user input.

## External Connections
- [[Neutralinojs_Integration]]
- [[Authentication_Flow]]
