---
title: Frontend Stack
aliases: [UI, Frontend]
tags: [architecture, frontend]
created: "2026-04-18"
updated: "2026-08-19"
sources: ["[[2026-04-18_project_overview]]"]
status: active
confidence: high
---
# Frontend Stack

Vanilla ES modules, no framework and no build step. The source that ships is the source in the
repository.

## Layout
```
resources/
  index.html            markup, and the Content-Security-Policy
  css/app.css           one stylesheet; the Inter font is vendored alongside it
  js/
    app.js              DOM wiring only
    core/               decisions: curl, http, pia, serverlist, wireguard, dns, prefs, errors
    platform/           every native call, behind one adapter
    vendor/             tweetnacl, qrcode-generator, and the generated Neutralino client
```

Modules under `core/` touch neither the DOM nor any Neutralino global; they take what they need
through injection. That is what allows the same files to be exercised by Node and by a headless
browser without the desktop runtime, and it keeps the untested surface down to `app.js`.

## Views
Four sections in one document — sign in, configure, result, and a blocking screen for a machine that
cannot run the app — switched by a class. A stepper in the header tracks progress.

Every asynchronous action has a real state: a busy button with `aria-busy`, an error region with
`role="alert"` carrying a sentence a person can act on plus an optional technical detail, and an
empty state where a list can come back empty. Version 1 had a "Loading regions…" placeholder that
could never resolve, and a Generate button that could be enabled with nothing selected; both are
gone, and there are browser tests for both.

## Presentation
A dark palette defined as custom properties. Interactive controls have visible focus rings, the
region list is a keyboard-navigable listbox with a text filter, and `prefers-reduced-motion` is
honoured.

The generated configuration is displayed with the private key masked until revealed, and can be
copied or turned into a QR code — with a warning, since that image is the key.

## Rendering rules
Values from the network reach the DOM through `textContent` and `createElement`; `innerHTML` is
forbidden by lint. The Content-Security-Policy (`default-src 'none'`) means no remote script, style,
font or image can load, and no `eval`.

## External Connections
- [[Neutralinojs_Integration]]
- [[Security_Model]]
- [[Authentication_Flow]]
