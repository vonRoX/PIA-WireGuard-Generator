---
title: Neutralinojs Integration
aliases: [Neutralino, Wrapper]
tags: [architecture, neutralino]
created: "2026-04-18"
updated: "2026-08-19"
sources: []
status: active
confidence: high
---
# Neutralinojs Integration

Neutralinojs provides the desktop shell. It uses the operating system's own webview rather than
bundling a browser, which is why a release binary is a few megabytes instead of a hundred.

## Configuration
`neutralino.config.json` defines a single `window` mode. The browser, cloud and chrome modes were
removed: the application needs native APIs that those modes block, so offering them would only
advertise something that cannot work.

`nativeAllowList` enumerates the methods actually called rather than granting `os.*` and
`filesystem.*` wholesale:

```
app.*  events.*  window.*  storage.*  clipboard.writeText  debug.log
os.execCommand  os.getPath  os.showSaveDialog
filesystem.getJoinedPath  filesystem.remove  filesystem.setPermissions  filesystem.writeFile
```

`logging.writeToLogFile` is off — a privacy tool should not leave a log next to its binary.

## Process execution
`Neutralino.os.execCommand` runs its argument through the platform shell. Every call is confined to
`resources/js/platform/neutralino.js`, and the only command the application can run is the constant
`curl -q --config -`, with the request supplied on standard input. [[Security_Model]] explains why.

## Storage
`Neutralino.storage` holds preferences under a versioned schema (`resources/js/core/prefs.js`):
username, chosen region id, pinned regions, DNS choice, and — only behind an explicit opt-in — the
session token and its issue time. Reading a key that was never written throws in this API, which the
adapter treats as "absent" rather than as an error.

The framework writes these as `<NL_PATH>/.storage/<key>.neustorage` — beside the executable, not in a
per-user application directory — with default permissions of `0644` in a `0755` directory. Since one
of those files can be a bearer token, the adapter restricts the directory to its owner on the first
write. Two consequences worth knowing: the app must live somewhere writable, and deleting that folder
resets it completely.

## Filesystem
Saved configurations are written and then restricted to the owner via
`filesystem.setPermissions`. Windows maps POSIX modes loosely and may refuse; the app reports that
instead of assuming the file is protected.

## Client library
The framework serves its globals by prepending them to `js/neutralino.js` rather than injecting an
inline script, so a strict `script-src 'self'` policy does not break the app. That file is generated
by `neu update` and is not committed — which is why `npm run build` runs `neu update` first.

## External Connections
- [[Frontend_Stack]]
- [[Security_Model]]
- [[WireGuard_Generation]]
