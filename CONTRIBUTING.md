# Contributing

Bug reports and pull requests are welcome. For anything security-related, see
[SECURITY.md](SECURITY.md) instead — please do not open a public issue.

## Getting set up

```bash
npm install
npm start            # run the app
```

## Before opening a pull request

```bash
npm run lint
npm test             # unit and integration tests, all offline
npm run test:e2e     # browser tests; first run needs: npx playwright install chromium
```

CI runs the same on Linux, macOS and Windows. Windows matters more than it looks: the app runs its
one command through `cmd.exe`, and the quoting tests are why that is safe.

## Things worth knowing before changing the network code

Two properties are load-bearing, and there are tests that fail if either is weakened:

1. **The shell never sees user data.** The only command the app runs is the constant
   `curl -q --config -`; the request goes over standard input. Do not build a command string, and do
   not add an argument that comes from a variable.
2. **Certificates are always verified.** `-k` / `--insecure` must not appear anywhere. If a handshake
   fails, the operation fails — there is no fallback to an unverified connection.

Logic lives in `resources/js/core/` as plain modules that take their platform through injection.
`resources/js/platform/neutralino.js` holds every native call, and `resources/js/app.js` does DOM
wiring only. Keeping that split is what lets the logic be tested in Node and in a browser without
the Neutralino runtime.

## Style

Two-space indent, semicolons, single quotes — `npm run lint` is the arbiter. Comments should explain
why something is the way it is, particularly where it is defending against something.

Commit messages: a short imperative subject, then a body explaining the reasoning if it is not
obvious from the diff.
