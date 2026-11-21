# Contributing

## Setup

```sh
git clone https://github.com/mynameistito/tplink-hb810-mcp && cd tplink-hb810-mcp
bun install --frozen-lockfile
bun run test:integration
```

The tests launch the built TypeScript server over stdio and exercise it against a loopback HB810 simulator. Install Node.js 22.19 or newer, Bun, and uv to run the suite.

To try it on your own router:

```sh
TPLINK_PASSWORD=... TPLINK_LOG=DEBUG node build/main.js sample
```

`sample` logs in, reads the client list once and prints any join or leave events, so it is a quick check that login and parsing work on your model.

## Before you send a pull request

- `bun run check`, `bun run typecheck`, `bun test` and `bun run test:integration` pass.
- Document new `TPLINK_*` settings in the README.
- Register changes in `src/writes.ts`. Check write policy, show a preview and require confirmation. Keep firmware-specific requests in the driver adapter.

## Adding a router model

Most models are handled by tplinkrouterc6u; if yours is not detected, try `TPLINK_CLIENT` with one of its class names first. Support for a new model usually belongs upstream in [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U).

`legacy.py` is for older ISP firmwares that log in through `/cgi/login`. Things worth knowing:

- These firmwares allow one admin session at a time. Logging in on every call throws a person out of the web UI, so the client keeps its login for two minutes, and `Router.call` logs in again once if a call fails.
- The password is RSA-encrypted with the key from `/cgi/getParm` after base64; the user name is encrypted as is.
- Some firmwares need a `TokenID` header taken from the index page; the Archer C5v does not.

If you get a new model working, report its model and firmware version.
