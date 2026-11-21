# tplink-hb810-mcp

[Türkçe](README.tr.md)

A local [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for the **TP-Link Aginet HB810** Wi-Fi 7 router. Use an MCP client to inspect connected devices, Wi-Fi signal and link rates, EasyMesh, WAN and LAN status, DHCP, and system logs. Configuration tools can preview changes and require confirmation before applying them.

The live read-only checks used a **2degrees HB810 v1.0** in Router mode, firmware `0.5.0 3.0.0 v6095.0 Build 251128 Rel.64645n`. Write workflows were exercised against an encrypted loopback simulator. The [HB810 admin menu inventory](docs/hb810-admin-menu.md) maps the browser pages to MCP tools and describes the remaining gaps.

This is a fork of [tplink-modem-mcp](https://github.com/YakupEmreYerli/tplink-modem-mcp), created by [Yakup Emre Yerli](https://github.com/YakupEmreYerli). The original project provided the MCP server, legacy router support, presence history, and configuration tools. Router communication builds on [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U).

## Quick start

Install Node.js 22.19 or newer and [uv](https://docs.astral.sh/uv/). Run the server on a machine that can reach the router's local admin interface. The TypeScript server uses Effect for tool execution and presence tracking. A bundled Python adapter still runs the existing firmware drivers. On the first router call, uv prepares the adapter's locked dependencies.

Install [Bun](https://bun.sh/) to build from a checkout:

```sh
git clone https://github.com/mynameistito/tplink-hb810-mcp
cd tplink-hb810-mcp
bun install --frozen-lockfile
bun run build
```

In your MCP client, use the absolute path to the built server:

```json
{
  "mcpServers": {
    "tplink-hb810": {
      "command": "node",
      "args": ["/absolute/path/to/tplink-hb810-mcp/build/main.js"],
      "env": {
        "TPLINK_HOST": "http://192.168.1.1",
        "TPLINK_USERNAME": "admin",
        "TPLINK_PASSWORD": "<HB810 web admin password>",
        "TPLINK_CLIENT": "TPLinkEXClient",
        "TPLINK_WRITE": "off"
      }
    }
  }
}
```

Set `TPLINK_HOST` to your router's actual address. After connecting, call `router_status`, then try `list_clients` or `wifi_networks`.

For a packaged install, download the `.tgz` from a [GitHub release](https://github.com/mynameistito/tplink-hb810-mcp/releases) and run `npm install -g ./tplink-hb810-mcp-VERSION.tgz`. Set the MCP command to `tplink-hb810-mcp`, clear its arguments, and keep the same environment variables.

## What the MCP can do

| Area | Tools |
| --- | --- |
| Status and clients | `router_status`, `list_clients`, `find_client`, `client_history`, `ipv6_status` |
| Wireless and DHCP | `wifi_networks`, `dhcp_leases`, `dhcp_reservations`, `set_wifi`, `set_static_ip`, `remove_static_ip` |
| Firmware settings | `router_objects`, `router_read`, `router_change`, `router_apply`, `router_run` |
| Logs and diagnostics | `router_logs`, `diagnostic_status`, `start_diagnostic` |
| EasyMesh | `mesh_pairing_status`, `start_mesh_pairing`, `mesh_scan_status`, `manage_mesh_scan` |
| Maintenance | `export_router_file` for configuration backups and OpenVPN profiles, `import_router_file` for local restore and firmware uploads, `reboot_router` |

The example configuration exposes read tools only. If you enable writes, tools preview the requested operation before `confirm=true` applies it. An MCP client that supports elicitation can also ask you to approve the operation directly. For broad settings access, use `router_objects` to find a firmware object and `router_read` to inspect it. A catalog entry can belong to a different model or operating mode.

The guided Quick Setup wizard, TP-Link Cloud sign-in, and online or satellite firmware upgrades use the browser.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `TPLINK_HOST` | `http://192.168.1.1` | Local web admin address |
| `TPLINK_USERNAME` | `admin` | Local web admin username |
| `TPLINK_PASSWORD` | Required | Local web admin password |
| `TPLINK_CLIENT` | Auto-detect | Set to `TPLinkEXClient` for the tested HB810 firmware |
| `TPLINK_WRITE` | `on` | Set to `off` to hide tools with side effects |
| `TPLINK_ALLOW` | All | Comma-separated allowlist for objects and operations |
| `TPLINK_DENY` | Empty | Comma-separated denylist that takes precedence over the allowlist |
| `TPLINK_SHOW_SECRETS` | `0` | Set to `1` to include fields that are normally masked in settings reads |
| `TPLINK_TIMEOUT` | `20` | Router request timeout in seconds |
| `TPLINK_PRESENCE_INTERVAL` | `60` | Seconds between presence samples. Set to `0` to disable background sampling. |
| `TPLINK_STATE_DIR` | `$XDG_STATE_HOME/tplink-modem-mcp` | Presence history directory, retaining the upstream name for existing installs |
| `TPLINK_LEGACY_STATE_ENCODING` | Python locale encoding | Set to the original encoding if migrating non-UTF-8 history from a different locale |
| `TPLINK_LOG` | `WARNING` | Server log level |

Client presence history records joins, leaves, and IP changes while the sampler runs. Use `node build/main.js sample` or `tplink-hb810-mcp sample` after a global install for a one-shot sample from a scheduler. The router's admin session can be shared between the MCP and the web panel only as the firmware permits.

## Tests

```sh
bun run check
bun run typecheck
bun test
bun run test:integration
npm pack --dry-run
```

The [end-to-end test](tests/test_hb810_e2e.py) starts the MCP server over stdio and runs authenticated requests against an encrypted loopback router. It needs no physical router or credentials.

## License

[GPL-3.0-or-later](LICENSE), inherited from the original project.
