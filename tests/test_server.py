"""Starts the real server over stdio (no router needed) and checks what an MCP client sees."""
import os
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = Path(__file__).resolve().parents[1] / "build/main.js"

READ_TOOLS = {"router_status", "list_clients", "find_client", "client_history", "wifi_networks", "router_logs",
              "dhcp_leases", "dhcp_reservations", "ipv6_status", "router_objects", "router_read",
              "diagnostic_status", "mesh_pairing_status", "mesh_scan_status"}
WRITE_TOOLS = {"router_change", "router_run", "set_static_ip", "remove_static_ip", "set_wifi", "reboot_router",
               "router_apply", "start_diagnostic", "start_mesh_pairing", "manage_mesh_scan",
               "export_router_file", "import_router_file"}


def params(tmp_path, **extra):
    env = {**os.environ, "TPLINK_PRESENCE_INTERVAL": "0", "TPLINK_STATE_DIR": str(tmp_path),
           "TPLINK_HOST": "http://127.0.0.1:9", "TPLINK_PASSWORD": "x", **extra}
    return StdioServerParameters(command="node", args=[os.environ.get("TPLINK_TEST_SERVER", str(SERVER))], env=env)


@pytest.mark.anyio
async def test_tools_and_previews(tmp_path):
    async with stdio_client(params(tmp_path)) as (read, write), ClientSession(read, write) as s:
        await s.initialize()
        tools = {t.name: t for t in (await s.list_tools()).tools}
        assert set(tools) == READ_TOOLS | WRITE_TOOLS
        assert all(tools[n].annotations.read_only_hint for n in READ_TOOLS)
        assert all(tools[n].annotations.destructive_hint for n in WRITE_TOOLS)
        assert "ctx" not in tools["set_wifi"].input_schema["properties"]
        assert tools["client_history"].output_schema["properties"]["result"]["type"] == "array"
        assert tools["reboot_router"].output_schema["properties"]["result"]["type"] == "string"
        assert tools["router_run"].output_schema is None

        # Without confirm nothing reaches the router (there is none at 127.0.0.1:9).
        r = await s.call_tool("reboot_router", {})
        assert "Not rebooted" in r.content[0].text
        assert r.structured_content == {"result": r.content[0].text}
        r = await s.call_tool("set_wifi", {"network_index": 1, "ssid": "home", "password": "a-long-secret"})
        assert not r.is_error and "not applied" in r.content[0].text
        assert "a-long-secret" not in r.content[0].text
        r = await s.call_tool("router_run", {"operation": "ACT_DHCP_RENEW"})
        assert "not applied" in r.content[0].text

        r = await s.call_tool("client_history", {})
        assert not r.is_error
        assert r.content == [] and r.structured_content == {"result": []}


@pytest.mark.anyio
async def test_read_only_mode_hides_change_tools(tmp_path):
    async with stdio_client(params(tmp_path, TPLINK_WRITE="off")) as (read, write), ClientSession(read, write) as s:
        await s.initialize()
        assert {t.name for t in (await s.list_tools()).tools} == READ_TOOLS


@pytest.mark.anyio
async def test_deny_list_blocks_before_preview(tmp_path):
    async with stdio_client(params(tmp_path, TPLINK_DENY="LAN_WLAN,ACT_REBOOT")) as (read, write), \
            ClientSession(read, write) as s:
        await s.initialize()
        r = await s.call_tool("set_wifi", {"network_index": 1, "ssid": "x"})
        assert r.is_error and "TPLINK_DENY" in r.content[0].text
        r = await s.call_tool("reboot_router", {})
        assert r.is_error and "TPLINK_DENY" in r.content[0].text


@pytest.mark.anyio
async def test_batch_policy_matches_driver_character_classes(tmp_path):
    conn = params(tmp_path, TPLINK_DENY="DEV2_[^X]*")
    steps = [{"action": "set", "object": "LAN_WLAN"}, {"action": "set", "object": "DEV2_X_TEST"}]
    async with stdio_client(conn) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        for confirm in (False, True):
            result = await session.call_tool("router_apply", {"steps": steps, "confirm": confirm})
            assert result.is_error and "DEV2_X_TEST is in TPLINK_DENY" in result.content[0].text
