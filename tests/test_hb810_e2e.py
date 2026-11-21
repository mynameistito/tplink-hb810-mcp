"""Run the real stdio server end to end against an encrypted loopback HB810 simulator."""

import json
import subprocess
from time import time
from base64 import b64decode, b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.types import ElicitResult

from test_server import params


@pytest.fixture
def hb810():
    # The EX firmware advertises a 512-bit modulus. PyCryptodome's key generator
    # has a higher minimum, so build a fixture-only key from two primes.
    exponent = 65537
    while True:
        p, q = getPrime(256), getPrime(256)
        modulus = p * q
        if modulus.bit_length() == 512 and (p - 1) % exponent and (q - 1) % exponent:
            private = pow(exponent, -1, (p - 1) * (q - 1))
            break
    events = []
    uploads = []
    reject_upload = [False]
    cipher_pair = None
    objects = {
        "DEV2_DEV_INFO": {"modelName": "HB810", "X_TP_DevModelVersion": "1.0",
                          "X_TP_BuildDate": "251128", "X_TP_BuildTime": "64645"},
        "DEV2_ADT_LAN": [{"MACAddress": "11:22:33:44:55:66", "IPAddress": "192.0.2.1",
                          "IPv6Enable": "1", "IPv6Address": "2001:db8::1"}],
        "DEV2_ADT_WAN": [{"enable": "1", "connIPv6Enabled": "1", "connIPv6Address": "2001:db8::2"}],
        "DEV2_HOST_ENTRY": [{"active": "1", "X_TP_LanConnType": "0", "physAddress": "AA:BB:CC:DD:EE:FF",
                             "IPAddress": "192.0.2.20", "hostName": "test-device", "leaseTimeRemaining": "60"}],
        "DEV2_MEM_STATUS": {"total": "100", "free": "50"},
        "DEV2_PROC_STATUS": {"CPUUsage": "10"},
        "DEV2_ADT_WIFI_CLIENT": [{"MACAddress": "AA:BB:CC:DD:EE:FF", "signalStrength": "-58"}],
        "DEV2_WIFI_APDEV_ASSOCDEV": [{"MACAddress": "AA:BB:CC:DD:EE:FF", "lastDataDownlinkRate": "320000"}],
        "DEV2_ADT_WIFI_COMMON": [{"stack": "3,0,0,0,0,0", "band": "6GHz", "primarySSID": "Home",
                                  "primaryEnable": "1", "WPSEnable": "1", "WPSState": "Idle",
                                  "primaryPSK": "simulator-wifi-key"}],
        "DEV2_DHCPV4_POOL_STATICADDR": [],
        "DEV2_DHCPV4_SERVER_POOL": [{"stack": "1,2,0,0,0,0", "X_TP_MainPool": "1"}],
        "DEV2_X_TP_ONBOARDBYSCANNING": {"status": "statusIdle"},
        "DEV2_X_TP_AGENTINFO": [{"stack": "1,0,0,0,0,0", "mac": "AA-BB-CC-DD-EE-FF",
                                  "deviceModel": "HB810", "agentStatus": "agentStatusIdle"}],
        "DEV2_DIAG_IPPING": {"diagnosticsState": "None"},
        "DEV2_DIAG_TRACERT": {"diagnosticsState": "None"},
        "DEV2_DIAG_NSLOOKUP": {"diagnosticsState": "None"},
        "DEV2_ROUTE_HOPS": [{"hostAddress": "192.0.2.1"}],
        "DEV2_NSLOOKUP_RESULT": [{"HostNameReturned": "example.test"}],
    }

    def crypt():
        return AES.new(*cipher_pair)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, value: str | bytes, status=200, attachment=False):
            value = value.encode() if isinstance(value, str) else value
            self.send_response(status)
            if attachment:
                self.send_header("Content-Disposition", "attachment")
                self.send_header("Content-Type", "application/octet-stream")
            else:
                self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(value)))
            self.end_headers()
            self.wfile.write(value)

        def authenticated(self):
            return self.headers.get("TokenID") == "simulated-token"

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                self.send('var token="simulated-token";')
            elif path == "/js/oid_str.js":
                self.send('var INCLUDE_OPTION66=1; var DEV2_ADT_WIFI_COMMON="DEV2_ADT_WIFI_COMMON";')
            elif path == "/js/proxy.js":
                self.send('var ACT_OP_TR143_STARTDIAG = "ACT_TR143_STARTDIAG";')
            elif not self.authenticated():
                self.send("missing token", 403)
            elif path == "/cgi/log":
                text = b"0\n2026-11-21 12:00:00 [5] DHCPD: lease renewed\n2026-11-21 12:01:00 [6] SYSTEM: started\n"
                self.send(b64encode(crypt().encrypt(pad(text, 16))))
            elif path == "/cgi/HB810V125112864645n.bin":
                query = parse_qs(urlsplit(self.path).query)
                assert query == {"backupPassword": ["simulator-backup"], "enableBackupPassword": ["on"]}
                self.send(b"synthetic backup", attachment=True)
            elif path == "/cgi/openvpn" and urlsplit(self.path).query == "cliOvpnDown":
                self.send(b"synthetic vpn profile", attachment=True)
            elif path in ("/cgi/bnr", "/cgi/softburn"):
                uploads.append(path)
                self.send("$.ret=0;")
            else:
                self.send("unsupported", 404)

        def do_POST(self):
            nonlocal cipher_pair
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            path = urlsplit(self.path).path
            if path == "/cgi/getGDPRParm":
                self.send(f'$.ret=0;\nvar nn="{modulus:0128x}";\nvar ee="{exponent:06x}";\nvar seq="1";')
                return
            if path in ("/cgi/confup", "/cgi/softup") and self.authenticated():
                assert b'name="filename"' in body and b"synthetic image" in body
                uploads.append(path)
                self.send("upload result missing" if reject_upload[0] else "$.ret=0;")
                return
            if path != "/cgi_gdpr":
                self.send("unsupported", 404)
                return
            fields = dict(line.split("=", 1) for line in body.decode().splitlines())
            width = 64
            signature = bytes.fromhex(fields["sign"])
            clear_signature = b"".join(
                pow(int.from_bytes(signature[i:i + width]), private, modulus).to_bytes(width)
                for i in range(0, len(signature), width)
            ).rstrip(b"\0")
            if clear_signature.startswith(b"key="):
                secret = parse_qs(clear_signature.decode())
                cipher_pair = (secret["key"][0].encode(), AES.MODE_CBC, secret["iv"][0].encode())
            request = json.loads(unpad(crypt().decrypt(b64decode(fields["data"])), 16))
            if request["oid"] == "/cgi/login":
                assert b64decode(request["data"]["Passwd"]) == b"simulator-only"
                payload = "$.ret=0;"
            elif self.authenticated():
                payload = json.dumps(self.apply(request))
            else:
                self.send("missing token", 403)
                return
            self.send(b64encode(crypt().encrypt(pad(payload.encode(), 16))))

        def apply(self, request):
            op, oid, fields = request["operation"], request["oid"], request["data"]
            stack, parent = fields.pop("stack"), fields.pop("pstack")
            if op in {"gl", "go"}:
                if oid not in objects:
                    return {"success": False, "errorcode": 9804}
                value = objects[oid]
                if op == "gl" and isinstance(value, dict):
                    return {"success": False, "errorcode": 9003}

                def select(row):
                    return {k: v for k, v in row.items() if not fields or k in fields or k == "stack"}

                if op == "go" and isinstance(value, list):
                    value = next((r for r in value if r["stack"] == stack), None)
                result = [select(row) for row in value] if isinstance(value, list) else select(value)
                return {"success": True, "data": result}

            events.append((op, oid, stack, parent, fields))
            if op == "op":
                if oid == "ACT_WIFI_START_WPS":
                    objects["DEV2_ADT_WIFI_COMMON"][0]["WPSState"] = "InProgress"
                if oid == "ACT_TR143_STARTDIAG":
                    for name in ("DEV2_DIAG_IPPING", "DEV2_DIAG_TRACERT", "DEV2_DIAG_NSLOOKUP"):
                        if objects[name]["diagnosticsState"] == "Requested":
                            objects[name]["diagnosticsState"] = "Complete"
                return {"success": True}
            if oid not in objects:
                return {"success": False, "errorcode": 9804}
            if op == "so":
                current = objects[oid]
                row = next(r for r in current if r["stack"] == stack) if isinstance(current, list) else current
                row.update(fields)
            elif op == "add":
                objects[oid].append({"stack": "1,2,1,0,0,0", **fields})
            elif op == "del":
                objects[oid][:] = [row for row in objects[oid] if row["stack"] != stack]
            return {"success": True}

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", events, uploads, reject_upload, objects
        finally:
            server.shutdown()
            thread.join()


async def call(session, name, **args):
    result = await session.call_tool(name, args)
    assert not result.is_error, result.content
    if result.structured_content is not None:
        return result.structured_content.get("result", result.structured_content)
    blocks = [json.loads(block.text) for block in result.content]
    return blocks[0] if len(blocks) == 1 else blocks


@pytest.mark.anyio
async def test_hb810_workflows_over_mcp_stdio(tmp_path, hb810):
    host, events, uploads, reject_upload, objects = hb810
    conn = params(tmp_path, TPLINK_HOST=host, TPLINK_PASSWORD="simulator-only", TPLINK_CLIENT="TPLinkEXClient",
                  TPLINK_WRITE="on", TPLINK_ALLOW="", TPLINK_DENY="")
    prompts = []

    async def confirm_change(_context, request):
        prompts.append(request.message)
        return ElicitResult(action="accept", content={"approve": len(prompts) > 1})

    async with (stdio_client(conn) as (read, write),
                ClientSession(read, write, elicitation_callback=confirm_change) as session):
        await session.initialize()
        catalog = await call(session, "router_objects")
        assert "ACT_TR143_STARTDIAG" in catalog["operations"]
        assert events == []
        preview = await call(session, "set_wifi", band="6GHz", ssid="New home", password="not-shown-password")
        assert preview["status"] == "not applied" and "not-shown-password" not in str(preview)
        assert events == [] and prompts == []
        rejected = await call(session, "set_wifi", band="6GHz", password="not-shown-password", confirm=True)
        assert rejected["reason"] == "the user did not approve it"
        assert events == [] and "not-shown-password" not in prompts[0]
        await call(session, "set_wifi", band="6GHz", ssid="New home", confirm=True)
        assert events[-1][2:5] == ("3,0,0,0,0,0", "0,0,0,0,0,0", {"primarySSID": "New home"})

        args = {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.0.2.20"}
        await call(session, "set_static_ip", **args, confirm=True)
        assert events[-1][0] == "add" and events[-1][3] == "1,2,0,0,0,0"
        preview = await call(session, "set_static_ip", **{**args, "ip": "192.0.2.21"})
        assert "from 192.0.2.20 to 192.0.2.21" in preview["would_do"]
        await call(session, "set_static_ip", **{**args, "ip": "192.0.2.21"}, confirm=True)
        assert "from 192.0.2.20 to 192.0.2.21" in prompts[-1]
        assert events[-1][0] == "so"
        objects["DEV2_DHCPV4_POOL_STATICADDR"].insert(0, {"stack": "1,2,2,0,0,0"})
        await call(session, "remove_static_ip", mac=args["mac"], confirm=True)
        assert events[-1][0] == "del"

        steps = [{"action": "set", "object": "DEV2_ADT_WIFI_COMMON", "stack": "3", "attributes": {"primaryEnable": 1}},
                 {"action": "set", "object": "DEV2_UNSUPPORTED"},
                 {"action": "set", "object": "DEV2_ADT_WIFI_COMMON", "stack": "3", "attributes": {"primaryEnable": 0}}]
        count = len(events)
        assert (await call(session, "router_apply", steps=steps))["status"] == "not applied"
        assert len(events) == count
        result = await call(session, "router_apply", steps=steps, confirm=True)
        assert result["status"] == "stopped" and len(result["applied"]) == 1 and result["failed_step"] == 2
        assert len(events) == count + 2

        for kind in ("ping", "traceroute", "nslookup"):
            await call(session, "start_diagnostic", kind=kind, host="example.test", confirm=True)
            status = await call(session, "diagnostic_status", kind=kind)
            assert status["state"] == "Complete"
            if kind != "ping":
                assert status["results"]
        await call(session, "start_mesh_pairing", confirm=True)
        state = await call(session, "mesh_pairing_status")
        assert (state[0] if isinstance(state, list) else state)["WPSState"] == "InProgress"
        assert (await call(session, "manage_mesh_scan", action="start"))["status"] == "not applied"
        await call(session, "manage_mesh_scan", action="start", confirm=True)
        assert events[-1][1] == "ACT_EASYMESH_UPDATE_AGENTINFO"
        assert (await call(session, "mesh_scan_status"))["state"] == "statusScanning"
        await call(session, "manage_mesh_scan", action="add", mac=args["mac"], confirm=True)
        assert (await call(session, "mesh_scan_status"))["candidates"][0]["agentStatus"] == "agentStatusAdding"
        await call(session, "manage_mesh_scan", action="refresh", confirm=True)
        assert events[-1][1] == "ACT_UPDATE_MAPINFO"
        await call(session, "manage_mesh_scan", action="cancel", confirm=True)
        assert (await call(session, "mesh_scan_status"))["state"] == "statusIdle"

        for kind, data in (("backup", b"synthetic backup"), ("openvpn", b"synthetic vpn profile")):
            path = tmp_path / kind
            password = "simulator-backup" if kind == "backup" else ""
            await call(session, "export_router_file", kind=kind, path=str(path), password=password, confirm=True)
            assert path.read_bytes() == data
            result = await session.call_tool("export_router_file", {"kind": kind, "path": str(path), "confirm": True})
            assert result.is_error and path.read_bytes() == data

        path = tmp_path / "image.bin"
        path.write_bytes(b"synthetic image")
        assert (await call(session, "import_router_file", kind="restore", path=str(path)))["status"] == "not applied"
        assert uploads == []
        await call(session, "import_router_file", kind="restore", path=str(path), confirm=True)
        await call(session, "import_router_file", kind="firmware", path=str(path), confirm=True)
        assert uploads == ["/cgi/confup", "/cgi/bnr", "/cgi/softup", "/cgi/softburn"]
        reject_upload[0] = True
        result = await session.call_tool("import_router_file", {"kind": "firmware", "path": str(path), "confirm": True})
        assert result.is_error and uploads[4:] == ["/cgi/softup"]

        result = await session.call_tool("reboot_router", {"confirm": True})
        assert not result.is_error and events[-1][:2] == ("op", "ACT_REBOOT")


@pytest.mark.anyio
async def test_hb810_reads_and_one_shot_sample(tmp_path, hb810):
    host, events, _, _, _ = hb810
    conn = params(tmp_path, TPLINK_HOST=host, TPLINK_PASSWORD="simulator-only", TPLINK_CLIENT="TPLinkEXClient",
                  TPLINK_WRITE="off", TPLINK_SHOW_SECRETS="0")
    (tmp_path / "last.json").write_text("{}")
    sample = subprocess.run([conn.command, *conn.args, "sample"], env=conn.env,
                            check=True, capture_output=True, text=True, timeout=30)
    assert json.loads(sample.stdout)["event"] == "join"
    with (tmp_path / "presence.jsonl").open("a", encoding="ascii") as history:
        history.write(sample.stdout)
    async with stdio_client(conn) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        status = await call(session, "router_status")
        assert status["client_class"] == "TPLinkEXClient" and status["online_devices"] == 1
        clients = await call(session, "list_clients")
        assert clients[0]["signal_dbm"] == -58 and clients[0]["rate_mbps"] == 320
        assert (await call(session, "find_client", query="AA-BB-CC")) == clients
        assert (await call(session, "client_history", mac="AA-BB-CC-DD-EE-FF"))[0]["name"] == "test-device"
        history = await session.call_tool("client_history", {})
        assert len(history.content) == 2
        assert [json.loads(block.text) for block in history.content] == history.structured_content["result"]
        assert (await call(session, "wifi_networks"))[0]["ssid"] == "Home"
        assert (await call(session, "router_logs", module="dhcpd", contains="RENEWED"))[0]["severity"] == "notice"
        assert len(await call(session, "dhcp_leases")) == 1
        assert await call(session, "dhcp_reservations") == []
        assert (await call(session, "ipv6_status"))["wan"][0]["address"] == "2001:db8::2"
        rows = await call(session, "router_read", object="DEV2_ADT_WIFI_COMMON")
        assert rows[0]["primaryPSK"] == "***"
        assert events == []


@pytest.mark.anyio
async def test_reads_a_legacy_presence_file_before_migrating_it(tmp_path, hb810):
    host, _, _, _, _ = hb810
    conn = params(tmp_path, TPLINK_HOST=host, TPLINK_PASSWORD="simulator-only", TPLINK_CLIENT="TPLinkEXClient",
                  TPLINK_LEGACY_STATE_ENCODING="cp1252")
    mac = "11:22:33:44:55:66"
    old = {"name": "téléphone", "ip": "192.0.2.30", "connection": "wired"}
    (tmp_path / "last.json").write_bytes(json.dumps({mac: old}, ensure_ascii=False).encode("cp1252"))
    payload = {"t": time(), "event": "join", "mac": mac, **old}
    (tmp_path / "presence.jsonl").write_bytes((json.dumps(payload, ensure_ascii=False) + "\n").encode("cp1252"))
    sample = subprocess.run([conn.command, *conn.args, "sample"], env=conn.env,
                            check=True, capture_output=True, encoding="utf-8", timeout=30)
    assert any(e["event"] == "leave" and e["name"] == "téléphone"
               for e in map(json.loads, sample.stdout.splitlines()))
    async with stdio_client(conn) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        events = await call(session, "client_history", mac=mac)
        assert [(e["event"], e["name"]) for e in events] == [("join", "téléphone"), ("leave", "téléphone")]
