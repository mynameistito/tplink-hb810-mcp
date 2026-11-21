"""Firmware driver operations exposed to the TypeScript application."""
import functools
from pathlib import Path

from tplinkrouterc6u.client.ex import TPLinkEXClient

from . import control, ex, workflows
from .router import plain


def _clients(c, *, diagnostics: bool = False) -> list[dict]:
    """One shape for every client class: hostname, ip, mac, active, connection, ssid, signal_dbm, rate_mbps."""
    if hasattr(c, "hosts"):
        return c.hosts()
    out = []
    for d in plain(c.get_status().devices):
        out.append({"hostname": d.get("hostname", ""), "ip": d.get("ipaddr", ""), "mac": d.get("macaddr", ""),
                    "active": d.get("active", True), "connection": d.get("type", ""), "ssid": d.get("ssid"),
                    "signal_dbm": d.get("signal"), "rate_mbps": d.get("tx_rate")})
    if diagnostics and out and isinstance(c, TPLinkEXClient):
        wifi = ex.client_diagnostics(c)
        for device in out:
            device.update(wifi.get(device["mac"].upper().replace("-", ":"), {}))
    return out


def _wifi_reader(client):
    if isinstance(client, TPLinkEXClient):
        return functools.partial(ex.wifi_networks, client)
    return getattr(client, "wifi_networks", None)


def _reservation_rows(c):
    oid = "DEV2_DHCPV4_POOL_STATICADDR" if isinstance(c, TPLinkEXClient) else "LAN_DHCP_STATIC_ADDR"
    control.check_allowed(oid)
    return oid, control.DataModel(c).read(oid, attributes=["chaddr", "yiaddr"])


def status(c):
    out = {"firmware": plain(c.get_firmware()),
           "network": c.internet() if hasattr(c, "internet") else plain(c.get_ipv4_status())}
    if wifi := _wifi_reader(c):
        out["wifi"] = [n for n in wifi() if n["enabled"]]
    out["online_devices"] = sum(1 for d in _clients(c) if d["active"])
    return out


def logs(c):
    if isinstance(c, TPLinkEXClient):
        return ex.logs(c)
    if not hasattr(c, "logs"):
        raise RuntimeError("this router model does not expose its system log here")
    return c.logs()


def apply_steps(c, plan):
    for step in plan:
        control.check_allowed(step["object"])
    dm = control.DataModel(c)
    applied = []
    for index, step in enumerate(plan):
        try:
            applied.append(dm.change(step["action"], step["object"], step["stack"],
                                     step["parent_stack"], step["attributes"]))
        except (PermissionError, ValueError, RuntimeError) as error:
            return {"status": "stopped", "applied": applied, "failed_step": index + 1, "error": str(error)}
    return {"status": "applied", "applied": applied}


def reservation_plan(c, mac, ip):
    oid, rows = _reservation_rows(c)
    same = next((r for r in rows if r.get("chaddr", "").upper().replace("-", ":") == mac), None)
    taken = next((r for r in rows if r.get("yiaddr") == ip and r is not same), None)
    return oid, same, taken


def reboot(c):
    control.check_allowed("ACT_REBOOT")
    if isinstance(c, TPLinkEXClient):
        control.DataModel(c).run("ACT_REBOOT")
    else:
        c.reboot()


def wifi(c):
    reader = _wifi_reader(c)
    if reader is None:
        raise RuntimeError("this router model does not expose its Wi-Fi network list here")
    return reader()


def catalog(c):
    model = control.DataModel(c)
    return {"objects": model.objects(), "operations": model.operations()}


def set_reservation(c, mac, ip, expected):
    oid, same, taken = reservation_plan(c, mac, ip)
    if [oid, same, taken] != expected:
        raise RuntimeError("the reservations changed while waiting for approval; preview again")
    model = control.DataModel(c)
    attrs = {"chaddr": mac, "yiaddr": ip, "enable": "1"}
    if same:
        return model.change("set", oid, same["_stack"], attributes=attrs)
    parent = "1"
    if isinstance(c, TPLinkEXClient):
        pools = model.read("DEV2_DHCPV4_SERVER_POOL", attributes=["X_TP_MainPool"])
        parents = [row["_stack"] for row in pools if str(row.get("X_TP_MainPool")) == "1"]
        if len(parents) != 1 or parents[0] == control.ZERO:
            raise RuntimeError("multiple or missing main DHCP pools; use router_change with a parent stack")
        parent = parents[0]
    return model.change("add", oid, parent_stack=parent, attributes=attrs)


def remove_reservation(c, oid, row):
    current_oid, current = _reservation_rows(c)
    if current_oid != oid or row not in current:
        raise RuntimeError("the reservation changed while waiting for approval; preview again")
    return control.DataModel(c).change("delete", oid, row["_stack"])


def export_file(c, kind, path, password):
    control.check_allowed(f"EXPORT_{kind.upper()}")
    try:
        return workflows.download(c, kind, Path(path), password)
    except OSError as error:
        raise RuntimeError(f"could not save export: {error.strerror}") from None
