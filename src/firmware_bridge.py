# /// script
# requires-python = ">=3.12"
# dependencies = ["tplinkrouterc6u==5.40.0"]
# ///
"""JSON-lines transport for the bundled firmware drivers."""

import base64
import contextlib
import json
import locale
import sys
from pathlib import Path

from tplinkrouterc6u.client.ex import TPLinkEXClient

from tplink_modem_mcp import adapter, control, ex, workflows
from tplink_modem_mcp.router import Router, plain


READS = {
    "status": adapter.status,
    "clients": lambda c, diagnostics: adapter._clients(c, diagnostics=diagnostics),
    "wifi": adapter.wifi,
    "logs": adapter.logs,
    "leases": lambda c: plain(c.get_ipv4_dhcp_leases()),
    "reservations": lambda c: plain(c.get_ipv4_reservations()),
    "ipv6": lambda c: ex.ipv6_status(c) if isinstance(c, TPLinkEXClient) else plain(c.get_ipv6_status()),
    "catalog": adapter.catalog,
    "read": lambda c, *args: control.DataModel(c).read(*args),
    "diagnosticStatus": workflows.diagnostic_status,
    "meshPairStatus": workflows.mesh_pair_status,
    "meshScanStatus": workflows.mesh_scan_status,
    "reservationPlan": adapter.reservation_plan,
    "reservationRows": adapter._reservation_rows,
}
WRITES = {
    "change": lambda c, *args: control.DataModel(c).change(*args),
    "run": lambda c, op: control.DataModel(c).run(op),
    "applySteps": adapter.apply_steps,
    "startDiagnostic": workflows.diagnostic_start,
    "meshPair": lambda c: workflows.model(c).run(workflows.MESH_PAIR),
    "meshScan": workflows.mesh_scan,
    "exportFile": adapter.export_file,
    "importFile": lambda c, kind, path, payload, password: workflows.upload(
        c, kind, Path(path), base64.b64decode(payload, validate=True), password),
    "setReservation": adapter.set_reservation,
    "removeReservation": adapter.remove_reservation,
    "setWifi": workflows.set_wifi,
    "reboot": adapter.reboot,
}


def dispatch(router, request):
    operation, args = request["operation"], request["args"]
    if operation == "checkWrites":
        for target in args[0]:
            control.check_allowed(target)
        return None
    if operation == "decodeLegacyState":
        encoding = args[1] or locale.getencoding()
        return base64.b64decode(args[0], validate=True).decode(encoding)
    if operation in WRITES and not control.writes_enabled():
        raise PermissionError("changes are turned off (TPLINK_WRITE=off)")
    result = router.call(lambda c: (READS | WRITES)[operation](c, *args), retry=operation in READS)
    if operation == "status":
        result["client_class"] = router.client_name
    return result


def main():
    output = sys.stdout
    router = Router()
    # A firmware driver may print diagnostics. Keep the response stream isolated.
    with contextlib.redirect_stdout(sys.stderr):
        for line in sys.stdin.buffer:
            try:
                response = {"ok": True, "value": dispatch(router, json.loads(line))}
                encoded = json.dumps(response, allow_nan=False)
            except (PermissionError, NotImplementedError, RuntimeError) as error:
                encoded = json.dumps({"ok": False, "message": str(error)})
            except Exception:
                encoded = json.dumps({"ok": False, "message": "firmware adapter request failed"})
            print(encoded, file=output, flush=True)


if __name__ == "__main__":
    main()
