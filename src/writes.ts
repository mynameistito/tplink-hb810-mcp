import { createHash } from "node:crypto";
import { lstat, readFile, stat } from "node:fs/promises";
import { isIP } from "node:net";
import { homedir } from "node:os";
import paths from "node:path";

import { Effect, Schema } from "effect";
import * as z from "zod";

import { firmware, readFirmware } from "./firmware.js";
import { macKey } from "./history.js";
import { mask, ToolFailure } from "./policy.js";
import type { Approve, Register, ToolEffect } from "./tools.js";

const writePolicy = (targets: readonly string[]) =>
  firmware("checkWrites", targets);

const zeroStack = "0,0,0,0,0,0";
const stackPattern = /^\d+$/u;
const objectName = /^[A-Z][A-Z0-9_]*$/u;
const attributeName = /^[A-Za-z_][A-Za-z0-9_.-]*$/u;
const macPattern = /^(?:[A-F0-9]{2}:){5}[A-F0-9]{2}$/u;

const hostname =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$/iu;

const missingFile = Schema.is(
  Schema.Struct({ code: Schema.Literal("ENOENT") })
);

const notApplied = "not applied";

const rejected = {
  status: notApplied,
  reason: "the user did not approve it",
};

const confirmField = { confirm: z.boolean().default(false) };
const setAction = "set";
const actions = z.enum([setAction, "add", "delete"]);

const attributes = z.record(
  z.string(),
  z.union([z.string(), z.number(), z.boolean()])
);

const changeFields = {
  action: actions,
  object: z.string(),
  stack: z.string().default(""),
  parent_stack: z.string().default(""),
  attributes: attributes.nullish(),
};

const step = z.object(changeFields);

const reservation = Schema.StructWithRest(
  Schema.Struct({
    _stack: Schema.String,
    chaddr: Schema.optionalKey(Schema.String),
    yiaddr: Schema.optionalKey(Schema.String),
  }),
  [Schema.JsonObject]
);

const reservationPlan = Schema.Tuple([
  Schema.String,
  Schema.NullOr(reservation),
  Schema.NullOr(reservation),
]);

const reservationRows = Schema.Tuple([
  Schema.String,
  Schema.Array(reservation),
]);

const diagnosticObjects = {
  ping: "DEV2_DIAG_IPPING",
  traceroute: "DEV2_DIAG_TRACERT",
  nslookup: "DEV2_DIAG_NSLOOKUP",
};

const meshScan = "DEV2_X_TP_ONBOARDBYSCANNING";
const meshCandidate = "DEV2_X_TP_AGENTINFO";

const uploadRoutes = {
  restore: ["/cgi/confup", "/cgi/bnr"],
  firmware: ["/cgi/softup", "/cgi/softburn"],
};

const failure = (message: string) => new ToolFailure({ message });

const preview = (
  summary: string,
  details: Readonly<Record<string, Schema.Json>> = {}
) => ({
  ...details,
  status: notApplied,
  would_do: summary,
  next: "Show this to the user. If they approve, call again with confirm=true.",
});

const applyApproved = Effect.fn("Router.applyApproved")(
  function* applyApproved(options: {
    confirm: boolean;
    approve: Approve;
    summary: string;
    apply: ToolEffect;
    details?: Readonly<Record<string, Schema.Json>>;
  }) {
    if (!options.confirm) {
      return preview(options.summary, options.details);
    }

    if (!(yield* options.approve(options.summary))) {
      return rejected;
    }

    return yield* options.apply;
  }
);

const parseStack = (value: string) => {
  if (!value.trim()) {
    return Effect.succeed(zeroStack);
  }

  const parts = value.split(",").map((part) => part.trim());

  if (parts.length > 6 || !parts.every((part) => stackPattern.test(part))) {
    return Effect.fail(
      failure("stack must be up to six comma-separated numbers")
    );
  }

  return Effect.succeed(
    [...parts, ...Array.from({ length: 6 - parts.length }, () => "0")].join(",")
  );
};

const parseChange = Effect.fn("Router.parseChange")(function* parseChange(
  input: z.output<typeof step>
) {
  const oid = input.object.trim().toUpperCase();

  if (!objectName.test(oid)) {
    return yield* failure("expected a firmware object name");
  }

  yield* writePolicy([oid]);
  const fields = input.attributes ?? {};
  const keys = Object.keys(fields);

  if (!keys.every((field) => attributeName.test(field))) {
    return yield* failure("expected attribute names");
  }

  if (keys.includes("stack") || keys.includes("pstack")) {
    return yield* failure("pass stack and parent_stack as arguments");
  }

  return {
    action: input.action,
    object: oid,
    stack: yield* parseStack(input.stack),
    parent_stack: yield* parseStack(input.parent_stack),
    attributes: fields,
  };
});

const parseMac = (value: string) => {
  const mac = macKey(value.trim()).toUpperCase();

  return macPattern.test(mac)
    ? Effect.succeed(mac)
    : Effect.fail(failure("provide a MAC address"));
};

const localPath = (value: string) =>
  paths.resolve(
    value === "~" ? homedir() : value.replace(/^~[/\\]/u, `${homedir()}/`)
  );

const loadImage = Effect.fn("Router.loadImage")(function* loadImage(
  file: string
) {
  if (paths.extname(file).toLowerCase() !== ".bin") {
    return yield* failure("provide an existing server-local .bin file");
  }

  const image = yield* Effect.tryPromise({
    try: async () => {
      const info = await stat(file);

      return info.isFile() ? await readFile(file) : null;
    },
    catch: () => failure("could not read the supplied file"),
  });

  if (image === null) {
    return yield* failure("provide an existing server-local .bin file");
  }

  if (image.length === 0) {
    return yield* failure("the supplied file is empty");
  }

  return image;
});

const registerSettings = (write: Register) => {
  write(
    "router_change",
    "Set, add or delete a router object instance. Pass its stack or parent stack as needed.",
    {
      ...changeFields,
      ...confirmField,
    },
    Effect.fn("Tools.routerChange")(function* routerChange(input, approve) {
      const change = yield* parseChange(input);
      yield* writePolicy([change.object]);
      const shown = JSON.stringify(mask(change.attributes));
      const address = input.stack ? ` at ${input.stack}` : "";
      const values = shown === "{}" ? "" : ` with ${shown}`;
      const summary = `${change.action} ${change.object}${address}${values}`;

      const current =
        !input.confirm && input.stack && input.action !== "add"
          ? mask(yield* firmware("read", change.object, change.stack, null))
          : null;

      return yield* applyApproved({
        approve,
        summary,
        confirm: input.confirm,
        details: { current },
        apply: firmware(
          "change",
          change.action,
          change.object,
          change.stack,
          change.parent_stack,
          change.attributes
        ),
      });
    })
  );
  write(
    "router_run",
    "Preview or run a published router operation.",
    {
      operation: z.string(),
      ...confirmField,
    },
    Effect.fn("Tools.routerRun")(function* routerRun(
      { operation, confirm },
      approve
    ) {
      const name = operation.trim().toUpperCase();
      const op = name.startsWith("ACT_") ? name : `ACT_${name}`;

      if (!objectName.test(op)) {
        return yield* failure("expected a firmware operation name");
      }

      yield* writePolicy([op]);

      return yield* applyApproved({
        confirm,
        approve,
        summary: `run ${name}`,
        apply: firmware("run", op),
      });
    })
  );
  write(
    "router_apply",
    "Apply ordered settings changes. Stops at the first failure and reports prior steps.",
    {
      steps: z.array(step).min(1),
      ...confirmField,
    },
    Effect.fn("Tools.routerApply")(function* routerApply(
      { steps, confirm },
      approve
    ) {
      const changes = [];

      for (const item of steps) {
        changes.push(yield* parseChange(item));
      }

      yield* writePolicy(changes.map((change) => change.object));

      const shown = mask(changes);

      return yield* applyApproved({
        confirm,
        approve,
        summary: `apply ${
          changes.length
        } ordered settings changes: ${JSON.stringify(shown)}`,
        apply: firmware("applySteps", changes),
        details: { steps: shown },
      });
    })
  );
};

const registerDiagnosticsAndMesh = (write: Register) => {
  write(
    "start_diagnostic",
    "Run one ping, traceroute or DNS lookup from the router.",
    {
      kind: z.enum(["ping", "traceroute", "nslookup"]),
      host: z.string().trim(),
      ...confirmField,
    },
    Effect.fn("Tools.startDiagnostic")(function* startDiagnostic(
      { kind, host, confirm },
      approve
    ) {
      if (!(isIP(host) || (host.length <= 253 && hostname.test(host)))) {
        return yield* failure("provide one IP address or DNS hostname");
      }

      yield* writePolicy([diagnosticObjects[kind], "ACT_TR143_STARTDIAG"]);

      return yield* applyApproved({
        confirm,
        approve,
        summary: `run ${kind} from the router to ${host}`,
        apply: firmware("startDiagnostic", kind, host),
      });
    })
  );
  write(
    "start_mesh_pairing",
    "Open the HB810 EasyMesh push-button pairing window.",
    confirmField,
    Effect.fn("Tools.startMeshPairing")(function* startMeshPairing(
      { confirm },
      approve
    ) {
      yield* writePolicy(["ACT_WIFI_START_WPS"]);

      return yield* applyApproved({
        confirm,
        approve,
        summary: "open the EasyMesh push-button pairing window",
        apply: firmware("meshPair"),
      });
    })
  );
  write(
    "manage_mesh_scan",
    "Start or refresh an EasyMesh scan, add a scanned MAC, or return to idle.",
    {
      action: z.enum(["start", "refresh", "add", "cancel"]),
      mac: z.string().default(""),
      ...confirmField,
    },
    Effect.fn("Tools.manageMeshScan")(function* manageMeshScan(
      { action, mac, confirm },
      approve
    ) {
      if (action !== "add" && mac) {
        return yield* failure("mac applies only when adding a scanned device");
      }

      const normalized = action === "add" ? yield* parseMac(mac) : "";

      if (action === "add") {
        yield* writePolicy([meshCandidate]);
      }

      if (action !== "refresh") {
        yield* writePolicy([meshScan]);
      }

      if (action === "start") {
        yield* writePolicy(["ACT_EASYMESH_UPDATE_AGENTINFO"]);
      }

      const summary = normalized
        ? `add scanned EasyMesh device ${normalized}`
        : `${action} EasyMesh scanning`;

      return yield* applyApproved({
        confirm,
        approve,
        summary,
        apply: firmware("meshScan", action, normalized),
      });
    })
  );
};

const registerFiles = (write: Register) => {
  const file = {
    path: z.string(),
    password: z.string().default(""),
    ...confirmField,
  };

  write(
    "export_router_file",
    "Save a router backup or OpenVPN profile to a new server-local file.",
    {
      ...file,
      kind: z.enum(["backup", "openvpn"]),
    },
    Effect.fn("Tools.exportRouterFile")(function* exportRouterFile(
      { kind, path, password, confirm },
      approve
    ) {
      yield* writePolicy([`EXPORT_${kind.toUpperCase()}`]);
      const target = localPath(path);

      const exists = yield* Effect.tryPromise({
        try: async () => {
          try {
            await lstat(target);

            return true;
          } catch (error) {
            if (missingFile(error)) {
              return false;
            }

            throw error;
          }
        },
        catch: () => failure("could not check the export destination"),
      });

      if (exists) {
        return yield* failure("export destination already exists");
      }

      if (password && kind !== "backup") {
        return yield* failure(
          "password applies only to a configuration backup"
        );
      }

      return yield* applyApproved({
        confirm,
        approve,
        summary: `save the router ${kind} export to ${target}`,
        apply: firmware("exportFile", kind, target, password),
      });
    })
  );
  write(
    "import_router_file",
    "Apply a backup restore or firmware upgrade from a local .bin file. May reboot the router.",
    {
      ...file,
      kind: z.enum(["restore", "firmware"]),
    },
    Effect.fn("Tools.importRouterFile")(function* importRouterFile(
      { kind, path, password, confirm },
      approve
    ) {
      yield* writePolicy(uploadRoutes[kind]);

      if (password && kind !== "restore") {
        return yield* failure(
          "password applies only to a configuration restore"
        );
      }

      const source = localPath(path);
      const image = yield* loadImage(source);
      const digest = createHash("sha256").update(image).digest("hex");

      const summary = `apply ${kind} from ${source} (SHA-256 ${
        digest
      }); the router may reboot and disconnect the network`;

      return yield* applyApproved({
        confirm,
        approve,
        summary,
        details: { sha256: digest, bytes: image.length },
        apply: Effect.suspend(() =>
          firmware(
            "importFile",
            kind,
            source,
            image.toString("base64"),
            password
          )
        ),
      });
    })
  );
};

const registerReservations = (write: Register) => {
  write(
    "set_static_ip",
    "Add or update a fixed IPv4 reservation for a MAC address.",
    {
      mac: z.string(),
      ip: z.string(),
      ...confirmField,
    },
    Effect.fn("Tools.setStaticIp")(function* setStaticIp(input, approve) {
      const mac = yield* parseMac(input.mac);
      const { ip, confirm } = input;

      if (isIP(ip) !== 4) {
        return yield* failure("provide an IPv4 address");
      }

      const plan = yield* readFirmware(
        reservationPlan,
        "reservationPlan",
        mac,
        ip
      );

      const [oid, same, taken] = plan;
      yield* writePolicy([oid]);

      if (taken) {
        return {
          status: notApplied,
          reason: `${ip} is already reserved for ${taken.chaddr ?? "another device"}`,
        };
      }

      let summary = `reserve ${ip} for ${mac}`;

      if (same) {
        summary = `change ${mac} reservation to ${ip}`;

        if (same.yiaddr !== undefined && same.yiaddr !== "") {
          summary = `change ${mac} reservation from ${same.yiaddr} to ${ip}`;
        }
      }

      return yield* applyApproved({
        confirm,
        approve,
        summary,
        apply: firmware("setReservation", mac, ip, plan),
      });
    })
  );
  write(
    "remove_static_ip",
    "Remove a fixed IPv4 reservation for a MAC address.",
    {
      mac: z.string(),
      ...confirmField,
    },
    Effect.fn("Tools.removeStaticIp")(function* removeStaticIp(input, approve) {
      const mac = yield* parseMac(input.mac);

      const [oid, rows] = yield* readFirmware(
        reservationRows,
        "reservationRows"
      );

      yield* writePolicy([oid]);

      const row = rows.find(
        (entry) => macKey(entry.chaddr ?? "") === macKey(mac)
      );

      if (!row) {
        return { status: notApplied, reason: `no reservation for ${mac}` };
      }

      return yield* applyApproved({
        approve,
        confirm: input.confirm,
        summary:
          row.yiaddr !== undefined && row.yiaddr !== ""
            ? `remove reservation ${row.yiaddr} for ${mac}`
            : `remove reservation for ${mac}`,
        apply: firmware("removeReservation", oid, row),
      });
    })
  );
};

const wifiInput = {
  network_index: z.int().nullish(),
  band: z.enum(["2.4GHz", "5GHz", "6GHz"]).nullish(),
  kind: z
    .enum(["primary", "guest", "iot", "mlo", "mssid1", "mssid2", "mssid3"])
    .default("primary"),
  ssid: z.string().default(""),
  password: z.string().default(""),
  enabled: z.boolean().nullish(),
  hidden: z.boolean().nullish(),
  ...confirmField,
};

const wifiSchema = z.object(wifiInput);

const wifiFields = (input: z.output<typeof wifiSchema>) => {
  const { band, kind, ssid, password, enabled, hidden } = input;
  const prefix = kind === "iot" ? "ioT" : kind;
  const enableField = kind === "iot" ? "ioTssidEnable" : `${prefix}Enable`;
  const fields: Record<string, string> = {};

  if (ssid) {
    fields[band ? `${prefix}SSID` : "SSID"] = ssid;
  }

  if (password) {
    fields[band ? `${prefix}PSK` : "X_TP_PreSharedKey"] = password;
  }

  if (enabled !== undefined && enabled !== null) {
    fields[band ? enableField : "Enable"] = enabled ? "1" : "0";
  }

  if (hidden !== undefined && hidden !== null) {
    fields[band ? `${prefix}SSIDAdvertise` : "SSIDAdvertisementEnabled"] =
      hidden ? "0" : "1";
  }

  return fields;
};

const setWifi = Effect.fn("Tools.setWifi")(function* setWifi(
  input: z.output<typeof wifiSchema>,
  approve: Approve
) {
  const { band, network_index: index, kind, password, confirm } = input;
  const hasIndex = index !== null && index !== undefined;

  if (Boolean(band) === hasIndex) {
    return yield* failure(
      "provide either an EX band or a legacy network index"
    );
  }

  yield* writePolicy([band ? "DEV2_ADT_WIFI_COMMON" : "LAN_WLAN"]);
  const length = password.match(/./gsu)?.length ?? 0;

  if (password && (length < 8 || length > 63)) {
    return yield* failure("a WPA password is 8 to 63 characters");
  }

  const fields = wifiFields(input);

  if (Object.keys(fields).length === 0) {
    return yield* failure("nothing to change");
  }

  const displayed = JSON.stringify(mask(fields));

  if (band) {
    return yield* applyApproved({
      confirm,
      approve,
      summary: `Wi-Fi ${band} ${kind}: ${displayed}`,
      apply: firmware("setWifi", band, fields),
    });
  }

  const stack = yield* parseStack(`1,${index}`);

  return yield* applyApproved({
    confirm,
    approve,
    summary: `Wi-Fi network ${index}: ${displayed}`,
    apply: firmware("change", setAction, "LAN_WLAN", stack, zeroStack, fields),
  });
});

/**
 * Register every tool that can change router state or write a local file.
 * @param write - MCP write tool registrar.
 */
export const registerWrites = (write: Register) => {
  registerSettings(write);
  registerDiagnosticsAndMesh(write);
  registerFiles(write);
  registerReservations(write);
  write(
    "set_wifi",
    "Change a single EX Wi-Fi profile by band and kind, or a legacy profile by index.",
    wifiInput,
    setWifi
  );
  write(
    "reboot_router",
    "Reboot the router. The local network and internet will briefly disconnect.",
    confirmField,
    Effect.fn("Tools.reboot")(function* reboot({ confirm }, approve) {
      yield* writePolicy(["ACT_REBOOT"]);

      if (!confirm) {
        return "Not rebooted. Call again with confirm=true to reboot.";
      }

      if (
        !(yield* approve(
          "reboot (network and internet drop for a minute or two)"
        ))
      ) {
        return "Not rebooted: the user did not approve it.";
      }

      yield* firmware("reboot");

      return "Reboot requested; the router is back in about two minutes.";
    })
  );
};
