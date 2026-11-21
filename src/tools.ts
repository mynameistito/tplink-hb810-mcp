import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Config } from "effect";
import { Effect, Schema } from "effect";
import * as z from "zod";

import { firmware, readFirmware } from "./firmware.js";
import type { Firmware } from "./firmware.js";
import { device, History, macKey } from "./history.js";
import { configuration, ToolFailure } from "./policy.js";
import { registerWrites } from "./writes.js";

/** Runtime requirements shared by the MCP tools. */
export type ToolEffect = Effect.Effect<
  Schema.Json,
  ToolFailure | Config.ConfigError,
  Firmware | History
>;

/** Ask the MCP client to approve a specific change when it supports elicitation. */
export type Approve = (summary: string) => Effect.Effect<boolean, ToolFailure>;

type ToolFields = Record<string, z.ZodType>;

/** Bind a typed tool implementation to MCP registration. */
export type Register = <S extends ToolFields>(
  name: string,
  description: string,
  fields: S,
  handler: (input: z.output<z.ZodObject<S>>, approve: Approve) => ToolEffect
) => void;

const catalog = Schema.Struct({
  objects: Schema.Array(Schema.String),
  operations: Schema.Array(Schema.String),
});

const logEntry = Schema.Struct({
  severity: Schema.Int,
  module: Schema.String,
  message: Schema.String,
});

const severity = [
  "emerg",
  "alert",
  "crit",
  "err",
  "warn",
  "notice",
  "info",
  "debug",
];

const logRows = Schema.Array(
  Schema.StructWithRest(logEntry, [Schema.JsonObject])
);

const devices = Schema.Array(
  Schema.StructWithRest(device, [Schema.JsonObject])
);

/** Sample the router's current clients into persistent history. */
export const samplePresence = Effect.fn("Presence.sample")(
  function* samplePresence() {
    const history = yield* History;

    const snapshot = yield* readFirmware(
      Schema.Array(device),
      "clients",
      false
    );

    return yield* history.sample(snapshot);
  }
);

type RunTool = (
  effect: Effect.Effect<CallToolResult, never, Firmware | History>,
  signal: AbortSignal
) => Promise<CallToolResult>;

const approveWithClient: (server: McpServer, signal: AbortSignal) => Approve =
  (server, signal) => (summary) =>
    Effect.tryPromise({
      try: async () => {
        if (!server.server.getClientCapabilities()?.elicitation) {
          return true;
        }

        const result = await server.server.elicitInput(
          {
            message: `Change the router: ${summary}`,
            requestedSchema: {
              type: "object",
              properties: {
                approve: {
                  type: "boolean",
                  description: "Apply this change to the router",
                },
              },
              required: ["approve"],
            },
          },
          { signal }
        );

        return result.action === "accept" && result.content?.approve === true;
      },
      catch: () =>
        new ToolFailure({
          message: "could not confirm approval with the MCP client",
        }),
    });

const asError = (message: string) =>
  ({
    content: [{ type: "text", text: message }],
    isError: true,
  }) satisfies CallToolResult;

const isText = Schema.is(Schema.String);
const isList = Schema.is(Schema.Array(Schema.Json));

const listOutputs = new Set([
  "list_clients",
  "find_client",
  "client_history",
  "wifi_networks",
  "router_logs",
  "dhcp_leases",
  "dhcp_reservations",
  "router_read",
  "mesh_pairing_status",
]);

const listOutput = { result: z.array(z.record(z.string(), z.json())) };
const textOutput = { result: z.string() };

const asResult = (value: Schema.Json) => {
  if (isList(value)) {
    return {
      content: value.map((row) => ({
        type: "text" as const,
        text: JSON.stringify(row, null, 2),
      })),
      structuredContent: { result: value },
    } satisfies CallToolResult;
  }

  if (isText(value)) {
    return {
      content: [{ type: "text", text: value }],
      structuredContent: { result: value },
    } satisfies CallToolResult;
  }

  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  } satisfies CallToolResult;
};

const makeRegister: (
  server: McpServer,
  run: RunTool,
  write: boolean
) => Register =
  (server, run, write) => (name, description, fields, handler) => {
    const inputSchema: ToolFields = fields;
    const parse = z.object(fields);

    const options: Parameters<
      typeof server.registerTool<ToolFields, ToolFields>
    >[1] = {
      description,
      inputSchema,
      annotations: write
        ? { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
        : { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    };

    if (listOutputs.has(name)) {
      options.outputSchema = listOutput;
    } else if (name === "reboot_router") {
      options.outputSchema = textOutput;
    }

    server.registerTool<ToolFields, ToolFields>(
      name,
      options,
      async (input, { signal }) => {
        const args = parse.safeParse(input);

        if (!args.success) {
          return asError("invalid tool arguments");
        }

        const approve = approveWithClient(server, signal);

        return await run(
          handler(args.data, approve).pipe(
            Effect.match({
              onFailure: (failure) => asError(failure.message),
              onSuccess: asResult,
            })
          ),
          signal
        );
      }
    );
  };

/** Register the public MCP tool surface. */
export const registerTools = Effect.fn("MCP.registerTools")(
  function* registerTools(server: McpServer, run: RunTool) {
    const config = yield* configuration;

    const read = makeRegister(server, run, false);
    read(
      "router_status",
      "Model, firmware, internet and LAN status, enabled Wi-Fi and online device count.",
      {},
      () => firmware("status")
    );
    read(
      "list_clients",
      "Network devices with IP, MAC, Wi-Fi signal in dBm and link rate where available.",
      {
        include_inactive: z.boolean().default(false),
      },
      ({ include_inactive }) =>
        readFirmware(devices, "clients", true).pipe(
          Effect.map((entries) =>
            entries.filter((entry) => include_inactive || entry.active)
          )
        )
    );
    read(
      "find_client",
      "Find devices by part of their hostname, IP or MAC address.",
      { query: z.string() },
      ({ query }) =>
        readFirmware(devices, "clients", true).pipe(
          Effect.map((entries) => {
            const needle = macKey(query);

            return entries.filter(
              (entry) =>
                entry.hostname?.toLowerCase().includes(needle) === true ||
                entry.ip?.includes(needle) === true ||
                macKey(entry.mac).includes(needle)
            );
          })
        )
    );
    read(
      "client_history",
      "Join, leave and IP-change events recorded by the presence sampler.",
      {
        since_hours: z.number().default(24),
        mac: z.string().default(""),
        limit: z.int().default(200),
      },
      ({ since_hours, mac, limit }) =>
        History.use((history) => history.query(since_hours, mac, limit))
    );
    read(
      "wifi_networks",
      "Configured SSIDs, bands, channels, standards and enabled state.",
      {},
      () => firmware("wifi")
    );
    read(
      "router_logs",
      "Newest router log entries first. Severity 0 is emergency and 7 includes debug.",
      {
        module: z.string().default(""),
        contains: z.string().default(""),
        max_severity: z.int().default(7),
        limit: z.int().default(100),
      },
      ({ module, contains, max_severity, limit }) =>
        readFirmware(logRows, "logs").pipe(
          Effect.map((entries) =>
            entries
              .filter(
                (entry) =>
                  (!module || entry.module === module.toUpperCase()) &&
                  entry.severity <= max_severity &&
                  entry.message.toLowerCase().includes(contains.toLowerCase())
              )
              .slice(0, Math.max(1, limit))
              .map((entry) => ({
                ...entry,
                severity: severity[entry.severity] ?? entry.severity,
              }))
          )
        )
    );
    read("dhcp_leases", "Active DHCP leases.", {}, () => firmware("leases"));
    read("dhcp_reservations", "Configured DHCP address reservations.", {}, () =>
      firmware("reservations")
    );
    read(
      "ipv6_status",
      "IPv6 status including WAN address, gateway and DNS when available.",
      {},
      () => firmware("ipv6")
    );
    read(
      "router_objects",
      "List object and operation names published by the router firmware.",
      {
        contains: z.string().default(""),
      },
      ({ contains }) =>
        readFirmware(catalog, "catalog").pipe(
          Effect.map(({ objects, operations }) => {
            const needle = contains.toUpperCase();

            return {
              objects: objects.filter((name) => name.includes(needle)),
              operations: operations.filter((name) => name.includes(needle)),
            };
          })
        )
    );
    read(
      "router_read",
      "Read a firmware object and its instance stacks. Optionally limit the fields returned.",
      {
        object: z.string(),
        stack: z.string().default(""),
        attributes: z.array(z.string()).nullish(),
      },
      (input) =>
        firmware("read", input.object, input.stack, input.attributes ?? null)
    );

    read(
      "diagnostic_status",
      "Read the most recent EX router diagnostic.",
      {
        kind: z.enum(["ping", "traceroute", "nslookup"]),
      },
      ({ kind }) => firmware("diagnosticStatus", kind)
    );
    read(
      "mesh_pairing_status",
      "Read per-radio EasyMesh pairing state.",
      {},
      () => firmware("meshPairStatus")
    );
    read(
      "mesh_scan_status",
      "Read EasyMesh scan state and cached candidates.",
      {},
      () => firmware("meshScanStatus")
    );

    if (config.writesEnabled) {
      registerWrites(makeRegister(server, run, true));
    }
  }
);
