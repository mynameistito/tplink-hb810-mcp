#!/usr/bin/env node
import process from "node:process";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Effect, Layer, Schedule } from "effect";

import manifest from "../package.json" with { type: "json" };
import type { Firmware } from "./firmware.js";
import { firmwareLayer } from "./firmware.js";
import type { History } from "./history.js";
import { historyLayer } from "./history.js";
import { configuration, ToolFailure } from "./policy.js";
import { registerTools, samplePresence } from "./tools.js";

const instructions =
  "Manage a TP-Link router or ISP modem on its local network. " +
  "For a change, call the tool without confirmation, show the preview to the user, and call again with confirm=true only after approval. " +
  "Use router_objects and router_read to discover firmware settings. For connection drops, combine list_clients, client_history and router_logs.";

const serve = Effect.gen(function* serve() {
  const config = yield* configuration;
  const context = yield* Effect.context<Firmware | History>();
  const run = Effect.runPromiseWith(context);

  const server = new McpServer(
    { name: "tplink-hb810", version: manifest.version },
    { instructions }
  );

  const transport = new StdioServerTransport();
  yield* registerTools(
    server,
    async (effect, signal) => await run(effect, { signal })
  );
  yield* Effect.acquireRelease(
    Effect.tryPromise({
      try: async () => {
        await server.connect(transport);
      },
      catch: () =>
        new ToolFailure({ message: "could not start the MCP stdio server" }),
    }),
    () =>
      Effect.promise(async () => {
        await server.close();
      })
  );

  if (config.interval > 0) {
    yield* samplePresence().pipe(
      Effect.catch((error) =>
        Effect.sync(() => {
          if (config.log === "DEBUG") {
            process.stderr.write(`Presence sample failed: ${error.message}\n`);
          }
        })
      ),
      Effect.repeat(Schedule.spaced(config.interval * 1000)),
      Effect.forkScoped
    );
  }

  yield* Effect.callback<null>((resume) => {
    const finish = () => {
      resume(Effect.succeed(null));
    };

    process.stdin.once("end", finish);
    process.stdin.once("close", finish);
    process.once("SIGINT", finish);
    process.once("SIGTERM", finish);

    if (process.stdin.readableEnded) {
      finish();
    }

    return Effect.sync(() => {
      process.stdin.off("end", finish);
      process.stdin.off("close", finish);
      process.off("SIGINT", finish);
      process.off("SIGTERM", finish);
    });
  });
});

const sample = samplePresence().pipe(
  Effect.tap((events) =>
    Effect.sync(() => {
      for (const event of events) {
        process.stdout.write(`${JSON.stringify(event)}\n`);
      }
    })
  )
);

const program =
  process.argv.length === 3 && process.argv[2] === "sample" ? sample : serve;

await Effect.runPromise(
  program.pipe(
    Effect.scoped,
    Effect.provide(Layer.provideMerge(historyLayer, firmwareLayer)),
    Effect.catch((error) =>
      Effect.sync(() => {
        process.stderr.write(`${error.message}\n`);
        process.exitCode = 1;
      })
    )
  )
);
