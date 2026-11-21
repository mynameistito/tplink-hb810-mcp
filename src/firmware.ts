import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { Context, Effect, Layer, Schema, Semaphore } from "effect";

import { ToolFailure } from "./policy.js";

const script = fileURLToPath(
  new URL("../src/firmware_bridge.py", import.meta.url)
);

const response = Schema.Union([
  Schema.Struct({ ok: Schema.Literal(true), value: Schema.Json }),
  Schema.Struct({ ok: Schema.Literal(false), message: Schema.String }),
]);

const decodeResponse = Schema.decodeUnknownEffect(
  Schema.fromJsonString(response)
);

const launch = () => {
  // oxlint-disable-next-line sonarjs/no-os-command-from-path -- uv is an explicit user-installed executable.
  const child = spawn("uv", ["run", "--locked", "--script", script], {
    stdio: ["pipe", "pipe", "inherit"],
    windowsHide: true,
  });

  const lines = createInterface({
    input: child.stdout,
    crlfDelay: Number.POSITIVE_INFINITY,
  });

  child.on("error", () => {
    lines.close();
  });
  child.stdin.on("error", () => {
    lines.close();
  });
  const replies = lines[Symbol.asyncIterator]();

  return {
    send: async (request: string) => {
      child.stdin.write(`${request}\n`, "utf-8");
      const reply = await replies.next();

      return reply.value ?? "";
    },
    close: () => {
      child.stdin.end();
      lines.close();
    },
  };
};

/** Router firmware calls, serialized through one local driver process. */
export class Firmware extends Context.Service<
  Firmware,
  {
    readonly request: (
      operation: string,
      ...args: readonly Schema.Json[]
    ) => Effect.Effect<Schema.Json, ToolFailure>;
  }
>()("tplink/Firmware") {}

/** Local firmware adapter backed by the existing TP-Link model drivers. */
export const firmwareLayer = Layer.effect(
  Firmware,
  Effect.gen(function* firmwareLayer() {
    const gate = yield* Semaphore.make(1);
    let worker: ReturnType<typeof launch> | null = null;

    const close = () => {
      worker?.close();
      worker = null;
    };

    yield* Effect.addFinalizer(() => Effect.sync(close));

    const request = Effect.fn("Firmware.request")(
      function* request(operation: string, ...args: readonly Schema.Json[]) {
        const message = JSON.stringify({ operation, args });

        const transportFailure =
          "firmware adapter unavailable or returned invalid data; check uv and router status before retrying";

        const received = yield* Effect.tryPromise({
          try: async () => {
            worker ??= launch();

            return await worker.send(message);
          },
          catch: () => new ToolFailure({ message: transportFailure }),
        }).pipe(
          Effect.flatMap(decodeResponse),
          Effect.mapError(() => {
            close();

            return new ToolFailure({ message: transportFailure });
          })
        );

        if (!received.ok) {
          return yield* new ToolFailure({ message: received.message });
        }

        return received.value;
      },
      (effect) => gate.withPermit(Effect.uninterruptible(effect))
    );

    return Firmware.of({ request });
  })
);

/** Call the driver from an Effect workflow. */
export const firmware = Effect.fn("Router.firmware")(function* firmware(
  operation: string,
  ...args: readonly Schema.Json[]
) {
  const driver = yield* Firmware;

  return yield* driver.request(operation, ...args);
});

/**
 * Decode a typed firmware result before using its fields.
 * @param schema - Expected response.
 * @param operation - Firmware operation.
 * @param args - Arguments passed to the firmware adapter.
 * @returns The decoded firmware response.
 */
export const readFirmware = <A extends Schema.Json>(
  schema: Schema.Codec<A>,
  operation: string,
  ...args: readonly Schema.Json[]
) =>
  Effect.gen(function* readFirmwareResult() {
    const value = yield* firmware(operation, ...args);

    return yield* Schema.decodeUnknownEffect(schema)(value).pipe(
      Effect.mapError(
        () =>
          new ToolFailure({
            message: `unexpected data from firmware operation ${operation}`,
          })
      )
    );
  });
