import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import {
  appendFile,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

import {
  Clock,
  Context,
  Effect,
  Layer,
  Option,
  Schema,
  Semaphore,
} from "effect";

import { Firmware } from "./firmware.js";
import { configuration, ToolFailure } from "./policy.js";

const optionalText = Schema.optionalKey(Schema.NullOr(Schema.String));

const presence = Schema.Struct({
  ip: optionalText,
  name: optionalText,
  connection: optionalText,
});

const snapshot = Schema.Record(Schema.String, presence);

const event = Schema.Struct({
  ...presence.fields,
  mac: Schema.String,
  t: Schema.Number,
  event: Schema.Literals(["join", "leave", "ip_change"]),
  old_ip: optionalText,
});

type PresenceEvent = typeof event.Type;

const parseSnapshot = Schema.decodeUnknownOption(
  Schema.fromJsonString(snapshot)
);

const parseEvent = Schema.decodeUnknownOption(Schema.fromJsonString(event));

const missingFile = Schema.is(
  Schema.Struct({ code: Schema.Literal("ENOENT") })
);

/** Device fields used by presence tracking and client search. */
export const device = Schema.Struct({
  mac: Schema.String,
  ip: optionalText,
  hostname: optionalText,
  connection: optionalText,
  active: Schema.Boolean,
});

/** Presence storage uses the same JSON and JSONL files as earlier versions. */
export class History extends Context.Service<
  History,
  {
    readonly sample: (
      devices: readonly (typeof device.Type)[]
    ) => Effect.Effect<readonly PresenceEvent[], ToolFailure>;
    readonly query: (
      hours: number,
      mac: string,
      limit: number
    ) => Effect.Effect<
      readonly (PresenceEvent & { time: string })[],
      ToolFailure
    >;
  }
>()("tplink/History") {}

const readOptional = (file: string) =>
  Effect.tryPromise({
    try: async () => {
      try {
        return await readFile(file);
      } catch (error) {
        if (missingFile(error)) {
          return Buffer.alloc(0);
        }

        throw error;
      }
    },
    catch: () =>
      new ToolFailure({ message: "could not read presence history" }),
  });

const utf8 = new TextDecoder("utf-8", { fatal: true });
const decodeText = Schema.decodeUnknownEffect(Schema.String);

const encodeState = (value: Schema.Json) =>
  JSON.stringify(value).replaceAll(/[^\u0020-\u007E]/gu, (character) =>
    Array.from(
      { length: character.length },
      (_, index) =>
        `\\u${(character[index]?.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}`
    ).join("")
  );

const padded = (number: number) => String(number).padStart(2, "0");

const localTime = (seconds: number) => {
  const date = new Date(seconds * 1000);

  return [
    [
      date.getFullYear(),
      padded(date.getMonth() + 1),
      padded(date.getDate()),
    ].join("-"),
    [date.getHours(), date.getMinutes(), date.getSeconds()]
      .map(padded)
      .join(":"),
  ].join(" ");
};

/**
 * Normalize separator and case for MAC comparisons.
 * @param value - MAC address or search text.
 * @returns Normalized text.
 */
export const macKey = (value: string) =>
  value.toLowerCase().replaceAll("-", ":");

/** Implement presence sampling and lookup against the configured state directory. */
export const historyLayer = Layer.effect(
  History,
  Effect.gen(function* historyLayer() {
    const { stateDir, legacyStateEncoding } = yield* configuration;
    const driver = yield* Firmware;

    const readState = Effect.fn("History.readState")(function* readState(
      file: string
    ) {
      const contents = yield* readOptional(file);

      const decodeLegacy = driver
        .request(
          "decodeLegacyState",
          contents.toString("base64"),
          legacyStateEncoding
        )
        .pipe(
          Effect.flatMap((value) => decodeText(value)),
          Effect.mapError(
            () =>
              new ToolFailure({
                message:
                  "could not decode legacy presence history; check TPLINK_LEGACY_STATE_ENCODING",
              })
          )
        );

      if (legacyStateEncoding !== "" && contents.length > 0) {
        return yield* decodeLegacy;
      }

      return yield* Effect.try(() => utf8.decode(contents)).pipe(
        Effect.catch(() => decodeLegacy)
      );
    });

    const previousPath = path.join(stateDir, "last.json");
    const eventPath = path.join(stateDir, "presence.jsonl");
    const gate = yield* Semaphore.make(1);

    const sample = Effect.fn("History.sample")(
      function* sample(devices: readonly (typeof device.Type)[]) {
        const now = (yield* Clock.currentTimeMillis) / 1000;

        const current = Object.fromEntries(
          devices
            .values()
            .filter((entry) => entry.mac !== "" && entry.active)
            .map((entry) => [
              entry.mac,
              {
                ip: entry.ip ?? null,
                name: entry.hostname ?? null,
                connection: entry.connection ?? null,
              },
            ])
        );

        const previous = parseSnapshot(yield* readState(previousPath));
        const events: PresenceEvent[] = [];

        if (Option.isSome(previous)) {
          const last = new Map(Object.entries(previous.value));

          for (const [mac, entry] of Object.entries(current)) {
            const prior = last.get(mac);

            if (!prior) {
              events.push({ t: now, mac, event: "join", ...entry });
            } else if (prior.ip !== entry.ip) {
              events.push({
                t: now,
                mac,
                event: "ip_change",
                old_ip: prior.ip ?? null,
                ...entry,
              });
            }

            last.delete(mac);
          }

          for (const [mac, entry] of last) {
            events.push({ t: now, mac, event: "leave", ...entry });
          }
        }

        yield* Effect.tryPromise({
          try: async () => {
            await mkdir(stateDir, { recursive: true, mode: 0o700 });
            const temp = path.join(stateDir, `last.${randomUUID()}.tmp`);

            try {
              await writeFile(temp, encodeState(current), {
                flag: "wx",
                mode: 0o600,
              });
              await rename(temp, previousPath);
            } finally {
              await rm(temp, { force: true });
            }

            if (events.length > 0) {
              const lines = events.map(encodeState).join("\n");

              await appendFile(eventPath, `${lines}\n`, { mode: 0o600 });
            }
          },
          catch: () =>
            new ToolFailure({ message: "could not record presence history" }),
        });

        return events;
      },
      (effect) => gate.withPermit(Effect.uninterruptible(effect))
    );

    const query = Effect.fn("History.query")(
      function* query(hours: number, mac: string, limit: number) {
        const cutoff = (yield* Clock.currentTimeMillis) / 1000 - hours * 3600;
        const key = macKey(mac);

        const entries = (yield* readState(eventPath))
          .split("\n")
          .flatMap((line) => {
            const decoded = parseEvent(line);

            if (Option.isNone(decoded)) {
              return [];
            }

            const entry = decoded.value;

            return entry.t >= cutoff && (!key || macKey(entry.mac) === key)
              ? [{ ...entry, time: localTime(entry.t) }]
              : [];
          });

        return entries.slice(-limit);
      },
      (effect) => gate.withPermit(effect)
    );

    return History.of({ sample, query });
  })
);
