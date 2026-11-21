import { homedir } from "node:os";
import path from "node:path";

import { Config, Schema } from "effect";

const taggedError = Schema.TaggedError;

/** A user-facing tool failure with a safe message. */
export class ToolFailure extends taggedError<ToolFailure>()("ToolFailure", {
  message: Schema.String,
}) {}

/** Configuration owned by the MCP application. */
export const configuration = Config.all({
  write: Config.String("TPLINK_WRITE").pipe(Config.withDefault("on")),
  interval: Config.Int("TPLINK_PRESENCE_INTERVAL").pipe(Config.withDefault(60)),
  stateDir: Config.String("TPLINK_STATE_DIR").pipe(Config.withDefault("")),
  stateHome: Config.String("XDG_STATE_HOME").pipe(
    Config.withDefault(path.join(homedir(), ".local", "state"))
  ),
  legacyStateEncoding: Config.String("TPLINK_LEGACY_STATE_ENCODING").pipe(
    Config.withDefault("")
  ),
  log: Config.String("TPLINK_LOG").pipe(Config.withDefault("WARNING")),
}).pipe(
  Config.map((config) => ({
    writesEnabled: !["off", "0", "false", "no"].includes(
      config.write.toLowerCase()
    ),
    interval: config.interval,
    stateDir:
      config.stateDir || path.join(config.stateHome, "tplink-modem-mcp"),
    legacyStateEncoding: config.legacyStateEncoding,
    log: config.log.toUpperCase(),
  }))
);

const secret =
  /(?:key|pass|psk|pwd|secret|pin|token|credential|community)(?!.*(?:enable|index|interval|failures|size))/iu;

const isScalar = Schema.is(
  Schema.Union([Schema.String, Schema.Number, Schema.Boolean, Schema.Null])
);

/**
 * Recursively mask secrets in a tool preview.
 * @param value - Preview data.
 * @returns A copy with sensitive fields masked.
 */
export const mask: (value: Schema.Json) => Schema.Json = (value) => {
  if (Array.isArray(value)) {
    return value.map(mask);
  }

  if (isScalar(value)) {
    return value;
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, field]) => [
      key,
      Boolean(field) && secret.test(key) ? "***" : mask(field),
    ])
  );
};
