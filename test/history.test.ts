import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { ConfigProvider, Effect, Layer } from "effect";

import { firmwareLayer } from "../src/firmware.js";
import { History, historyLayer } from "../src/history.js";

const client = (suffix: string, ip: string) => ({
  mac: `aa:bb:cc:00:00:${suffix}`,
  hostname: "phone",
  active: true,
  connection: "2.4G",
  ip,
});

test("samples joins, leaves and IP changes across runs", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "tplink-history-"));

  const provider = ConfigProvider.layer(
    ConfigProvider.fromUnknown({ TPLINK_STATE_DIR: directory })
  );

  const storage = Layer.provide(
    historyLayer,
    Layer.merge(provider, firmwareLayer)
  );

  const sample = async (devices: readonly ReturnType<typeof client>[]) =>
    await Effect.runPromise(
      History.use((history) => history.sample(devices)).pipe(
        Effect.provide(storage)
      )
    );

  const query = async (mac: string) =>
    await Effect.runPromise(
      History.use((history) => history.query(24, mac, 200)).pipe(
        Effect.provide(storage)
      )
    );

  try {
    expect(
      await sample([
        client("01", "192.0.2.1"),
        client("02", "192.0.2.2"),
        { ...client("04", "192.0.2.4"), active: false },
      ])
    ).toEqual([]);
    expect(await query("")).toEqual([]);

    const changes = await sample([
      client("01", "192.0.2.10"),
      client("03", "192.0.2.3"),
    ]);

    expect(changes.map(({ event, mac }) => [event, mac])).toEqual([
      ["ip_change", "aa:bb:cc:00:00:01"],
      ["join", "aa:bb:cc:00:00:03"],
      ["leave", "aa:bb:cc:00:00:02"],
    ]);
    expect(await query("AA-BB-CC-00-00-01")).toEqual([
      expect.objectContaining({
        ip: "192.0.2.10",
        old_ip: "192.0.2.1",
      }),
    ]);
    expect(await query("")).toHaveLength(3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reads history and a snapshot written by the Python version", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "tplink-history-"));
  const previous = path.join(directory, "last.json");
  const events = path.join(directory, "presence.jsonl");

  const provider = ConfigProvider.layer(
    ConfigProvider.fromUnknown({ TPLINK_STATE_DIR: directory })
  );

  const storage = Layer.provide(
    historyLayer,
    Layer.merge(provider, firmwareLayer)
  );

  try {
    await writeFile(
      previous,
      '{"aa:bb:cc:00:00:01": {"ip": "192.0.2.1", "name": "téléphone", "connection": null}}'
    );
    await writeFile(
      events,
      `${JSON.stringify({
        t: Date.now() / 1000,
        event: "join",
        mac: "aa:bb:cc:00:00:01",
        ip: "192.0.2.1",
        name: "téléphone",
        connection: null,
      })}\ntruncated line\n`
    );

    const result = Effect.gen(function* readAndSample() {
      const history = yield* History;
      const before = yield* history.query(24, "", 1);
      const differences = yield* history.sample([]);

      return { before, differences };
    });

    const { before, differences } = await Effect.runPromise(
      result.pipe(Effect.provide(storage))
    );

    expect(before).toEqual([
      expect.objectContaining({ event: "join", name: "téléphone" }),
    ]);
    expect(differences).toEqual([
      expect.objectContaining({ event: "leave", name: "téléphone" }),
    ]);
    expect(await readFile(previous, "utf-8")).toBe("{}");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
