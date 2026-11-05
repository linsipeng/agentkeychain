import { expect, test } from "bun:test";
import { CloudEngine } from "../src/cloud/engine.ts";
import { createDevice, signOperation } from "../src/cloud/device.ts";
import type { ManagedOperation, ManagedVersion, PullPage } from "../src/cloud/protocol.ts";
import { fixture, operation } from "./cloud-fixtures.ts";

const page = (versions: ManagedVersion[], hasMore = false): PullPage => ({ versions, nextCursor: versions.at(-1)?.serverSequence ?? 0, hasMore });
const transport = (pull: () => Promise<PullPage>) => ({ pull, push: async () => { throw new Error("unexpected push"); } });

test("pinned key rejects transport key substitution for an existing device", async () => {
  const { a, b } = await fixture();
  const attacker = await createDevice(a.record.vaultId, a.record.deviceId);
  const wire = { ...transport(async () => page([{ signed: await signOperation(attacker, operation()), serverSequence: 1 }])), device: async () => attacker.record };
  const engine = await CloudEngine.create(b, wire, [a.record, b.record]);
  await expect(engine.sync()).rejects.toThrow("signature");
  expect(engine.snapshot().cursor).toBe(0);
  expect(engine.head("opaque-object")).toBeUndefined();
});

test("replays and invalid transitions cannot advance cursor or resurrect a tombstone, including restart", async () => {
  const { a, b } = await fixture();
  const put = await signOperation(a, operation());
  const del = await signOperation(a, { ...operation(), operationId: "delete", kind: "delete", envelope: null, approvalRef: "approved-delete" });
  let response = page([{ signed: put, serverSequence: 1 }, { signed: del, serverSequence: 2 }]);
  let engine = await CloudEngine.create(b, transport(async () => response), [a.record, b.record]);
  await engine.sync();
  engine = await CloudEngine.create(b, transport(async () => response), [a.record, b.record], engine.snapshot());
  const before = engine.snapshot();
  const invalid: ManagedOperation[] = [
    operation(), { ...operation(), keyEpoch: 2 },
    { ...operation(), operationId: "fresh" },
    { ...operation(), operationId: "fresh", generation: 2 },
    { ...operation(), operationId: "restore", kind: "restore", generation: 2 },
    { ...operation(), operationId: "restore", kind: "restore", approvalRef: "grant" },
  ];
  for (const op of invalid) {
    response = page([{ signed: await signOperation(a, op), serverSequence: 3 }]);
    await expect(engine.sync()).rejects.toThrow();
    expect(engine.snapshot()).toEqual(before);
  }
  response = page([{ signed: await signOperation(a, { ...operation(), operationId: "restore", kind: "restore", generation: 2, approvalRef: "grant" }), serverSequence: 3 }]);
  await engine.sync();
  expect(engine.snapshot().cursor).toBe(3);
});

test("malformed pages fail atomically including promised continuation and acknowledged writes", async () => {
  const { a, b } = await fixture();
  const v = { signed: await signOperation(a, operation()), serverSequence: 1 };
  const w = { signed: await signOperation(a, { ...operation(), operationId: "second" }), serverSequence: 2 };
  for (const bad of [
    page([{ ...v, serverSequence: 2 }]), page([v, v]), page([v, { ...v, serverSequence: 2 }]),
    page([], true), { ...page([v]), nextCursor: 2 }, page([v, w]),
    { ...page([v]), hasMore: "false" } as unknown as PullPage,
  ]) {
    const engine = await CloudEngine.create(b, transport(async () => bad), [a.record, b.record], undefined, 1);
    await expect(engine.sync()).rejects.toThrow();
    expect(engine.snapshot().cursor).toBe(0);
  }
  let calls = 0;
  const engine = await CloudEngine.create(b, transport(async () => ++calls === 1 ? page([v], true) : { versions: [], nextCursor: 1, hasMore: false }), [a.record, b.record], undefined, 1);
  await expect(engine.sync()).rejects.toThrow();
  await expect(engine.sync()).rejects.toThrow();
  const restarted = await CloudEngine.create(b, transport(async () => ({ versions: [], nextCursor: 1, hasMore: false })), [a.record, b.record], engine.snapshot());
  await expect(restarted.sync()).rejects.toThrow();
  const acknowledged = await CloudEngine.create(a, { ...transport(async () => page([])), push: async () => ({ vaultId: a.record.vaultId, deviceId: a.record.deviceId, operationId: "op-1", serverSequence: 1 }) }, [a.record]);
  await acknowledged.enqueue(operation());
  await expect(acknowledged.sync()).rejects.toThrow();
});

test("snapshot validates signatures, complete history, unique heads/identities and transitions", async () => {
  const { a, b } = await fixture();
  const v = { signed: await signOperation(a, operation()), serverSequence: 1 };
  const engine = await CloudEngine.create(b, transport(async () => page([v])), [a.record, b.record]);
  await engine.sync();
  await engine.enqueue({ ...operation("device-b"), operationId: "pending" });
  const good = engine.snapshot();
  const clone = () => JSON.parse(JSON.stringify(good)) as typeof good;
  const bads = [];
  let bad = clone(); bad.pending[0]!.signed.signature = "bad"; bads.push(bad);
  bad = clone(); bad.heads[0]!.signed.signature = "bad"; bads.push(bad);
  bad = clone(); bad.heads.push(bad.heads[0]!); bads.push(bad);
  bad = clone(); bad.pending.push(bad.pending[0]!); bads.push(bad);
  bad = clone(); bad.cursor = 2; bads.push(bad);
  bad = clone(); bad.history.push({ ...v, serverSequence: 2 }); bad.cursor = 2; bads.push(bad);
  bad = clone(); bad.history[0]!.serverSequence = 0; bads.push(bad);
  bad = clone(); bad.history[0]!.signed = await signOperation(a, { ...operation(), generation: 2 }); bad.heads = bad.history; bads.push(bad);
  bad = clone(); bad.heads = []; bads.push(bad);
  bad = clone(); bad.heads[0]!.serverSequence = 2; bads.push(bad);
  bad = clone(); bad.pending[0]!.signed = v.signed; bads.push(bad);
  const forged = await createDevice(a.record.vaultId, a.record.deviceId);
  bad = clone(); bad.history[0]!.signed = await signOperation(forged, operation()); bad.heads = bad.history; bads.push(bad);
  bad = clone(); bad.history.push({ signed: await signOperation(a, { ...operation(), keyEpoch: 2 }), serverSequence: 2 }); bad.cursor = 2; bad.heads = [bad.history[1]!]; bads.push(bad);
  const del = { signed: await signOperation(a, { ...operation(), operationId: "delete", kind: "delete", envelope: null, approvalRef: "grant" }), serverSequence: 2 };
  const stale = { signed: await signOperation(a, { ...operation(), operationId: "stale" }), serverSequence: 3 };
  bad = clone(); bad.history.push(del, stale); bad.cursor = 3; bad.heads = [stale]; bads.push(bad);
  for (const snapshot of bads) await expect(CloudEngine.create(b, transport(async () => page([])), [a.record, b.record], snapshot)).rejects.toThrow();
  expect((await CloudEngine.create(b, transport(async () => page([])), [a.record, b.record], good)).snapshot()).toEqual(good);
});

test("client enforces generation and key epoch transitions while allowing another device's operation ID", async () => {
  const { a, b } = await fixture();
  const first = { signed: await signOperation(a, { ...operation(), keyEpoch: 2 }), serverSequence: 1 };
  let response = page([first]);
  const pins = [a.record, b.record].map(r => ({ ...r }));
  const engine = await CloudEngine.create(b, transport(async () => response), pins);
  pins[0]!.publicKey = b.record.publicKey; // Enrollment input cannot mutate the stored pin.
  await engine.sync();
  const before = engine.snapshot();
  for (const op of [
    { ...operation(), operationId: "epoch-regression" },
    { ...operation(), operationId: "generation-jump", generation: 2, keyEpoch: 2 },
    { ...operation(), operationId: "restore", kind: "restore" as const, generation: 2, approvalRef: "grant" },
    { ...operation(), operationId: "op-1", keyEpoch: 3 },
  ]) {
    response = page([{ signed: await signOperation(a, op), serverSequence: 2 }]);
    await expect(engine.sync()).rejects.toThrow();
    expect(engine.snapshot()).toEqual(before);
  }
  response = page([{ signed: await signOperation(b, { ...operation("device-b"), keyEpoch: 2 }), serverSequence: 2 }]);
  await engine.sync();
  expect(engine.snapshot().cursor).toBe(2);
});
