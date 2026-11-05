import { expect, test } from "bun:test";
import { canonicalOperation, parseCanonicalOperation } from "../src/cloud/protocol.ts";
import { createDevice, signOperation, verifyOperation } from "../src/cloud/device.ts";

import { operation } from "./cloud-fixtures.ts";

test("canonical operation normalizes object order; wire rejects noncanonical or unknown fields", () => {
  const op = operation();
  const reversed = Object.fromEntries(Object.entries(op).reverse());
  expect(canonicalOperation(reversed)).toBe(canonicalOperation(op));
  expect(parseCanonicalOperation(canonicalOperation(op))).toEqual(op);
  expect(() => parseCanonicalOperation(JSON.stringify(reversed))).toThrow();
  for (const bad of [{ ...op, extra: 1 }, { ...op, generation: 0 }, { ...op, keyEpoch: NaN },
    { ...op, envelope: { ...op.envelope, plaintext: "bad" } }, { ...op, envelope: null },
    { ...op, kind: "delete" }, { ...op, protocolVersion: 3 }]) {
    expect(() => canonicalOperation(bad)).toThrow();
  }
});

test("independent Ed25519 devices bind every operation field and reject tampering", async () => {
  const a = await createDevice("synthetic-vault", "device-a");
  const b = await createDevice("synthetic-vault", "device-b");
  expect(a.record.publicKey).not.toBe(b.record.publicKey);
  const op = operation();
  const signed = await signOperation(a, op);
  expect(await verifyOperation(a.record, signed)).toBe(true);
  expect(await verifyOperation(b.record, signed)).toBe(false);
  for (const [field, value] of Object.entries({ protocolVersion: 3, vaultId: "other", objectId: "other", deviceId: "other", operationId: "other", kind: "restore", generation: 2, keyEpoch: 2, envelope: null, approvalRef: "grant" })) {
    const changed = JSON.parse(signed.canonical);
    changed[field] = value;
    expect(await verifyOperation(a.record, { ...signed, canonical: JSON.stringify(changed) })).toBe(false);
  }
  expect(await verifyOperation(a.record, { ...signed, signature: "bad" })).toBe(false);
});
