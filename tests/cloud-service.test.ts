import { expect, test } from "bun:test";
import { createDevice, signOperation, verifyOperation } from "../src/cloud/device.ts";
import { MemoryRepository } from "../src/cloud/service.ts";
import { type ManagedOperation } from "../src/cloud/protocol.ts";
import { operation } from "./cloud-fixtures.ts";

import { fixture, approve } from "./cloud-fixtures.ts";

test("service atomic receive order, idempotency conflicts, immutable history and pagination", async () => {
  const { service, a, b } = await fixture();
  const first = await signOperation(a, operation());
  const results = await Promise.all([service.push(first), service.push(first)]);
  expect(results[0]).toEqual(results[1]);
  expect(results[0]!.serverSequence).toBe(1);
  const other = await signOperation(b, { ...operation("device-b"), operationId: "op-2" });
  expect((await service.push(other)).serverSequence).toBe(2);
  expect(service.head("synthetic-vault", "opaque-object")!.signed).toEqual(other);
  expect(service.history("synthetic-vault", "opaque-object")).toHaveLength(2);
  const page = service.pull("synthetic-vault", 0, 1);
  expect(page.hasMore).toBe(true); expect(page.nextCursor).toBe(1);
  page.versions[0]!.signed.signature = "mutated";
  expect(service.pull("synthetic-vault", 0, 1).versions[0]!.signed).toEqual(first);
  expect(service.pull("synthetic-vault", 1, 1).nextCursor).toBe(2);
  expect(() => service.pull("synthetic-vault", -1, 1)).toThrow();
  expect(() => service.pull("synthetic-vault", 0, 0)).toThrow();
  await expect(service.push(await signOperation(a, { ...operation(), keyEpoch: 2 }))).rejects.toThrow("idempotency");
});

test("delete and restore require bound approval, generation barriers survive restore", async () => {
  const { service, approvals, a, b } = await fixture();
  await service.push(await signOperation(a, operation()));
  const del: ManagedOperation = { ...operation(), operationId: "delete", kind: "delete", envelope: null, approvalRef: "delete-grant" };
  await expect(service.push(await signOperation(a, del))).rejects.toThrow("approval");
  approve(approvals, del);
  await service.push(await signOperation(a, del));
  const stale = await signOperation(b, operation("device-b"));
  await expect(service.push(stale)).rejects.toThrow("generation");
  await expect(service.push(await signOperation(b, { ...operation("device-b"), generation: 2 }))).rejects.toThrow("generation");
  const restore: ManagedOperation = { ...operation(), operationId: "restore", kind: "restore", generation: 2, approvalRef: "restore-grant" };
  await expect(service.push(await signOperation(a, restore))).rejects.toThrow("approval");
  approve(approvals, restore);
  await expect(service.push(await signOperation(a, { ...restore, keyEpoch: 2 }))).rejects.toThrow("approval");
  const signed = await signOperation(a, restore);
  const receipt = await service.push(signed);
  expect(await service.push(signed)).toEqual(receipt);
  await expect(service.push(stale)).rejects.toThrow("generation");
  expect(service.history("synthetic-vault", "opaque-object")).toHaveLength(3);
});

test("device membership, revocation and tampered signatures fail closed", async () => {
  const { service, a } = await fixture();
  const signed = await signOperation(a, operation());
  await expect(service.push({ ...signed, signature: "bad" })).rejects.toThrow("signature");
  const stranger = await createDevice("other-vault", "device-a");
  await expect(service.push(await signOperation(stranger, { ...operation(), vaultId: "other-vault" }))).rejects.toThrow("device");
  await service.push(signed);
  service.revokeDevice("synthetic-vault", "device-a");
  await expect(service.push(signed)).rejects.toThrow("revoked");
  expect(await verifyOperation({ ...a.record, revoked: true }, signed)).toBe(true);
  expect(() => service.registerDevice(a.record)).toThrow();
});

test("per-vault sequences and device-scoped operation identities are isolated", async () => {
  const { service, a, b } = await fixture();
  expect((await service.push(await signOperation(a, operation()))).serverSequence).toBe(1);
  expect((await service.push(await signOperation(b, operation("device-b")))).serverSequence).toBe(2);
  const other = await createDevice("second-vault", "device-a");
  service.registerDevice(other.record);
  expect((await service.push(await signOperation(other, { ...operation(), vaultId: "second-vault" }))).serverSequence).toBe(1);
  expect(service.pull("synthetic-vault", 0).versions).toHaveLength(2);
  expect(service.pull("second-vault", 0).versions).toHaveLength(1);
  await expect(service.push(await signOperation(a, { ...operation(), objectId: "conflict" }))).rejects.toThrow("idempotency");
});

test("revocation between asynchronous verification and acceptance rejects without a version", async () => {
  const { ManagedService } = await import("../src/cloud/service.ts");
  class RacingRepository extends MemoryRepository {
    beforeAccept: (() => void) | undefined;
    override transaction<T>(...args: Parameters<MemoryRepository["transaction"]>): T {
      const hook = this.beforeAccept; this.beforeAccept = undefined; hook?.();
      return super.transaction(...args) as T;
    }
  }
  const repo = new RacingRepository();
  const service = new ManagedService(repo);
  const a = await createDevice("synthetic-vault", "device-a");
  service.registerDevice(a.record);
  repo.beforeAccept = () => service.revokeDevice(a.record.vaultId, a.record.deviceId);
  await expect(service.push(await signOperation(a, operation()))).rejects.toThrow("revoked");
  expect(service.pull(a.record.vaultId, 0).versions).toHaveLength(0);
});

test("service rejects expired approval and cross-operation nonce reuse", async () => {
  const { ManagedService } = await import("../src/cloud/service.ts");
  const { MemoryApprovals } = await import("../src/auth/approval.ts");
  const approvals = new MemoryApprovals();
  let now = 1000;
  const service = new ManagedService(new MemoryRepository(), approvals, () => now);
  const a = await createDevice("synthetic-vault", "device-a");
  service.registerDevice(a.record);
  await service.push(await signOperation(a, operation()));
  const del: ManagedOperation = { ...operation(), operationId: "delete", kind: "delete", envelope: null, approvalRef: "grant" };
  approve(approvals, del);
  await expect(service.push(await signOperation(a, del))).rejects.toThrow("approval");
  expect(service.pull(a.record.vaultId, 0).versions).toHaveLength(1);
  now = 10;
  await expect(service.push(await signOperation(a, { ...del, operationId: "swapped" }))).rejects.toThrow("approval");
  await service.push(await signOperation(a, del));
  await expect(service.push(await signOperation(a, { ...operation(), operationId: "restore", kind: "restore", generation: 2, approvalRef: "grant" }))).rejects.toThrow("approval");
  expect(service.pull(a.record.vaultId, 0).versions).toHaveLength(2);
});
