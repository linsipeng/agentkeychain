import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { CloudEngine } from "../src/cloud/engine.ts";
import { LocalTransport } from "../src/cloud/transport.ts";
import { encrypt, decrypt } from "../src/crypto/xchacha.ts";
import { signOperation } from "../src/cloud/device.ts";
import { parseCanonicalOperation, type ManagedOperation } from "../src/cloud/protocol.ts";
import { fixture, approve } from "./cloud-fixtures.ts";
import { operation } from "./cloud-fixtures.ts";

test("two isolated clients: ciphertext, offline receive order, lost response/restart, pagination, delete/restore, revoke", async () => {
  const roots = [mkdtempSync(join(tmpdir(), "akc-cloud-a-")), mkdtempSync(join(tmpdir(), "akc-cloud-b-"))];
  const saved = process.env.AGENTKEYCHAIN_HOME;
  const { service, approvals, a, b } = await fixture();
  const key = new Uint8Array(32).fill(7); // synthetic vault key; memory only
  try {
    const payload = async (value: string) => {
      const encrypted = await encrypt(value, key);
      return { nonce: Buffer.from(encrypted.nonce).toString("base64"), ciphertext: Buffer.from(encrypted.ciphertext).toString("base64") };
    };
    const transport = new LocalTransport(service);
    let drop = true;
    const lostResponse = {
      push: async (signed: Parameters<typeof transport.push>[0]) => {
        const receipt = await transport.push(signed);
        if (drop) { drop = false; throw new Error("synthetic lost response"); }
        return receipt;
      },
      pull: transport.pull.bind(transport),
    };
    process.env.AGENTKEYCHAIN_HOME = roots[0];
    let ca = await CloudEngine.create(a, lostResponse, [a.record, b.record], undefined, 1);
    process.env.AGENTKEYCHAIN_HOME = roots[1];
    const cb = await CloudEngine.create(b, transport, [a.record, b.record], undefined, 1);
    const create = { ...operation(), envelope: await payload("synthetic-initial") };
    await ca.enqueue(create);
    const bytes = ca.snapshot().pending[0]!.signed;
    await expect(ca.sync()).rejects.toThrow("lost response");
    expect(ca.state).toBe("backoff");
    expect(service.history(create.vaultId, create.objectId)).toHaveLength(1);
    ca = await CloudEngine.create(a, lostResponse, [a.record, b.record], ca.snapshot(), 1);
    expect(ca.snapshot().pending[0]!.signed).toEqual(bytes);
    await ca.sync(); await cb.sync();
    expect(ca.state).toBe("idle"); expect(cb.pendingCount).toBe(0);
    expect(cb.head(create.objectId)).toEqual(ca.head(create.objectId));
    // Both updates were queued offline. The later server acceptance wins.
    await ca.enqueue({ ...create, operationId: "a-update", envelope: await payload("synthetic-A") });
    await cb.enqueue({ ...create, deviceId: "device-b", operationId: "b-update", envelope: await payload("synthetic-B") });
    await cb.sync(); await ca.sync(); await cb.sync();
    const history = service.history(create.vaultId, create.objectId);
    expect(history.map(v => v.serverSequence)).toEqual([1, 2, 3]);
    const current = parseCanonicalOperation(cb.head(create.objectId)!.signed.canonical);
    expect(current.operationId).toBe("a-update");
    expect(new TextDecoder().decode(await decrypt(Buffer.from(current.envelope!.ciphertext, "base64"), Buffer.from(current.envelope!.nonce, "base64"), key))).toBe("synthetic-A");
    expect(cb.snapshot().cursor).toBe(3);
    const stale = { ...create, deviceId: "device-b", operationId: "stale" };
    const del: ManagedOperation = { ...create, operationId: "delete", kind: "delete", envelope: null, approvalRef: "confirm-delete" };
    approve(approvals, del); await ca.enqueue(del); await ca.sync(); await cb.sync();
    expect(parseCanonicalOperation(cb.head(create.objectId)!.signed.canonical).kind).toBe("delete");
    await expect(service.push(await signOperation(b, stale))).rejects.toThrow("generation");
    const restore: ManagedOperation = { ...create, operationId: "restore", kind: "restore", generation: 2, approvalRef: "confirm-restore" };
    approve(approvals, restore); await ca.enqueue(restore); await ca.sync(); await cb.sync();
    expect(cb.head(create.objectId)).toEqual(ca.head(create.objectId));
    expect(cb.pendingCount).toBe(0);
    expect(service.history(create.vaultId, create.objectId)).toHaveLength(5);
    const tampered = await signOperation(b, { ...stale, generation: 2 });
    await expect(service.push({ ...tampered, canonical: tampered.canonical.replace('"stale"', '"forged"') })).rejects.toThrow("signature");
    service.revokeDevice(create.vaultId, "device-b");
    await cb.enqueue({ ...stale, generation: 2 });
    await expect(cb.sync()).rejects.toThrow("revoked");
    expect(cb.state).toBe("revoked");
    expect(service.history(create.vaultId, create.objectId)).toHaveLength(5);
  } finally {
    key.fill(0); a.privateKey.fill(0); b.privateKey.fill(0);
    if (saved === undefined) delete process.env.AGENTKEYCHAIN_HOME; else process.env.AGENTKEYCHAIN_HOME = saved;
    for (const root of roots) rmSync(root, { recursive: true, force: true });
  }
});

test("remote tampering does not advance cursor or enqueue echo", async () => {
  const { service, a, b } = await fixture();
  await service.push(await signOperation(a, operation()));
  const transport = new LocalTransport(service);
  const client = await CloudEngine.create(b, {
    push: transport.push.bind(transport),
    pull: async (...args) => {
      const page = await transport.pull(...args);
      page.versions[0]!.signed.signature = "bad";
      return page;
    },
  }, [a.record, b.record]);
  await expect(client.sync()).rejects.toThrow("signature");
  expect(client.snapshot().cursor).toBe(0); expect(client.pendingCount).toBe(0);
});
