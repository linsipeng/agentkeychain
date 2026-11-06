import { afterEach, describe, expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import { randomUUID } from "node:crypto";
import { createCloudKeys, destroyCloudKeys, objectId, sealPayload, openPayload, sealKeyPackage, openKeyPackage, type CloudKeys } from "../src/cloud/crypto.ts";
import type { ManagedOperation } from "../src/cloud/protocol.ts";

const header = { protocolVersion: 2, vaultId: "vault", objectId: "object", deviceId: "device", operationId: "operation", kind: "put", generation: 1, keyEpoch: 1, approvalRef: null } as const;
const payload = () => ({ name: randomUUID(), value: randomUUID(), scopes: ["test:read"], metadata: { synthetic: true }, localVersion: 1 });
const allocated: CloudKeys[] = [];
async function makeKeys() { const keys = await createCloudKeys(); allocated.push(keys); return keys; }
afterEach(() => { for (const keys of allocated.splice(0)) destroyCloudKeys(keys); });
describe("cloud cryptographic boundaries", () => {
  test("independent keys and opaque deterministic names", async () => {
    const a = await makeKeys(), b = await makeKeys();
    expect(new Set([a.vdk, a.csk, a.signingPrivate, a.wrappingPrivate].map(v => Buffer.from(v).toString("hex"))).size).toBe(4);
    expect(objectId(a.vdk, "name")).toBe(objectId(a.vdk, "name"));
    expect(objectId(a.vdk, "name")).not.toBe(objectId(b.vdk, "name"));
    expect(a.signingPublic).not.toEqual(a.wrappingPublic);
  });
  test("whole payload is encrypted and exact operation header is AAD", async () => {
    const keys = await makeKeys(), p = payload();
    const envelope = sealPayload(keys.vdk, header, p);
    const operation: ManagedOperation = { ...header, envelope };
    expect(JSON.stringify(envelope).includes(p.value)).toBe(false);
    expect(JSON.stringify(openPayload(keys.vdk, operation)) === JSON.stringify(p)).toBe(true);
    for (const changed of [{ operationId: "other" }, { deviceId: "other" }, { vaultId: "other" }, { objectId: "other" }, { generation: 2 }, { keyEpoch: 2 }, { approvalRef: "approval" }, { kind: "restore" as const }]) {
      expect(() => openPayload(keys.vdk, { ...operation, ...changed })).toThrow();
    }
    expect(() => openPayload(keys.csk, operation)).toThrow();
  });
  test("key package requires pinned issuer and exact grant, target, vault and epoch", async () => {
    const issuer = await makeKeys(), target = await makeKeys();
    const binding = { vaultId: "vault", targetDeviceId: "target", keyEpoch: 1, issuerDeviceId: "issuer", grantId: "grant" };
    const signed = sealKeyPackage(issuer.vdk, binding, target.wrappingPublic, issuer.signingPrivate);
    const opened = openKeyPackage(signed, binding, issuer.signingPublic, target.wrappingPublic, target.wrappingPrivate);
    try { expect(sodium.memcmp(opened, issuer.vdk)).toBe(true); }
    finally { opened.fill(0); }
    for (const changed of [{ vaultId: "other" }, { targetDeviceId: "other" }, { keyEpoch: 2 }, { issuerDeviceId: "other" }, { grantId: "other" }]) {
      expect(() => openKeyPackage(signed, { ...binding, ...changed }, issuer.signingPublic, target.wrappingPublic, target.wrappingPrivate)).toThrow();
    }
    expect(() => openKeyPackage(signed, binding, target.signingPublic, target.wrappingPublic, target.wrappingPrivate)).toThrow();
    expect(() => openKeyPackage(signed, binding, issuer.signingPublic, issuer.wrappingPublic, issuer.wrappingPrivate)).toThrow();
    const malformed = { ...signed, canonical: signed.canonical + " " };
    malformed.signature = Buffer.from(sodium.crypto_sign_detached(malformed.canonical, issuer.signingPrivate)).toString("base64");
    expect(() => openKeyPackage(malformed, binding, issuer.signingPublic, target.wrappingPublic, target.wrappingPrivate)).toThrow();
  });
  test("rejects malformed and oversized payloads and clears allocated key buffers", async () => {
    const keys = await makeKeys();
    for (const invalid of [{ ...payload(), localVersion: 0 }, { ...payload(), name: "" }, { ...payload(), value: "x".repeat(256 * 1024) }]) {
      expect(() => sealPayload(keys.vdk, header, invalid)).toThrow();
    }
    destroyCloudKeys(keys);
    expect(Object.values(keys).every(v => v.every((byte: number) => byte === 0))).toBe(true);
  });
});
