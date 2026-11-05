import { Buffer } from "node:buffer";
/** Managed protocol v2. IDs are opaque; envelopes contain encrypted bytes only. */
export interface ManagedOperation {
  protocolVersion: 2;
  vaultId: string;
  objectId: string;
  deviceId: string;
  operationId: string;
  kind: "put" | "delete" | "restore";
  generation: number;
  keyEpoch: number;
  envelope: { nonce: string; ciphertext: string } | null;
  approvalRef: string | null;
}
export interface SignedManagedOperation { canonical: string; signature: string }
export interface PushReceipt { vaultId: string; deviceId: string; operationId: string; serverSequence: number }
export interface ManagedVersion { signed: SignedManagedOperation; serverSequence: number }
export interface PullPage { versions: ManagedVersion[]; nextCursor: number; hasMore: boolean }
export interface DeviceRecord { vaultId: string; deviceId: string; publicKey: string; revoked: boolean }
/** Design only: no key distribution or recovery implementation in this slice. */
export interface DeviceKeyPackage { vaultId: string; deviceId: string; keyEpoch: number; encryptedKey: string }

export function exactFields(value: unknown, fields: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) throw new Error("invalid fields");
}
export function identifier(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new Error("invalid identifier");
}
export function base64(value: unknown, min: number, exact?: number): asserts value is string {
  if (typeof value !== "string" || value.length > 2_000_000) throw new Error("invalid encoding");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || bytes.length < min || (exact !== undefined && bytes.length !== exact)) throw new Error("invalid encoding");
}
export function canonicalOperation(input: unknown): string {
  exactFields(input, ["protocolVersion", "vaultId", "objectId", "deviceId", "operationId", "kind", "generation", "keyEpoch", "envelope", "approvalRef"]);
  if (input.protocolVersion !== 2) throw new Error("invalid protocol version");
  for (const key of ["vaultId", "objectId", "deviceId", "operationId"]) identifier(input[key]);
  for (const key of ["generation", "keyEpoch"]) if (!Number.isSafeInteger(input[key]) || (input[key] as number) < 1) throw new Error("invalid counter");
  if (!["put", "delete", "restore"].includes(input.kind as string)) throw new Error("invalid kind");
  if (input.approvalRef !== null) identifier(input.approvalRef);
  let envelope = null;
  if (input.kind === "delete") {
    if (input.envelope !== null) throw new Error("delete requires tombstone");
  } else {
    exactFields(input.envelope, ["nonce", "ciphertext"]);
    base64(input.envelope.nonce, 24, 24);
    base64(input.envelope.ciphertext, 16);
    envelope = { nonce: input.envelope.nonce, ciphertext: input.envelope.ciphertext };
  }
  return JSON.stringify({ protocolVersion: 2, vaultId: input.vaultId, objectId: input.objectId,
    deviceId: input.deviceId, operationId: input.operationId, kind: input.kind,
    generation: input.generation, keyEpoch: input.keyEpoch, envelope, approvalRef: input.approvalRef });
}
export function parseCanonicalOperation(bytes: string): ManagedOperation {
  if (typeof bytes !== "string" || bytes.length > 2_100_000) throw new Error("invalid operation");
  const parsed: unknown = JSON.parse(bytes);
  if (canonicalOperation(parsed) !== bytes) throw new Error("noncanonical operation");
  return parsed as ManagedOperation;
}
