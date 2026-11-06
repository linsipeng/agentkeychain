import sodium from "libsodium-wrappers-sumo";
import { createHmac } from "node:crypto";
import { canonicalPackage, type KeyPackage } from "../../managed-cloud/shared/device-protocol.ts";
import { base64, canonicalOperation, exactFields, type ManagedOperation, type SignedManagedOperation } from "./protocol.ts";

await sodium.ready;

export interface CloudKeys {
  vdk: Uint8Array;
  csk: Uint8Array;
  signingPublic: Uint8Array;
  signingPrivate: Uint8Array;
  wrappingPublic: Uint8Array;
  wrappingPrivate: Uint8Array;
}
export async function createCloudKeys(): Promise<CloudKeys> {
  await sodium.ready;
  const signing = sodium.crypto_sign_keypair(), wrapping = sodium.crypto_box_keypair();
  return { vdk: sodium.randombytes_buf(32), csk: sodium.randombytes_buf(32), signingPublic: signing.publicKey, signingPrivate: signing.privateKey, wrappingPublic: wrapping.publicKey, wrappingPrivate: wrapping.privateKey };
}
export function destroyCloudKeys(keys: CloudKeys): void {
  for (const bytes of Object.values(keys)) bytes.fill(0);
}
function derived(vdk: Uint8Array, purpose: string): Buffer {
  if (vdk.length !== 32) throw new Error("invalid_cloud_key");
  return createHmac("sha256", vdk).update(`AgentKeychain-cloud-${purpose}-v1\0`).digest();
}
export function objectId(vdk: Uint8Array, name: string): string {
  const key = derived(vdk, "name");
  try { return createHmac("sha256", key).update(name, "utf8").digest("base64url"); }
  finally { key.fill(0); }
}
export type OperationHeader = Omit<ManagedOperation, "envelope">;
export interface CloudPayload {
  name: string;
  value: string;
  scopes: string[];
  metadata: Record<string, unknown> | null;
  localVersion: number;
}
export function validatePayload(value: unknown): asserts value is CloudPayload {
  exactFields(value, ["name", "value", "scopes", "metadata", "localVersion"]);
  if (typeof value.name !== "string" || !value.name.length || value.name.length > 1024 || typeof value.value !== "string" ||
      !Array.isArray(value.scopes) || value.scopes.length > 256 || !value.scopes.every(v => typeof v === "string" && v.length <= 1024) ||
      (value.metadata !== null && (typeof value.metadata !== "object" || Array.isArray(value.metadata))) ||
      !Number.isSafeInteger(value.localVersion) || (value.localVersion as number) < 1) throw new Error("invalid_cloud_payload");
}
function aad(header: OperationHeader): string {
  exactFields(header, ["protocolVersion", "vaultId", "objectId", "deviceId", "operationId", "kind", "generation", "keyEpoch", "approvalRef"]);
  // Reuse wire validation and ordering, excluding only the encrypted envelope.
  const ordered = JSON.parse(canonicalOperation({ ...header, envelope: header.kind === "delete" ? null : { nonce: Buffer.alloc(24).toString("base64"), ciphertext: Buffer.alloc(16).toString("base64") } })) as ManagedOperation;
  const fields = { protocolVersion: ordered.protocolVersion, vaultId: ordered.vaultId, objectId: ordered.objectId, deviceId: ordered.deviceId, operationId: ordered.operationId, kind: ordered.kind, generation: ordered.generation, keyEpoch: ordered.keyEpoch, approvalRef: ordered.approvalRef };
  return JSON.stringify(["AgentKeychain-cloud-payload-v1", fields]);
}
export function sealPayload(vdk: Uint8Array, header: OperationHeader, payload: CloudPayload): NonNullable<ManagedOperation["envelope"]> {
  validatePayload(payload);
  if (header.kind === "delete") throw new Error("invalid_cloud_payload");
  const bytes = Buffer.from(JSON.stringify(payload)), key = derived(vdk, "payload"), nonce = sodium.randombytes_buf(24);
  try {
    if (bytes.length > 256 * 1024 - 16) throw new Error("cloud_payload_too_large");
    return { nonce: Buffer.from(nonce).toString("base64"), ciphertext: Buffer.from(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, aad(header), null, nonce, key)).toString("base64") };
  } finally { bytes.fill(0); key.fill(0); }
}
export function openPayload(vdk: Uint8Array, operation: ManagedOperation): CloudPayload {
  canonicalOperation(operation);
  if (!operation.envelope || operation.envelope.ciphertext.length > 349528) throw new Error("invalid_cloud_payload");
  const { envelope, ...header } = operation, key = derived(vdk, "payload");
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, Buffer.from(envelope.ciphertext, "base64"), aad(header), Buffer.from(envelope.nonce, "base64"), key);
    const payload: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    validatePayload(payload);
    return payload;
  } catch { throw new Error("invalid_cloud_payload"); }
  finally { plaintext?.fill(0); key.fill(0); }
}
export type PackageBinding = Omit<KeyPackage, "version" | "wrappedVDK">;
export function sealKeyPackage(vdk: Uint8Array, binding: PackageBinding, wrappingPublic: Uint8Array, signingPrivate: Uint8Array): SignedManagedOperation {
  if (vdk.length !== 32) throw new Error("invalid_cloud_key");
  const wrappedVDK = Buffer.from(sodium.crypto_box_seal(vdk, wrappingPublic)).toString("base64");
  const canonical = canonicalPackage({ version: 1, ...binding, wrappedVDK });
  return { canonical, signature: Buffer.from(sodium.crypto_sign_detached(canonical, signingPrivate)).toString("base64") };
}
/** Issuer pin and complete binding must come from independently trusted enrollment. */
export function openKeyPackage(signed: SignedManagedOperation, binding: PackageBinding, issuerPin: Uint8Array, wrappingPublic: Uint8Array, wrappingPrivate: Uint8Array): Uint8Array {
  try {
    exactFields(signed, ["canonical", "signature"]);
    if (typeof signed.canonical !== "string" || signed.canonical.length > 4096) throw new Error();
    base64(signed.signature, 64, 64);
    const p = JSON.parse(signed.canonical) as KeyPackage;
    if (canonicalPackage(p) !== signed.canonical || !sodium.crypto_sign_verify_detached(Buffer.from(signed.signature, "base64"), signed.canonical, issuerPin)) throw new Error();
    exactFields(binding, ["vaultId", "targetDeviceId", "keyEpoch", "issuerDeviceId", "grantId"]);
    if (Object.entries(binding).some(([k, v]) => p[k as keyof KeyPackage] !== v)) throw new Error();
    base64(p.wrappedVDK, 80, 80);
    const key = sodium.crypto_box_seal_open(Buffer.from(p.wrappedVDK, "base64"), wrappingPublic, wrappingPrivate);
    if (key.length !== 32) { key.fill(0); throw new Error(); }
    return key;
  } catch { throw new Error("invalid_device_key_package"); }
}
