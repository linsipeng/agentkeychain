import sodium from "libsodium-wrappers-sumo";
import { generateKeypair } from "../crypto/keys.ts";
import { base64, canonicalOperation, exactFields, identifier, parseCanonicalOperation, type DeviceRecord, type ManagedOperation, type SignedManagedOperation } from "./protocol.ts";

/** Slice 1 identity: memory only. Never serialize or log this object. */
export interface DeviceIdentity { record: DeviceRecord; privateKey: Uint8Array }
export async function createDevice(vaultId: string, deviceId: string): Promise<DeviceIdentity> {
  identifier(vaultId); identifier(deviceId);
  const keys = await generateKeypair();
  return { record: { vaultId, deviceId, publicKey: Buffer.from(keys.publicKey).toString("base64"), revoked: false }, privateKey: keys.privateKey };
}
export async function signOperation(identity: DeviceIdentity, operation: ManagedOperation): Promise<SignedManagedOperation> {
  await sodium.ready;
  if (operation.deviceId !== identity.record.deviceId || operation.vaultId !== identity.record.vaultId) throw new Error("device mismatch");
  const canonical = canonicalOperation(operation);
  return { canonical, signature: Buffer.from(sodium.crypto_sign_detached(canonical, identity.privateKey)).toString("base64") };
}
/** Revocation is acceptance policy, not historical signature validity. */
export async function verifyOperation(record: DeviceRecord, signed: SignedManagedOperation): Promise<boolean> {
  await sodium.ready;
  try {
    exactFields(signed, ["canonical", "signature"]);
    const op = parseCanonicalOperation(signed.canonical);
    base64(record.publicKey, 32, 32); base64(signed.signature, 64, 64);
    return op.vaultId === record.vaultId && op.deviceId === record.deviceId &&
      sodium.crypto_sign_verify_detached(Buffer.from(signed.signature, "base64"), signed.canonical, Buffer.from(record.publicKey, "base64"));
  } catch { return false; }
}
