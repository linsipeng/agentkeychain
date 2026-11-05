/** Synthetic fixtures only: no filesystem, Keychain, Vault or network access. */
import { ManagedService, MemoryRepository } from "../src/cloud/service.ts";
import { createDevice } from "../src/cloud/device.ts";
import { canonicalOperation, type ManagedOperation } from "../src/cloud/protocol.ts";
import { MemoryApprovals, requestDigest } from "../src/auth/approval.ts";

export const operation = (deviceId = "device-a"): ManagedOperation => ({
  protocolVersion: 2, vaultId: "synthetic-vault", objectId: "opaque-object", deviceId,
  operationId: "op-1", kind: "put", generation: 1, keyEpoch: 1,
  envelope: { nonce: Buffer.alloc(24, 1).toString("base64"), ciphertext: Buffer.alloc(20, 2).toString("base64") }, approvalRef: null,
});

export function approve(approvals: MemoryApprovals, op: ManagedOperation): void {
  approvals.approve({ agentId: op.deviceId, action: op.kind, credentialRef: JSON.stringify([op.vaultId, op.objectId]), requestDigest: requestDigest(canonicalOperation(op)), expiresAt: 1000, nonce: op.approvalRef! });
}
export async function fixture() {
  const approvals = new MemoryApprovals();
  const service = new ManagedService(new MemoryRepository(), approvals, () => 10);
  const a = await createDevice("synthetic-vault", "device-a");
  const b = await createDevice("synthetic-vault", "device-b");
  service.registerDevice(a.record); service.registerDevice(b.record);
  return { service, approvals, a, b };
}

