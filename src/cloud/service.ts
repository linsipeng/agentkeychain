/* eslint-disable no-unused-vars -- TS parameter properties and interface arguments are checked by @typescript-eslint/no-unused-vars. */
import { MemoryApprovals, requestDigest } from "../auth/approval.ts";
import { validateTransition } from "./transitions.ts";
import { verifyOperation } from "./device.ts";
import { base64, exactFields, identifier, parseCanonicalOperation, type DeviceRecord, type ManagedVersion, type PullPage, type PushReceipt, type SignedManagedOperation } from "./protocol.ts";

interface VaultState { devices: Record<string, DeviceRecord>; versions: ManagedVersion[] }
/** Production adapter requirement: approval lookup/consumption, revocation check,
 * idempotency, sequence allocation and version append MUST share one durable transaction.
 * This interface alone cannot provide that guarantee: ManagedService + MemoryApprovals
 * is a local simulation, not a production-compatible approval transaction adapter. */
export interface ManagedRepository {
  read(vaultId: string): VaultState;
  // Synchronous, serialized, copy-on-write transaction; callbacks must not await.
  transaction<T>(vaultId: string, change: (state: VaultState) => T): T;
}
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const empty = (): VaultState => ({ devices: {}, versions: [] });
/** Local simulation only; this does not demonstrate D1 transactional behavior. */
export class MemoryRepository implements ManagedRepository {
  private vaults = new Map<string, VaultState>();
  read(vaultId: string): VaultState { return copy(this.vaults.get(vaultId) ?? empty()); }
  transaction<T>(vaultId: string, change: (state: VaultState) => T): T {
    const state = this.read(vaultId);
    const result = change(state);
    this.vaults.set(vaultId, copy(state));
    return copy(result);
  }
}
export class ManagedError extends Error {
  constructor(public readonly code: "revoked" | "device" | "signature" | "idempotency" | "generation" | "approval", message = code) { super(message); }
}
/** Domain core. Registration/revocation and inspection are trusted control-plane
 * seams, not public endpoints. Account authentication is outside Slice 1. */
export class ManagedService {
  readonly transactionScope = "local-memory-only; durable approval/repository transaction required" as const;
  constructor(private repo: ManagedRepository, private approvals = new MemoryApprovals(), private now: () => number = Date.now) {}
  registerDevice(record: DeviceRecord): void {
    exactFields(record, ["vaultId", "deviceId", "publicKey", "revoked"]);
    identifier(record.vaultId); identifier(record.deviceId); base64(record.publicKey, 32, 32);
    if (record.revoked !== false) throw new ManagedError("device");
    this.repo.transaction(record.vaultId, state => {
      if (Object.hasOwn(state.devices, record.deviceId)) throw new ManagedError("device");
      Object.defineProperty(state.devices, record.deviceId, { value: copy(record), enumerable: true, writable: true, configurable: true });
      return null;
    });
  }
  revokeDevice(vaultId: string, deviceId: string): void {
    this.repo.transaction(vaultId, state => {
      const record = Object.hasOwn(state.devices, deviceId) ? state.devices[deviceId] : undefined;
      if (!record) throw new ManagedError("device");
      record.revoked = true;
      return null;
    });
  }
  device(vaultId: string, deviceId: string): DeviceRecord {
    const devices = this.repo.read(vaultId).devices;
    const record = Object.hasOwn(devices, deviceId) ? devices[deviceId] : undefined;
    if (!record) throw new ManagedError("device");
    return record;
  }
  async push(input: SignedManagedOperation): Promise<PushReceipt> {
    // Snapshot before asynchronous verification to prevent caller mutation races.
    exactFields(input, ["canonical", "signature"]);
    const signed = copy(input);
    const op = parseCanonicalOperation(signed.canonical);
    const devices = this.repo.read(op.vaultId).devices;
    const record = Object.hasOwn(devices, op.deviceId) ? devices[op.deviceId] : undefined;
    if (!record) throw new ManagedError("device");
    if (record.revoked) throw new ManagedError("revoked");
    if (!await verifyOperation(record, signed)) throw new ManagedError("signature");
    return this.repo.transaction(op.vaultId, state => {
      const currentDevice = state.devices[op.deviceId];
      if (!currentDevice || currentDevice.publicKey !== record.publicKey) throw new ManagedError("device");
      if (currentDevice.revoked) throw new ManagedError("revoked");
      const receipt = (serverSequence: number): PushReceipt => ({ vaultId: op.vaultId, deviceId: op.deviceId, operationId: op.operationId, serverSequence });
      const previous = state.versions.find(v => {
        const old = parseCanonicalOperation(v.signed.canonical);
        return old.deviceId === op.deviceId && old.operationId === op.operationId;
      });
      if (previous) {
        if (previous.signed.canonical !== signed.canonical || previous.signed.signature !== signed.signature) throw new ManagedError("idempotency");
        return receipt(previous.serverSequence);
      }
      const head = state.versions.filter(v => parseCanonicalOperation(v.signed.canonical).objectId === op.objectId).at(-1);
      const old = head ? parseCanonicalOperation(head.signed.canonical) : undefined;
      try { validateTransition(old, op); }
      catch (error) { throw new ManagedError(error instanceof Error && error.message === "approval" ? "approval" : "generation"); }
      if (op.kind === "delete" || op.kind === "restore") {
        const grant = op.approvalRef ? this.approvals.get(op.approvalRef) : undefined;
        if (!grant) throw new ManagedError("approval");
        try {
          this.approvals.consume({ ...grant, agentId: op.deviceId, action: op.kind,
            credentialRef: JSON.stringify([op.vaultId, op.objectId]), requestDigest: requestDigest(signed.canonical) }, this.now());
        } catch { throw new ManagedError("approval"); }
      } else if (op.approvalRef !== null) throw new ManagedError("approval");
      const serverSequence = state.versions.length + 1;
      state.versions.push({ signed, serverSequence });
      return receipt(serverSequence);
    });
  }
  history(vaultId: string, objectId: string): ManagedVersion[] {
    return this.repo.read(vaultId).versions.filter(v => parseCanonicalOperation(v.signed.canonical).objectId === objectId);
  }
  head(vaultId: string, objectId: string): ManagedVersion | undefined { return this.history(vaultId, objectId).at(-1); }
  pull(vaultId: string, cursor: number, limit = 100): PullPage {
    if (!Number.isSafeInteger(cursor) || cursor < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new Error("invalid pagination");
    const all = this.repo.read(vaultId).versions;
    if (cursor > all.length) throw new Error("invalid cursor");
    const versions = all.slice(cursor, cursor + limit);
    const nextCursor = versions.at(-1)?.serverSequence ?? cursor;
    return { versions, nextCursor, hasMore: nextCursor < all.length };
  }
}
