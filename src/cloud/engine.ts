/* eslint-disable no-unused-vars -- TS parameter properties and interface arguments are checked by @typescript-eslint/no-unused-vars. */
import { signOperation, verifyOperation, type DeviceIdentity } from "./device.ts";
import { base64, exactFields, identifier, parseCanonicalOperation, type DeviceRecord, type ManagedOperation, type ManagedVersion, type SignedManagedOperation } from "./protocol.ts";
import { ManagedError } from "./service.ts";
import type { ManagedTransport } from "./transport.ts";
import { validateTransition } from "./transitions.ts";

export interface QueuedOperation { signed: SignedManagedOperation }
/** Full signed history retains operation identities/bytes and permits replay validation on restart.
 * Memory-only in this slice; persistence must also protect against rollback of the entire snapshot. */
export interface EngineSnapshot { pending: QueuedOperation[]; cursor: number; heads: ManagedVersion[]; history: ManagedVersion[]; requiredThrough: number }
export type EngineState = "idle" | "syncing" | "backoff" | "revoked";
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const operationKey = (op: ManagedOperation) => JSON.stringify([op.deviceId, op.operationId]);
export class CloudEngine {
  private running: Promise<void> | undefined;
  private pins = new Map<string, DeviceRecord>();
  state: EngineState = "idle";
  private constructor(private identity: DeviceIdentity, private transport: ManagedTransport, private data: EngineSnapshot, private pageSize: number) {}
  /** Pins must come from explicit trusted enrollment/control-plane approval, never sync transport.
   * Copies are held privately; a transport cannot replace keys during verification. */
  static async create(identity: DeviceIdentity, transport: ManagedTransport, enrolledDevices: readonly DeviceRecord[], snapshot?: EngineSnapshot, pageSize = 100): Promise<CloudEngine> {
    const engine = new CloudEngine({ record: copy(identity.record), privateKey: identity.privateKey.slice() }, transport,
      copy(snapshot ?? { pending: [], cursor: 0, heads: [], history: [], requiredThrough: 0 }), pageSize);
    for (const input of enrolledDevices) {
      const record = copy(input);
      exactFields(record, ["vaultId", "deviceId", "publicKey", "revoked"]);
      identifier(record.deviceId); base64(record.publicKey, 32, 32);
      if (record.vaultId !== identity.record.vaultId || typeof record.revoked !== "boolean" || engine.pins.has(record.deviceId)) throw new Error("invalid enrollment");
      engine.pins.set(record.deviceId, record);
    }
    if (engine.pins.get(identity.record.deviceId)?.publicKey !== identity.record.publicKey) throw new Error("local identity not enrolled");
    await engine.validateSnapshot();
    return engine;
  }
  private async apply(history: ManagedVersion[], heads: ManagedVersion[], versions: ManagedVersion[]): Promise<void> {
    const seen = new Set(history.map(v => operationKey(parseCanonicalOperation(v.signed.canonical))));
    for (const version of versions) {
      exactFields(version, ["signed", "serverSequence"]);
      const op = parseCanonicalOperation(version.signed.canonical);
      if (op.vaultId !== this.identity.record.vaultId || version.serverSequence !== history.length + 1) throw new Error("invalid sequence");
      const record = this.pins.get(op.deviceId);
      if (!record || !await verifyOperation(record, version.signed)) throw new Error("invalid signature");
      const key = operationKey(op);
      if (seen.has(key)) throw new Error("replayed operation identity");
      const index = heads.findIndex(v => parseCanonicalOperation(v.signed.canonical).objectId === op.objectId);
      validateTransition(index < 0 ? undefined : parseCanonicalOperation(heads[index]!.signed.canonical), op);
      if (index >= 0) heads.splice(index, 1);
      heads.push(copy(version)); history.push(copy(version)); seen.add(key);
    }
  }
  private async validateSnapshot(): Promise<void> {
    const data = this.data;
    exactFields(data, ["pending", "cursor", "heads", "history", "requiredThrough"]);
    if (!Number.isSafeInteger(data.cursor) || data.cursor < 0 || !Number.isSafeInteger(data.requiredThrough) || data.requiredThrough < 0 ||
        !Number.isSafeInteger(this.pageSize) || this.pageSize < 1 || this.pageSize > 1000 ||
        !Array.isArray(data.pending) || !Array.isArray(data.history) || !Array.isArray(data.heads) || data.history.length !== data.cursor) throw new Error("invalid engine state");
    const history: ManagedVersion[] = [], heads: ManagedVersion[] = [];
    await this.apply(history, heads, data.history);
    // Comparing exact derived heads also rejects duplicates, invalid signatures and sequence mismatches.
    if (JSON.stringify(heads) !== JSON.stringify(data.heads)) throw new Error("invalid snapshot heads");
    const pendingIds = new Set<string>();
    for (const entry of data.pending) {
      exactFields(entry, ["signed"]);
      const op = parseCanonicalOperation(entry.signed.canonical);
      if (!await verifyOperation(this.identity.record, entry.signed)) throw new Error("invalid pending signature");
      const key = operationKey(op);
      if (pendingIds.has(key)) throw new Error("duplicate pending operation");
      const previous = history.find(v => operationKey(parseCanonicalOperation(v.signed.canonical)) === key);
      // A lost push acknowledgement remains pending before pull; accepted history
      // and the outgoing queue must never contain the same identity in a snapshot.
      if (previous) throw new Error("duplicate pending/history operation");
      pendingIds.add(key);
    }
  }
  get pendingCount(): number { return this.data.pending.length; }
  snapshot(): EngineSnapshot { return copy(this.data); }
  head(objectId: string): ManagedVersion | undefined {
    const head = this.data.heads.find(v => parseCanonicalOperation(v.signed.canonical).objectId === objectId);
    return head ? copy(head) : undefined;
  }
  async enqueue(op: ManagedOperation): Promise<void> {
    const signed = await signOperation(this.identity, op);
    const key = operationKey(parseCanonicalOperation(signed.canonical));
    const duplicate = [...this.data.pending, ...this.data.history].find(q => operationKey(parseCanonicalOperation(q.signed.canonical)) === key);
    if (duplicate) {
      if (duplicate.signed.canonical !== signed.canonical || duplicate.signed.signature !== signed.signature) throw new Error("queue idempotency conflict");
      return;
    }
    this.data.pending.push({ signed });
  }
  sync(): Promise<void> {
    if (this.running) return this.running;
    if (this.state === "revoked") return Promise.reject(new ManagedError("revoked"));
    this.running = this.run().finally(() => { this.running = undefined; });
    return this.running;
  }
  private async run(): Promise<void> {
    this.state = "syncing";
    try {
      while (this.data.pending.length) {
        const queued = this.data.pending[0]!;
        const op = parseCanonicalOperation(queued.signed.canonical);
        const receipt = await this.transport.push(copy(queued.signed));
        if (receipt.vaultId !== op.vaultId || receipt.deviceId !== op.deviceId || receipt.operationId !== op.operationId || !Number.isSafeInteger(receipt.serverSequence) || receipt.serverSequence < 1) throw new Error("invalid receipt");
        this.data.requiredThrough = Math.max(this.data.requiredThrough, receipt.serverSequence);
        this.data.pending.shift();
      }
      let promisedMore = false;
      for (;;) {
        const page = copy(await this.transport.pull(this.identity.record.vaultId, this.data.cursor, this.pageSize));
        exactFields(page, ["versions", "nextCursor", "hasMore"]);
        if (!Array.isArray(page.versions) || page.versions.length > this.pageSize || typeof page.hasMore !== "boolean" ||
            page.nextCursor !== this.data.cursor + page.versions.length ||
            ((page.hasMore || promisedMore) && !page.versions.length) ||
            (!page.hasMore && page.nextCursor < this.data.requiredThrough)) throw new Error("invalid continuation");
        const history = copy(this.data.history), heads = copy(this.data.heads);
        await this.apply(history, heads, page.versions);
        this.data.history = history; this.data.heads = heads; this.data.cursor = page.nextCursor;
        if (page.hasMore) this.data.requiredThrough = Math.max(this.data.requiredThrough, page.nextCursor + 1);
        if (!page.hasMore) break;
        promisedMore = true;
      }
      this.state = "idle";
    } catch (error) {
      this.state = error instanceof ManagedError && error.code === "revoked" ? "revoked" : "backoff";
      throw error;
    }
  }
}
