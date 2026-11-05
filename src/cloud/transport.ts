/* eslint-disable no-unused-vars -- TS parameter properties and interface arguments are checked by @typescript-eslint/no-unused-vars. */
import type { PullPage, PushReceipt, SignedManagedOperation } from "./protocol.ts";
import type { ManagedService } from "./service.ts";
export interface ManagedTransport {
  push(signed: SignedManagedOperation): Promise<PushReceipt>;
  pull(vaultId: string, cursor: number, limit: number): Promise<PullPage>;
}
/** Trusted in-process transport only. No endpoint, bearer token or network IO.
 * Production account/session authentication and trusted key discovery are deferred. */
export class LocalTransport implements ManagedTransport {
  constructor(private service: ManagedService) {}
  async push(signed: SignedManagedOperation): Promise<PushReceipt> { return this.service.push(signed); }
  async pull(vaultId: string, cursor: number, limit: number): Promise<PullPage> { return this.service.pull(vaultId, cursor, limit); }
}
