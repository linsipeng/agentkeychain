import { createHash } from "node:crypto";
import { exactFields, identifier } from "../cloud/protocol.ts";

export function classifyAction(action: string, scoped = false): "automatic" | "confirmation" {
  return ["metadata", "status", "sync"].includes(action) || (action === "read" && scoped) ? "automatic" : "confirmation";
}
export interface ApprovalRequest {
  agentId: string;
  action: string;
  credentialRef: string;
  requestDigest: string;
  expiresAt: number;
  nonce: string;
}
export function requestDigest(canonicalRequest: string): string {
  return createHash("sha256").update("AgentKeychain-approval-v1\0").update(canonicalRequest).digest("hex");
}
function canonicalApproval(req: ApprovalRequest): string {
  exactFields(req, ["agentId", "action", "credentialRef", "requestDigest", "expiresAt", "nonce"]);
  identifier(req.agentId); identifier(req.action); identifier(req.nonce);
  if (typeof req.credentialRef !== "string" || !req.credentialRef || req.credentialRef.length > 512 ||
      !/^[a-f0-9]{64}$/.test(req.requestDigest) || !Number.isSafeInteger(req.expiresAt) || req.expiresAt <= 0) throw new Error("invalid approval");
  return JSON.stringify([req.agentId, req.action, req.credentialRef, req.requestDigest, req.expiresAt, req.nonce]);
}
/** Test-only trusted confirmation boundary. Not exposed by the client transport.
 * A request/digest alone is not authorization. Production UI/storage is deferred.
 */
export class MemoryApprovals {
  private grants = new Map<string, ApprovalRequest>();
  private used = new Set<string>();
  approve(req: ApprovalRequest): void {
    canonicalApproval(req);
    if (this.grants.has(req.nonce) || this.used.has(req.nonce)) throw new Error("approval nonce already exists");
    this.grants.set(req.nonce, { ...req });
  }
  get(nonce: string): ApprovalRequest | undefined {
    const grant = this.grants.get(nonce);
    return grant ? { ...grant } : undefined;
  }
  consume(req: ApprovalRequest, now: number): void {
    const grant = this.grants.get(req.nonce);
    if (!grant || this.used.has(req.nonce) || !Number.isSafeInteger(now) || now >= grant.expiresAt || canonicalApproval(req) !== canonicalApproval(grant)) throw new Error("approval required or invalid");
    this.used.add(req.nonce);
    this.grants.delete(req.nonce);
  }
}
