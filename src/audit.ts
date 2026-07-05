/**
 * Audit log — minimal write-only stub for F-2.
 * Full signature chain added in F-10.
 */
import { Database } from "bun:sqlite";

export type AuditAction =
  | "store"
  | "get"
  | "list"
  | "delete"
  | "delegate"
  | "revoke"
  | "failed_auth";

export function append(
  db: Database,
  args: {
    agentId: string;
    action: AuditAction;
    target: string | null;
    success: boolean;
  }
): void {
  db.prepare(
    `INSERT INTO audit_log (ts, agent_id, action, target, success, sig)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    Date.now(),
    args.agentId,
    args.action,
    args.target,
    args.success ? 1 : 0,
    new Uint8Array(64)
  );
}
