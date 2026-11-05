import { lstatSync } from "node:fs";
import { syncConfigPath } from "../sync.ts";
export type LegacyStatus = { kind: "none" | "legacy_byo_cloudflare" | "unrecognized" };
/** Return classification only; never return endpoint, device identifier or token. */
export function detectLegacyConfig(input: unknown): LegacyStatus {
  if (input === null) return { kind: "none" };
  if (!input || typeof input !== "object" || Array.isArray(input)) return { kind: "unrecognized" };
  const value = input as Record<string, unknown>;
  const valid = ["url", "token", "deviceId"].every(k => typeof value[k] === "string" && value[k].length > 0) &&
    ["lastPushAt", "lastPullAt"].every(k => Number.isSafeInteger(value[k]) && (value[k] as number) >= 0);
  return { kind: valid ? "legacy_byo_cloudflare" : "unrecognized" };
}
export function legacyStatus(): LegacyStatus {
  const path = syncConfigPath(); // Isolation errors must never fall back to host HOME.
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (!stat) return { kind: "none" };
  if (stat.isSymbolicLink()) throw new Error("sync config symlink refused");
  return { kind: stat.isFile() ? "legacy_byo_cloudflare" : "unrecognized" };
}
export function migrationMessage(status: LegacyStatus): string {
  const prefix = status.kind === "legacy_byo_cloudflare" ? "Legacy sync configuration detected and preserved. " :
    status.kind === "unrecognized" ? "Unrecognized sync configuration preserved. " : "No legacy sync configuration detected. ";
  return prefix + "Managed Cloud is the only planned cloud mode. Slice 1 is local/test-only; account connection and migration are not available. No endpoint contacted or data uploaded. Local vault use remains available.";
}
