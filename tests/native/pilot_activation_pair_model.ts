// Inert pilot activation/recovery model. No product callers or I/O.
// Observations must already be made under one exclusive lease, through the
// native trusted profile and protected-slot adapters. Hashes are not authority.
export interface ActivationBasis {
  readonly version: 1;
  readonly profileDigest: string; // signed install + native profile identity
  readonly stageDigest: string; // exact protected continuation record
  readonly commitDigest: string; // exact projection committed as one SQLite transaction
  readonly slotDigest: string; // independently derived protected anchor/roster/key identity
}
export interface ProtectedSlotRecord {
  readonly status: "prepared" | "finalized";
  readonly basis: ActivationBasis;
}
export interface DatabaseCommitRecord {
  readonly status: "committed";
  readonly basis: ActivationBasis;
}
export type DatabaseObservation =
  | { readonly status: "empty" | "unknown" | "conflict" }
  | DatabaseCommitRecord;
export type SlotObservation =
  | { readonly status: "absent" | "unknown" | "conflict" }
  | ProtectedSlotRecord;
export type Decision =
  | "blocked"
  | "verify-fresh-then-commit-database"
  | "verify-fresh-then-finalize-slot"
  | "local-active-recorded";

const digest = (candidate: string) => candidate.length === 64 && /^[0-9a-f]{64}$/.test(candidate);
function valid(b: ActivationBasis): boolean {
  return b.version === 1 && digest(b.profileDigest) && digest(b.stageDigest)
    && digest(b.commitDigest) && digest(b.slotDigest);
}
function same(a: ActivationBasis, b: ActivationBasis): boolean {
  return valid(b) && a.profileDigest === b.profileDigest && a.stageDigest === b.stageDigest
    && a.commitDigest === b.commitDigest && a.slotDigest === b.slotDigest;
}

export function decidePilotActivation(
  expected: ActivationBasis,
  db: DatabaseObservation,
  slot: SlotObservation,
): Decision {
  if (!valid(expected) || (slot.status !== "prepared" && slot.status !== "finalized")
      || !same(expected, slot.basis)) return "blocked";
  if (db.status === "empty" && slot.status === "prepared") return "verify-fresh-then-commit-database";
  if (db.status !== "committed" || !same(expected, db.basis)) return "blocked";
  return slot.status === "prepared" ? "verify-fresh-then-finalize-slot" : "local-active-recorded";
}
