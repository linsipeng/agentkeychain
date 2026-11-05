import type { ManagedOperation } from "./protocol.ts";

/** Shared protocol rules, enforced independently at service acceptance and client apply. */
export function validateTransition(old: ManagedOperation | undefined, op: ManagedOperation): void {
  if (op.kind === "restore") {
    if (!old || op.generation <= old.generation) throw new Error("generation");
  } else if (!old) {
    if (op.generation !== 1 || op.kind !== "put") throw new Error("generation");
  } else if (old.kind === "delete" || op.generation !== old.generation) throw new Error("generation");
  if (old && op.keyEpoch < old.keyEpoch) throw new Error("generation");
  if ((op.kind === "put") !== (op.approvalRef === null)) throw new Error("approval");
}
