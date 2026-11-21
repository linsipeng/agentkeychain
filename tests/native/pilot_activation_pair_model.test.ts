import { expect, test } from "bun:test";
import { decidePilotActivation, type ActivationBasis, type DatabaseObservation, type SlotObservation } from "./pilot_activation_pair_model.ts";

const d = (c: string) => c.repeat(64);
const basis: ActivationBasis = { version: 1, profileDigest: d("1"), stageDigest: d("2"), commitDigest: d("3"), slotDigest: d("4") };
const empty = { status: "empty" } as const;
const committed = { status: "committed", basis } as const;
const prepared = { status: "prepared", basis } as const;
const finalized = { status: "finalized", basis } as const;

test("all crash cuts remain closed until the persisted pair agrees", () => {
  expect(decidePilotActivation(basis, empty, { status: "absent" })).toBe("blocked");
  expect(decidePilotActivation(basis, empty, prepared)).toBe("verify-fresh-then-commit-database");
  expect(decidePilotActivation(basis, committed, prepared)).toBe("verify-fresh-then-finalize-slot");
  expect(decidePilotActivation(basis, committed, finalized)).toBe("local-active-recorded");
  expect(decidePilotActivation(basis, committed, finalized)).toBe("local-active-recorded"); // lost response/restart
});

test("missing, inaccessible, conflicting or rewound half cannot be recreated", () => {
  for (const status of ["empty", "unknown", "conflict"] as const) {
    expect(decidePilotActivation(basis, { status }, finalized)).toBe("blocked");
  }
  for (const status of ["absent", "unknown", "conflict"] as const) {
    expect(decidePilotActivation(basis, committed, { status })).toBe("blocked");
  }
  const observed: DatabaseObservation[] = [empty, committed, { status: "unknown" }, { status: "conflict" }];
  const slots: SlotObservation[] = [prepared, finalized, { status: "absent" }, { status: "unknown" }, { status: "conflict" }];
  expect(observed.flatMap(db => slots.map(slot => decidePilotActivation(basis, db, slot))).filter(x => x === "local-active-recorded")).toHaveLength(1);
});

test("all four matching fields come from the exact expected authority, on both reads", () => {
  for (const field of ["profileDigest", "stageDigest", "commitDigest", "slotDigest"] as const) {
    const other = { ...basis, [field]: d("f") };
    expect(decidePilotActivation(basis, { ...committed, basis: other }, finalized)).toBe("blocked");
    expect(decidePilotActivation(basis, committed, { ...finalized, basis: other })).toBe("blocked");
    expect(decidePilotActivation(basis, empty, { ...prepared, basis: other })).toBe("blocked");
    expect(decidePilotActivation(basis, { ...committed, basis: other }, { ...finalized, basis: other })).toBe("blocked");
  }
  expect(decidePilotActivation({ ...basis, stageDigest: "invalid" }, committed, finalized)).toBe("blocked");
});
