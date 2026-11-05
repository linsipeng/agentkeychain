import { expect, test } from "bun:test";
import { classifyAction, requestDigest, MemoryApprovals, type ApprovalRequest } from "../src/auth/approval.ts";

test("risk classification fails closed and requires scoped reads", () => {
  for (const action of ["metadata", "status", "sync"]) expect(classifyAction(action)).toBe("automatic");
  expect(classifyAction("read", true)).toBe("automatic");
  for (const action of ["read", "publish", "payment", "purchase", "transfer", "delete", "permission", "scope", "device", "member", "export", "restore", "rotate", "unknown"]) expect(classifyAction(action)).toBe("confirmation");
});

test("trusted approvals bind all fields, expire, and consume nonce once", () => {
  const store = new MemoryApprovals();
  const req: ApprovalRequest = { agentId: "device-a", action: "restore", credentialRef: "object-a", requestDigest: requestDigest("canonical request"), expiresAt: 100, nonce: "approval-a" };
  store.approve(req);
  for (const [key, value] of Object.entries({ agentId: "other", action: "delete", credentialRef: "other", requestDigest: requestDigest("tampered"), expiresAt: 101, nonce: "other" })) {
    expect(() => store.consume({ ...req, [key]: value }, 10)).toThrow();
  }
  expect(() => store.consume(req, 100)).toThrow();
  store.consume(req, 99);
  expect(() => store.consume(req, 99)).toThrow();
  expect(() => store.approve(req)).toThrow();
});
