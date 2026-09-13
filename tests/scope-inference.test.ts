import { describe, expect, test } from "bun:test";
import { inferCredentialScope } from "../src/capture/scope.ts";

describe("credential scope inference", () => {
  test("infers narrow scopes for common model providers", () => {
    expect(inferCredentialScope("openai-prod", "用于聊天和代码生成")).toEqual({
      service: "openai",
      scope: "openai:chat",
      permission: "仅允许用于 OpenAI 模型调用",
    });
    expect(inferCredentialScope("anthropic-api-key", "Claude API 调用").scope).toBe("anthropic:chat");
  });

  test("infers read versus write for infrastructure providers", () => {
    expect(inferCredentialScope("cloudflare-token", "只查询 DNS 和状态").scope).toBe("cloudflare:read");
    expect(inferCredentialScope("cloudflare-token", "部署 Worker 并修改 DNS").scope).toBe("cloudflare:write");
  });

  test("uses a service-level use scope instead of universal wildcard", () => {
    const decision = inferCredentialScope("acme-service-key", "调用 Acme Service API");
    expect(decision.scope).toBe("acme-service:use");
    expect(decision.scope).not.toBe("*");
    expect(decision.permission).toContain("Acme Service");
  });
});
