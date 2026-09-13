import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { URLSearchParams } from "node:url";

// Bun runs test files in one process: this file sets AKC_PASSWORD for its own
// vault, so it must restore the ambient environment or later files (keychain)
// see a stale env var and fail. Matches the explicit-env-state rule.
let savedAkcPassword: string | undefined;

beforeEach(async () => {
  savedAkcPassword = process.env.AKC_PASSWORD;
  process.env.AGENTKEYCHAIN_HOME = mkdtempSync(join(tmpdir(), "akc-capture-store-"));
  process.env.AKC_PASSWORD = "test-password-123";
  const { init } = await import("./helpers.ts");
  await init("test-password-123");
});

afterAll(() => {
  if (savedAkcPassword === undefined) delete process.env.AKC_PASSWORD;
  else process.env.AKC_PASSWORD = savedAkcPassword;
});

describe("secure capture store integration", () => {
  test("stores an inferred-scope value encrypted at rest", async () => {
    const { requestSecureStore } = await import("../src/capture/store.ts");
    const handle = await requestSecureStore({
      name: "openai-prod",
      purpose: "用于聊天和代码生成",
      openBrowser: false,
    });
    const synthetic = "capture-secret-should-not-be-plaintext";
    const response = await fetch(handle.url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ value: synthetic }),
    });
    expect(response.status).toBe(200);
    expect(await handle.done).toBe("stored");

    const { openDb, dbPath } = await import("../src/vault.ts");
    const { listSecrets } = await import("../src/secrets.ts");
    const item = listSecrets(openDb()).find((entry) => entry.name === "openai-prod");
    expect(item?.scopes).toEqual(["openai:chat"]);
    expect(readFileSync(dbPath()).includes(Buffer.from(synthetic))).toBe(false);
  });

  test("refuses to overwrite an existing live secret", async () => {
    const { requestSecureStore } = await import("../src/capture/store.ts");
    const first = await requestSecureStore({ name: "duplicate", purpose: "use duplicate", openBrowser: false });
    await fetch(first.url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "value=first",
    });
    await first.done;
    await expect(requestSecureStore({
      name: "duplicate",
      purpose: "use duplicate",
      openBrowser: false,
    })).rejects.toThrow("already exists");
  });
});
