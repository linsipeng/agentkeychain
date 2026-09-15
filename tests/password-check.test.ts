import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { URL, URLSearchParams } from "node:url";
import { startPasswordCheck, type PasswordCheckHandle } from "../src/password-check/server.ts";

const handles: PasswordCheckHandle[] = [];
let tmpDir = "";
let savedVaultHome: string | undefined;

beforeEach(async () => {
  savedVaultHome = process.env.AGENTKEYCHAIN_HOME;
  tmpDir = mkdtempSync(join(tmpdir(), "akc-password-check-"));
  process.env["AGENTKEYCHAIN_HOME"] = tmpDir;
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  const db = openDb();
  await initVault(db, "remembered-correct-password");
  db.close();
});

afterEach(() => {
  for (const handle of handles.splice(0)) handle.close();
  if (savedVaultHome === undefined) delete process.env.AGENTKEYCHAIN_HOME;
  else process.env.AGENTKEYCHAIN_HOME = savedVaultHome;
  if (tmpDir && existsSync(tmpDir)) rmSync(tmpDir, { recursive: true });
});

async function submit(handle: PasswordCheckHandle, password: string): Promise<Response> {
  return fetch(handle.url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ password }),
  });
}

describe("local master-password check", () => {
  test("serves a hardened local-only form", async () => {
    const handle = await startPasswordCheck({ openBrowser: false, onVerify: async () => true });
    handles.push(handle);
    const response = await fetch(handle.url);
    const html = await response.text();
    expect(new URL(handle.url).hostname).toBe("127.0.0.1");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(html).toContain("验证主密码");
    expect(html).toContain("不会修改");
  });

  test("reports a correct password without returning it", async () => {
    const synthetic = "remembered-correct-password";
    const { verifyVaultPassword } = await import("../src/vault.ts");
    const handle = await startPasswordCheck({ openBrowser: false, onVerify: verifyVaultPassword });
    handles.push(handle);
    const response = await submit(handle, synthetic);
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain("主密码正确");
    expect(body).not.toContain(synthetic);
    expect(await handle.done).toBe("correct");
  });

  test("allows ten incorrect attempts before the check expires", async () => {
    const dbPath = join(tmpDir, "vault.db");
    const before = statSync(dbPath).mtimeMs;
    const { verifyVaultPassword } = await import("../src/vault.ts");
    const handle = await startPasswordCheck({ openBrowser: false, onVerify: verifyVaultPassword });
    handles.push(handle);

    for (let attempt = 1; attempt <= 9; attempt++) {
      const response = await submit(handle, `wrong-remembered-password-${attempt}`);
      const body = await response.text();
      expect(response.status).toBe(200);
      expect(response.redirected).toBe(true);
      expect(body).toContain("主密码不正确");
      expect(body).toContain(`还可尝试 ${10 - attempt} 次`);
      expect((await fetch(handle.url)).status).toBe(200);
    }

    const finalResponse = await submit(handle, "wrong-remembered-password-10");
    expect(finalResponse.status).toBe(200);
    expect(await finalResponse.text()).toContain("10 次验证机会已用完");
    expect(await handle.done).toBe("incorrect");
    expect((await fetch(handle.url)).status).toBe(410);
    expect(statSync(dbPath).mtimeMs).toBe(before);
  });

  test("allows only one verification while concurrent submissions are in flight", async () => {
    let calls = 0;
    const handle = await startPasswordCheck({
      openBrowser: false,
      onVerify: async () => {
        calls++;
        await Bun.sleep(50);
        return true;
      },
    });
    handles.push(handle);
    const responses = await Promise.all([
      submit(handle, "candidate-one"),
      submit(handle, "candidate-two"),
      submit(handle, "candidate-three"),
    ]);
    expect(calls).toBe(1);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 410, 410]);
    expect(await handle.done).toBe("correct");
  });

  test("rejects wrong paths, non-form submissions, empty and oversized passwords", async () => {
    const handle = await startPasswordCheck({ openBrowser: false, onVerify: async () => true });
    handles.push(handle);
    const wrong = new URL(handle.url);
    wrong.pathname = "/verify-password/wrong-token";
    expect((await fetch(wrong)).status).toBe(404);
    expect((await fetch(handle.url, { method: "POST", body: "password=x" })).status).toBe(415);
    expect((await submit(handle, "")).status).toBe(400);
    const oversized = await fetch(handle.url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "content-length": "20000" },
      body: `password=${"a".repeat(20_000)}`,
    });
    expect(oversized.status).toBe(413);
  });
});
