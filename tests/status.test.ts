import { beforeEach, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let home = "";

beforeEach(() => {
  if (home && existsSync(home)) rmSync(home, { recursive: true });
  home = mkdtempSync(join(tmpdir(), "akc-status-"));
  process.env["AGENTKEYCHAIN_HOME"] = home;
  delete process.env["AKC_PASSWORD"];
});

test("status reports an absent vault without creating a database", async () => {
  const { getStatusSnapshot } = await import("../src/cli/status.ts");
  const status = await getStatusSnapshot();
  expect(status.vaultInitialized).toBe(false);
  expect(status.passwordAvailable).toBe(false);
  expect(existsSync(join(home, "vault.db"))).toBe(false);
});

test("status treats a schema-only database without KEK metadata as uninitialized", async () => {
  const { openDb } = await import("../src/vault.ts");
  const db = openDb();
  db.close();

  const { getStatusSnapshot } = await import("../src/cli/status.ts");
  const status = await getStatusSnapshot();
  expect(status.vaultInitialized).toBe(false);
  expect(status.passwordAvailable).toBe(false);
});

test("status reports an initialized vault and available password without exposing it", async () => {
  const password = "status-test-password";
  process.env["AKC_PASSWORD"] = password;
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  await initVault(openDb(), password);

  const { getStatusSnapshot } = await import("../src/cli/status.ts");
  const status = await getStatusSnapshot();
  expect(status.vaultInitialized).toBe(true);
  expect(status.passwordAvailable).toBe(true);
  expect(JSON.stringify(status)).not.toContain(password);

  delete process.env["AKC_PASSWORD"];
  rmSync(home, { recursive: true });
});

test("status rejects a stale password channel that does not unlock this vault", async () => {
  const correctPassword = "status-correct-password";
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  await initVault(openDb(), correctPassword);
  process.env["AKC_PASSWORD"] = "stale-password-from-another-vault";

  const { getStatusSnapshot } = await import("../src/cli/status.ts");
  const status = await getStatusSnapshot();
  expect(status.vaultInitialized).toBe(true);
  expect(status.passwordAvailable).toBe(false);
  expect(JSON.stringify(status)).not.toContain(correctPassword);
  expect(JSON.stringify(status)).not.toContain(process.env["AKC_PASSWORD"]);
  delete process.env["AKC_PASSWORD"];
  rmSync(home, { recursive: true });
});
