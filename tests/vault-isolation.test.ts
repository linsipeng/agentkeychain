import { expect, test } from "bun:test";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function restore(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

test("test mode refuses to resolve the default production vault", async () => {
  const saved = process.env["AGENTKEYCHAIN_HOME"];
  delete process.env["AGENTKEYCHAIN_HOME"];
  try {
    const { vaultDir } = await import("../src/vault.ts");
    expect(() => vaultDir()).toThrow("test vault");
  } finally {
    restore("AGENTKEYCHAIN_HOME", saved);
  }
});

test("test mode refuses a vault path outside the system temp directory", async () => {
  const saved = process.env["AGENTKEYCHAIN_HOME"];
  process.env["AGENTKEYCHAIN_HOME"] = join(process.env["HOME"] ?? "/", ".agentkeychain");
  try {
    const { vaultDir } = await import("../src/vault.ts");
    expect(() => vaultDir()).toThrow("system temporary directory");
  } finally {
    restore("AGENTKEYCHAIN_HOME", saved);
  }
});

test("test mode accepts an explicit vault under the system temp directory", async () => {
  const saved = process.env["AGENTKEYCHAIN_HOME"];
  const isolated = mkdtempSync(join(tmpdir(), "akc-vault-guard-"));
  process.env["AGENTKEYCHAIN_HOME"] = isolated;
  try {
    const { vaultDir } = await import("../src/vault.ts");
    expect(vaultDir()).toBe(realpathSync(isolated));
  } finally {
    restore("AGENTKEYCHAIN_HOME", saved);
    rmSync(isolated, { recursive: true, force: true });
  }
});
