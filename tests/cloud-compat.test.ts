import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, realpathSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectLegacyConfig, legacyStatus } from "../src/cloud/legacy.ts";
import { syncConfigPath, readSyncConfigText, loadSyncConfig } from "../src/sync.ts";

const legacy = { url: "https://synthetic.invalid", token: "synthetic-token-never-print", deviceId: "test-device", lastPushAt: 0, lastPullAt: 0 };
test("legacy shape detection never returns endpoint or token", () => {
  expect(detectLegacyConfig(legacy)).toEqual({ kind: "legacy_byo_cloudflare" });
  expect(detectLegacyConfig(null)).toEqual({ kind: "none" });
  for (const input of [{}, { ...legacy, token: 1 }, { ...legacy, lastPullAt: -1 }]) expect(detectLegacyConfig(input)).toEqual({ kind: "unrecognized" });
  expect(JSON.stringify(detectLegacyConfig(legacy))).not.toContain(legacy.token);
});

test("legacy path fails closed without isolated home; status and deprecated commands preserve synthetic config", async () => {
  const saved = process.env.AGENTKEYCHAIN_HOME;
  const root = mkdtempSync(join(tmpdir(), "akc-legacy-"));
  try {
    delete process.env.AGENTKEYCHAIN_HOME;
    expect(() => syncConfigPath()).toThrow("test vault");
    process.env.AGENTKEYCHAIN_HOME = root;
    expect(syncConfigPath()).toBe(join(realpathSync(root), "sync.json"));
    const config = JSON.stringify(legacy);
    writeFileSync(syncConfigPath(), config);
    expect(legacyStatus().kind).toBe("legacy_byo_cloudflare");
    expect(loadSyncConfig()).toBeNull();
    for (const command of ["status", "init", "connect", "push", "pull", "disconnect"]) {
      // Empty PATH and test Keychain guard: no tools or host credentials available.
      const result = Bun.spawnSync([process.execPath, "run", "src/cli/index.ts", "sync", command], {
        env: { TMPDIR: tmpdir(), HOME: root, AGENTKEYCHAIN_HOME: root, AKC_KEYCHAIN_TEST_MODE: "1", PATH: "" }, stdout: "pipe", stderr: "pipe",
      });
      const out = result.stdout.toString() + result.stderr.toString();
      expect(result.exitCode, out).toBe(command === "status" ? 0 : 1);
      expect(out).toContain("Managed Cloud");
      expect(out).not.toContain(legacy.token); expect(out).not.toContain(legacy.url);
      expect(readFileSync(syncConfigPath(), "utf8")).toBe(config);
    }
  } finally {
    if (saved === undefined) delete process.env.AGENTKEYCHAIN_HOME; else process.env.AGENTKEYCHAIN_HOME = saved;
    rmSync(root, { recursive: true, force: true });
  }
});

test("legacy sync.json symlink cannot read outside the isolated root", async () => {
  const { symlinkSync } = await import("node:fs");
  const saved = process.env.AGENTKEYCHAIN_HOME;
  const root = mkdtempSync(join(tmpdir(), "akc-legacy-link-"));
  const outside = mkdtempSync(join(tmpdir(), "akc-legacy-outside-"));
  try {
    process.env.AGENTKEYCHAIN_HOME = root;
    const target = join(outside, "synthetic.json");
    writeFileSync(target, JSON.stringify(legacy));
    symlinkSync(target, join(root, "sync.json"));
    expect(() => legacyStatus()).toThrow("symlink");
    expect(loadSyncConfig()).toBeNull();
    expect(readFileSync(target, "utf8")).toBe(JSON.stringify(legacy));
  } finally {
    if (saved === undefined) delete process.env.AGENTKEYCHAIN_HOME; else process.env.AGENTKEYCHAIN_HOME = saved;
    rmSync(root, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true });
  }
});

test("legacy read rejects parent-directory replacement after path validation", () => {
  const saved = process.env.AGENTKEYCHAIN_HOME;
  const base = mkdtempSync(join(tmpdir(), "akc-legacy-parent-race-"));
  const root = join(base, "vault");
  const original = join(base, "vault-original");
  const outside = join(base, "outside");
  mkdirSync(root); mkdirSync(outside);
  try {
    process.env.AGENTKEYCHAIN_HOME = root;
    const approvedPath = syncConfigPath();
    writeFileSync(approvedPath, JSON.stringify({ ...legacy, token: "approved-synthetic" }));
    renameSync(root, original);
    writeFileSync(join(outside, "sync.json"), JSON.stringify({ ...legacy, token: "outside-must-not-read" }));
    symlinkSync(outside, root, "dir");
    expect(() => readSyncConfigText(approvedPath)).toThrow();
  } finally {
    if (saved === undefined) delete process.env.AGENTKEYCHAIN_HOME; else process.env.AGENTKEYCHAIN_HOME = saved;
    rmSync(base, { recursive: true, force: true });
  }
});
