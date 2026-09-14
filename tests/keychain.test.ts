/**
 * Tests for src/util/keychain.ts.
 *
 * OS keychain access is fail-closed in test mode. Tests inject explicit stub
 * binaries; they never rely on PATH discovery of the host `security` or
 * `secret-tool` executable.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("keychain", () => {
  let fakeBinDir: string;
  let savedEnv: Record<string, string | undefined>;

  beforeEach(() => {
    savedEnv = {
      HOME: process.env["HOME"],
      AGENTKEYCHAIN_HOME: process.env["AGENTKEYCHAIN_HOME"],
      AKC_PASSWORD: process.env["AKC_PASSWORD"],
      PATH: process.env["PATH"],
      AKC_KEYCHAIN_TEST_MODE: process.env["AKC_KEYCHAIN_TEST_MODE"],
      AKC_KEYCHAIN_SECURITY_BIN: process.env["AKC_KEYCHAIN_SECURITY_BIN"],
      AKC_KEYCHAIN_SECRET_TOOL_BIN: process.env["AKC_KEYCHAIN_SECRET_TOOL_BIN"],
      AKC_STUB_OUT: process.env["AKC_STUB_OUT"],
      AKC_STUB_FAIL: process.env["AKC_STUB_FAIL"],
    };

    fakeBinDir = mkdtempSync(join(tmpdir(), "akc-kc-test-"));
    const securityStub = `#!/bin/sh
case "$1" in
  find-generic-password)
    if [ -n "$AKC_STUB_FAIL" ]; then echo "could not be found" >&2; exit 44; fi
    if [ -n "$AKC_STUB_OUT" ]; then echo "$AKC_STUB_OUT"; exit 0; fi
    echo "could not be found" >&2; exit 44 ;;
  add-generic-password|delete-generic-password) exit 0 ;;
esac
exit 1
`;
    const secretToolStub = `#!/bin/sh
case "$1" in
  lookup)
    if [ -n "$AKC_STUB_FAIL" ]; then echo "could not be found" >&2; exit 44; fi
    if [ -n "$AKC_STUB_OUT" ]; then echo "$AKC_STUB_OUT"; exit 0; fi
    echo "could not be found" >&2; exit 44 ;;
  store|clear) cat >/dev/null; exit 0 ;;
esac
exit 1
`;
    writeFileSync(join(fakeBinDir, "security"), securityStub, { mode: 0o755 });
    writeFileSync(join(fakeBinDir, "secret-tool"), secretToolStub, { mode: 0o755 });

    process.env["AKC_KEYCHAIN_TEST_MODE"] = "1";
    process.env["AKC_KEYCHAIN_SECURITY_BIN"] = join(fakeBinDir, "security");
    process.env["AKC_KEYCHAIN_SECRET_TOOL_BIN"] = join(fakeBinDir, "secret-tool");
    delete process.env["AKC_PASSWORD"];
    delete process.env["AKC_STUB_OUT"];
    delete process.env["AKC_STUB_FAIL"];
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    rmSync(fakeBinDir, { recursive: true, force: true });
  });

  test("detectBackend returns platform-appropriate backend", async () => {
    const { detectBackend } = await import("../src/util/keychain.ts");
    const expected = process.platform === "darwin"
      ? "macos-keychain"
      : process.platform === "linux"
        ? "linux-libsecret"
        : "unsupported";
    expect(detectBackend()).toBe(expected);
  });

  test("resolvePassword returns AKC_PASSWORD env var when set", async () => {
    process.env["AKC_PASSWORD"] = "from-env";
    const { resolvePassword } = await import("../src/util/keychain.ts");
    expect(await resolvePassword()).toBe("from-env");
  });

  test("keychainGet returns null when entry does not exist", async () => {
    process.env["AKC_STUB_FAIL"] = "1";
    const { keychainGet } = await import("../src/util/keychain.ts");
    expect(await keychainGet()).toBeNull();
  });

  test("keychainGet returns null when injected binary is missing", async () => {
    process.env["AKC_KEYCHAIN_SECURITY_BIN"] = "/nonexistent/security";
    process.env["AKC_KEYCHAIN_SECRET_TOOL_BIN"] = "/nonexistent/secret-tool";
    const { keychainGet } = await import("../src/util/keychain.ts");
    expect(await keychainGet()).toBeNull();
  });

  test("resolvePassword falls back to keychainGet", async () => {
    process.env["AKC_STUB_OUT"] = "from-keychain";
    process.env["AKC_PASSWORD"] = "";
    const { resolvePassword } = await import("../src/util/keychain.ts");
    expect(await resolvePassword()).toBe("from-keychain");
  });

  test("keychainSet uses an explicitly injected stub", async () => {
    process.env["AKC_PASSWORD"] = "";
    const { keychainSet } = await import("../src/util/keychain.ts");
    expect(await keychainSet("test-password")).toBe(true);
  });

  test("keychainDelete uses an explicitly injected stub", async () => {
    process.env["AKC_PASSWORD"] = "";
    const { keychainDelete } = await import("../src/util/keychain.ts");
    expect(await keychainDelete()).toBe(true);
  });

  test("test mode refuses OS keychain access without an explicit stub binary", async () => {
    const marker = join(fakeBinDir, "REAL_KEYCHAIN_WAS_CALLED");
    writeFileSync(
      join(fakeBinDir, "security"),
      `#!/bin/sh\ntouch '${marker}'\nexit 0\n`,
      { mode: 0o755 }
    );
    process.env["PATH"] = `${fakeBinDir}:${savedEnv.PATH ?? ""}`;
    delete process.env["AKC_KEYCHAIN_SECURITY_BIN"];
    delete process.env["AKC_KEYCHAIN_SECRET_TOOL_BIN"];

    const { keychainSet } = await import("../src/util/keychain.ts");
    expect(await keychainSet("must-never-reach-real-keychain")).toBe(false);
    expect(existsSync(marker)).toBe(false);
  });

  test("custom vault homes use a different deterministic keychain service", async () => {
    const { keychainService } = await import("../src/util/keychain.ts");
    delete process.env["AGENTKEYCHAIN_HOME"];
    const defaultService = keychainService();
    process.env["AGENTKEYCHAIN_HOME"] = "/tmp/akc-e2e-vault-a";
    const customA1 = keychainService();
    const customA2 = keychainService();
    process.env["AGENTKEYCHAIN_HOME"] = "/tmp/akc-e2e-vault-b";
    const customB = keychainService();

    expect(defaultService).toBe("agentkeychain.vault");
    expect(customA1).toBe(customA2);
    expect(customA1).not.toBe(defaultService);
    expect(customA1).not.toBe(customB);
  });
});
