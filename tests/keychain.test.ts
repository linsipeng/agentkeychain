/**
 * Tests for src/util/keychain.ts
 *
 * Strategy: we don't hit a real OS keychain. Instead we test the pure logic:
 *   - detectBackend() picks based on platform + AKC_PASSWORD env var
 *   - resolvePassword() prefers AKC_PASSWORD over keychainGet()
 *   - keychainGet() returns null when security binary is missing (ENOENT)
 *   - keychainGet() returns null when security returns "not found" stderr
 *   - keychainGet() returns trimmed stdout on success
 */
import { describe, expect, test, beforeEach } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("keychain", () => {
  let savedHome: string | undefined;
  let savedAkcPw: string | undefined;
  let fakeBinDir: string;
  let savedPath: string | undefined;

  beforeEach(() => {
    savedHome = process.env["HOME"];
    savedAkcPw = process.env["AKC_PASSWORD"];
    savedPath = process.env["PATH"];

    // Make a fake bin dir with a stub `security` command
    fakeBinDir = mkdtempSync(join(tmpdir(), "akc-kc-test-"));
    const securityStub = `#!/bin/sh
# Stub for macOS security command, controllable via AKC_STUB_OUT env var
case "$1" in
  find-generic-password)
    if [ -n "$AKC_STUB_FAIL" ]; then
      echo "could not be found" >&2
      exit 44
    fi
    if [ -n "$AKC_STUB_OUT" ]; then
      echo "$AKC_STUB_OUT"
      exit 0
    fi
    echo "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." >&2
    exit 44
    ;;
  add-generic-password)
    exit 0
    ;;
  delete-generic-password)
    exit 0
    ;;
esac
exit 1
`;
    writeFileSync(join(fakeBinDir, "security"), securityStub, { mode: 0o755 });
    writeFileSync(join(fakeBinDir, "secret-tool"), "#!/bin/sh\n# stub for tests\nif [ -n \"$AKC_STUB_OUT\" ]; then echo \"$AKC_STUB_OUT\"; else cat >/dev/null; fi\nexit 0\n", { mode: 0o755 });
    process.env["PATH"] = fakeBinDir + ":" + (savedPath ?? "");
    delete process.env["AKC_STUB_OUT"];
    delete process.env["AKC_STUB_FAIL"];
  });

  test("detectBackend returns platform-appropriate backend", async () => {
    const { detectBackend } = await import("../src/util/keychain.ts");
    const p = process.platform;
    const expected = p === "darwin" ? "macos-keychain" : p === "linux" ? "linux-libsecret" : "unsupported";
    expect(detectBackend()).toBe(expected);
  });

  test("resolvePassword returns AKC_PASSWORD env var when set", async () => {
    process.env["AKC_PASSWORD"] = "from-env";
    const { resolvePassword } = await import("../src/util/keychain.ts");
    expect(await resolvePassword()).toBe("from-env");
  });

  test("keychainGet returns null when entry does not exist (non-zero exit)", async () => {
    process.env["AKC_STUB_FAIL"] = "1";
    const { keychainGet } = await import("../src/util/keychain.ts");
    expect(await keychainGet()).toBeNull();
  });

  test("keychainGet returns null when binary is missing", async () => {
    process.env["PATH"] = "/nonexistent-no-binaries-here";
    const { keychainGet } = await import("../src/util/keychain.ts");
    expect(await keychainGet()).toBeNull();
  });

  test("resolvePassword falls back to keychainGet when AKC_PASSWORD is empty", async () => {
    process.env["AKC_STUB_OUT"] = "from-keychain";
    process.env["AKC_PASSWORD"] = ""; // empty string should NOT take priority
    const { resolvePassword } = await import("../src/util/keychain.ts");
    expect(await resolvePassword()).toBe("from-keychain");
  });

  test("keychainSet returns true on success", async () => {
    const { keychainSet } = await import("../src/util/keychain.ts");
    expect(await keychainSet("test-password")).toBe(true);
  });

  test("keychainDelete returns true on success", async () => {
    const { keychainDelete } = await import("../src/util/keychain.ts");
    expect(await keychainDelete()).toBe(true);
  });

  // Cleanup helper
  test("cleanup", () => {
    if (savedHome === undefined) delete process.env["HOME"];
    else process.env["HOME"] = savedHome;
    if (savedAkcPw === undefined) delete process.env["AKC_PASSWORD"];
    else process.env["AKC_PASSWORD"] = savedAkcPw;
    if (savedPath === undefined) delete process.env["PATH"];
    else process.env["PATH"] = savedPath;
    rmSync(fakeBinDir, { recursive: true, force: true });
  });
});