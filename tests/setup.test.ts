import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const projectRoot = join(import.meta.dir, "..");

test("setup rejects a stale keychain password and replaces it after verification", async () => {
  const root = mkdtempSync(join(tmpdir(), "akc-setup-stale-"));
  const vaultHome = join(root, "vault");
  const fakeBin = join(root, "bin");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(fakeBin, { recursive: true });

  const previousHome = process.env["AGENTKEYCHAIN_HOME"];
  process.env["AGENTKEYCHAIN_HOME"] = vaultHome;
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  const db = openDb();
  await initVault(db, "correct-setup-password");
  db.close();
  if (previousHome === undefined) delete process.env["AGENTKEYCHAIN_HOME"];
  else process.env["AGENTKEYCHAIN_HOME"] = previousHome;

  const securityStub = `#!/bin/sh
case "$1" in
  find-generic-password) printf '%s\\n' 'stale-keychain-password'; exit 0 ;;
  add-generic-password) exit 0 ;;
esac
exit 1
`;
  writeFileSync(join(fakeBin, "security"), securityStub, { mode: 0o755 });
  const secretToolStub = `#!/bin/sh
case "$1" in
  lookup) printf '%s\\n' 'stale-keychain-password'; exit 0 ;;
  store) cat >/dev/null; exit 0 ;;
esac
exit 1
`;
  writeFileSync(join(fakeBin, "secret-tool"), secretToolStub, { mode: 0o755 });

  const proc = Bun.spawn(
    [process.execPath, "run", "src/cli/index.ts", "setup"],
    {
      cwd: projectRoot,
      env: {
        ...process.env,
        AGENTKEYCHAIN_HOME: vaultHome,
        AKC_PASSWORD: "",
        AKC_KEYCHAIN_TEST_MODE: "1",
        AKC_KEYCHAIN_SECURITY_BIN: join(fakeBin, "security"),
        AKC_KEYCHAIN_SECRET_TOOL_BIN: join(fakeBin, "secret-tool"),
      },
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    }
  );
  proc.stdin.write("correct-setup-password\n");
  proc.stdin.end();
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);

  expect(exitCode).toBe(0);
  expect(stdout).toContain("does not unlock this vault");
  expect(stdout).toContain("master password saved to OS keychain");
  expect(stdout).not.toContain("correct-setup-password");
  expect(stdout).not.toContain("stale-keychain-password");
  expect(stderr).not.toContain("correct-setup-password");
  expect(stderr).not.toContain("stale-keychain-password");

  rmSync(root, { recursive: true, force: true });
});

test("setup never updates keychain when the entered password cannot unlock the vault", async () => {
  const root = mkdtempSync(join(tmpdir(), "akc-setup-reject-"));
  const vaultHome = join(root, "vault");
  const fakeBin = join(root, "bin");
  const writeMarker = join(root, "keychain-write-attempted");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(fakeBin, { recursive: true });

  const previousHome = process.env["AGENTKEYCHAIN_HOME"];
  process.env["AGENTKEYCHAIN_HOME"] = vaultHome;
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  const db = openDb();
  await initVault(db, "correct-existing-password");
  db.close();
  if (previousHome === undefined) delete process.env["AGENTKEYCHAIN_HOME"];
  else process.env["AGENTKEYCHAIN_HOME"] = previousHome;

  const securityStub = `#!/bin/sh
case "$1" in
  find-generic-password) printf '%s\\n' 'stale-keychain-password'; exit 0 ;;
  add-generic-password) touch '${writeMarker}'; exit 0 ;;
esac
exit 1
`;
  writeFileSync(join(fakeBin, "security"), securityStub, { mode: 0o755 });
  writeFileSync(
    join(fakeBin, "secret-tool"),
    `#!/bin/sh
case "$1" in
  lookup) printf '%s\\n' 'stale-keychain-password'; exit 0 ;;
  store) touch '${writeMarker}'; cat >/dev/null; exit 0 ;;
esac
exit 1
`,
    { mode: 0o755 }
  );

  const proc = Bun.spawn(
    [process.execPath, "run", "src/cli/index.ts", "setup"],
    {
      cwd: projectRoot,
      env: {
        ...process.env,
        AGENTKEYCHAIN_HOME: vaultHome,
        AKC_PASSWORD: "",
        AKC_KEYCHAIN_TEST_MODE: "1",
        AKC_KEYCHAIN_SECURITY_BIN: join(fakeBin, "security"),
        AKC_KEYCHAIN_SECRET_TOOL_BIN: join(fakeBin, "secret-tool"),
      },
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    }
  );
  proc.stdin.write("wrong-password\n");
  proc.stdin.end();
  const [exitCode, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stderr).text(),
  ]);

  expect(exitCode).toBe(1);
  expect(stderr).toContain("master password rejected");
  expect(existsSync(writeMarker)).toBe(false);
  rmSync(root, { recursive: true, force: true });
});
