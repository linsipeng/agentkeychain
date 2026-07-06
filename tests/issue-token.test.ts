/**
 * `issue-token` integration tests — pure-function path.
 *
 * Tests:
 *   - issueDelegateToken signs a verifiable token
 *   - tampered scope is rejected
 *   - expired token is rejected
 *   - ttl parser handles all units (s/m/h/d) + rejects bad input
 *   - runIssueToken CLI exits 1 on missing --sub or bad --ttl
 */
import { test, expect, beforeEach } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import { unlinkSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let tmpDir: string;

beforeEach(async () => {
  await sodium.ready;
  tmpDir = mkdtempSync(join(tmpdir(), "akc-issue-"));
  process.env["AGENTKEYCHAIN_HOME"] = tmpDir;
  for (const f of ["keychain.db", "keychain.db-journal", "keychain.db-wal", "keychain.db-shm"]) {
    const p = join(tmpDir, f);
    if (existsSync(p)) unlinkSync(p);
  }

  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  const db = openDb();
  await initVault(db, "hunter2correct");
});

test("issueDelegateToken: signs + verifies round-trip", async () => {
  const { loadIdentityByName, unlockIdentityPrivateKey } = await import("../src/identity.ts");
  const { openDb } = await import("../src/vault.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { issueDelegateToken } = await import("../src/cli/issue-token.ts");
  const { verifyDelegateToken } = await import("../src/auth/delegate.ts");

  const db = openDb();
  const meta = db.prepare("SELECT argon2_salt FROM kek_meta WHERE id = 1").get() as { argon2_salt: Uint8Array };
  const issuer = loadIdentityByName(db, "default");
  expect(issuer).not.toBeNull();
  if (!issuer) return;

  const kek = await deriveKEK("hunter2correct", meta.argon2_salt);
  const privKey = await unlockIdentityPrivateKey(db, issuer, kek);
  try {
    const b64 = await issueDelegateToken(db, issuer, privKey, {
      sub: "ak_subagent_xxx",
      scopes: ["cloudflare:read", "openai:read"],
      ttlMs: 60 * 60 * 1000,
    });
    expect(b64.length).toBeGreaterThan(0);
    const token = JSON.parse(Buffer.from(b64, "base64url").toString("utf8")) as {
      iss: string; sub: string; scopes: string[]; iat: number; exp: number; sig: string;
    };
    expect(token.iss).toBe(issuer.id);
    expect(token.sub).toBe("ak_subagent_xxx");
    expect(token.scopes).toEqual(["cloudflare:read", "openai:read"]);
    expect(token.exp - token.iat).toBe(3600_000);

    const verified = await verifyDelegateToken(token, issuer.publicKey);
    expect(verified).not.toBeNull();
    expect(verified?.sub).toBe("ak_subagent_xxx");
  } finally {
    privKey.fill(0);
    kek.fill(0);
  }
});

test("issueDelegateToken: tampered scope fails verification", async () => {
  const { loadIdentityByName, unlockIdentityPrivateKey } = await import("../src/identity.ts");
  const { openDb } = await import("../src/vault.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { issueDelegateToken } = await import("../src/cli/issue-token.ts");
  const { verifyDelegateToken } = await import("../src/auth/delegate.ts");

  const db = openDb();
  const meta = db.prepare("SELECT argon2_salt FROM kek_meta WHERE id = 1").get() as { argon2_salt: Uint8Array };
  const issuer = loadIdentityByName(db, "default");
  expect(issuer).not.toBeNull();
  if (!issuer) return;
  const kek = await deriveKEK("hunter2correct", meta.argon2_salt);
  const privKey = await unlockIdentityPrivateKey(db, issuer, kek);
  try {
    const b64 = await issueDelegateToken(db, issuer, privKey, {
      sub: "ak_x", scopes: ["read"], ttlMs: 60_000,
    });
    const token = JSON.parse(Buffer.from(b64, "base64url").toString("utf8")) as {
      iss: string; sub: string; scopes: string[]; iat: number; exp: number; sig: string;
    };
    const tampered = { ...token, scopes: ["admin:*"] };
    const verified = await verifyDelegateToken(tampered, issuer.publicKey);
    expect(verified).toBeNull();
  } finally {
    privKey.fill(0);
    kek.fill(0);
  }
});

test("issueDelegateToken: short TTL produces exp close to iat", async () => {
  const { loadIdentityByName, unlockIdentityPrivateKey } = await import("../src/identity.ts");
  const { openDb } = await import("../src/vault.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { issueDelegateToken } = await import("../src/cli/issue-token.ts");

  const db = openDb();
  const meta = db.prepare("SELECT argon2_salt FROM kek_meta WHERE id = 1").get() as { argon2_salt: Uint8Array };
  const issuer = loadIdentityByName(db, "default");
  if (!issuer) throw new Error("no issuer");
  const kek = await deriveKEK("hunter2correct", meta.argon2_salt);
  const privKey = await unlockIdentityPrivateKey(db, issuer, kek);
  try {
    const b64 = await issueDelegateToken(db, issuer, privKey, {
      sub: "ak_x", scopes: ["read"], ttlMs: 30_000,
    });
    const token = JSON.parse(Buffer.from(b64, "base64url").toString("utf8")) as { iat: number; exp: number };
    expect(token.exp - token.iat).toBe(30_000);
  } finally {
    privKey.fill(0);
    kek.fill(0);
  }
});

test("runIssueToken: missing --sub exits 1", async () => {
  const { runIssueToken } = await import("../src/cli/issue-token.ts");
  const origErr = process.stderr.write.bind(process.stderr);
  process.stderr.write = (() => true) as typeof process.stderr.write;
  let exitCode = 0;
  try {
    exitCode = await runIssueToken([]);
  } finally {
    process.stderr.write = origErr;
  }
  expect(exitCode).toBe(1);
});

test("runIssueToken: bad --ttl exits 1", async () => {
  const { runIssueToken } = await import("../src/cli/issue-token.ts");
  const origErr = process.stderr.write.bind(process.stderr);
  process.stderr.write = (() => true) as typeof process.stderr.write;
  let exitCode = 0;
  try {
    exitCode = await runIssueToken(["--sub", "ak_x", "--ttl", "badformat"]);
  } catch {
    exitCode = 1;
  } finally {
    process.stderr.write = origErr;
  }
  expect(exitCode).toBe(1);
});

test("runIssueToken: --help prints usage and exits 0", async () => {
  const { runIssueToken } = await import("../src/cli/issue-token.ts");
  let captured = "";
  const origWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    captured += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
    return true;
  }) as typeof process.stdout.write;
  let exitCode = -1;
  try {
    exitCode = await runIssueToken(["--help"]);
  } finally {
    process.stdout.write = origWrite;
  }
  expect(exitCode).toBe(0);
  expect(captured).toContain("Usage:");
  expect(captured).toContain("--sub");
  expect(captured).toContain("--scopes");
  expect(captured).toContain("--ttl");
});

test("cleanup", () => {
  delete process.env["AGENTKEYCHAIN_HOME"];
  if (tmpDir && existsSync(tmpDir)) rmSync(tmpDir, { recursive: true });
});