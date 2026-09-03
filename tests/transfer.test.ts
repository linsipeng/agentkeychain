/**
 * Transfer (export/import) tests — v0.2 Phase 1.
 * Isolated AGENTKEYCHAIN_HOME per test; never prints secret values.
 */
import { test, expect, beforeEach } from "bun:test";
import { mkdtempSync, existsSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), "agentkeychain-transfer-test-"));
  process.env.AGENTKEYCHAIN_HOME = testDir;
});

async function setup(password: string): Promise<void> {
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  const db = openDb();
  await initVault(db, password);
}

async function seed(db: Awaited<ReturnType<typeof import("../src/vault.ts").openDb>>): Promise<void> {
  const { storeSecret } = await import("../src/secrets.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { loadIdentityByName } = await import("../src/identity.ts");
  const salt = (
    db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as {
      argon2_salt: Uint8Array;
    }
  ).argon2_salt;
  const kek = await deriveKEK("correct-horse-battery", salt);
  const agent = loadIdentityByName(db, "default");
  if (!agent) throw new Error("no default identity");
  await storeSecret(db, {
    name: "openai-prod",
    value: "sk-redacted-value-1",
    scopes: ["openai:chat"],
    metadata: { env: "prod" },
    kek,
    agent,
  });
  await storeSecret(db, {
    name: "cf-token",
    value: "cf-redacted-value-2",
    scopes: ["*"],
    kek,
    agent,
  });
  kek.fill(0);
}

test("export writes a 0600 bundle that contains no plaintext values", async () => {
  await setup("correct-horse-battery");
  const { openDb } = await import("../src/vault.ts");
  const db = openDb();
  await seed(db);

  const { exportVault } = await import("../src/transfer.ts");
  const out = join(testDir, "test-bundle.akcbundle");
  const result = await exportVault(db, "correct-horse-battery", out);

  expect(result.entryCount).toBe(2);
  expect(existsSync(out)).toBe(true);
  expect(statSync(out).mode & 0o777).toBe(0o600);

  const raw = readFileSync(out, "utf8");
  expect(raw).not.toContain("sk-redacted-value-1");
  expect(raw).not.toContain("cf-redacted-value-2");
  expect(raw).not.toContain("openai-prod");
});

test("roundtrip: export from vault A, import into fresh vault B, values match", async () => {
  const PASSWORD = "correct-horse-battery";
  await setup(PASSWORD);
  const { openDb, dbPath } = await import("../src/vault.ts");
  const dbA = openDb();
  await seed(dbA);

  const { exportVault } = await import("../src/transfer.ts");
  const bundlePath = join(testDir, "roundtrip.akcbundle");
  await exportVault(dbA, PASSWORD, bundlePath);

  // Fresh vault B: wipe files, re-init with the same master password.
  const { rmSync } = await import("node:fs");
  rmSync(dbPath());
  await setup(PASSWORD);
  const dbB = openDb();

  const { importBundle, readBundle } = await import("../src/transfer.ts");
  const result = await importBundle(dbB, readBundle(bundlePath), PASSWORD, {
    overwrite: false,
    sourceFileName: "roundtrip.akcbundle",
  });

  expect(result.imported.sort()).toEqual(["cf-token", "openai-prod"]);
  expect(result.skipped).toEqual([]);

  const { getSecret, listSecrets } = await import("../src/secrets.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { loadIdentityByName } = await import("../src/identity.ts");
  const salt = (
    dbB.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as {
      argon2_salt: Uint8Array;
    }
  ).argon2_salt;
  const kek = await deriveKEK(PASSWORD, salt);
  const agent = loadIdentityByName(dbB, "default")!;

  expect(await getSecret(dbB, { name: "openai-prod", kek, agent })).toBe("sk-redacted-value-1");
  expect(await getSecret(dbB, { name: "cf-token", kek, agent })).toBe("cf-redacted-value-2");

  const metas = listSecrets(dbB);
  const openai = metas.find((m) => m.name === "openai-prod");
  expect(openai?.scopes).toEqual(["openai:chat"]);
  expect(openai?.metadata).toEqual({ env: "prod" });
  kek.fill(0);
});

test("wrong bundle password aborts with no partial writes", async () => {
  const PASSWORD = "correct-horse-battery";
  await setup(PASSWORD);
  const { openDb, dbPath } = await import("../src/vault.ts");
  const dbA = openDb();
  await seed(dbA);

  const { exportVault } = await import("../src/transfer.ts");
  const bundlePath = join(testDir, "wrongpw.akcbundle");
  await exportVault(dbA, PASSWORD, bundlePath);

  const { rmSync } = await import("node:fs");
  rmSync(dbPath());
  await setup(PASSWORD);
  const dbB = openDb();
  // Give vault B one pre-existing secret so we can assert no changes happened.
  const { storeSecret } = await import("../src/secrets.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { loadIdentityByName } = await import("../src/identity.ts");
  const salt = (
    dbB.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as {
      argon2_salt: Uint8Array;
    }
  ).argon2_salt;
  const kek = await deriveKEK(PASSWORD, salt);
  const agent = loadIdentityByName(dbB, "default")!;
  await storeSecret(dbB, { name: "preexisting", value: "v", scopes: ["*"], kek, agent });

  const { importBundle, readBundle } = await import("../src/transfer.ts");
  expect(
    importBundle(dbB, readBundle(bundlePath), "totally-wrong-password", {
      overwrite: false,
      sourceFileName: "wrongpw.akcbundle",
    })
  ).rejects.toThrow("cannot decrypt bundle");

  const { listSecrets } = await import("../src/secrets.ts");
  expect(listSecrets(dbB).map((m) => m.name)).toEqual(["preexisting"]);
  kek.fill(0);
});

test("default conflict policy skips; --overwrite replaces and resurrects tombstones", async () => {
  const PASSWORD = "correct-horse-battery";
  await setup(PASSWORD);
  const { openDb, dbPath } = await import("../src/vault.ts");
  const dbA = openDb();
  await seed(dbA);

  const { exportVault } = await import("../src/transfer.ts");
  const bundlePath = join(testDir, "conflict.akcbundle");
  await exportVault(dbA, PASSWORD, bundlePath);

  const { rmSync } = await import("node:fs");
  rmSync(dbPath());
  await setup(PASSWORD);
  const dbB = openDb();

  // B has its own different value under the same name.
  const { storeSecret, getSecret } = await import("../src/secrets.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");
  const { loadIdentityByName } = await import("../src/identity.ts");
  const salt = (
    dbB.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as {
      argon2_salt: Uint8Array;
    }
  ).argon2_salt;
  const kek = await deriveKEK(PASSWORD, salt);
  const agent = loadIdentityByName(dbB, "default")!;
  await storeSecret(dbB, { name: "openai-prod", value: "b-local-value", scopes: ["*"], kek, agent });

  const { importBundle, readBundle } = await import("../src/transfer.ts");

  // 1) default: skip
  const skip = await importBundle(dbB, readBundle(bundlePath), PASSWORD, {
    overwrite: false,
    sourceFileName: "conflict.akcbundle",
  });
  expect(skip.imported).toEqual(["cf-token"]);
  expect(skip.skipped.map((s) => s.name)).toEqual(["openai-prod"]);
  expect(await getSecret(dbB, { name: "openai-prod", kek, agent })).toBe("b-local-value");

  // 2) overwrite: replace, and even resurrect a tombstoned entry
  const { deleteSecret } = await import("../src/secrets.ts");
  deleteSecret(dbB, { name: "openai-prod", agent, kek });
  const ow = await importBundle(dbB, readBundle(bundlePath), PASSWORD, {
    overwrite: true,
    sourceFileName: "conflict.akcbundle",
  });
  expect(ow.imported.sort()).toEqual(["cf-token", "openai-prod"]);
  expect(await getSecret(dbB, { name: "openai-prod", kek, agent })).toBe("sk-redacted-value-1");
  kek.fill(0);
});

test("parseBundleFile rejects garbage", async () => {
  const { parseBundleFile } = await import("../src/transfer.ts");
  expect(() => parseBundleFile("not a bundle")).toThrow("invalid bundle format");
});
