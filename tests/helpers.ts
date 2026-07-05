/**
 * Shared test helper: initialize vault with a password.
 */
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function init(password: string): Promise<void> {
  const { openDb } = await import("../src/vault.ts");
  const { deriveKEK, generateSalt, hashKEK, ARGON2_PARAMS } = await import(
    "../src/crypto/argon2.ts"
  );
  const { createIdentity } = await import("../src/identity.ts");

  if (!process.env.AGENTKEYCHAIN_HOME) {
    const td = mkdtempSync(join(tmpdir(), "agentkeychain-helper-"));
    process.env.AGENTKEYCHAIN_HOME = td;
  }

  // Force fresh db: delete any existing vault.db in this test dir
  const dbFile = join(process.env.AGENTKEYCHAIN_HOME, "vault.db");
  if (existsSync(dbFile)) {
    try {
      rmSync(dbFile);
    } catch {
      // best effort
    }
  }

  const salt = await generateSalt();
  const kek = await deriveKEK(password, salt);
  const kekHash = await hashKEK(kek);

  const db = openDb();
  const now = Date.now();
  db.prepare(
    `INSERT INTO kek_meta (id, argon2_salt, argon2_params, kek_hash, created_at, updated_at)
     VALUES (1, ?, ?, ?, ?, ?)`
  ).run(salt, JSON.stringify(ARGON2_PARAMS), kekHash, now, now);

  await createIdentity(db, {
    name: "default",
    scopes: ["*"],
    kek,
  });

  kek.fill(0);
}
