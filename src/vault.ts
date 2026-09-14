/**
 * Vault file paths + open helper.
 */
import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, realpathSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { homedir, tmpdir } from "node:os";
import { timingSafeEqual } from "node:crypto";
import { migrate } from "./db/migrate.ts";
import { deriveKEK, hashKEK } from "./crypto/argon2.ts";

export const VAULT_DIR_NAME = ".agentkeychain";
export const DB_FILENAME = "vault.db";

export function vaultDir(): string {
  const configured = process.env.AGENTKEYCHAIN_HOME;
  if (process.env["AKC_KEYCHAIN_TEST_MODE"] === "1") {
    if (!configured) {
      throw new Error("test vault path required: AGENTKEYCHAIN_HOME is not set");
    }
    let testRoot: string;
    let candidate: string;
    try {
      testRoot = realpathSync(tmpdir());
      candidate = realpathSync(configured);
    } catch {
      throw new Error("test vault must already exist inside the system temporary directory");
    }
    if (candidate !== testRoot && !candidate.startsWith(`${testRoot}${sep}`)) {
      throw new Error("test vault must be inside the system temporary directory");
    }
    return candidate;
  }
  return resolve(configured ?? join(homedir(), VAULT_DIR_NAME));
}

export function dbPath(): string {
  return join(vaultDir(), DB_FILENAME);
}

/**
 * True iff the vault file exists AND has been fully initialized
 * (i.e. kek_meta row is present). A bare db file with just the schema
 * from a prior failed init() is NOT a vault.
 */
export function vaultExists(): boolean {
  const path = dbPath();
  if (!existsSync(path)) return false;
  let db: Database | null = null;
  try {
    db = new Database(path, { create: false, readonly: true });
    const row = db
      .prepare(`SELECT 1 AS x FROM kek_meta WHERE id = 1 LIMIT 1`)
      .get() as { x: number } | null;
    return row !== null;
  } catch {
    return false;
  } finally {
    db?.close();
  }
}

/** Verify a password against KEK metadata without reading credential rows. */
export async function verifyVaultPassword(password: string): Promise<boolean> {
  if (!vaultExists()) return false;
  const db = new Database(dbPath(), { create: false, readonly: true });
  let kek: Uint8Array | null = null;
  let actualHash: Uint8Array | null = null;
  let expected: Buffer | null = null;
  let actual: Buffer | null = null;
  try {
    const meta = db
      .prepare(`SELECT argon2_salt, kek_hash FROM kek_meta WHERE id = 1`)
      .get() as { argon2_salt: Uint8Array; kek_hash: Uint8Array } | undefined;
    if (!meta) return false;
    kek = await deriveKEK(password, meta.argon2_salt);
    actualHash = await hashKEK(kek);
    expected = Buffer.from(meta.kek_hash);
    actual = Buffer.from(actualHash);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  } finally {
    kek?.fill(0);
    actualHash?.fill(0);
    expected?.fill(0);
    actual?.fill(0);
    db.close();
  }
}

export function ensureVaultDir(): void {
  const dir = vaultDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

export function openDb(): Database {
  ensureVaultDir();
  const db = new Database(dbPath(), { create: true });
  migrate(db);
  return db;
}
