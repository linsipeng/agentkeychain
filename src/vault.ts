/**
 * Vault file paths + open helper.
 */
import { Database } from "bun:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { migrate } from "./db/migrate.ts";

export const VAULT_DIR_NAME = ".agentkeychain";
export const DB_FILENAME = "vault.db";

export function vaultDir(): string {
  return process.env.AGENTKEYCHAIN_HOME ?? join(homedir(), VAULT_DIR_NAME);
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
  try {
    const db = new Database(path, { create: false, readonly: true });
    const row = db
      .prepare(`SELECT 1 AS x FROM kek_meta WHERE id = 1 LIMIT 1`)
      .get() as { x: number } | undefined;
    db.close();
    return row !== undefined;
  } catch {
    return false;
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
