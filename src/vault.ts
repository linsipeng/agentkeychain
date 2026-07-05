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

export function vaultExists(): boolean {
  return existsSync(dbPath());
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
