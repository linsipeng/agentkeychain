/**
 * Vault export/import — encrypted bundle transfer between machines (v0.2 Phase 1).
 *
 * Bundle file layout: base64(nonce):base64(salt):base64(ciphertext), mode 0600.
 * KDF params (salt) travel OUTSIDE the envelope so the KEK can be derived before
 * decryption. The bundle salt is fresh and independent of the source vault's
 * salt — ANY machine with the same master password can decrypt (1Password-style
 * portability). Integrity: XChaCha20-Poly1305 AEAD auth tag.
 */
import { writeFileSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import sodium from "libsodium-wrappers-sumo";
import type { Database } from "bun:sqlite";
import { encrypt, decrypt } from "./crypto/xchacha.ts";
import { deriveKEK, hashKEK } from "./crypto/argon2.ts";
import { append as auditAppend, unlockIdentity } from "./audit.ts";
import { loadIdentityByName } from "./identity.ts";
import { redact } from "./util/redact.ts";

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) initPromise = sodium.ready;
  await initPromise;
  return sodium;
}

export const BUNDLE_FORMAT = "agentkeychain-export";
export const BUNDLE_FORMAT_VERSION = 1;

export interface BundleEntry {
  name: string;
  scopes: string[];
  metadata: Record<string, unknown> | null;
  version: number;
  createdAt: number;
  updatedAt: number;
  value: string;
}

export interface BundleEnvelope {
  format: string;
  version: number;
  exportedAt: number;
  kekCheckHex: string;
  entries: BundleEntry[];
}

export interface ExportResult {
  path: string;
  fileName: string;
  entryCount: number;
}

/** Bundle file layout: base64(nonce):base64(salt):base64(ciphertext) */
export interface ParsedBundle {
  nonce: Uint8Array;
  salt: Uint8Array;
  ciphertext: Uint8Array;
}

export function parseBundleFile(raw: string): ParsedBundle {
  const parts = raw.trim().split(":");
  if (parts.length !== 3) {
    throw new Error(
      "invalid bundle format (expected nonce:salt:ciphertext) — is this an agentkeychain bundle?"
    );
  }
  const [n, s, c] = parts as [string, string, string];
  return {
    nonce: Buffer.from(n, "base64"),
    salt: Buffer.from(s, "base64"),
    ciphertext: Buffer.from(c, "base64"),
  };
}

function vaultSalt(db: Database): Uint8Array {
  const row = db
    .prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`)
    .get() as { argon2_salt: Uint8Array } | undefined;
  if (!row) throw new Error("vault corrupted — kek_meta missing");
  return row.argon2_salt;
}

async function auditOne(
  db: Database,
  kek: Uint8Array,
  action: "export" | "import",
  target: string,
  success: boolean
): Promise<void> {
  const defaultAgent = loadIdentityByName(db, "default");
  if (!defaultAgent) return;
  const unlocked = await unlockIdentity(db, defaultAgent.id, kek);
  if (!unlocked) return;
  await auditAppend(db, { agent: unlocked, action, target, success, kek });
}

/**
 * Export all live secrets from the vault into an encrypted bundle file.
 * Bundle file is written with mode 0600.
 */
export async function exportVault(
  db: Database,
  password: string,
  outPath: string
): Promise<ExportResult> {
  await ensureSodium();

  const rows = db
    .prepare(
      `SELECT name, ciphertext, nonce, scopes, metadata, version, created_at, updated_at
       FROM secrets WHERE deleted_at IS NULL ORDER BY name ASC`
    )
    .all() as Array<{
      name: string;
      ciphertext: Uint8Array;
      nonce: Uint8Array;
      scopes: string;
      metadata: string | null;
      version: number;
      created_at: number;
      updated_at: number;
    }>;

  const vaultKek = await deriveKEK(password, vaultSalt(db));
  try {
    const entries: BundleEntry[] = [];
    for (const row of rows) {
      const plaintext = await decrypt(row.ciphertext, row.nonce, vaultKek);
      entries.push({
        name: row.name,
        scopes: JSON.parse(row.scopes) as string[],
        metadata: row.metadata ? (JSON.parse(row.metadata) as Record<string, unknown>) : null,
        version: row.version,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        value: new TextDecoder().decode(plaintext),
      });
      plaintext.fill(0);
    }

    // Fresh random salt — bundle decouples from the source vault's salt.
    const s = await ensureSodium();
    const salt = s.randombytes_buf(16);
    const bundleKek = await deriveKEK(password, salt);
    try {
      const kekCheck = await hashKEK(bundleKek);
      const envelope: BundleEnvelope = {
        format: BUNDLE_FORMAT,
        version: BUNDLE_FORMAT_VERSION,
        exportedAt: Date.now(),
        kekCheckHex: Buffer.from(kekCheck).toString("hex"),
        entries,
      };
      const jsonBytes = new TextEncoder().encode(JSON.stringify(envelope));
      const { ciphertext, nonce } = await encrypt(jsonBytes, bundleKek);
      const payload = [
        Buffer.from(nonce).toString("base64"),
        Buffer.from(salt).toString("base64"),
        Buffer.from(ciphertext).toString("base64"),
      ].join(":");

      writeFileSync(outPath, payload + "\n", { mode: 0o600 });

      await auditOne(db, vaultKek, "export", basename(outPath), entries.length > 0);

      return { path: outPath, fileName: basename(outPath), entryCount: entries.length };
    } finally {
      bundleKek.fill(0);
    }
  } finally {
    vaultKek.fill(0);
  }
}

export interface ImportResult {
  imported: string[];
  skipped: Array<{ name: string; reason: string }>;
}

/**
 * Import entries from an encrypted bundle into the target vault.
 *
 * Conflict policy: same-name entries are SKIPPED by default; with
 * `overwrite: true` they are replaced (and a deleted_at tombstone is
 * resurrected — same semantics as the v0.1.1 re-store fix).
 *
 * Wrong password / tampered bundle aborts with NO partial writes (decrypt
 * happens before any DB mutation).
 */
export async function importBundle(
  db: Database,
  bundle: ParsedBundle,
  bundlePassword: string,
  options: { overwrite: boolean; sourceFileName: string }
): Promise<ImportResult> {
  await ensureSodium();
  const targetSalt = vaultSalt(db);

  const bundleKek = await deriveKEK(bundlePassword, bundle.salt);
  try {
    let envelope: BundleEnvelope;
    try {
      const jsonBytes = await decrypt(bundle.ciphertext, bundle.nonce, bundleKek);
      envelope = JSON.parse(new TextDecoder().decode(jsonBytes)) as BundleEnvelope;
      jsonBytes.fill(0);
    } catch {
      throw new Error(
        "cannot decrypt bundle: wrong master password or tampered file (no changes written)"
      );
    }

    if (envelope.format !== BUNDLE_FORMAT) {
      throw new Error(`unsupported bundle format: ${redact(String(envelope.format))}`);
    }
    if (envelope.version !== BUNDLE_FORMAT_VERSION) {
      throw new Error(`unsupported bundle version: ${envelope.version}`);
    }

    const vaultKek = await deriveKEK(bundlePassword, targetSalt);
    try {
      const imported: string[] = [];
      const skipped: Array<{ name: string; reason: string }> = [];
      const now = Date.now();

      for (const entry of envelope.entries) {
        const existing = db
          .prepare(`SELECT version, deleted_at FROM secrets WHERE name = ?`)
          .get(entry.name) as { version: number; deleted_at: number | null } | undefined;

        if (existing && existing.deleted_at === null && !options.overwrite) {
          skipped.push({ name: entry.name, reason: "exists (use --overwrite to replace)" });
          continue;
        }

        const { ciphertext, nonce } = await encrypt(entry.value, vaultKek);
        if (existing) {
          db.prepare(
            `UPDATE secrets
             SET ciphertext = ?, nonce = ?, scopes = ?, metadata = ?,
                 updated_at = ?, version = ?, deleted_at = NULL
             WHERE name = ?`
          ).run(
            ciphertext,
            nonce,
            JSON.stringify(entry.scopes),
            entry.metadata ? JSON.stringify(entry.metadata) : null,
            now,
            Math.max(existing.version, entry.version),
            entry.name
          );
        } else {
          db.prepare(
            `INSERT INTO secrets (name, ciphertext, nonce, scopes, metadata, created_at, updated_at, version)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            entry.name,
            ciphertext,
            nonce,
            JSON.stringify(entry.scopes),
            entry.metadata ? JSON.stringify(entry.metadata) : null,
            entry.createdAt,
            now,
            entry.version
          );
        }
        imported.push(entry.name);
      }

      await auditOne(db, vaultKek, "import", options.sourceFileName, imported.length > 0);

      return { imported, skipped };
    } finally {
      vaultKek.fill(0);
    }
  } finally {
    bundleKek.fill(0);
  }
}

/** Convenience: read a bundle file from disk and parse it. */
export function readBundle(path: string): ParsedBundle {
  return parseBundleFile(readFileSync(path, "utf8"));
}
