/**
 * Cloud sync (BYO Cloudflare) — client core.
 *
 * sync.json layout (0600): { url, token, deviceId, lastPushAt, lastPullAt }
 * Name privacy: rows are keyed by BLAKE2b-256 keyed hash of the real name
 * (key derived from master password). The cloud never sees plaintext names.
 */
import { readFileSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import sodium from "libsodium-wrappers-sumo";
import type { Database } from "bun:sqlite";
import { deriveKEK, hashKEK } from "./crypto/argon2.ts";
import { encrypt } from "./crypto/xchacha.ts";
import { decrypt } from "./crypto/xchacha.ts";
import { append as auditAppend, unlockIdentity } from "./audit.ts";
import { loadIdentityByName } from "./identity.ts";
import { redact } from "./util/redact.ts";

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) initPromise = sodium.ready;
  await initPromise;
  return sodium;
}

export const SYNC_CONFIG_FILE = "sync.json";

export interface SyncConfig {
  url: string;
  token: string;
  deviceId: string;
  lastPushAt: number;
  lastPullAt: number;
}

export function syncConfigPath(): string {
  const home = process.env.AGENTKEYCHAIN_HOME ?? join(process.env.HOME ?? "", ".agentkeychain");
  return join(home, SYNC_CONFIG_FILE);
}

export function loadSyncConfig(): SyncConfig | null {
  const path = syncConfigPath();
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as SyncConfig;
  } catch {
    return null;
  }
}

export function saveSyncConfig(config: SyncConfig): void {
  writeFileSync(syncConfigPath(), JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
}

export function deleteSyncConfig(): boolean {
  const path = syncConfigPath();
  if (!existsSync(path)) return false;
  unlinkSync(path);
  return true;
}

/** Random URL-safe device id (persists per vault in sync.json). */
export async function generateSyncToken(): Promise<string> {
  const s = await ensureSodium();
  return Buffer.from(s.randombytes_buf(32)).toString("base64url");
}

export async function generateDeviceId(): Promise<string> {
  const s = await ensureSodium();
  const bytes = s.randombytes_buf(8);
  return "dev_" + Buffer.from(bytes).toString("hex");
}

/**
 * Deterministic name hint: BLAKE2b-256 keyed with a name-key derived from the
 * master password. Irreversible; same name on two machines → same hint.
 * (Master password may rotate per machine in future — hint uses the BUNDLE-
 * INDEPENDENT derivation so it stays stable per name+password.)
 */
export async function nameHint(db: Database, password: string, name: string): Promise<string> {
  const metaRow = db
    .prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`)
    .get() as { argon2_salt: Uint8Array } | undefined;
  if (!metaRow) throw new Error("vault corrupted — kek_meta missing");
  const kek = await deriveKEK(password, metaRow.argon2_salt);
  try {
    // name-key = BLAKE2b("akc-name-key" || KEK); hint = BLAKE2b-256(name, key=name-key)
    const s = await ensureSodium();
    const kekStr = Buffer.from(kek).toString("base64");
    const nameKey = s.crypto_generichash(32, "akc-name-key|" + kekStr, null);
    const hint = s.crypto_generichash(32, name, nameKey);
    return Buffer.from(hint).toString("hex");
  } finally {
    // kek is a fresh buffer we own
  }
}

/** Self-contained envelope for a secret row: base64(nonce:salt:ciphertext). */
export interface RowEnvelope {
  nonceB64: string;
  saltB64: string;
  ciphertextB64: string;
  name: string; // encrypted inside the envelope payload, not readable by cloud
}

interface EnvelopePayload {
  name: string;
  value: string;
  scopes: string[];
  metadata: Record<string, unknown> | null;
  version: number;
}

/**
 * Build the cloud envelope for one secret: the whole payload (including the
 * NAME) is encrypted with a fresh random salt + master password, so the cloud
 * sees nothing readable. Format matches the v0.2 export bundle layout.
 */
export async function buildEnvelope(
  db: Database,
  password: string,
  name: string
): Promise<{ nameHint: string; envelope: string; updatedAt: number; deleted: 0 } | null> {
  const row = db
    .prepare(
      `SELECT ciphertext, nonce, scopes, metadata, version, updated_at
       FROM secrets WHERE name = ? AND deleted_at IS NULL`
    )
    .get(name) as
    | { ciphertext: Uint8Array; nonce: Uint8Array; scopes: string; metadata: string | null; version: number; updated_at: number }
    | undefined;
  if (!row) return null;

  const vaultKek = await deriveKEK(password, vaultSalt(db));
  try {
    const plaintext = await decrypt(row.ciphertext, row.nonce, vaultKek);
    const payload: EnvelopePayload = {
      name,
      value: new TextDecoder().decode(plaintext),
      scopes: JSON.parse(row.scopes) as string[],
      metadata: row.metadata ? (JSON.parse(row.metadata) as Record<string, unknown>) : null,
      version: row.version,
    };
    plaintext.fill(0);

    const s = await ensureSodium();
    const salt = s.randombytes_buf(16);
    const envKek = await deriveKEK(password, salt);
    try {
      const jsonBytes = new TextEncoder().encode(JSON.stringify(payload));
      const { ciphertext, nonce } = await encrypt(jsonBytes, envKek);
      const envelope = [
        Buffer.from(nonce).toString("base64"),
        Buffer.from(salt).toString("base64"),
        Buffer.from(ciphertext).toString("base64"),
      ].join(":");
      return {
        nameHint: await nameHint(db, password, name),
        envelope,
        updatedAt: Math.floor(row.updated_at / 1000),
        deleted: 0,
      };
    } finally {
      envKek.fill(0);
    }
  } finally {
    vaultKek.fill(0);
  }
}

/** Decrypt a cloud envelope back into a secret payload. */
export async function openEnvelope(
  db: Database,
  password: string,
  envelope: string
): Promise<EnvelopePayload> {
  const parts = envelope.trim().split(":");
  if (parts.length !== 3) throw new Error("invalid envelope from cloud");
  const nonce = Buffer.from(parts[0]!, "base64");
  const salt = Buffer.from(parts[1]!, "base64");
  const ciphertext = Buffer.from(parts[2]!, "base64");
  const envKek = await deriveKEK(password, salt);
  try {
    const jsonBytes = await decrypt(ciphertext, nonce, envKek);
    const parsed = JSON.parse(new TextDecoder().decode(jsonBytes)) as EnvelopePayload;
    jsonBytes.fill(0);
    return parsed;
  } catch {
    throw new Error("cannot decrypt cloud row — master password mismatch?");
  } finally {
    envKek.fill(0);
  }
}

function vaultSalt(db: Database): Uint8Array {
  const row = db
    .prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`)
    .get() as { argon2_salt: Uint8Array } | undefined;
  if (!row) throw new Error("vault corrupted — kek_meta missing");
  return row.argon2_salt;
}

async function auditSync(
  db: Database,
  password: string,
  action: "sync_push" | "sync_pull",
  rowCount: number
): Promise<void> {
  try {
    const defaultAgent = loadIdentityByName(db, "default");
    if (!defaultAgent) return;
    const vaultKek = await deriveKEK(password, vaultSalt(db));
    const unlocked = await unlockIdentity(db, defaultAgent.id, vaultKek);
    if (unlocked) {
      await auditAppend(db, {
        agent: unlocked,
        action,
        target: `${rowCount} row(s)`,
        success: true,
        kek: vaultKek,
      });
    }
    vaultKek.fill(0);
  } catch {
    // audit is best-effort for sync operations
  }
}

// ---- HTTP helpers ----------------------------------------------------------

async function apiCall(
  config: SyncConfig,
  method: string,
  path: string,
  body?: unknown
): Promise<{ status: number; json: unknown }> {
  const res = await fetch(config.url.replace(/\/$/, "") + path, {
    method,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${config.token}`,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    // non-json response
  }
  return { status: res.status, json };
}

// ---- Sync operations -------------------------------------------------------

export interface PushResult {
  pushed: number;
  written: number;
}

/** Push live secrets (or all on first sync) to the cloud. */
export async function syncPush(db: Database, password: string, config: SyncConfig): Promise<PushResult> {
  const sinceMs = config.lastPushAt > 0 ? config.lastPushAt : 0;
  const names = (
    db
      .prepare(
        `SELECT name FROM secrets WHERE deleted_at IS NULL AND updated_at > ? ORDER BY name`
      )
      .all(sinceMs) as Array<{ name: string }>
  ).map((r) => r.name);

  let pushed = 0;
  let written = 0;

  for (let i = 0; i < names.length; i += 100) {
    const batch = names.slice(i, i + 100);
    const rows: Array<{ name_hint: string; envelope: string; updated_at: number; deleted: 0 }> = [];
    for (const name of batch) {
      const built = await buildEnvelope(db, password, name);
      if (built) {
        rows.push({
          name_hint: built.nameHint,
          envelope: built.envelope,
          updated_at: built.updatedAt,
          deleted: 0,
        });
      }
    }
    if (rows.length === 0) continue;
    const { status, json } = await apiCall(config, "POST", "/v1/rows", { rows });
    if (status === 401) throw new Error("sync auth failed (401) — token mismatch, run sync connect");
    if (status !== 200) throw new Error(`sync push failed (${status}): ${redact(JSON.stringify(json))}`);
    const result = json as { written?: number };
    pushed += rows.length;
    written += result.written ?? 0;
  }

  config.lastPushAt = Date.now(); // ms precision — truncating to seconds skips same-second rows
  saveSyncConfig(config);
  await auditSync(db, password, "sync_push", pushed);
  return { pushed, written };
}

export interface PullResult {
  pulled: number;
  applied: number;
  skipped: number;
}

/** Pull rows from the cloud and LWW-merge into the local vault. */
export async function syncPull(db: Database, password: string, config: SyncConfig): Promise<PullResult> {
  const sinceSec = config.lastPullAt > 0 ? Math.floor(config.lastPullAt / 1000) : 0;
  const { status, json } = await apiCall(config, "GET", `/v1/rows?since=${sinceSec}`);
  if (status === 401) throw new Error("sync auth failed (401) — token mismatch, run sync connect");
  if (status !== 200) throw new Error(`sync pull failed (${status})`);

  const rows = (json as { rows: Array<{ name_hint: string; envelope: string; updated_at: number; deleted: number }> }).rows ?? [];
  const vaultKek = await deriveKEK(password, vaultSalt(db));
  let applied = 0;
  let skipped = 0;
  const nowMs = Date.now();

  try {
    for (const row of rows) {
      if (row.deleted === 1) continue; // v0.3: tombstones don't propagate deletes locally

      let payload: EnvelopePayload;
      try {
        payload = await openEnvelope(db, password, row.envelope);
      } catch {
        skipped++;
        continue; // wrong password or corrupt row
      }

      const existing = db
        .prepare(`SELECT updated_at, version, deleted_at FROM secrets WHERE name = ?`)
        .get(payload.name) as { updated_at: number; version: number; deleted_at: number | null } | undefined;

      const cloudUpdatedAt = row.updated_at * 1000;
      if (existing && existing.updated_at >= cloudUpdatedAt && existing.deleted_at === null) {
        skipped++;
        continue; // local is same or newer — LWW keeps local
      }

      const { encrypt } = await import("./crypto/xchacha.ts");
      const { ciphertext, nonce } = await encrypt(payload.value, vaultKek);
      if (existing) {
        db.prepare(
          `UPDATE secrets SET ciphertext = ?, nonce = ?, scopes = ?, metadata = ?,
           updated_at = ?, version = ?, deleted_at = NULL WHERE name = ?`
        ).run(
          ciphertext,
          nonce,
          JSON.stringify(payload.scopes),
          payload.metadata ? JSON.stringify(payload.metadata) : null,
          nowMs,
          Math.max(existing.version, payload.version),
          payload.name
        );
      } else {
        db.prepare(
          `INSERT INTO secrets (name, ciphertext, nonce, scopes, metadata, created_at, updated_at, version)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          payload.name,
          ciphertext,
          nonce,
          JSON.stringify(payload.scopes),
          payload.metadata ? JSON.stringify(payload.metadata) : null,
          nowMs,
          nowMs,
          payload.version
        );
      }
      applied++;
    }
  } finally {
    vaultKek.fill(0);
  }

  config.lastPullAt = nowMs;
  saveSyncConfig(config);
  await auditSync(db, password, "sync_pull", rows.length);
  return { pulled: rows.length, applied, skipped };
}

export interface HealthResult {
  ok: boolean;
  version?: number | undefined;
}

export async function syncHealth(config: SyncConfig): Promise<HealthResult> {
  try {
    const res = await fetch(config.url.replace(/\/$/, "") + "/v1/health");
    if (!res.ok) return { ok: false };
    const body = (await res.json()) as { ok: boolean; version?: number };
    return { ok: body.ok === true, version: body.version };
  } catch {
    return { ok: false };
  }
}

/** Count live local rows (for status reconciliation). */
export function localRowCount(db: Database): number {
  const row = db
    .prepare(`SELECT COUNT(*) AS n FROM secrets WHERE deleted_at IS NULL`)
    .get() as { n: number };
  return row.n;
}

export { hashKEK };
