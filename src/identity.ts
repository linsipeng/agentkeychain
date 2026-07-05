/**
 * Agent Identity: generate Ed25519 keypair, encrypt private key, persist.
 */
import sodium from 'libsodium-wrappers-sumo';
import { Database } from "bun:sqlite";
import { generateKeypair, encryptPrivKey } from "./crypto/keys.ts";

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) initPromise = sodium.ready;
  await initPromise;
  return sodium;
}

export interface Identity {
  id: string;
  name: string;
  publicKey: Uint8Array;
  scopes: string[];
  parentId: string | null;
  createdAt: number;
  expiresAt: number | null;
}

async function generateAgentId(): Promise<string> {
  const s = await ensureSodium();
  const bytes = s.randombytes_buf(16);
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(value >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 0x1f];
  return "ak_" + out;
}

export async function createIdentity(
  db: Database,
  args: {
    name: string;
    scopes: string[];
    kek: Uint8Array;
    parentId?: string;
    expiresAt?: number;
  }
): Promise<Identity> {
  const id = await generateAgentId();
  const { publicKey, privateKey } = await generateKeypair();
  const { ciphertext, nonce } = await encryptPrivKey(privateKey, args.kek);

  const now = Date.now();
  db.prepare(
    `INSERT INTO identities
       (id, name, public_key, encrypted_priv, priv_nonce, scopes, parent_id, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    args.name,
    publicKey,
    ciphertext,
    nonce,
    JSON.stringify(args.scopes),
    args.parentId ?? null,
    now,
    args.expiresAt ?? null
  );

  privateKey.fill(0);

  return {
    id,
    name: args.name,
    publicKey,
    scopes: args.scopes,
    parentId: args.parentId ?? null,
    createdAt: now,
    expiresAt: args.expiresAt ?? null,
  };
}

export function loadIdentity(db: Database, id: string): Identity | null {
  const row = db
    .prepare(
      `SELECT id, name, public_key, scopes, parent_id, created_at, expires_at
       FROM identities WHERE id = ? AND revoked_at IS NULL`
    )
    .get(id) as
    | {
        id: string;
        name: string;
        public_key: Uint8Array;
        scopes: string;
        parent_id: string | null;
        created_at: number;
        expires_at: number | null;
      }
    | undefined;
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    publicKey: row.public_key,
    scopes: JSON.parse(row.scopes) as string[],
    parentId: row.parent_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

/**
 * Load identity by human-readable name (e.g. "default").
 */
export function loadIdentityByName(db: Database, name: string): Identity | null {
  const row = db
    .prepare(
      `SELECT id, name, public_key, scopes, parent_id, created_at, expires_at
       FROM identities WHERE name = ? AND revoked_at IS NULL`
    )
    .get(name) as
    | {
        id: string;
        name: string;
        public_key: Uint8Array;
        scopes: string;
        parent_id: string | null;
        created_at: number;
        expires_at: number | null;
      }
    | undefined;
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    publicKey: row.public_key,
    scopes: JSON.parse(row.scopes) as string[],
    parentId: row.parent_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

export function listIdentities(db: Database): Identity[] {
  const rows = db
    .prepare(
      `SELECT id, name, public_key, scopes, parent_id, created_at, expires_at
       FROM identities WHERE revoked_at IS NULL ORDER BY created_at ASC`
    )
    .all() as Array<{
      id: string;
      name: string;
      public_key: Uint8Array;
      scopes: string;
      parent_id: string | null;
      created_at: number;
      expires_at: number | null;
    }>;
  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    publicKey: row.public_key,
    scopes: JSON.parse(row.scopes) as string[],
    parentId: row.parent_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  }));
}
