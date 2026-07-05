/**
 * Secrets CRUD: store / get / list / delete.
 */
import { Database } from "bun:sqlite";
import { encrypt, decrypt } from "./crypto/xchacha.ts";
import { checkScope } from "./auth/scope.ts";
import { append } from "./audit.ts";
import type { Identity } from "./identity.ts";

export interface SecretMeta {
  name: string;
  scopes: string[];
  version: number;
  createdAt: number;
  updatedAt: number;
  metadata: Record<string, unknown> | null;
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ForbiddenError";
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export async function storeSecret(
  db: Database,
  args: {
    name: string;
    value: string;
    scopes: string[];
    metadata?: Record<string, unknown>;
    kek: Uint8Array;
    agent: Identity;
  }
): Promise<SecretMeta> {
  const now = Date.now();
  const { ciphertext, nonce } = await encrypt(args.value, args.kek);

  const existing = db
    .prepare(`SELECT version FROM secrets WHERE name = ?`)
    .get(args.name) as { version: number } | undefined;

  if (existing) {
    db.prepare(
      `UPDATE secrets
       SET ciphertext = ?, nonce = ?, scopes = ?, metadata = ?, updated_at = ?, version = version + 1
       WHERE name = ?`
    ).run(
      ciphertext,
      nonce,
      JSON.stringify(args.scopes),
      args.metadata ? JSON.stringify(args.metadata) : null,
      now,
      args.name
    );
  } else {
    db.prepare(
      `INSERT INTO secrets (name, ciphertext, nonce, scopes, metadata, created_at, updated_at, version)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1)`
    ).run(
      args.name,
      ciphertext,
      nonce,
      JSON.stringify(args.scopes),
      args.metadata ? JSON.stringify(args.metadata) : null,
      now,
      now
    );
  }

  append(db, {
    agentId: args.agent.id,
    action: "store",
    target: args.name,
    success: true,
  });

  return {
    name: args.name,
    scopes: args.scopes,
    version: existing ? existing.version + 1 : 1,
    createdAt: now,
    updatedAt: now,
    metadata: args.metadata ?? null,
  };
}

export async function getSecret(
  db: Database,
  args: {
    name: string;
    kek: Uint8Array;
    agent: Identity;
  }
): Promise<string> {
  const row = db
    .prepare(
      `SELECT ciphertext, nonce, scopes FROM secrets WHERE name = ? AND deleted_at IS NULL`
    )
    .get(args.name) as
    | { ciphertext: Uint8Array; nonce: Uint8Array; scopes: string }
    | undefined;

  if (!row) {
    append(db, {
      agentId: args.agent.id,
      action: "get",
      target: args.name,
      success: false,
    });
    throw new NotFoundError(`secret not found: ${args.name}`);
  }

  const requiredScopes = JSON.parse(row.scopes) as string[];
  if (!checkScope(args.agent.scopes, requiredScopes)) {
    append(db, {
      agentId: args.agent.id,
      action: "get",
      target: args.name,
      success: false,
    });
    throw new ForbiddenError(
      `agent ${args.agent.id} lacks required scope for ${args.name}`
    );
  }

  const plaintext = await decrypt(row.ciphertext, row.nonce, args.kek);

  append(db, {
    agentId: args.agent.id,
    action: "get",
    target: args.name,
    success: true,
  });

  return new TextDecoder().decode(plaintext);
}

export function listSecrets(db: Database): SecretMeta[] {
  const rows = db
    .prepare(
      `SELECT name, scopes, version, created_at, updated_at, metadata
       FROM secrets WHERE deleted_at IS NULL ORDER BY name ASC`
    )
    .all() as Array<{
      name: string;
      scopes: string;
      version: number;
      created_at: number;
      updated_at: number;
      metadata: string | null;
    }>;

  return rows.map((row) => ({
    name: row.name,
    scopes: JSON.parse(row.scopes) as string[],
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    metadata: row.metadata ? (JSON.parse(row.metadata) as Record<string, unknown>) : null,
  }));
}

export function deleteSecret(
  db: Database,
  args: {
    name: string;
    agent: Identity;
  }
): boolean {
  const now = Date.now();
  const result = db
    .prepare(`UPDATE secrets SET deleted_at = ? WHERE name = ? AND deleted_at IS NULL`)
    .run(now, args.name);

  append(db, {
    agentId: args.agent.id,
    action: "delete",
    target: args.name,
    success: result.changes > 0,
  });

  return result.changes > 0;
}
