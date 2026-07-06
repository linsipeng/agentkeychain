/**
 * `agentkeychain init` — initialize vault.
 */
import { readPassword } from "../util/prompt.ts";
import {
  ARGON2_PARAMS,
  deriveKEK,
  generateSalt,
  hashKEK,
} from "../crypto/argon2.ts";
import { openDb, vaultExists, vaultDir } from "../vault.ts";
import { createIdentity } from "../identity.ts";
import type { Database } from "bun:sqlite";

/**
 * Pure init logic — write KEK meta + default identity, no I/O.
 * Used by `agentkeychain init` CLI and by tests.
 */
export async function initVault(db: Database, password: string): Promise<{
  identityId: string;
  salt: Uint8Array;
}> {
  const salt = await generateSalt();
  const kek = await deriveKEK(password, salt);
  const kekHash = await hashKEK(kek);

  const now = Date.now();
  db.prepare(
    `INSERT INTO kek_meta
       (id, argon2_salt, argon2_params, kek_hash, created_at, updated_at)
     VALUES (1, ?, ?, ?, ?, ?)`
  ).run(
    salt,
    JSON.stringify(ARGON2_PARAMS),
    kekHash,
    now,
    now
  );

  const identity = await createIdentity(db, {
    name: "default",
    scopes: ["*"],
    kek,
  });

  kek.fill(0);
  return { identityId: identity.id, salt };
}

export async function runInit(): Promise<number> {
  if (vaultExists()) {
    process.stderr.write(
      `vault already exists at ${vaultDir()}\n` +
        `to reinitialize, remove ${vaultDir()} manually\n`
    );
    return 1;
  }

  const password = await readPassword("Master password (min 8 chars): ");
  if (password.length < 8) {
    throw new Error("password must be at least 8 characters");
  }
  const db = openDb();
  const { identityId, salt } = await initVault(db, password);

  process.stdout.write(
    `vault initialized at ${vaultDir()}\n` +
      `default identity: ${identityId} ("default")\n` +
      `Argon2id: memory=${ARGON2_PARAMS.memory / 1024 / 1024}MB, ` +
      `iterations=${ARGON2_PARAMS.iterations}\n` +
      `salt: ${Buffer.from(salt).toString("hex").slice(0, 16)}...\n`
  );

  return 0;
}