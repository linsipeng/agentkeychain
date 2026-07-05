/**
 * `agentkeychain init` — initialize vault.
 */
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  ARGON2_PARAMS,
  deriveKEK,
  generateSalt,
  hashKEK,
} from "../crypto/argon2.ts";
import { openDb, vaultExists, vaultDir } from "../vault.ts";
import { createIdentity } from "../identity.ts";

async function promptPassword(confirm = false): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    process.stdout.write("Master password: ");
    const pw = await rl.question("");
    if (confirm) {
      process.stdout.write("Confirm: ");
      const pw2 = await rl.question("");
      if (pw !== pw2) {
        throw new Error("passwords do not match");
      }
    }
    if (pw.length < 8) {
      throw new Error("password must be at least 8 characters");
    }
    return pw;
  } finally {
    rl.close();
  }
}

export async function runInit(): Promise<number> {
  if (vaultExists()) {
    process.stderr.write(
      `vault already exists at ${vaultDir()}\n` +
        `to reinitialize, remove ${vaultDir()} manually\n`
    );
    return 1;
  }

  const password = await promptPassword(true);
  const salt = await generateSalt();
  const kek = await deriveKEK(password, salt);
  const kekHash = await hashKEK(kek);

  const db = openDb();
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

  process.stdout.write(
    `vault initialized at ${vaultDir()}\n` +
      `default identity: ${identity.id} ("${identity.name}")\n` +
      `Argon2id: memory=${ARGON2_PARAMS.memory / 1024 / 1024}MB, ` +
      `iterations=${ARGON2_PARAMS.iterations}, ` +
      `parallelism=${ARGON2_PARAMS.parallelism}\n`
  );

  return 0;
}
