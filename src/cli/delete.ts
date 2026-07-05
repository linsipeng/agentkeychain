/**
 * `agentkeychain delete <name>` command.
 */
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { openDb } from "../vault.ts";
import { loadIdentityByName } from "../identity.ts";
import { deleteSecret } from "../secrets.ts";
import { deriveKEK } from "../crypto/argon2.ts";

async function promptConfirm(name: string): Promise<boolean> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    process.stdout.write(`Delete secret '${name}'? [y/N] `);
    const answer = await rl.question("");
    return answer.toLowerCase().startsWith("y");
  } finally {
    rl.close();
  }
}

async function promptUnlock(): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    process.stdout.write("Master password: ");
    return await rl.question("");
  } finally {
    rl.close();
  }
}

export async function runDelete(argv: string[]): Promise<number> {
  const name = argv[0];
  const yes = argv.includes("--yes");
  if (!name) {
    process.stderr.write("usage: agentkeychain delete <name> [--yes]\n");
    return 1;
  }
  if (!yes) {
    const confirmed = await promptConfirm(name);
    if (!confirmed) {
      process.stdout.write("aborted\n");
      return 0;
    }
  }
  const db = openDb();
  const agent = loadIdentityByName(db, "default");
  if (!agent) {
    process.stderr.write("vault not initialized\n");
    return 1;
  }
  const meta = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!meta) {
    process.stderr.write("vault corrupted\n");
    return 4;
  }
  const password = await promptUnlock();
  const kek = await deriveKEK(password, meta.argon2_salt);
  try {
    const ok = deleteSecret(db, { name, agent, kek });
    if (ok) {
      process.stdout.write(`✓ deleted: ${name}\n`);
      return 0;
    } else {
      process.stderr.write(`not found: ${name}\n`);
      return 1;
    }
  } finally {
    kek.fill(0);
  }
}
