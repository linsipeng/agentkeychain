/**
 * `agentkeychain get <name> [--json]` command.
 */
import { openDb } from "../vault.ts";
import { loadIdentityByName } from "../identity.ts";
import { getSecret } from "../secrets.ts";
import { deriveKEK } from "../crypto/argon2.ts";
import { readPassword } from "../util/prompt.ts";
import { resolvePassword } from "../util/keychain.ts";

export async function runGet(argv: string[]): Promise<number> {
  const name = argv[0];
  const json = argv.includes("--json");
  if (!name) {
    process.stderr.write("usage: agentkeychain get <name> [--json]\n");
    return 1;
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
  const password = (await resolvePassword()) ?? (await readPassword("Master password: "));
  const kek = await deriveKEK(password, meta.argon2_salt);
  try {
    const value = await getSecret(db, { name, kek, agent });
    if (json) {
      process.stdout.write(JSON.stringify({ name, value, agentId: agent.id }) + "\n");
    } else {
      process.stdout.write(value + "\n");
    }
    return 0;
  } finally {
    kek.fill(0);
  }
}
