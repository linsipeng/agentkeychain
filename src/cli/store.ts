/**
 * `agentkeychain store <name> --value <value> --scopes "..."` command.
 */
import { loadIdentityByName } from "../identity.ts";
import { openDb, vaultDir } from "../vault.ts";
import { storeSecret } from "../secrets.ts";
import { deriveKEK } from "../crypto/argon2.ts";
import { readPassword, readLine } from "../util/prompt.ts";
import { parseScopes } from "../auth/scope.ts";

function parseStoreArgs(argv: string[]): {
  name: string | null;
  value: string | null;
  scopes: string[];
} {
  let name: string | null = null;
  let value: string | null = null;
  let scopesRaw = "";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--value" || a === "-v") {
      value = argv[++i] ?? null;
    } else if (a === "--scopes" || a === "-s") {
      scopesRaw = argv[++i] ?? "";
    } else if (!a.startsWith("-") && name === null) {
      name = a;
    }
  }
  return { name, value, scopes: parseScopes(scopesRaw) };
}

export async function runStore(argv: string[]): Promise<number> {
  const parsed = parseStoreArgs(argv);
  const { name, scopes } = parsed;
  let value = parsed.value;
  if (!name) {
    process.stderr.write('usage: agentkeychain store <name> --value <value> --scopes "..."\n');
    return 1;
  }
  if (value === null) {
    value = await readLine("Value: ");
  }
  if (scopes.length === 0) {
    process.stderr.write('error: --scopes required (e.g. --scopes "openai:chat")\n');
    return 1;
  }

  const db = openDb();
  const agent = loadIdentityByName(db, "default");
  if (!agent) {
    process.stderr.write("vault not initialized — run `agentkeychain init` first\n");
    return 1;
  }

  const metaRow = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!metaRow) {
    process.stderr.write("vault corrupted — kek_meta missing\n");
    return 4;
  }

  const password = await readPassword("Master password: ");
  const kek = await deriveKEK(password, metaRow.argon2_salt);

  try {
    const meta = await storeSecret(db, {
      name,
      value,
      scopes,
      kek,
      agent,
    });
    process.stdout.write(
      `✓ encrypted and stored: ${meta.name}
` +
        `  scopes: ${meta.scopes.join(", ")}
` +
        `  version: ${meta.version}
` +
        `  vault: ${vaultDir()}
`
    );
    return 0;
  } finally {
    kek.fill(0);
  }
}
