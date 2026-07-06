/**
 * `agentkeychain store <name> --value <value> --scopes "..."` command.
 *
 * Human-friendly default: when invoked interactively (no `--scopes` flag),
 * the secret is stored with `["*"]` (universal scope) so the user doesn't
 * have to invent scope strings. Programmatic callers should ALWAYS pass
 * `--scopes` explicitly — this is the IAM contract.
 */
import { loadIdentityByName } from "../identity.ts";
import { openDb, vaultDir } from "../vault.ts";
import { storeSecret } from "../secrets.ts";
import { deriveKEK } from "../crypto/argon2.ts";
import { readPassword, readLines } from "../util/prompt.ts";
import { resolvePassword } from "../util/keychain.ts";
import { parseScopes } from "../auth/scope.ts";

function parseStoreArgs(argv: string[]): {
  name: string | null;
  value: string | null;
  scopes: string[] | null; // null = user did not pass --scopes
} {
  let name: string | null = null;
  let value: string | null = null;
  let scopesRaw: string | null = null;
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
  return {
    name,
    value,
    scopes: scopesRaw === null ? null : parseScopes(scopesRaw),
  };
}

export async function runStore(argv: string[]): Promise<number> {
  const parsed = parseStoreArgs(argv);
  const { name, scopes: scopesOrNull } = parsed;
  let value = parsed.value;
  if (!name) {
    process.stderr.write(
      "usage (human):    agentkeychain store <name>\n" +
        "usage (program):  agentkeychain store <name> --value <v> --scopes \"a:1,b:2\"\n"
    );
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

  // Resolve master password from keychain (or AKC_PASSWORD env var) — falls
  // back to a single prompt only if neither is available. This is the
  // "type once, never again" path that makes Hermes-from-Telegram work.
  const keychainPassword = await resolvePassword();

  // Human path: only ask for value if --value not provided.
  // ASK FOR VALUE (+ PASSWORD if needed) in one batched read so piped stdin
  // works: `printf 'myvalue\n' | akc store mykey` works when keychain has it.
  let password: string;
  if (value === null) {
    if (keychainPassword) {
      value = await readLines(["Value: "]).then(([v]) => {
        if (v === undefined) throw new Error("no value provided");
        return v;
      });
      password = keychainPassword;
    } else {
      const lines = await readLines(["Value: ", "Master password: "]);
      value = lines[0];
      password = lines[1];
      if (value === undefined || password === undefined) {
        throw new Error("stdin closed before all prompts answered");
      }
    }
  } else {
    password = keychainPassword ?? (await readPassword("Master password: "));
  }

  // Default to universal scope when user did not pass --scopes. Programmatic
  // callers should ALWAYS pass --scopes explicitly — this is the IAM contract.
  const scopes = scopesOrNull ?? ["*"];
  if (scopes.length === 0) {
    process.stderr.write(
      "error: --scopes cannot be empty. Use --scopes \"*\" for universal, or omit the flag entirely.\n"
    );
    return 1;
  }

  const kek = await deriveKEK(password, metaRow.argon2_salt);

  try {
    const meta = await storeSecret(db, {
      name,
      value,
      scopes,
      kek,
      agent,
    });
    const scopeNote =
      scopes[0] === "*"
        ? "  (universal — any agent with access to this vault can read it)"
        : `  scopes: ${meta.scopes.join(", ")}`;
    process.stdout.write(
      `✓ encrypted and stored: ${meta.name}\n` +
        scopeNote +
        `\n` +
        `  version: ${meta.version}\n` +
        `  vault: ${vaultDir()}\n`
    );
    return 0;
  } finally {
    kek.fill(0);
  }
}
