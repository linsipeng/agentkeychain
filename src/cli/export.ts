/**
 * `agentkeychain export` — export the vault to an encrypted bundle file.
 *
 *   agentkeychain export [--out <path>]
 *
 * The bundle is encrypted with Argon2id(master password, fresh salt) and can
 * be imported on any machine by someone with the same master password.
 */
import { join } from "node:path";
import { openDb, vaultExists } from "../vault.ts";
import { exportVault } from "../transfer.ts";
import { resolvePassword } from "../util/keychain.ts";
import { readPassword } from "../util/prompt.ts";

function parseArgs(argv: string[]): { out: string | null } {
  let out: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a === "--out" || a === "-o") {
      out = argv[++i] ?? null;
    }
  }
  return { out };
}

export async function runExport(argv: string[]): Promise<number> {
  const { out } = parseArgs(argv);

  if (!vaultExists()) {
    process.stderr.write("vault not initialized — run `agentkeychain init` first\n");
    return 1;
  }

  const db = openDb();
  const password = await resolvePassword() ?? (await readPassword("Master password: "));

  const stamp = new Date()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace("T", "-")
    .slice(0, 15); // YYYYMMDD-HHmmss
  const outPath = out ?? join(process.cwd(), `agentkeychain-export-${stamp}.akcbundle`);

  const result = await exportVault(db, password, outPath);

  if (result.entryCount === 0) {
    process.stdout.write(
      `✓ bundle written (0 entries): ${result.path}\n` +
        `  note: vault has no live secrets to export\n`
    );
  } else {
    process.stdout.write(
      `✓ exported ${result.entryCount} secret(s) → ${result.path}\n` +
        `  bundle is ENCRYPTED — but treat it as sensitive and delete after import\n` +
        `  on the other machine: agentkeychain import <bundle> (same master password)\n`
    );
  }
  return 0;
}
