/**
 * `agentkeychain import <bundle>` — import secrets from an export bundle.
 *
 *   agentkeychain import <bundle> [--overwrite]
 *
 * Default: same-name entries are skipped. --overwrite replaces them.
 * Wrong bundle password aborts with no changes written.
 */
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { openDb, vaultExists } from "../vault.ts";
import { importBundle, readBundle } from "../transfer.ts";
import { resolvePassword } from "../util/keychain.ts";
import { readPassword } from "../util/prompt.ts";

function parseArgs(argv: string[]): { bundle: string | null; overwrite: boolean } {
  let bundle: string | null = null;
  let overwrite = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a === "--overwrite") {
      overwrite = true;
    } else if (!a.startsWith("-") && bundle === null) {
      bundle = a;
    }
  }
  return { bundle, overwrite };
}

export async function runImport(argv: string[]): Promise<number> {
  const { bundle, overwrite } = parseArgs(argv);

  if (!bundle) {
    process.stderr.write(
      "usage: agentkeychain import <bundle> [--overwrite]\n" +
        "  --overwrite  replace same-name secrets instead of skipping them\n"
    );
    return 1;
  }
  if (!existsSync(bundle)) {
    process.stderr.write(`error: bundle not found: ${bundle}\n`);
    return 1;
  }
  if (!vaultExists()) {
    process.stderr.write(
      "target vault not initialized — run `agentkeychain init` first\n" +
        "(use the SAME master password as the machine that exported the bundle)\n"
    );
    return 1;
  }

  const db = openDb();

  // Bundle password: keychain/AKC_PASSWORD if available (same-password machines),
  // otherwise a single silent prompt.
  const password = await resolvePassword() ?? (await readPassword("Bundle master password: "));

  const parsed = readBundle(bundle);
  const result = await importBundle(db, parsed, password, {
    overwrite,
    sourceFileName: basename(bundle),
  });

  process.stdout.write(`✓ imported ${result.imported.length} secret(s)\n`);
  for (const name of result.imported) {
    process.stdout.write(`  + ${name}\n`);
  }
  if (result.skipped.length > 0) {
    process.stdout.write(`  skipped ${result.skipped.length} (already exist here)\n`);
    for (const s of result.skipped) {
      process.stdout.write(`  - ${s.name}: ${s.reason}\n`);
    }
  }
  if (result.imported.length > 0) {
    process.stdout.write(
      `\nnext: delete the bundle file — it is no longer needed\n` +
        `  verify with: agentkeychain list\n`
    );
  }
  return 0;
}
