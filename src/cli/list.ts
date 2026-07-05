/**
 * `agentkeychain list [--json]` command.
 */
import { openDb } from "../vault.ts";
import { listSecrets } from "../secrets.ts";

export async function runList(argv: string[]): Promise<number> {
  const json = argv.includes("--json");
  const db = openDb();
  const secrets = listSecrets(db);
  if (json) {
    process.stdout.write(JSON.stringify(secrets, null, 2) + "\n");
    return 0;
  }
  if (secrets.length === 0) {
    process.stdout.write("no secrets stored\n");
    return 0;
  }
  process.stdout.write(`${"NAME".padEnd(20)} ${"VERSION".padEnd(8)} ${"SCOPES".padEnd(30)} UPDATED\n`);
  process.stdout.write("-".repeat(86) + "\n");
  for (const s of secrets) {
    const name = s.name.padEnd(20);
    const ver = String(s.version).padEnd(8);
    const scopes = s.scopes.join(",").slice(0, 30).padEnd(30);
    const updated = new Date(s.updatedAt).toISOString().slice(0, 19).replace("T", " ");
    process.stdout.write(`${name} ${ver} ${scopes} ${updated}\n`);
  }
  return 0;
}
