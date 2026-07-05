/**
 * `agentkeychain audit [--since <duration>]` command.
 *
 * Display the audit log. Default shows last 24h.
 */
import { openDb } from "../vault.ts";
import { query } from "../audit.ts";

function parseSince(arg: string | undefined): number {
  if (!arg || arg === "24h") return Date.now() - 24 * 60 * 60 * 1000;
  if (arg === "1h") return Date.now() - 60 * 60 * 1000;
  if (arg === "7d") return Date.now() - 7 * 24 * 60 * 60 * 1000;
  if (arg === "all") return 0;
  // Try parsing as "Nh" or "Nd"
  const m = arg.match(/^(\d+)([hd])$/);
  if (m) {
    const n = parseInt(m[1]!, 10);
    const unit = m[2] === "h" ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    return Date.now() - n * unit;
  }
  return Date.now() - 24 * 60 * 60 * 1000;
}

export async function runAudit(argv: string[]): Promise<number> {
  let sinceArg: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--since") sinceArg = argv[++i];
  }
  const since = parseSince(sinceArg);

  const db = openDb();
  const rows = query(db, { since });

  if (rows.length === 0) {
    process.stdout.write("no audit entries\n");
    return 0;
  }

  // Human-readable table
  process.stdout.write(
    `${"TIMESTAMP".padEnd(20)} ${"AGENT".padEnd(28)} ${"ACTION".padEnd(10)} ${"TARGET".padEnd(20)} RESULT
`
  );
  process.stdout.write("-".repeat(86) + "\n");
  for (const r of rows.reverse()) {
    const ts = new Date(r.ts).toISOString().slice(0, 19).replace("T", " ");
    const agent = r.agentId.padEnd(28);
    const action = r.action.padEnd(10);
    const target = (r.target ?? "-").padEnd(20);
    const result = r.success ? "✓" : "✗";
    process.stdout.write(`${ts} ${agent} ${action} ${target} ${result}\n`);
  }
  return 0;
}
