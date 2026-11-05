/** Safe legacy deprecation boundary. Never opens a vault or contacts endpoints. */
import { legacyStatus, migrationMessage } from "../cloud/legacy.ts";

export async function runSync(argv: string[]): Promise<number> {
  if (argv[0] === "status") {
    process.stdout.write(migrationMessage(legacyStatus()) + "\n");
    return 0;
  }
  process.stderr.write(
    "Managed Cloud: legacy sync commands are deprecated and disabled. " +
    "Use `agentkeychain sync status` for safe compatibility information. " +
    "Slice 1 is local/test-only; no account connection or migration is available. Configuration is unchanged.\n"
  );
  return 1;
}
