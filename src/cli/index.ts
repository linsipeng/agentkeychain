#!/usr/bin/env bun
/**
 * agentkeychain CLI entry — command router.
 */
import { VERSION } from "../index.ts";
import { runInit } from "./init.ts";
import { runStore } from "./store.ts";
import { runGet } from "./get.ts";
import { runList } from "./list.ts";
import { runDelete } from "./delete.ts";
import { runAudit } from "./audit.ts";
import { runServe } from "./serve.ts";
import { runIssueToken } from "./issue-token.ts";
import { redact } from "../util/redact.ts";

type Command =
  | "init"
  | "store"
  | "get"
  | "list"
  | "delete"
  | "audit"
  | "serve"
  | "issue-token"
  | "help"
  | "version";

function parseArgs(argv: string[]): { command: Command; rest: string[] } {
  const first = argv[0] ?? "help";
  switch (first) {
    case "init": return { command: "init", rest: argv.slice(1) };
    case "store": return { command: "store", rest: argv.slice(1) };
    case "get": return { command: "get", rest: argv.slice(1) };
    case "list": return { command: "list", rest: argv.slice(1) };
    case "delete": case "rm": return { command: "delete", rest: argv.slice(1) };
    case "audit": return { command: "audit", rest: argv.slice(1) };
    case "serve": return { command: "serve", rest: argv.slice(1) };
    case "issue-token": return { command: "issue-token", rest: argv.slice(1) };
    case "--version": case "-v": case "version": return { command: "version", rest: [] };
    default: return { command: "help", rest: [] };
  }
}

function printHelp(): void {
  process.stdout.write(
    `agentkeychain v${VERSION}\n\n` +
      `Usage:\n` +
      `  agentkeychain init                  Initialize vault\n` +
      `  agentkeychain store <name> --value <v> --scopes "..."   Store encrypted secret\n` +
      `  agentkeychain get <name> [--json]  Retrieve and decrypt\n` +
      `  agentkeychain list [--json]        List all secrets (metadata only)\n` +
      `  agentkeychain delete <name> [--yes]  Delete a secret\n` +
      `  agentkeychain audit [--since 24h]  Show audit log\n` +
      `  agentkeychain serve                Start MCP server (stdio transport)\n` +
      `  agentkeychain issue-token --sub <id> --scopes "..." [--ttl 1h]\n` +
      `                                    Issue a cross-agent delegate token\n` +
      `  agentkeychain --version            Print version\n\n`
  );
}

export async function main(): Promise<number> {
  const { command, rest } = parseArgs(process.argv.slice(2));
  try {
    switch (command) {
      case "init": return runInit();
      case "store": return runStore(rest);
      case "get": return runGet(rest);
      case "list": return runList(rest);
      case "delete": return runDelete(rest);
      case "audit": return runAudit(rest);
      case "serve": return runServe(rest);
      case "issue-token": return runIssueToken(rest);
      case "version":
        process.stdout.write(`agentkeychain v${VERSION}\n`);
        return 0;
      case "help":
      default:
        printHelp();
        return 0;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: ${redact(msg)}\n`);
    return 1;
  }
}

main().then((code) => process.exit(code)).catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
