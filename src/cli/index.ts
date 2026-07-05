#!/usr/bin/env bun
/**
 * agentkeychain CLI entry — command router.
 */
import { VERSION } from "../index.ts";
import { runInit } from "./init.ts";
import { runStore } from "./store.ts";
import { redact } from "../util/redact.ts";

type Command = "init" | "store" | "help" | "version";

function parseArgs(argv: string[]): { command: Command; rest: string[] } {
  const first = argv[0] ?? "help";
  switch (first) {
    case "init":
      return { command: "init", rest: argv.slice(1) };
    case "store":
      return { command: "store", rest: argv.slice(1) };
    case "--version":
    case "-v":
    case "version":
      return { command: "version", rest: [] };
    default:
      return { command: "help", rest: [] };
  }
}

function printHelp(): void {
  process.stdout.write(
    `agentkeychain v${VERSION}

` +
      `Usage:
` +
      `  agentkeychain init                              Initialize vault
` +
      `  agentkeychain store <name> --value <v> --scopes ...   Store encrypted secret
` +
      `  agentkeychain --version                        Print version

` +
      `(More commands coming in F-3..F-7)
`
  );
}

export async function main(): Promise<number> {
  const { command, rest } = parseArgs(process.argv.slice(2));
  try {
    switch (command) {
      case "init":
        return runInit();
      case "store":
        return runStore(rest);
      case "version":
        process.stdout.write(`agentkeychain v${VERSION}
`);
        return 0;
      case "help":
      default:
        printHelp();
        return 0;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: ${redact(msg)}
`);
    return 1;
  }
}

main();
