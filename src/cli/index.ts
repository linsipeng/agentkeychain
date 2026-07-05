#!/usr/bin/env bun
/**
 * agentkeychain CLI entry — command router.
 */
import { VERSION } from "../index.ts";
import { runInit } from "./init.ts";

type Command = "init" | "help" | "version";

function parseArgs(argv: string[]): { command: Command; rest: string[] } {
  const first = argv[0] ?? "help";
  switch (first) {
    case "init":
      return { command: "init", rest: argv.slice(1) };
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
    `agentkeychain v${VERSION}\n\n` +
      `Usage:\n` +
      `  agentkeychain init        Initialize vault\n` +
      `  agentkeychain --version  Print version\n\n` +
      `(More commands coming in F-2..F-7)\n`
  );
}

export async function main(): Promise<number> {
  const { command } = parseArgs(process.argv.slice(2));
  switch (command) {
    case "init":
      return runInit();
    case "version":
      process.stdout.write(`agentkeychain v${VERSION}\n`);
      return 0;
    case "help":
    default:
      printHelp();
      return 0;
  }
}

main();
