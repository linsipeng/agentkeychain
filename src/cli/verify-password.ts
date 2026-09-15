import { requestMasterPasswordCheck } from "../password-check/check.ts";

export interface VerifyPasswordArgs {
  openBrowser: boolean;
  json: boolean;
}

export function parseVerifyPasswordArgs(argv: string[]): VerifyPasswordArgs {
  let openBrowser = true;
  let json = false;
  for (const arg of argv) {
    if (arg === "--no-open") openBrowser = false;
    else if (arg === "--json") json = true;
    else throw new Error("unknown option; expected --no-open or --json");
  }
  if (!openBrowser && json) throw new Error("--no-open and --json cannot be combined");
  return { openBrowser, json };
}

export async function runVerifyPassword(argv: string[]): Promise<number> {
  const args = parseVerifyPasswordArgs(argv);
  const handle = await requestMasterPasswordCheck({ openBrowser: args.openBrowser });
  if (!args.json) {
    if (args.openBrowser) process.stdout.write("Private local password check opened. Waiting up to 5 minutes…\n");
    else process.stdout.write(`Open this local one-time URL: ${handle.url}\n`);
  }

  const result = await handle.done;
  if (args.json) process.stdout.write(JSON.stringify({
    status: result,
    matches: result === "correct" ? true : result === "incorrect" ? false : null,
  }) + "\n");
  else if (result === "correct") process.stdout.write("✓ master password is correct\n");
  else if (result === "incorrect") process.stdout.write("✗ master password is incorrect; vault and keychain were not changed\n");
  else process.stderr.write(result === "expired" ? "password check expired\n" : "password check cancelled\n");

  return result === "correct" ? 0 : 1;
}
