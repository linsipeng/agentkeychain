/**
 * Shared prompt helpers that work under both TTY and piped stdin.
 *
 * `node:readline/promises` `rl.question("")` hangs on piped stdin in
 * bun-compiled binaries, so we use `rl.once("line")` + `rl.once("close")`
 * which gives us a Promise that resolves on first line, or rejects on EOF.
 */
import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";

export interface PromptOptions {
  /** If true, do not write a prompt (e.g. when reading a secret silently). */
  silent?: boolean;
}

/**
 * Read one line from stdin (the first line before EOF).
 *
 * @param prompt - prompt text written to stdout before reading
 * @param opts - options
 * @returns the line, with trailing newline stripped
 * @throws Error if stdin closes before any line arrives
 */
export async function readLine(
  prompt: string,
  opts: PromptOptions = {}
): Promise<string> {
  const input: Readable = process.stdin;
  const output: Writable = process.stdout;
  const rl = createInterface({ input, output });
  try {
    if (prompt && !opts.silent) {
      process.stdout.write(prompt);
    }
    const line = await new Promise<string>((resolve, reject) => {
      rl.once("line", (l) => resolve(l));
      rl.once("close", () => reject(new Error("stdin closed before input")));
    });
    return line;
  } finally {
    rl.close();
  }
}

/**
 * Read a password from stdin (silent, no echo).
 */
export async function readPassword(prompt: string): Promise<string> {
  return readLine(prompt, { silent: false });
}

/**
 * Prompt for y/n confirmation. Returns true if user typed something starting
 * with y/Y. Defaults to false (N) if stdin closes.
 */
export async function readConfirm(question: string): Promise<boolean> {
  try {
    const answer = await readLine(question);
    return answer.trim().toLowerCase().startsWith("y");
  } catch {
    return false;
  }
}