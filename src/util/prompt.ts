/**
 * Shared prompt helpers that work under both TTY and piped stdin.
 *
 * `node:readline/promises` `rl.question("")` hangs on piped stdin in
 * bun-compiled binaries. Using `rl.once("line")` per-prompt causes
 * "stdin closed before input" on the SECOND read because the readline
 * interface drains the input stream on close(). Solution: pass BOTH
 * prompts up-front, consume lines as they arrive, in order, then close.
 */
import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";

export interface PromptOptions {
  /** If true, do not write a prompt (e.g. when reading a secret silently). */
  silent?: boolean;
}

/**
 * Read N lines from stdin in order, with prompts interleaved.
 *
 * Each line is collected as soon as it arrives; the readline interface stays
 * open for the whole sequence so multiple prompts work under piped stdin.
 *
 * @param prompts - prompt texts, one per expected line
 * @returns the N lines (without trailing newlines)
 * @throws Error if stdin closes before all lines arrive
 */
export async function readLines(prompts: string[]): Promise<string[]> {
  const input: Readable = process.stdin;
  const output: Writable = process.stdout;
  const rl = createInterface({ input, output });
  const lines: string[] = [];
  try {
    await new Promise<void>((resolve, reject) => {
      const queue = [...prompts];
      const next = (): void => {
        if (queue.length === 0) {
          resolve();
          return;
        }
        const prompt = queue.shift()!;
        process.stdout.write(prompt);
        rl.once("line", (line: string) => {
          lines.push(line);
          next();
        });
        rl.once("close", () => {
          reject(
            new Error(
              `stdin closed before all ${prompts.length} prompt(s) answered (got ${lines.length})`
            )
          );
        });
      };
      next();
    });
    return lines;
  } finally {
    rl.close();
  }
}

/**
 * Read a single line from stdin (helper for callers that only need one prompt).
 */
export async function readLine(
  prompt: string
): Promise<string> {
  const [line] = await readLines([prompt]);
  if (line === undefined) {
    throw new Error("readLine: no line received");
  }
  return line;
}

/**
 * Read a password from stdin (silent, no echo).
 */
export async function readPassword(prompt: string): Promise<string> {
  return readLine(prompt);
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