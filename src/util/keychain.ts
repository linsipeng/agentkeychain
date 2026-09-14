/**
 * OS keychain integration — stores/retrieves the master password so the user
 * only has to type it ONCE (during `agentkeychain init` / `agentkeychain setup`).
 *
 * Platforms:
 *   - macOS:   `security` command (Keychain Access)
 *   - Linux:   `secret-tool` command (libsecret / GNOME Keyring / KWallet)
 *   - Other:   returns null on lookup, throws on store (no keychain to use)
 *
 * Override:
 *   - AKC_PASSWORD env var wins over keychain (for CI / scripts)
 *
 * Security notes:
 *   - We never log the password value.
 *   - On macOS, the entry is scoped to the current user account by default.
 *   - The keychain item is named with a fixed service+account tuple; we don't
 *     include vault path so the same master works for a moved vault.
 */
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { homedir, platform } from "node:os";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";

const execFileAsync = promisify(execFile);

function spawnWithInput(
  command: string,
  args: string[],
  input: string,
  timeoutMs: number
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "ignore", "pipe"] });
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${command} timed out`));
    }, timeoutMs);
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    // bun on Linux can emit EPIPE on the stdin pipe if the child exits before
    // consuming all input; the exit code is the source of truth, so swallow it.
    child.stdin.on("error", () => {});
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(Object.assign(new Error(`${command} exited with code ${code}`), { stderr }));
    });
    child.stdin.end(input);
  });
}

export const KEYCHAIN_SERVICE = "agentkeychain.vault";
export const KEYCHAIN_ACCOUNT = "master-password";
export const KEYCHAIN_LABEL = "AgentKeychain Vault Master Password";

export type Backend = "macos-keychain" | "linux-libsecret" | "unsupported";

/**
 * Isolate OS-keychain entries per vault. The default vault keeps the original
 * service name for backward compatibility; a custom AGENTKEYCHAIN_HOME gets a
 * stable path-derived suffix so an E2E/temp vault cannot overwrite production.
 */
export function keychainService(): string {
  const defaultHome = resolve(join(homedir(), ".agentkeychain"));
  const configuredHome = resolve(process.env["AGENTKEYCHAIN_HOME"] ?? defaultHome);
  if (configuredHome === defaultHome) return KEYCHAIN_SERVICE;
  const suffix = createHash("sha256").update(configuredHome).digest("hex").slice(0, 16);
  return `${KEYCHAIN_SERVICE}.${suffix}`;
}

function backendCommand(backend: Backend): string | null {
  const injected = backend === "macos-keychain"
    ? process.env["AKC_KEYCHAIN_SECURITY_BIN"]
    : backend === "linux-libsecret"
      ? process.env["AKC_KEYCHAIN_SECRET_TOOL_BIN"]
      : undefined;
  if (injected) return injected;
  // bunfig.toml enables this guard for every direct `bun test` invocation.
  // Tests must inject a stub by absolute path; PATH discovery is forbidden.
  if (process.env["AKC_KEYCHAIN_TEST_MODE"] === "1") return null;
  if (backend === "macos-keychain") return "security";
  if (backend === "linux-libsecret") return "secret-tool";
  return null;
}

export function detectBackend(): Backend {
  if (process.env["AKC_PASSWORD"]) return "unsupported"; // env var is primary
  const p = platform();
  if (p === "darwin") return "macos-keychain";
  if (p === "linux") return "linux-libsecret";
  return "unsupported";
}

/**
 * Look up the master password from the OS keychain.
 * Returns null if the entry doesn't exist, the backend isn't available,
 * or the user has not yet run `agentkeychain setup`.
 */
export async function keychainGet(): Promise<string | null> {
  const backend = detectBackend();
  const command = backendCommand(backend);
  if (!command) return null;
  try {
    if (backend === "macos-keychain") {
      const { stdout } = await execFileAsync(
        command,
        [
          "find-generic-password",
          "-a", KEYCHAIN_ACCOUNT,
          "-s", keychainService(),
          "-w", // print password only
        ],
        { encoding: "utf8", timeout: 5_000 }
      );
      const pw = stdout.trim();
      return pw.length > 0 ? pw : null;
    }
    if (backend === "linux-libsecret") {
      const { stdout } = await execFileAsync(
        command,
        ["lookup", "service", keychainService(), "account", KEYCHAIN_ACCOUNT],
        { encoding: "utf8", timeout: 5_000 }
      );
      const pw = stdout.trim();
      return pw.length > 0 ? pw : null;
    }
    return null;
  } catch (err: unknown) {
    // security / secret-tool return non-zero exit when entry not found.
    // Anything else (binary missing, dbus down) we treat as "no password".
    const e = err as { code?: string; stderr?: string };
    if (e.code === "ENOENT") return null; // binary not installed
    if (
      typeof e.stderr === "string" &&
      (e.stderr.includes("could not be found") ||
        e.stderr.includes("not found") ||
        e.stderr.includes("No matching"))
    ) {
      return null;
    }
    return null;
  }
}

/**
 * Store (or update) the master password in the OS keychain.
 * Returns true on success, false on failure (logs warning).
 */
export async function keychainSet(password: string): Promise<boolean> {
  const backend = detectBackend();
  const command = backendCommand(backend);
  if (!command) return false;
  try {
    if (backend === "macos-keychain") {
      // -U updates if entry exists, otherwise creates
      await execFileAsync(
        command,
        [
          "add-generic-password",
          "-a", KEYCHAIN_ACCOUNT,
          "-s", keychainService(),
          "-l", KEYCHAIN_LABEL,
          "-w", password,
          "-U",
        ],
        { encoding: "utf8", timeout: 10_000 }
      );
      return true;
    }
    if (backend === "linux-libsecret") {
      // secret-tool doesn't have a "store or update" — store just overwrites.
      await spawnWithInput(
        command,
        [
          "store",
          `--label=${KEYCHAIN_LABEL}`,
          "service",
          keychainService(),
          "account",
          KEYCHAIN_ACCOUNT,
        ],
        password,
        10_000
      );
      return true;
    }
    return false;
  } catch (err) {
    const e = err as { code?: string; stderr?: string; message?: string };
    process.stderr.write(
      `warning: failed to save password to keychain: ${e.message ?? e.code ?? "unknown"}\n` +
        (e.stderr ? `  (${e.stderr.trim()})\n` : "")
    );
    return false;
  }
}

/**
 * Remove the master password from the OS keychain.
 * Returns true on success or if entry didn't exist; false on real failure.
 */
export async function keychainDelete(): Promise<boolean> {
  const backend = detectBackend();
  const command = backendCommand(backend);
  if (!command) return backend === "unsupported";
  try {
    if (backend === "macos-keychain") {
      await execFileAsync(
        command,
        [
          "delete-generic-password",
          "-a", KEYCHAIN_ACCOUNT,
          "-s", keychainService(),
        ],
        { encoding: "utf8", timeout: 5_000 }
      );
      return true;
    }
    if (backend === "linux-libsecret") {
      await execFileAsync(
        command,
        ["clear", "service", keychainService(), "account", KEYCHAIN_ACCOUNT],
        { encoding: "utf8", timeout: 5_000 }
      );
      return true;
    }
    return true; // nothing to delete on unsupported
  } catch {
    return false;
  }
}

/**
 * Resolve the master password using the standard priority chain:
 *   1. AKC_PASSWORD env var (CI / scripts)
 *   2. OS keychain (set by `agentkeychain setup`)
 *   3. null (caller should prompt the user)
 */
export async function resolvePassword(): Promise<string | null> {
  const env = process.env["AKC_PASSWORD"];
  if (env && env.length > 0) return env;
  return await keychainGet();
}