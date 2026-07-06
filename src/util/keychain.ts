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
import { exec, execFile } from "node:child_process";
import { promisify } from "node:util";
import { platform } from "node:os";

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

export const KEYCHAIN_SERVICE = "agentkeychain.vault";
export const KEYCHAIN_ACCOUNT = "master-password";
export const KEYCHAIN_LABEL = "AgentKeychain Vault Master Password";

export type Backend = "macos-keychain" | "linux-libsecret" | "unsupported";

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
  try {
    if (backend === "macos-keychain") {
      const { stdout } = await execFileAsync(
        "security",
        [
          "find-generic-password",
          "-a", KEYCHAIN_ACCOUNT,
          "-s", KEYCHAIN_SERVICE,
          "-w", // print password only
        ],
        { encoding: "utf8", timeout: 5_000 }
      );
      const pw = stdout.trim();
      return pw.length > 0 ? pw : null;
    }
    if (backend === "linux-libsecret") {
      const { stdout } = await execFileAsync(
        "secret-tool",
        ["lookup", "service", KEYCHAIN_SERVICE, "account", KEYCHAIN_ACCOUNT],
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
  try {
    if (backend === "macos-keychain") {
      // -U updates if entry exists, otherwise creates
      await execFileAsync(
        "security",
        [
          "add-generic-password",
          "-a", KEYCHAIN_ACCOUNT,
          "-s", KEYCHAIN_SERVICE,
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
      // We use `exec` (not execFile) because secret-tool reads the secret
      // value from stdin, which execFile doesn't support.
      await execAsync(
        "secret-tool store --label=" +
          JSON.stringify(KEYCHAIN_LABEL) +
          " service " +
          KEYCHAIN_SERVICE +
          " account " +
          KEYCHAIN_ACCOUNT,
        { input: password, encoding: "utf8", timeout: 10_000 }
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
  try {
    if (backend === "macos-keychain") {
      await execFileAsync(
        "security",
        [
          "delete-generic-password",
          "-a", KEYCHAIN_ACCOUNT,
          "-s", KEYCHAIN_SERVICE,
        ],
        { encoding: "utf8", timeout: 5_000 }
      );
      return true;
    }
    if (backend === "linux-libsecret") {
      await execFileAsync(
        "secret-tool",
        ["clear", "service", KEYCHAIN_SERVICE, "account", KEYCHAIN_ACCOUNT],
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