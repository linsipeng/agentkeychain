/**
 * `agentkeychain status [--json]` — safe installation/readiness probe.
 * Never creates or opens a vault and never reads credential metadata.
 */
import { VERSION } from "../index.ts";
import { vaultExists } from "../vault.ts";
import { detectBackend, resolvePassword, type Backend } from "../util/keychain.ts";

export interface StatusSnapshot {
  version: string;
  vaultInitialized: boolean;
  passwordAvailable: boolean;
  keychainBackend: Backend;
}

export async function getStatusSnapshot(): Promise<StatusSnapshot> {
  const vaultInitialized = vaultExists();
  return {
    version: VERSION,
    vaultInitialized,
    passwordAvailable: vaultInitialized && (await resolvePassword()) !== null,
    keychainBackend: detectBackend(),
  };
}

export async function runStatus(argv: string[]): Promise<number> {
  const status = await getStatusSnapshot();
  if (argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify(status)}\n`);
    return 0;
  }
  process.stdout.write(
    `agentkeychain v${status.version}\n` +
      `vault initialized: ${status.vaultInitialized ? "yes" : "no"}\n` +
      `password available: ${status.passwordAvailable ? "yes" : "no"}\n` +
      `keychain backend: ${status.keychainBackend}\n`
  );
  return 0;
}
