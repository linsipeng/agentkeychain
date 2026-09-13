/**
 * `agentkeychain status [--json]` — safe installation/readiness probe.
 * Never creates or mutates a vault and never reads credential rows. It reads
 * only KEK metadata in read-only mode to prove the password channel works.
 */
import { VERSION } from "../index.ts";
import { vaultExists, verifyVaultPassword } from "../vault.ts";
import { detectBackend, resolvePassword, type Backend } from "../util/keychain.ts";

export interface StatusSnapshot {
  version: string;
  vaultInitialized: boolean;
  passwordAvailable: boolean;
  keychainBackend: Backend;
}

export async function getStatusSnapshot(): Promise<StatusSnapshot> {
  const vaultInitialized = vaultExists();
  const password = vaultInitialized ? await resolvePassword() : null;
  return {
    version: VERSION,
    vaultInitialized,
    passwordAvailable: password !== null && await verifyVaultPassword(password),
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
