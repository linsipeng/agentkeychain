import { verifyVaultPassword, vaultExists } from "../vault.ts";
import { startPasswordCheck, type PasswordCheckHandle } from "./server.ts";

export interface MasterPasswordCheckOptions {
  openBrowser?: boolean;
  timeoutMs?: number;
}

/** Open a private loopback form and allow up to ten candidates without mutating the vault or keychain. */
export async function requestMasterPasswordCheck(
  options: MasterPasswordCheckOptions = {}
): Promise<PasswordCheckHandle> {
  if (!vaultExists()) throw new Error("vault not initialized — run `agentkeychain init` first");
  return startPasswordCheck({
    ...(options.openBrowser === undefined ? {} : { openBrowser: options.openBrowser }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    onVerify: verifyVaultPassword,
  });
}
