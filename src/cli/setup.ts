/**
 * `agentkeychain setup` — bind an existing vault's master password to the
 * OS keychain so subsequent commands never ask for it.
 *
 * Flow:
 *   1. User runs this once after `agentkeychain init`.
 *   2. CLI verifies any existing OS-keychain password against read-only KEK metadata.
 *   3. A valid entry is preserved; a stale entry triggers a private password prompt.
 *   4. CLI verifies the entered password against the existing vault.
 *   5. Saves the verified password to the OS keychain.
 *   6. Prints "you're done" with the new keychain status.
 *
 * If the vault is not initialized, prints an error and exits 1.
 */
import { readPassword } from "../util/prompt.ts";
import {
  KEYCHAIN_SERVICE,
  detectBackend,
  keychainGet,
  keychainService,
  keychainSet,
} from "../util/keychain.ts";
import { vaultExists, verifyVaultPassword } from "../vault.ts";

export async function runSetup(): Promise<number> {
  if (!vaultExists()) {
    process.stderr.write(
      "error: vault not initialized. Run `agentkeychain init` first.\n"
    );
    return 1;
  }

  const backend = detectBackend();
  if (backend === "unsupported") {
    process.stderr.write(
      "warning: no keychain backend detected on this platform.\n" +
        "  You'll be asked for the master password each time you use the CLI.\n" +
        "  Supported: macOS (Keychain) and Linux (libsecret).\n"
    );
    return 1;
  }

  // Trust an existing keychain entry only after proving that it unlocks this vault.
  const existing = await keychainGet();
  if (existing && await verifyVaultPassword(existing)) {
    process.stdout.write(
      "✓ vault password is already saved in OS keychain.\n" +
        "  You can `agentkeychain get <name>` directly without re-entering the password.\n"
    );
    return 0;
  }

  // Before v0.6, every custom vault shared the default fixed keychain service.
  // Migrate only after proving that the legacy password unlocks THIS vault;
  // an unrelated production/default-vault password is never copied blindly.
  if (keychainService() !== KEYCHAIN_SERVICE) {
    const legacy = await keychainGet(KEYCHAIN_SERVICE);
    if (legacy && await verifyVaultPassword(legacy)) {
      const migrated = await keychainSet(legacy);
      if (!migrated) {
        process.stderr.write(
          "error: verified legacy password, but failed to migrate it to the vault-scoped keychain entry.\n"
        );
        return 1;
      }
      process.stdout.write(
        "✓ verified legacy keychain password migrated to this vault's isolated keychain entry.\n"
      );
      return 0;
    }
  }
  if (existing) {
    process.stdout.write(
      "warning: the saved OS keychain password does not unlock this vault.\n" +
        "  Enter the existing vault master password to replace the stale entry.\n\n"
    );
  }

  process.stdout.write(
    `Setting up master password for OS keychain (${backend}).\n` +
      `This is the LAST time you'll be asked for it.\n\n`
  );

  const password = await readPassword("Master password: ");
  if (!await verifyVaultPassword(password)) {
    process.stderr.write(
      "error: master password rejected.\n" +
        `  The keychain was NOT updated. Try again with the correct password.\n`
    );
    return 1;
  }

  // Password verified. Now save it.
  const ok = await keychainSet(password);
  if (!ok) {
    process.stderr.write(
      "error: failed to save password to OS keychain.\n" +
        "  Check your keychain is unlocked and the user has permission to add items.\n"
    );
    return 1;
  }

  process.stdout.write(
    "\n✓ master password saved to OS keychain.\n" +
      "  All future `agentkeychain` commands will read the password transparently.\n" +
      "  You'll only be prompted if the keychain entry is deleted (or expires).\n"
  );
  return 0;
}