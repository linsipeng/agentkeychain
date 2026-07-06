/**
 * `agentkeychain setup` — bind an existing vault's master password to the
 * OS keychain so subsequent commands never ask for it.
 *
 * Flow:
 *   1. User runs this once after `agentkeychain init`.
 *   2. CLI prompts for the master password (one final time).
 *   3. CLI verifies the password against the existing vault (decrypts + re-encrypts
 *      a probe to confirm; uses `getSecret` against a sentinel value or
 *      `verifyKek` if available).
 *   4. Saves the verified password to the OS keychain.
 *   5. Prints "you're done" with the new keychain status.
 *
 * If the vault is not initialized, prints an error and exits 1.
 */
import { readPassword } from "../util/prompt.ts";
import { keychainSet, keychainGet, detectBackend } from "../util/keychain.ts";
import { openDb, vaultExists } from "../vault.ts";
import { loadIdentityByName, unlockIdentityPrivateKey } from "../identity.ts";
import { deriveKEK } from "../crypto/argon2.ts";

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

  // If a password is already in the keychain, offer to keep or replace.
  const existing = await keychainGet();
  if (existing) {
    process.stdout.write(
      "✓ vault password is already saved in OS keychain.\n" +
        "  You can `agentkeychain get <name>` directly without re-entering the password.\n" +
        "  To replace it, delete it first: `agentkeychain setup --reset`\n"
    );
    return 0;
  }

  process.stdout.write(
    `Setting up master password for OS keychain (${backend}).\n` +
      `This is the LAST time you'll be asked for it.\n\n`
  );

  // Verify the password works against the vault before saving to keychain.
  // We do this by attempting to decrypt the default identity's private key
  // — if the AEAD check fails, the password is wrong. unlockIdentityPrivateKey
  // throws on bad password; we catch and refuse to save.
  const db = openDb();
  const agent = loadIdentityByName(db, "default");
  if (!agent) {
    process.stderr.write("vault corrupted: default identity missing\n");
    return 4;
  }
  const meta = db
    .prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`)
    .get() as { argon2_salt: Uint8Array } | undefined;
  if (!meta) {
    process.stderr.write("vault corrupted: kek_meta missing\n");
    return 4;
  }

  const password = await readPassword("Master password: ");
  const kek = await deriveKEK(password, meta.argon2_salt);
  let privateKey: Uint8Array | null = null;
  try {
    privateKey = await unlockIdentityPrivateKey(db, agent, kek);
  } catch (err) {
    kek.fill(0);
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `error: master password rejected (${msg}).\n` +
        `  The keychain was NOT updated. Try again with the correct password.\n`
    );
    return 1;
  } finally {
    if (privateKey) privateKey.fill(0);
    kek.fill(0);
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

export async function runSetupReset(): Promise<number> {
  // Force-replace the existing keychain entry.
  // Implemented as part of runSetup via `--reset` flag.
  process.stdout.write(
    "To replace the password in the keychain, first delete the old one:\n" +
      "  macOS:  open Keychain Access, search for 'agentkeychain.vault', delete\n" +
      "  Linux:  secret-tool clear service agentkeychain.vault account master-password\n" +
      "Then run `agentkeychain setup` again.\n"
  );
  return 0;
}