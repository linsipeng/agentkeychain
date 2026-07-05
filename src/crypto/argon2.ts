/**
 * Argon2id password-based KDF.
 *
 * Derives a KEK (Key Encryption Key) from master password using Argon2id.
 * Parameters (OWASP 2024 minimum for interactive):
 *   - memory: 64 MiB
 *   - iterations: 3
 *   - salt: 16 bytes (random)
 *   - output: 32 bytes
 *
 * NOTE: libsodium-wrappers-sumo is required for crypto_pwhash (Argon2id).
 * The non-sumo build excludes pwhash for bundle size.
 */
import sodium from "libsodium-wrappers-sumo";

// Argon2id params (frozen per threat model)
export const ARGON2_PARAMS = {
  memory: 64 * 1024 * 1024, // 64 MiB
  iterations: 3,
} as const;

export const SALT_BYTES = 16;
export const KEY_BYTES = 32;

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) {
    initPromise = sodium.ready;
  }
  await initPromise;
  return sodium;
}

/**
 * Generate a fresh random salt.
 */
export async function generateSalt(): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.randombytes_buf(SALT_BYTES);
}

/**
 * Derive a KEK from master password + salt.
 * Never stores the master password — only the derived KEK hash is persisted.
 */
export async function deriveKEK(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_pwhash(
    KEY_BYTES,
    password,
    salt,
    ARGON2_PARAMS.iterations,
    ARGON2_PARAMS.memory,
    s.crypto_pwhash_ALG_ARGON2ID13,
    "uint8array"
  );
}

/**
 * Compute BLAKE2b hash of KEK (used for verification + kek_meta.kek_hash).
 */
export async function hashKEK(kek: Uint8Array): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_generichash(32, kek, undefined);
}
