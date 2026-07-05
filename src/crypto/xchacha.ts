/**
 * XChaCha20-Poly1305 symmetric encryption (AEAD).
 * Used to encrypt stored credentials before persistence.
 */
import sodium from 'libsodium-wrappers-sumo';

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) initPromise = sodium.ready;
  await initPromise;
  return sodium;
}

export interface EncryptedBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Encrypt plaintext with XChaCha20-Poly1305.
 * Returns ciphertext + nonce. Both are required to decrypt.
 */
export async function encrypt(
  plaintext: Uint8Array | string,
  key: Uint8Array
): Promise<EncryptedBlob> {
  const s = await ensureSodium();
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null,
    null,
    nonce,
    key
  );
  return { ciphertext: ct, nonce };
}

/**
 * Decrypt ciphertext with XChaCha20-Poly1305.
 * Throws if the ciphertext was tampered with (auth tag mismatch).
 */
export async function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    undefined,
    ciphertext,
    undefined,
    nonce,
    key
  );
}

// (Removed unused NONCE_BYTES export)
