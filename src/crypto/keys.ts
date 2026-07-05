/**
 * Ed25519 identity keypair generation + symmetric encryption of private key.
 *
 * Private key is encrypted with the vault KEK using XChaCha20-Poly1305 before
 * being persisted to disk. The KEK never touches disk.
 */
import sodium from 'libsodium-wrappers-sumo';
import { KEY_BYTES } from "./argon2.ts";

const PUB_BYTES = sodium.crypto_sign_PUBLICKEYBYTES;
const PRIV_BYTES = sodium.crypto_sign_SECRETKEYBYTES;
const NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) initPromise = sodium.ready;
  await initPromise;
  return sodium;
}

export interface EncryptedPrivKey {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Generate a fresh Ed25519 keypair for an Agent identity.
 */
export async function generateKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const s = await ensureSodium();
  const kp = s.crypto_sign_keypair();
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
}

/**
 * Encrypt an Ed25519 private key with the vault KEK.
 * Output is XChaCha20-Poly1305 ciphertext + nonce.
 */
export async function encryptPrivKey(
  privateKey: Uint8Array,
  kek: Uint8Array
): Promise<EncryptedPrivKey> {
  const s = await ensureSodium();
  const nonce = s.randombytes_buf(NONCE_BYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    privateKey,
    null,
    null,
    nonce,
    kek
  );
  return { ciphertext, nonce };
}

/**
 * Decrypt an Ed25519 private key with the vault KEK.
 */
export async function decryptPrivKey(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  kek: Uint8Array
): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    kek
  );
}

export { PUB_BYTES, PRIV_BYTES, NONCE_BYTES, KEY_BYTES };
