/**
 * Cross-agent delegate tokens.
 *
 * A delegate token authorizes a sub-agent to access secrets with specific scopes
 * for a limited time. Tokens are signed by the issuing agent's Ed25519 key.
 *
 * Token format (URL-safe base64 JSON):
 *   {
 *     iss: "<agent_id>",       // issuer
 *     sub: "<agent_id>",       // subject (the sub-agent)
 *     scopes: ["..."],
 *     iat: <unix_ms>,
 *     exp: <unix_ms>,
 *     sig: "<base64 Ed25519 sig of iss|sub|scopes|iat|exp>"
 *   }
 */
import sodium from "libsodium-wrappers-sumo";

let initPromise: Promise<void> | null = null;
async function ensureSodium(): Promise<typeof sodium> {
  if (!initPromise) initPromise = sodium.ready;
  await initPromise;
  return sodium;
}

export interface DelegateTokenPayload {
  iss: string;
  sub: string;
  scopes: string[];
  iat: number;
  exp: number;
}

export interface DelegateToken extends DelegateTokenPayload {
  sig: string; // base64
}

/**
 * Serialize the payload (excluding sig) for signing/verification.
 */
function payloadString(p: DelegateTokenPayload): string {
  return `${p.iss}|${p.sub}|${p.scopes.join(",")}|${p.iat}|${p.exp}`;
}

/**
 * Sign a delegate token payload with the issuer's private key.
 */
export async function signDelegateToken(
  payload: DelegateTokenPayload,
  issuerPrivateKey: Uint8Array
): Promise<DelegateToken> {
  const s = await ensureSodium();
  const msg = new TextEncoder().encode(payloadString(payload));
  const sig = s.crypto_sign_detached(msg, issuerPrivateKey);
  return { ...payload, sig: sodium.to_base64(sig, sodium.base64_variants.ORIGINAL) };
}

/**
 * Verify a delegate token signature using the issuer's public key.
 * Returns the payload if valid, null if signature invalid or expired.
 */
export async function verifyDelegateToken(
  token: DelegateToken,
  issuerPublicKey: Uint8Array
): Promise<DelegateTokenPayload | null> {
  const s = await ensureSodium();
  const { sig, ...payload } = token;
  const msg = new TextEncoder().encode(payloadString(payload));
  const sigBytes = (() => {
    try {
      return sodium.from_base64(sig, sodium.base64_variants.ORIGINAL);
    } catch {
      return null;
    }
  })();
  if (!sigBytes || sigBytes.length !== sodium.crypto_sign_BYTES) return null;
  let valid: boolean;
  try {
    valid = s.crypto_sign_verify_detached(sigBytes, msg, issuerPublicKey);
  } catch {
    return null;
  }
  if (!valid) return null;
  if (Date.now() > payload.exp) return null;
  return payload;
}
