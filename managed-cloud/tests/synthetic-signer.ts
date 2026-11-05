import type { CheckpointSigner } from '../shared/checkpoints.ts';
import { digest } from '../shared/contracts.ts';
const b64 = (v: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(v)));
export async function syntheticSigner(): Promise<CheckpointSigner> {
    const k = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    const publicKey = b64(await crypto.subtle.exportKey('raw', k.publicKey));
    return { key: async () => ({ keyId: await digest(publicKey), publicKey }), sign: async (c: string) => b64(await crypto.subtle.sign('Ed25519', k.privateKey, new TextEncoder().encode(c))) };
}
