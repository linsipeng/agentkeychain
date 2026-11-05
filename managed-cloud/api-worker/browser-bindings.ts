import type { RecoveryBindings } from './recovery-repository.ts';
import type { CheckpointSigner } from '../shared/checkpoints.ts';
import { createBrowserAuth, unavailable } from './browser-auth.ts';
import { decode, encode } from './webauthn.ts';
/** Provisioning these bindings is a separate deployment gate. No defaults or
 * synthetic verifier can activate production registration. */
export interface BrowserBindings extends RecoveryBindings {
    CHECKPOINT_SIGNER?: CheckpointSigner;
    MAIN: D1Database;
    AUTH_ORIGIN?: string;
    AUTH_RP_ID?: string;
    AUTH_BOOTSTRAP_KEY?: string;
    AUTH_EMAIL_KEY?: string;
    AUTH_LOOKUP_KEY?: string;
    EMAIL_VERIFIER?: {
        verify(email: string, proof: string): Promise<boolean>;
    };
    TRUSTED_AUTH_SOURCE?: {
        resolve(request: Request): Promise<string>;
    };
}
export async function browserFetch(request: Request, env: BrowserBindings) {
    try {
        if (!env.AUTH_ORIGIN || !env.AUTH_RP_ID || !env.AUTH_BOOTSTRAP_KEY || !env.AUTH_EMAIL_KEY || !env.AUTH_LOOKUP_KEY || typeof env.EMAIL_VERIFIER?.verify !== 'function' || typeof env.TRUSTED_AUTH_SOURCE?.resolve !== 'function')
            return unavailable();
        const materials = [env.AUTH_BOOTSTRAP_KEY, env.AUTH_EMAIL_KEY, env.AUTH_LOOKUP_KEY].map(value => {
            const bytes = decode(value);
            if (bytes.length !== 32 || encode(bytes) !== value)
                throw new Error('invalid_auth_configuration');
            return bytes;
        });
        if (materials.some((a, i) => materials.slice(i + 1).some(b => a.every((v, j) => v === b[j]))))
            return unavailable();
        const key = (bytes: Uint8Array<ArrayBuffer>, kind: 'AES-GCM' | 'HMAC') => crypto.subtle.importKey('raw', bytes, kind === 'HMAC' ? { name: 'HMAC', hash: 'SHA-256' } : { name: 'AES-GCM' }, false, kind === 'HMAC' ? ['sign', 'verify'] : ['encrypt', 'decrypt']);
        const [bootstrapKey, emailKey, lookupKey] = await Promise.all([key(materials[0]!, 'HMAC'), key(materials[1]!, 'AES-GCM'), key(materials[2]!, 'HMAC')]);
        return await createBrowserAuth(env.MAIN, { recovery: env, checkpointSigner: env.CHECKPOINT_SIGNER, origin: env.AUTH_ORIGIN, rpId: env.AUTH_RP_ID, bootstrapKey, emailKey, lookupKey, verifyEmail: (email, proof) => env.EMAIL_VERIFIER!.verify(email, proof), trustedSource: r => env.TRUSTED_AUTH_SOURCE!.resolve(r) })(request);
    }
    catch { return unavailable(); }
}
