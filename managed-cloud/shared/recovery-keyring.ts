import { digest } from './contracts.ts';
import { encode64, open, seal } from './recovery-crypto.ts';
import type { RecoveryKeys } from './recovery.ts';
/** Private operator service composition. Keys are provisioned CryptoKeys, never
 * D1 rows. Old key IDs may remain decrypt-only during an explicit rotation. */
export async function recoveryKeyring(pairs: ReadonlyMap<string, CryptoKeyPair>, activeId: string): Promise<RecoveryKeys> {
    const publicKeys = new Map<string, string>();
    for (const [id, pair] of pairs) {
        if (pair.privateKey.type !== 'private' || pair.privateKey.algorithm.name !== 'X25519' || !pair.privateKey.usages.includes('deriveBits'))
            throw new Error('invalid_recovery_key');
        const publicKey = encode64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
        if (id !== await digest(publicKey))
            throw new Error('invalid_recovery_key_id');
        publicKeys.set(id, publicKey);
    }
    if (!publicKeys.has(activeId))
        throw new Error('missing_active_key');
    return {
        async key() { return { keyId: activeId, publicKey: publicKeys.get(activeId)! }; },
        async rewrap(keyId, box, sourceContext, targetKey, targetContext) {
            const pair = pairs.get(keyId);
            if (!pair)
                throw new Error('unknown_key_id');
            const share = await open(pair.privateKey, box, sourceContext);
            try {
                if (share.length !== 32)
                    throw new Error('invalid_share');
                return await seal(targetKey, share, targetContext);
            }
            finally {
                share.fill(0);
            }
        }
    };
}
