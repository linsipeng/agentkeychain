import { recoveryKeyring } from '../shared/recovery-keyring.ts';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { encode64, type SealedShare } from '../shared/recovery-crypto.ts';
import { digest } from '../shared/contracts.ts';
import { recoveryAuthority } from '../shared/recovery-authorization.ts';
import type { CancelAuthorization, RecoveryEvidence } from '../shared/recovery.ts';
const pair = crypto.subtle.generateKey('X25519', true, ['deriveBits']) as Promise<CryptoKeyPair>;
const devices = new Map<string, string>();
const verifiers = new Map<string, string>();
const authority = recoveryAuthority({ device: async (a, t, v, d) => devices.get(JSON.stringify([a, t, v, d])) ?? null, accountVerifier: async (a) => verifiers.get(a) ?? null });
/** Only compiled into test harnesses, never API/Custodian production bundles. */
export class RecoveryTestService extends WorkerEntrypoint {
    override async fetch() { return new Response(null, { status: 404 }); }
    async key() { const publicKey = encode64(new Uint8Array(await crypto.subtle.exportKey('raw', (await pair).publicKey))); return { keyId: await digest(publicKey), publicKey }; }
    async rewrap(keyId: string, box: SealedShare, source: string, target: string, context: string) { const key = await this.key(); return (await recoveryKeyring(new Map([[key.keyId, await pair]]), key.keyId)).rewrap(keyId, box, source, target, context); }
    async trust(a: string, t: string, v: string, d: string, key: string | null) {
        const id = JSON.stringify([a, t, v, d]);
        if (key)
            devices.set(id, key);
        else
            devices.delete(id);
    }
    async verifier(a: string, key: string) { verifiers.set(a, key); }
    async cancel(c: string, a: CancelAuthorization) { return authority.cancel(c, a); }
    async complete(c: string, p: string, s: string) { return authority.complete(c, p, s); }
    async enrollment(c: string, s: string) { return authority.enrollment(c, s); }
    async authorize(c: string, e: RecoveryEvidence) { return authority.authorize(c, e); }
}
export default RecoveryTestService;
export class RecoveryAuthority extends RecoveryTestService {
}
export class RecoveryKeys extends RecoveryTestService {
}
