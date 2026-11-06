import {rpcData} from './rpc-data.ts';
import { exactFields, identifier, base64 } from '../../src/cloud/protocol.ts';
import { cancelMessage, manifest, recoveryCase, type CancelAuthorization, type RecoveryEvidence } from './recovery.ts';
import { verify } from './contracts.ts';
/** Each operator provisions its own registry, independently of the API's permit.
 * resolve must recheck revocation on every invocation; cached booleans are unsafe. */
export interface RecoveryTrust {
    device(account: string, tenant: string, vault: string, device: string): Promise<string | null>;
    accountVerifier(account: string): Promise<string | null>;
}
export function recoveryAuthority(trust: RecoveryTrust) {
    return {
        async cancel(canonical: string, a: CancelAuthorization) {
            try {
                exactFields(a, ['action', 'nonce', 'expiresAt', 'deviceId', 'signature']);
                identifier(a.nonce);
                base64(a.signature, 64, 64);
                const c = recoveryCase(canonical), now = Math.floor(Date.now() / 1000);
                if (a.action !== 'cancel' || !Number.isSafeInteger(a.expiresAt) || a.expiresAt <= now || a.expiresAt > now + 600)
                    return false;
                if (a.deviceId !== null)
                    identifier(a.deviceId);
                const key = a.deviceId === null ? await trust.accountVerifier(c.accountId) : await trust.device(c.accountId, c.tenantId, c.vaultId, a.deviceId);
                return !!key && await verify(key, a.signature, cancelMessage(canonical, a));
            }
            catch {
                return false;
            }
        },
        async complete(canonical: string, proof: string, signature: string) {
            try {
                const c = recoveryCase(canonical);
                base64(proof, 32, 32);
                base64(signature, 64, 64);
                return await verify(c.signingKey, signature, JSON.stringify(['AgentKeychain-recovery-proof-v1', canonical, proof]));
            }
            catch {
                return false;
            }
        },
        async enrollment(canonical: string, signature: string) { const m = manifest(canonical), key = await trust.device(m.accountId, m.tenantId, m.vaultId, m.issuerDeviceId); return !!key && await verify(key, signature, canonical); },
        async authorize(canonical: string, evidence: RecoveryEvidence) {
            const c = recoveryCase(canonical), now = Math.floor(Date.now() / 1000);
            if (c.expiresAt <= now || c.createdAt > now + 60)
                return false;
            if (evidence.mode === 'device' && evidence.confirmerId && evidence.signature && evidence.proof === null) {
                const key = await trust.device(c.accountId, c.tenantId, c.vaultId, evidence.confirmerId);
                return !!key && await verify(key, evidence.signature, JSON.stringify(['AgentKeychain-recovery-confirm-v1', canonical]));
            }
            if (evidence.mode === 'cooldown' && evidence.confirmerId === null && evidence.signature === null && evidence.proof && c.notBefore <= now) {
                const key = await trust.accountVerifier(c.accountId);
                return !!key && await verify(key, evidence.proof, JSON.stringify(['AgentKeychain-recovery-account-verified-v1', canonical]));
            }
            return false;
        }
    };
}

/** Private identity-service adapter, invoked only after the public recovery route
 * has verified the account proof. Its key is independently pinned by both operators. */
export function recoveryAccountAttester(signer:import('./checkpoints.ts').CheckpointSigner,trust:Pick<RecoveryTrust,'accountVerifier'>){
 return {async attest(canonical:string){
  const c=recoveryCase(canonical),key=await rpcData(signer.key());
  if(c.createdAt>Math.floor(Date.now()/1000)+60||c.expiresAt<=Math.floor(Date.now()/1000)||await trust.accountVerifier(c.accountId)!==key.publicKey)throw new Error('unauthorized');
  const message=JSON.stringify(['AgentKeychain-recovery-account-verified-v1',canonical]),signature=await signer.sign(message);
  if(!await verify(key.publicKey,signature,message))throw new Error('invalid_account_attester');return signature;
 }};
}
