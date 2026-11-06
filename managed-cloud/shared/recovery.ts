import { base64, exactFields, identifier } from '../../src/cloud/protocol.ts';
import { digest } from './contracts.ts';
import type { SealedShare } from './recovery-crypto.ts';
export interface RecoveryManifest {
    version: 1;
    packageId: string;
    accountId: string;
    tenantId: string;
    vaultId: string;
    keyEpoch: number;
    policy: 'two-party-24h';
    issuerDeviceId: string;
    apiKeyId: string;
    custodianKeyId: string;
    wrappedVDK: string;
    apiShare: SealedShare;
    custodianShare: SealedShare;
}
export interface RecoveryCase {
    version: 1;
    id: string;
    packageId: string;
    accountId: string;
    tenantId: string;
    vaultId: string;
    keyEpoch: number;
    targetDeviceId: string;
    signingKey: string;
    wrappingKey: string;
    createdAt: number;
    notBefore: number;
    expiresAt: number;
    nonce: string;
}
export interface CancelAuthorization {
    action: 'cancel';
    nonce: string;
    expiresAt: number;
    deviceId: string | null;
    signature: string;
}
export const cancelMessage = (canonical: string, a: CancelAuthorization) => JSON.stringify(['AgentKeychain-recovery-cancel-v1', canonical, a.action, a.nonce, a.expiresAt, a.deviceId]);
export interface RecoveryEvidence {
    mode: 'device' | 'cooldown';
    confirmerId: string | null;
    signature: string | null;
    proof: string | null;
}
/** Private independently provisioned services. Neither authorization decision is
 * inferred from the other service's result. Providers must bind the exact bytes. */
export interface RecoveryAuthority {
    rosterRevocation?(canonical:string):Promise<boolean>;
    rosterGenesis?(roster:import('../../src/cloud/protocol.ts').SignedManagedOperation):Promise<boolean>;
    cancel(canonical: string, authorization: CancelAuthorization): Promise<boolean>;
    complete(canonical: string, proof: string, signature: string): Promise<boolean>;
    enrollment(canonical: string, signature: string): Promise<boolean>;
    authorize(canonical: string, evidence: RecoveryEvidence): Promise<boolean>;
}
export interface RecoveryKeys {
    key(): Promise<{
        keyId: string;
        publicKey: string;
    }>;
    rewrap(keyId: string, box: SealedShare, sourceContext: string, targetKey: string, targetContext: string): Promise<SealedShare>;
}
export interface RecoveryRPC {
    witnessHead?(tenant:string,vault:string):Promise<import('../../src/cloud/protocol.ts').SignedManagedOperation|null>;
    witnessRevocation?(canonical:string):Promise<import('../../src/cloud/protocol.ts').SignedManagedOperation>;
    committedVersion?(canonical:string):Promise<number|null>;
    commitTrust?(canonical:string,version:number,digest:string,signature:string):Promise<{committed:boolean}>;
    witness?(input:import('./roster-witness.ts').WitnessRequest):Promise<import('../../src/cloud/protocol.ts').SignedManagedOperation>;
    trustBundle?(canonical:string,rosters:import('../../src/cloud/protocol.ts').SignedManagedOperation[],checkpoint:import('./checkpoints.ts').Checkpoint,revocations?:{deviceId:string;acceptedThrough:import('./checkpoints.ts').Checkpoint}[],receiptVersion?:number):Promise<import('./trust-activation.ts').TrustActivationMaterial & {binding:import('./trust-activation.ts').TrustActivationBinding;sealed:SealedShare;refreshDigest:string;witness?:import('../../src/cloud/protocol.ts').SignedManagedOperation;roster:import('../../src/cloud/protocol.ts').SignedManagedOperation}>;
    authenticatedRelease?(canonical: string, evidence: RecoveryEvidence): Promise<import("../../src/cloud/protocol.ts").SignedManagedOperation>;
    key(): Promise<{
        keyId: string;
        publicKey: string;
    }>;
    enroll(canonical: string, signature: string): Promise<{
        packageId: string;
    }>;
    prepare(canonical: string): Promise<{
        id: string;
    }>;
    release(canonical: string, evidence: RecoveryEvidence): Promise<SealedShare>;
    cancel(canonical: string, authorization?: CancelAuthorization): Promise<void>;
    complete(canonical: string, proof: string, signature: string): Promise<void>;
}
export function manifest(raw: string): RecoveryManifest {
    const m = JSON.parse(raw) as RecoveryManifest;
    exactFields(m, ['version', 'packageId', 'accountId', 'tenantId', 'vaultId', 'keyEpoch', 'policy', 'issuerDeviceId', 'apiKeyId', 'custodianKeyId', 'wrappedVDK', 'apiShare', 'custodianShare']);
    for (const field of ['packageId', 'accountId', 'tenantId', 'vaultId', 'issuerDeviceId', 'apiKeyId', 'custodianKeyId'] as const)
        identifier(m[field]);
    if (m.version !== 1 || m.policy !== 'two-party-24h' || !Number.isSafeInteger(m.keyEpoch) || m.keyEpoch < 1 || raw.length > 16384)
        throw new Error('invalid_recovery');
    base64(m.wrappedVDK, 60, 60);
    if (m.wrappedVDK.length > 8192)
        throw new Error('invalid_recovery');
    for (const b of [m.apiShare, m.custodianShare]) {
        exactFields(b, ['version', 'ephemeralKey', 'nonce', 'ciphertext']);
        if (b.version !== 1)
            throw new Error('invalid_recovery');
        base64(b.ephemeralKey, 32, 32);
        base64(b.nonce, 12, 12);
        base64(b.ciphertext, 48, 48);
    }
    if (JSON.stringify(m) !== raw)
        throw new Error('invalid_recovery');
    return m;
}
export function recoveryCase(raw: string): RecoveryCase {
    const c = JSON.parse(raw) as RecoveryCase;
    exactFields(c, ['version', 'id', 'packageId', 'accountId', 'tenantId', 'vaultId', 'keyEpoch', 'targetDeviceId', 'signingKey', 'wrappingKey', 'createdAt', 'notBefore', 'expiresAt', 'nonce']);
    for (const f of ['id', 'packageId', 'accountId', 'tenantId', 'vaultId', 'targetDeviceId', 'nonce'] as const)
        identifier(c[f]);
    base64(c.signingKey, 32, 32);
    base64(c.wrappingKey, 32, 32);
    if (!/^[A-Za-z0-9_-]{43}$/.test(c.targetDeviceId) || c.version !== 1 || c.signingKey === c.wrappingKey || ![c.keyEpoch, c.createdAt, c.notBefore, c.expiresAt].every(Number.isSafeInteger) || c.keyEpoch < 1 || c.notBefore < c.createdAt + 86400 || c.expiresAt <= c.notBefore || c.expiresAt > c.createdAt + 604800)
        throw new Error('invalid_recovery');
    return c;
}
export const packageContext = (m: RecoveryManifest, party: 'api' | 'custodian') => JSON.stringify(['AgentKeychain-recovery-share-v1', m.packageId, m.accountId, m.tenantId, m.vaultId, m.keyEpoch, m.policy, party, party === 'api' ? m.apiKeyId : m.custodianKeyId]);
export const releaseContext = (canonical: string, party: 'api' | 'custodian') => JSON.stringify(['AgentKeychain-recovery-release-v1', canonical, party]);
export const recoveryAction = (action: string, canonical: string) => digest(JSON.stringify(['AgentKeychain-recovery-action-v1', action, canonical]));
export const vaultKeyContext = (m: RecoveryManifest) => JSON.stringify(['AgentKeychain-recovery-vdk-v1', m.packageId, m.accountId, m.tenantId, m.vaultId, m.keyEpoch, m.policy]);
