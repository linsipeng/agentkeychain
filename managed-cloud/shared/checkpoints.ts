import { digest, verify } from './contracts.ts';
import { exactFields, type ManagedVersion, type SignedManagedOperation } from '../../src/cloud/protocol.ts';
export interface CheckpointKey {
    keyId: string;
    publicKey: string;
}
export interface CheckpointSigner {
    key(): Promise<CheckpointKey>;
    sign(canonical: string): Promise<string>;
}
export interface Checkpoint {
    canonical: string;
    signature: string;
}
interface CheckpointData {
    version: 1;
    tenantId: string;
    vaultId: string;
    keyId: string;
    sequence: number;
    root: string;
    previousRoot: string | null;
    operationDigest: string | null;
}
export const genesisRoot = (tenant: string, vault: string) => digest(JSON.stringify(['AgentKeychain-sync-genesis-v1', tenant, vault]));
export async function advanceRoot(previous: string, sequence: number, signed: SignedManagedOperation) {
    const operationDigest = await digest(JSON.stringify(['AgentKeychain-signed-operation-v1', signed.canonical, signed.signature]));
    return { operationDigest, root: await digest(JSON.stringify(['AgentKeychain-sync-chain-v1', previous, sequence, operationDigest])) };
}
export async function checkpoint(signer: CheckpointSigner, tenantId: string, vaultId: string, sequence: number, root: string, previousRoot: string | null, operationDigest: string | null): Promise<Checkpoint> {
    const key = await signer.key();
    const canonical = JSON.stringify({ version: 1, tenantId, vaultId, keyId: key.keyId, sequence, root, previousRoot, operationDigest });
    const signature = await signer.sign(canonical);
    if (!await verify(key.publicKey, signature, canonical))
        throw new Error('invalid_checkpoint_signer');
    return { canonical, signature };
}
export async function verifyCheckpoint(pin: CheckpointKey, tenant: string, vault: string, c: Checkpoint): Promise<CheckpointData> {
    exactFields(c, ['canonical', 'signature']);
    const d = JSON.parse(c.canonical) as CheckpointData;
    exactFields(d, ['version', 'tenantId', 'vaultId', 'keyId', 'sequence', 'root', 'previousRoot', 'operationDigest']);
    if (d.version !== 1 || d.tenantId !== tenant || d.vaultId !== vault || d.keyId !== pin.keyId || !Number.isSafeInteger(d.sequence) || d.sequence < 0 || !/^[a-f0-9]{64}$/.test(d.root) || !await verify(pin.publicKey, c.signature, c.canonical))
        throw new Error('invalid_checkpoint');
    if (c.canonical !== JSON.stringify({ version: 1, tenantId: d.tenantId, vaultId: d.vaultId, keyId: d.keyId, sequence: d.sequence, root: d.root, previousRoot: d.previousRoot, operationDigest: d.operationDigest }))
        throw new Error('noncanonical_checkpoint');
    if (d.sequence === 0 && (d.previousRoot !== null || d.operationDigest !== null || d.root !== await genesisRoot(tenant, vault)))
        throw new Error('invalid_genesis');
    if (d.sequence > 0 && (!/^[a-f0-9]{64}$/.test(d.previousRoot ?? '') || !/^[a-f0-9]{64}$/.test(d.operationDigest ?? '')))
        throw new Error('invalid_chain');
    return d;
}
/** A trusted pin and independently retained sequence/root anchor are required.
 * Old valid signatures cannot prove freshness without such an anchor. */
export async function verifyCheckpointPage(pin: CheckpointKey, tenant: string, vault: string, after: number, root: string, requiredThrough: number, page: {
    versions: ManagedVersion[];
    checkpoint: Checkpoint;
    pageCheckpoint: Checkpoint;
    hasMore: boolean;
}) {
    const head = await verifyCheckpoint(pin, tenant, vault, page.checkpoint), end = await verifyCheckpoint(pin, tenant, vault, page.pageCheckpoint);
    let sequence = after;
    for (const v of page.versions) {
        if (v.serverSequence !== ++sequence)
            throw new Error('sequence_gap');
        root = (await advanceRoot(root, sequence, v.signed)).root;
    }
    if (end.sequence !== sequence || end.root !== root || head.sequence < Math.max(sequence, requiredThrough) || page.hasMore !== (sequence < head.sequence) || (!page.hasMore && head.root !== root) || (page.hasMore && page.versions.length === 0))
        throw new Error('checkpoint_page_mismatch');
    return { sequence, root, requiredThrough: Math.max(requiredThrough, head.sequence) };
}
