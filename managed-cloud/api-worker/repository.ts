import { advanceRoot, checkpoint, genesisRoot, type Checkpoint, type CheckpointSigner } from '../shared/checkpoints.ts';
import type { DeviceContext } from './auth.ts';
import { ApiError, approvalDigest, digest, PAGE_MAX, validateSigned, verify } from '../shared/contracts.ts';
import { parseCanonicalOperation, type ManagedVersion, type PushReceipt, type SignedManagedOperation } from '../../src/cloud/protocol.ts';
export interface SyncPage {
    versions: ManagedVersion[];
    nextCursor: string;
    hasMore: boolean;
    checkpoint: Checkpoint;
    pageCheckpoint: Checkpoint;
}
export interface SyncRepository {
    push(signed: SignedManagedOperation): Promise<PushReceipt & {
        checkpoint: Checkpoint;
    }>;
    pull(cursor: string | null, limit: number): Promise<SyncPage>;
}
function databaseError(error: unknown): never {
    const message = error instanceof Error ? error.message : '';
    for (const code of ['not_found', 'replayed_request', 'idempotency_conflict', 'invalid_transition', 'approval_required'] as const)
        if (message.includes(code))
            throw new ApiError(code);
    throw new ApiError('internal_error');
}
/** SQL is private to this adapter. Services receive only SyncRepository. No generic
 * query/table/transaction callback or unscoped get-by-id method is exported. */
export function createRepository(db: D1Database, ctx: DeviceContext, signer: CheckpointSigner): SyncRepository {
    const scope = [ctx.tenantId, ctx.vaultId];
    const authorize = () => db.prepare('INSERT INTO accept_device_nonce VALUES (?,?,?,?,?,?,?)').bind(ctx.sessionDigest, ...scope, ctx.deviceId, ctx.accountId, ctx.nonce, ctx.timestamp);
    const initialize = async () => {
        if (!signer || typeof signer.key !== 'function' || typeof signer.sign !== 'function')
            throw new ApiError('internal_error');
        const key = await signer.key();
        if (key.keyId !== await digest(key.publicKey))
            throw new ApiError('internal_error');
        const pinned = await db.prepare('SELECT key_id,public_key FROM checkpoint_key WHERE slot=1').first<{
            key_id: string;
            public_key: string;
        }>();
        if (pinned && (pinned.key_id !== key.keyId || pinned.public_key !== key.publicKey))
            throw new ApiError('internal_error');
        const genesis = await checkpoint({ key: async () => key, sign: c => signer.sign(c) }, ctx.tenantId, ctx.vaultId, 0, await genesisRoot(...scope as [
            string,
            string
        ]), null, null);
        await db.batch([
            db.prepare('INSERT INTO checkpoint_key SELECT 1,?,? WHERE NOT EXISTS(SELECT 1 FROM checkpoint_key)').bind(key.keyId, key.publicKey),
            db.prepare(`INSERT INTO sync_checkpoints SELECT ?,?,0,?,NULL,NULL,?,?,? WHERE NOT EXISTS(SELECT 1 FROM sync_checkpoints WHERE tenant_id=? AND vault_id=?) AND EXISTS(SELECT 1 FROM vaults WHERE tenant_id=? AND id=? AND sequence=0) AND EXISTS(SELECT 1 FROM checkpoint_key WHERE key_id=? AND public_key=?)`).bind(...scope, await genesisRoot(ctx.tenantId, ctx.vaultId), key.keyId, genesis.canonical, genesis.signature, ...scope, ...scope, key.keyId, key.publicKey),
        ]);
        const accepted = await db.prepare('SELECT key_id,public_key FROM checkpoint_key WHERE slot=1').first<{
            key_id: string;
            public_key: string;
        }>();
        if (accepted?.key_id !== key.keyId || accepted.public_key !== key.publicKey)
            throw new ApiError('internal_error');
        return key;
    };
    return {
        async push(input) {
            const signed = validateSigned(input), op = parseCanonicalOperation(signed.canonical);
            if (op.vaultId !== ctx.vaultId || op.deviceId !== ctx.deviceId)
                throw new ApiError('not_found');
            if (!await verify(ctx.publicKey, signed.signature, signed.canonical))
                throw new ApiError('invalid_signature');
            const hash = await approvalDigest(signed.canonical);
            const key = await initialize();
            for (let attempt = 0; attempt < 32; attempt++) {
                const previous = await db.prepare('SELECT sequence,root FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? ORDER BY sequence DESC LIMIT 1').bind(...scope).first<{
                    sequence: number;
                    root: string;
                }>();
                if (!previous)
                    throw new ApiError('internal_error');
                const next = previous.sequence + 1, chain = await advanceRoot(previous.root, next, signed);
                const cp = await checkpoint({ key: async () => key, sign: c => signer.sign(c) }, ctx.tenantId, ctx.vaultId, next, chain.root, previous.root, chain.operationDigest);
                try {
                    const result = await db.batch([
                        authorize(),
                        db.prepare('INSERT INTO accept_operation (tenant_id,vault_id,account_id,device_id,canonical,signature,request_digest) VALUES (?,?,?,?,?,?,?)').bind(...scope, ctx.accountId, ctx.deviceId, signed.canonical, signed.signature, hash),
                        // A racing exact retry already owns a checkpoint. A racing
                        // distinct operation must abort and recompute from its predecessor.
                        db.prepare(`INSERT INTO sync_checkpoints SELECT ?,?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM sync_checkpoints c JOIN idempotency i ON i.tenant_id=c.tenant_id AND i.vault_id=c.vault_id AND i.sequence=c.sequence WHERE i.tenant_id=? AND i.vault_id=? AND i.device_id=? AND i.operation_id=?)`).bind(...scope, next, chain.root, previous.root, chain.operationDigest, key.keyId, cp.canonical, cp.signature, ...scope, ctx.deviceId, op.operationId),
                        db.prepare('SELECT i.receipt,c.canonical,c.signature FROM idempotency i JOIN sync_checkpoints c ON c.tenant_id=i.tenant_id AND c.vault_id=i.vault_id AND c.sequence=i.sequence WHERE i.tenant_id=? AND i.vault_id=? AND i.device_id=? AND i.operation_id=?').bind(...scope, ctx.deviceId, op.operationId)
                    ]);
                    const row = result[3]!.results[0] as {
                        receipt: string;
                        canonical: string;
                        signature: string;
                    } | undefined;
                    if (!row)
                        throw new ApiError('internal_error');
                    return { ...JSON.parse(row.receipt) as PushReceipt, checkpoint: { canonical: row.canonical, signature: row.signature } };
                }
                catch (error) {
                    if (error instanceof Error && error.message.includes('checkpoint_conflict') && attempt < 31)
                        continue;
                    databaseError(error);
                }
            }
            throw new ApiError('internal_error');
        },
        async pull(cursor, limit) {
            if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
                throw new ApiError('invalid_request');
            let after = 0;
            if (cursor !== null) {
                try {
                    if (cursor.length > 1024)
                        throw new Error();
                    const value: unknown = JSON.parse(atob(cursor));
                    if (!Array.isArray(value) || value.length !== 4 || value[0] !== ctx.tenantId || value[1] !== ctx.vaultId || value[2] !== ctx.deviceId)
                        throw new ApiError('not_found');
                    if (!Number.isSafeInteger(value[3]) || value[3] < 0)
                        throw new Error();
                    after = value[3];
                }
                catch (error) {
                    if (error instanceof ApiError)
                        throw error;
                    throw new ApiError('invalid_request');
                }
            }
            await initialize();
            try {
                const result = await db.batch([authorize(), db.prepare('SELECT sequence FROM vaults WHERE tenant_id=? AND id=?').bind(...scope),
                    // Running byte bound keeps D1's materialized result bounded as well as the HTTP page.
                    db.prepare(`SELECT sequence,canonical,signature FROM (SELECT sequence,canonical,signature,SUM(length(CAST(canonical AS BLOB))+length(signature)+512) OVER (ORDER BY sequence) AS bytes FROM versions WHERE tenant_id=? AND vault_id=? AND sequence>? ORDER BY sequence LIMIT ?) WHERE bytes<=? ORDER BY sequence`).bind(...scope, after, limit, PAGE_MAX - 8192),
                    db.prepare('SELECT sequence,canonical,signature FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? ORDER BY sequence DESC LIMIT 1').bind(...scope),
                    db.prepare('SELECT sequence,canonical,signature FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? AND sequence BETWEEN ? AND ? ORDER BY sequence').bind(...scope, after, after + limit)]);
                const high = (result[1]!.results[0] as {
                    sequence: number;
                }).sequence;
                if (after > high)
                    throw new ApiError('invalid_request');
                const rows = result[2]!.results as {
                    sequence: number;
                    canonical: string;
                    signature: string;
                }[];
                if (rows.some((row, i) => row.sequence !== after + i + 1) || (!rows.length && after < high))
                    throw new ApiError('internal_error');
                const next = rows.at(-1)?.sequence ?? after;
                const head = result[3]!.results[0] as {
                    sequence: number;
                    canonical: string;
                    signature: string;
                } | undefined;
                const end = (result[4]!.results as {
                    sequence: number;
                    canonical: string;
                    signature: string;
                }[]).find(c => c.sequence === next);
                if (!head || !end || head.sequence !== high)
                    throw new ApiError('internal_error');
                return { checkpoint: { canonical: head.canonical, signature: head.signature }, pageCheckpoint: { canonical: end.canonical, signature: end.signature }, versions: rows.map(r => ({ serverSequence: r.sequence, signed: { canonical: r.canonical, signature: r.signature } })), nextCursor: btoa(JSON.stringify([...scope, ctx.deviceId, next])), hasMore: next < high };
            }
            catch (error) {
                if (error instanceof ApiError)
                    throw error;
                databaseError(error);
            }
        }
    };
}
