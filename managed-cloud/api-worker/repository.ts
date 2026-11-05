import type { DeviceContext } from './auth.ts';
import { ApiError, approvalDigest, PAGE_MAX, validateSigned, verify } from '../shared/contracts.ts';
import { parseCanonicalOperation, type ManagedVersion, type PushReceipt, type SignedManagedOperation } from '../../src/cloud/protocol.ts';
export interface SyncPage {
    versions: ManagedVersion[];
    nextCursor: string;
    hasMore: boolean;
}
export interface SyncRepository {
    push(signed: SignedManagedOperation): Promise<PushReceipt>;
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
export function createRepository(db: D1Database, ctx: DeviceContext): SyncRepository {
    const scope = [ctx.tenantId, ctx.vaultId];
    const authorize = () => db.prepare('INSERT INTO device_nonces VALUES (?,?,?,?,?,?)').bind(ctx.sessionDigest, ...scope, ctx.deviceId, ctx.accountId, ctx.nonce);
    return {
        async push(input) {
            const signed = validateSigned(input), op = parseCanonicalOperation(signed.canonical);
            if (op.vaultId !== ctx.vaultId || op.deviceId !== ctx.deviceId)
                throw new ApiError('not_found');
            if (!await verify(ctx.publicKey, signed.signature, signed.canonical))
                throw new ApiError('invalid_signature');
            const hash = await approvalDigest(signed.canonical);
            try {
                const result = await db.batch([
                    authorize(),
                    db.prepare('INSERT INTO accept_operation (tenant_id,vault_id,account_id,device_id,canonical,signature,request_digest) VALUES (?,?,?,?,?,?,?)').bind(...scope, ctx.accountId, ctx.deviceId, signed.canonical, signed.signature, hash),
                    db.prepare('SELECT receipt FROM idempotency WHERE tenant_id=? AND vault_id=? AND device_id=? AND operation_id=?').bind(...scope, ctx.deviceId, op.operationId)
                ]);
                const row = result[2]!.results[0] as {
                    receipt: string;
                } | undefined;
                if (!row)
                    throw new ApiError('internal_error');
                return JSON.parse(row.receipt) as PushReceipt;
            }
            catch (error) {
                databaseError(error);
            }
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
            try {
                const result = await db.batch([authorize(), db.prepare('SELECT sequence FROM vaults WHERE tenant_id=? AND id=?').bind(...scope),
                    // Running byte bound keeps D1's materialized result bounded as well as the HTTP page.
                    db.prepare(`SELECT sequence,canonical,signature FROM (SELECT sequence,canonical,signature,SUM(length(CAST(canonical AS BLOB))+length(signature)+512) OVER (ORDER BY sequence) AS bytes FROM versions WHERE tenant_id=? AND vault_id=? AND sequence>? ORDER BY sequence LIMIT ?) WHERE bytes<=? ORDER BY sequence`).bind(...scope, after, limit, PAGE_MAX - 2048)]);
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
                return { versions: rows.map(r => ({ serverSequence: r.sequence, signed: { canonical: r.canonical, signature: r.signature } })), nextCursor: btoa(JSON.stringify([...scope, ctx.deviceId, next])), hasMore: next < high };
            }
            catch (error) {
                if (error instanceof ApiError)
                    throw error;
                databaseError(error);
            }
        }
    };
}
