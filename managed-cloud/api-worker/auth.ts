import { ApiError, digest, proofBytes, verify } from '../shared/contracts.ts';
const authenticated: unique symbol = Symbol('authenticated-device');
export interface DeviceContext {
    readonly [authenticated]: true;
    readonly accountId: string;
    readonly tenantId: string;
    readonly vaultId: string;
    readonly deviceId: string;
    readonly publicKey: string;
    readonly sessionDigest: string;
    readonly nonce: string;
    readonly bodyDigest: string;
}
/** Only this boundary constructs contexts. Account/tenant come from a stored session,
 * never from request headers, body, or query. Session issuance is Phase 2C. */
export async function authenticate(db: D1Database, request: Request, vaultId: string, body: string): Promise<DeviceContext> {
    const token = request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_-]{1,256})$/)?.[1];
    const nonce = request.headers.get('x-device-nonce'), proof = request.headers.get('x-device-proof');
    if (!token || !nonce || !/^[A-Za-z0-9_-]{1,128}$/.test(nonce) || !proof)
        throw new ApiError('unauthorized');
    const sessionDigest = await digest(token);
    const row = await db.prepare(`SELECT s.account_id,s.tenant_id,s.device_id,d.public_key FROM device_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id JOIN devices d ON d.tenant_id=s.tenant_id AND d.id=s.device_id JOIN vault_devices v ON v.tenant_id=s.tenant_id AND v.vault_id=s.vault_id AND v.device_id=s.device_id WHERE s.digest=? AND s.vault_id=? AND s.active=1 AND s.expires_at>unixepoch() AND m.active=1 AND d.active=1 AND v.active=1`).bind(sessionDigest, vaultId).first<{
        account_id: string;
        tenant_id: string;
        device_id: string;
        public_key: string;
    }>();
    if (!row)
        throw new ApiError('not_found');
    const url = new URL(request.url), bodyDigest = await digest(body);
    if (!await verify(row.public_key, proof, proofBytes(request.method, url.pathname + url.search, bodyDigest, nonce, sessionDigest)))
        throw new ApiError('invalid_signature');
    return Object.freeze({ [authenticated]: true as const, accountId: row.account_id, tenantId: row.tenant_id, vaultId, deviceId: row.device_id, publicKey: row.public_key, sessionDigest, nonce, bodyDigest });
}
