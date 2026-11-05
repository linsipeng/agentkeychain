import { ApiError, digest, verify } from '../shared/contracts.ts';
import type { CheckpointSigner } from '../shared/checkpoints.ts';
import type { SessionRow } from './browser-repository.ts';
export interface AuditEvent {
    id: number;
    public_id: string;
    tenant_id: string | null;
    account_id: string | null;
    device_id: string | null;
    vault_id: string | null;
    event: string;
    reference: string | null;
    created_at: number;
}
export function validateAuditEvent(value: unknown): asserts value is AuditEvent {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('invalid_audit');
    const r = value as Record<string, unknown>;
    if (Object.keys(r).sort().join(',') !== ['id', 'public_id', 'tenant_id', 'account_id', 'device_id', 'vault_id', 'event', 'reference', 'created_at'].sort().join(','))
        throw new Error('invalid_audit');
    if (typeof r.public_id !== 'string' || !/^[a-f0-9]{32}$/.test(r.public_id))
        throw new Error('invalid_audit');
    for (const k of ['tenant_id', 'account_id', 'device_id', 'vault_id', 'reference'])
        if (r[k] !== null && (typeof r[k] !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(r[k] as string)))
            throw new Error('invalid_audit');
    for (const k of ['tenant_id', 'account_id', 'device_id', 'vault_id', 'reference'])
        if (typeof r[k] === 'string' && /^(sk-|AKIA|eyJ)|-----BEGIN|Bearer\s|password=/i.test(r[k] as string))
            throw new Error('invalid_audit');
    if (typeof r.event !== 'string' || !/^(account|browser|device|sync|approval|recovery)\.[a-z_]+$/.test(r.event) || !Number.isSafeInteger(r.id) || !Number.isSafeInteger(r.created_at))
        throw new Error('invalid_audit');
}
const bytes = (r: AuditEvent) => JSON.stringify([r.public_id, r.tenant_id, r.account_id, r.device_id, r.vault_id, r.event, r.reference, r.created_at]);
interface CP {
    through_id: number;
    count: number;
    root: string;
    previous_id: number;
    key_id: string;
    canonical: string;
    signature: string;
}
/** Checkpointing is bounded to 100 events per call; pending is explicit. A caller's
 * retained minimum detects known rollback. No signature alone proves freshness. */
export function auditRepository(db: D1Database, signer: CheckpointSigner) {
    const publicEvent = ({ id: _id, public_id, ...event }: AuditEvent) => ({ ...event, id: public_id });
    async function cursor(s: SessionRow, value: string | 0) {
        if (value === 0)
            return 0;
        if (typeof value !== 'string' || !/^[a-f0-9]{32}$/.test(value))
            throw new ApiError('invalid_request');
        const row = await db.prepare('SELECT id FROM activity WHERE tenant_id=? AND account_id=? AND public_id=?').bind(s.tenant_id, s.account_id, value).first<{
            id: number;
        }>();
        if (!row)
            throw new ApiError('not_found');
        return row.id;
    }
    async function snapshot(s: SessionRow, minimum: number, append = true) {
        const key = await signer.key();
        if (key.keyId !== await digest(key.publicKey))
            throw new Error('invalid_signer');
        await db.prepare('INSERT INTO activity_key SELECT 1,?,? WHERE NOT EXISTS(SELECT 1 FROM activity_key)').bind(key.keyId, key.publicKey).run();
        const pin = await db.prepare('SELECT * FROM activity_key').first<{
            key_id: string;
            public_key: string;
        }>();
        if (pin?.key_id !== key.keyId || pin.public_key !== key.publicKey)
            throw new Error('signer_substitution');
        const checkpoints = (await db.prepare('SELECT * FROM activity_checkpoints WHERE tenant_id=? AND account_id=? ORDER BY through_id').bind(s.tenant_id, s.account_id).all<CP>()).results;
        let root = await digest(JSON.stringify(['AgentKeychain-activity-v2', s.tenant_id, s.account_id])), through = 0, count = 0;
        let publicThrough: string | 0 = 0;
        let checkpoint: {
            canonical: string;
            signature: string;
        } | null = null;
        for (const cp of checkpoints) {
            const rows = (await db.prepare('SELECT * FROM activity WHERE tenant_id=? AND account_id=? AND id>? AND id<=? ORDER BY id').bind(s.tenant_id, s.account_id, through, cp.through_id).all<AuditEvent>()).results;
            for (const r of rows) {
                validateAuditEvent(r);
                root = await digest(JSON.stringify([root, bytes(r)]));
                count++;
            }
            const canonical = JSON.stringify(['AgentKeychain-activity-checkpoint-v2', await digest(JSON.stringify([s.tenant_id, s.account_id])), key.keyId, publicThrough, rows.at(-1)?.public_id, count, root]);
            if (!rows.length || cp.previous_id !== through || cp.count !== count || cp.root !== root || cp.canonical !== canonical || cp.key_id !== key.keyId || !await verify(key.publicKey, cp.signature, canonical))
                throw new Error('invalid_audit_chain');
            through = cp.through_id;
            publicThrough = rows.at(-1)!.public_id;
            checkpoint = { canonical: cp.canonical, signature: cp.signature };
        }
        const rows = (await db.prepare('SELECT * FROM activity WHERE tenant_id=? AND account_id=? AND id>? ORDER BY id LIMIT 100').bind(s.tenant_id, s.account_id, through).all<AuditEvent>()).results;
        if (rows.length && append) {
            const previous = through, previousPublic = publicThrough;
            for (const r of rows) {
                validateAuditEvent(r);
                root = await digest(JSON.stringify([root, bytes(r)]));
                count++;
                through = r.id;
                publicThrough = r.public_id;
            }
            const canonical = JSON.stringify(['AgentKeychain-activity-checkpoint-v2', await digest(JSON.stringify([s.tenant_id, s.account_id])), key.keyId, previousPublic, publicThrough, count, root]);
            const signature = await signer.sign(canonical);
            if (!await verify(key.publicKey, signature, canonical))
                throw new Error('invalid_signer');
            const inserted = await db.prepare('INSERT INTO activity_checkpoints SELECT ?,?,?,?,?,?,?,?,? WHERE COALESCE((SELECT max(through_id) FROM activity_checkpoints WHERE tenant_id=? AND account_id=?),0)=?').bind(s.tenant_id, s.account_id, through, count, root, previous, key.keyId, canonical, signature, s.tenant_id, s.account_id, previous).run();
            if (!inserted.meta.changes)
                return snapshot(s, minimum, false);
            checkpoint = { canonical, signature };
        }
        if (through < minimum)
            throw new Error('rollback');
        const pending = !!await db.prepare('SELECT 1 FROM activity WHERE tenant_id=? AND account_id=? AND id>? LIMIT 1').bind(s.tenant_id, s.account_id, through).first();
        return { verification: pending ? 'pending' : 'verified', checkpoint, through: publicThrough };
    }
    async function status(s: SessionRow, minimum: number) {
        try {
            return await snapshot(s, minimum);
        }
        catch {
            return { verification: 'failed', checkpoint: null, through: 0 };
        }
    }
    return {
        async list(s: SessionRow, after: string | 0, limit: number, minimum: string | 0) {
            if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
                throw new ApiError('invalid_request');
            const afterId = await cursor(s, after), minimumId = await cursor(s, minimum);
            const events = (await db.prepare('SELECT * FROM activity WHERE tenant_id=? AND account_id=? AND id>? ORDER BY id LIMIT ?').bind(s.tenant_id, s.account_id, afterId, limit).all<AuditEvent>()).results;
            try {
                for (const event of events)
                    validateAuditEvent(event);
            }
            catch {
                return { events: [], nextCursor: after, verification: 'failed', checkpoint: null, through: 0 };
            }
            return { events: events.map(publicEvent), nextCursor: events.at(-1)?.public_id ?? after, ...await status(s, minimumId) };
        },
        async detail(s: SessionRow, id: string, minimum: string | 0) {
            const internal = await cursor(s, id), minimumId = await cursor(s, minimum);
            const event = await db.prepare('SELECT * FROM activity WHERE tenant_id=? AND account_id=? AND id=?').bind(s.tenant_id, s.account_id, internal).first<AuditEvent>();
            if (!event)
                throw new ApiError('not_found');
            try {
                validateAuditEvent(event);
            }
            catch {
                return { event: null, verification: 'failed', checkpoint: null, through: 0 };
            }
            return { event: publicEvent(event), ...await status(s, minimumId) };
        }
    };
}
