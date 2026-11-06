import {exportSelect} from './export-repository.ts';
import { ApiError, approvalDigest, digest, validateSigned, verify } from '../shared/contracts.ts';
import { base64, exactFields, parseCanonicalOperation, type SignedManagedOperation } from '../../src/cloud/protocol.ts';
import type { DeviceContext } from './auth.ts';
import type { SessionRow } from './browser-repository.ts';
export interface ApprovalRow {
    ordinal: number;
    tenant_id: string;
    vault_id: string;
    id: string;
    account_id: string;
    device_id: string;
    action: string;
    object_id: string;
    request_digest: string;
    created_at: number;
    expires_at: number;
    state: string;
    decided_at: number | null;
    consumed_sequence: number | null;
    summary_digest: string | null;
    intent_signature?: string | null;
}
export const decisionDigest = (action: string, r: ApprovalRow) => digest(JSON.stringify(['AgentKeychain-approval-decision-v1', action, r.tenant_id, r.vault_id, r.account_id, r.device_id, r.id, r.action, r.object_id, r.request_digest, r.expires_at, r.summary_digest, ...(r.intent_signature?[r.intent_signature]:[])]));
const select = `SELECT (SELECT ordinal FROM approval_order WHERE tenant_id=r.tenant_id AND account_id=r.account_id AND request_id=r.id) AS ordinal,r.tenant_id,r.vault_id,r.id,r.account_id,r.device_id,r.action,r.object_id,r.request_digest,r.created_at,r.expires_at,r.decided_at,a.consumed_sequence,(SELECT signature FROM approval_intents WHERE tenant_id=r.tenant_id AND vault_id=r.vault_id AND request_id=r.id) AS intent_signature,(SELECT digest FROM approval_summaries WHERE tenant_id=r.tenant_id AND vault_id=r.vault_id AND request_id=r.id) AS summary_digest,CASE WHEN r.state='pending' AND r.expires_at<=unixepoch() THEN 'expired' ELSE r.state END AS state FROM approval_requests r LEFT JOIN approvals a ON a.tenant_id=r.tenant_id AND a.vault_id=r.vault_id AND a.id=r.id`;
export function approvalRepository(db: D1Database) {
    const detail = async (s: SessionRow, id: string) => {
        const r = await db.prepare(select + ' WHERE r.tenant_id=? AND r.account_id=? AND r.id=?').bind(s.tenant_id, s.account_id, id).first<ApprovalRow>() ?? await db.prepare(exportSelect+' WHERE tenant_id=? AND account_id=? AND id=?').bind(s.tenant_id,s.account_id,id).first<ApprovalRow>();
        if (!r)
            throw new ApiError('not_found');
        return r;
    };
    return {
        detail,
        async list(s: SessionRow, after: number, limit: number, mode: 'all' | 'pending' | 'recent' = 'all') {
            if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
                throw new ApiError('invalid_request');
            const filter = mode === 'pending' ? " AND state='pending' AND expires_at>unixepoch()" : '';
            const combined=`SELECT * FROM (${select} UNION ALL ${exportSelect}) WHERE tenant_id=? AND account_id=? AND ordinal${mode==='recent'?'<':'>'}?${filter} ORDER BY ordinal ${mode==='recent'?'DESC':'ASC'} LIMIT ?`;
            const rows=await db.prepare(combined).bind(s.tenant_id,s.account_id,mode==='recent'&&after===0?Number.MAX_SAFE_INTEGER:after,limit).all<ApprovalRow>();
            return { requests: rows.results, nextCursor: rows.results.at(-1)?.ordinal ?? after };
        },
        async create(c: DeviceContext, input: SignedManagedOperation, ttl: number, summary?: {
            ciphertext: string;
            nonce: string;
            signature: string;
        }, intent?: {action:string;signature:string}) {
            const signed = validateSigned(input), op = parseCanonicalOperation(signed.canonical);
            if (!Number.isInteger(ttl) || ttl < 30 || ttl > 900 || !op.approvalRef)
                throw new ApiError('invalid_request');
            if (op.vaultId !== c.vaultId || op.deviceId !== c.deviceId)
                throw new ApiError('not_found');
            if (!await verify(c.publicKey, signed.signature, signed.canonical))
                throw new ApiError('invalid_signature');
            let intentStatement: D1PreparedStatement | undefined;
            if(intent){
                exactFields(intent,['action','signature']);base64(intent.signature,64,64);
                if(op.kind!=='put'||!['rotate','scope'].includes(intent.action)||!await verify(c.publicKey,intent.signature,JSON.stringify(['AgentKeychain-approval-intent-v1',signed.canonical,signed.signature,intent.action])))throw new ApiError('invalid_signature');
                intentStatement=db.prepare('INSERT INTO approval_intents VALUES(?,?,?,?,?)').bind(c.tenantId,c.vaultId,op.approvalRef,intent.action,intent.signature);
            }
            const hash = await approvalDigest(signed.canonical);
            let summaryStatement: D1PreparedStatement | undefined;
            if (summary) {
                exactFields(summary, ['ciphertext', 'nonce', 'signature']);
                base64(summary.ciphertext, 16);
                base64(summary.nonce, 12, 12);
                base64(summary.signature, 64, 64);
                if (summary.ciphertext.length > 4096)
                    throw new ApiError('invalid_request');
                const value = JSON.stringify(['AgentKeychain-approval-summary-v1', hash, ttl, summary.nonce, summary.ciphertext]);
                if (!await verify(c.publicKey, summary.signature, value))
                    throw new ApiError('invalid_signature');
                summaryStatement = db.prepare('INSERT INTO approval_summaries VALUES(?,?,?,?,?,?)').bind(c.tenantId, c.vaultId, op.approvalRef, await digest(value), JSON.stringify({ nonce: summary.nonce, ciphertext: summary.ciphertext }), summary.signature);
            }
            const creationDigest = await digest(JSON.stringify([signed.canonical, signed.signature, ttl, summary ?? null, ...(intent?[intent]:[])]));
            const nonceStatement = () => db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest, c.tenantId, c.vaultId, c.deviceId, c.accountId, c.nonce, c.timestamp);
            const previous = () => db.prepare('SELECT creation_digest FROM approval_requests WHERE tenant_id=? AND account_id=? AND id=?').bind(c.tenantId, c.accountId, op.approvalRef).first<{
                creation_digest: string;
            }>();
            const receipt = async () => {
                const row=await db.prepare(select+' WHERE r.tenant_id=? AND r.account_id=? AND r.device_id=? AND r.id=?').bind(c.tenantId,c.accountId,c.deviceId,op.approvalRef).first<ApprovalRow>();
                if(!row)throw new ApiError('not_found');
                return {id:op.approvalRef,requestDigest:hash,state:row.consumed_sequence!==null?'consumed':row.expires_at<=Math.floor(Date.now()/1000)&&row.state==='approved'?'expired':row.state};
            };
            const old = await previous();
            if (old) {
                if (old.creation_digest !== creationDigest)
                    throw new ApiError('idempotency_conflict');
                await nonceStatement().run();
                return receipt();
            }
            let result: D1Result[];
            try {
                result = await db.batch([
                    db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest, c.tenantId, c.vaultId, c.deviceId, c.accountId, c.nonce, c.timestamp),
                    db.prepare(`INSERT INTO approval_requests(tenant_id,vault_id,id,account_id,device_id,action,object_id,request_digest,expires_at,creation_digest) SELECT ?,?,?,?,?,?,?,?,unixepoch()+?,? WHERE ?<>'put' OR EXISTS(SELECT 1 FROM heads WHERE tenant_id=? AND vault_id=? AND object_id=?) RETURNING *`).bind(c.tenantId, c.vaultId, op.approvalRef, c.accountId, c.deviceId, op.kind, op.objectId, hash, ttl, creationDigest, op.kind, c.tenantId, c.vaultId, op.objectId),
                    ...(summaryStatement ? [summaryStatement] : []), ...(intentStatement ? [intentStatement] : [])
                ]);
            }
            catch (error) {
                const concurrent = await previous();
                if (!concurrent)
                    throw error;
                if (concurrent.creation_digest !== creationDigest)
                    throw new ApiError('idempotency_conflict');
                await nonceStatement().run();
                return receipt();
            }
            if (!result[1]!.results.length)
                throw new ApiError('invalid_request');
            return receipt();
        },
        async decide(s: SessionRow, id: string, action: 'approve' | 'deny' | 'cancel') {
            const r = await detail(s, id);
            if(r.action==='export')await db.prepare('INSERT INTO export_decisions VALUES(?,?,?,?,?,?,?)').bind(crypto.randomUUID(),s.digest,s.tenant_id,s.account_id,r.id,action,await decisionDigest(action,r)).run();
            else await db.prepare('INSERT INTO approval_decisions VALUES(?,?,?,?,?,?,?)').bind(crypto.randomUUID(), s.digest, s.tenant_id, s.account_id, await db.prepare('SELECT ordinal FROM approval_requests WHERE tenant_id=? AND account_id=? AND id=?').bind(s.tenant_id,s.account_id,r.id).first<number>('ordinal'), action, await decisionDigest(action, r)).run();
            return detail(s, id);
        }
    };
}
