import { recoveryRepository } from './recovery-repository.ts';
import { ApiError, digest } from '../shared/contracts.ts';
import { exactFields, identifier } from '../../src/cloud/protocol.ts';
import { approvalRepository, decisionDigest, type ApprovalRow } from './approval-repository.ts';
import { deviceRepository } from './device-repository.ts';
import { auditRepository } from './audit-repository.ts';
import type { SessionRow } from './browser-repository.ts';
import type { BrowserConfig } from './browser-auth.ts';
import { random } from './webauthn.ts';
interface Action {
    kind: string;
    target: string;
    action_digest: string;
    context: string | null;
}
export function webRepository(db: D1Database, config: BrowserConfig, s: SessionRow) {
    const approvals = approvalRepository(db), devices = deviceRepository(db);
    async function action(kind: string, target: string, hash: string, context: string | null = null) {
        const ref = random();
        await db.prepare('DELETE FROM web_actions WHERE ref IN(SELECT ref FROM web_actions WHERE expires_at<=unixepoch() LIMIT 100)').run();
        await db.prepare('INSERT INTO web_actions VALUES(?,?,?,?,?,?,?,unixepoch()+300)').bind(ref, s.account_id, s.tenant_id, kind, target, hash, context).run();
        return ref;
    }
    async function resolve(ref: unknown) {
        identifier(ref);
        const a = await db.prepare('SELECT kind,target,action_digest,context FROM web_actions WHERE ref=? AND account_id=? AND tenant_id=? AND expires_at>unixepoch()').bind(ref, s.account_id, s.tenant_id).first<Action>();
        if (!a)
            throw new ApiError('not_found');
        return a;
    }
    async function request(r: ApprovalRow) {
        const complete = ['delete', 'restore'].includes(r.action) && !!r.object_id;
        return { id: r.id, action: r.action, state: r.consumed_sequence !== null ? 'completed' : r.state, deviceId: r.device_id, itemRef: r.object_id, createdAt: r.created_at, expiresAt: r.expires_at, canAllow: complete && r.state === 'pending', allowRef: complete && r.state === 'pending' ? await action('approve', r.id, await decisionDigest('approve', r)) : null, denyRef: r.state === 'pending' ? await action('deny', r.id, await decisionDigest('deny', r)) : null };
    }
    function aggregate(states: string[]) {
        if (!states.length) return 'waiting';
        return ['unavailable', 'paused', 'stale', 'waiting', 'updating'].find(state => states.includes(state)) ?? 'current';
    }
    async function deviceList() {
        const observations = (await db.prepare('SELECT vd.device_id,vd.active,v.sequence,p.last_seen,p.acknowledged FROM vault_devices vd JOIN vaults v ON v.tenant_id=vd.tenant_id AND v.id=vd.vault_id JOIN devices d ON d.tenant_id=vd.tenant_id AND d.id=vd.device_id LEFT JOIN device_sync_progress p ON p.tenant_id=vd.tenant_id AND p.vault_id=vd.vault_id AND p.device_id=vd.device_id WHERE vd.tenant_id=? AND d.account_id=?').bind(s.tenant_id,s.account_id).all<{device_id:string;active:number;sequence:number;last_seen:number|null;acknowledged:number|null}>()).results;
        return Promise.all((await devices.list(s)).devices.map(async d => {
            const rows = observations.filter(r => r.device_id === d.id);
            const states = rows.map(r => !r.active ? 'paused' : r.last_seen === null ? 'waiting' : r.last_seen > Date.now()/1000 + 60 || r.acknowledged === null || r.acknowledged > r.sequence ? 'unavailable' : r.last_seen <= Date.now()/1000 - 300 ? 'stale' : r.acknowledged < r.sequence ? 'updating' : 'current');
            return {id:d.id,active:!!d.active,status:!d.active ? 'removed' : rows.length ? aggregate(states) : 'unavailable',removeRef:d.active ? await action('remove',d.id,d.revokeActionDigest) : null};
        }));
    }
    async function activity(after: string | 0 = 0, minimum: string | 0 = 0) {
        if (!config.checkpointSigner)
            return { events: [], verification: 'failed' };
        const a = await auditRepository(db, config.checkpointSigner).list(s, after, 100, minimum);
        return { verification: a.verification, receipt: a.through, nextPage: a.events.length === 100 ? a.nextCursor : null, events: a.events.map(e => ({ id: e.id, category: e.event.split('.')[0], action: e.event.split('.')[1], createdAt: e.created_at, deviceId: e.device_id, related: e.reference })) };
    }
    return {
        resolve,
        async query(body: Record<string, unknown>) {
            exactFields(body, ['view', ...(body.id === undefined ? [] : ['id']), ...(body.page === undefined ? [] : ['page']), ...(body.receipt === undefined ? [] : ['receipt'])]);
            if (body.page !== undefined)
                identifier(body.page);
            if (body.receipt !== undefined)
                identifier(body.receipt);
            if (body.id !== undefined)
                identifier(body.id);
            if (body.view === 'account')
                return {
                    notifications: (await db.prepare('SELECT event,created_at FROM recovery_notifications WHERE account_id=? AND tenant_id=? ORDER BY id DESC LIMIT 20').bind(s.account_id,s.tenant_id).all<{event:string;created_at:number}>()).results.map(n=>({event:n.event,createdAt:n.created_at})),
                    passkeys: (await db.prepare('SELECT active FROM passkeys WHERE account_id=? ORDER BY id LIMIT 100').bind(s.account_id).all<{
                        active: number;
                    }>()).results.map(p => ({ active: !!p.active })),
                    sessions: (await db.prepare('SELECT digest,created_at,absolute_expires FROM browser_sessions WHERE account_id=? AND tenant_id=? AND revoked=0 AND absolute_expires>unixepoch() AND last_seen>unixepoch()-1800 ORDER BY created_at LIMIT 100').bind(s.account_id, s.tenant_id).all<{
                        digest: string;
                        created_at: number;
                        absolute_expires: number;
                    }>()).results.map(r => ({ current: r.digest === s.digest, createdAt: r.created_at, expiresAt: r.absolute_expires })),
                    recoveries: (await db.prepare('SELECT id,state,expires_at,review_required FROM recovery_sagas WHERE account_id=? AND tenant_id=? ORDER BY expires_at DESC LIMIT 20').bind(s.account_id, s.tenant_id).all<{
                        id: string;
                        state: string;
                        expires_at: number;
                        review_required: number;
                    }>()).results.map(r => ({ id: r.id, state: r.expires_at < Date.now() / 1000 && !['completed', 'cancelled', 'activating'].includes(r.state) ? 'expired' : r.state, reviewRequired: !!r.review_required })),
                };
            if (body.view === 'recovery') {
                const r = await recoveryRepository(db, config.recovery ?? {}).detail(s, body.id as string);
                return { id: r.id, state: r.state, reviewRequired: r.reviewRequired, reviewRef: r.state === 'completed' && r.reviewRequired ? await action('review', r.id, r.reviewDigest) : null, cancelRef: !['activating', 'completed', 'cancelled', 'expired'].includes(r.state) ? await action('recovery-cancel', r.id, r.cancelDigest) : null };
            }
            if (body.view === 'devices')
                return { devices: await deviceList() };
            if (body.view === 'device') {
                const d = (await deviceList()).find(d => d.id === body.id);
                if (!d)
                    throw new ApiError('not_found');
                return d;
            }
            if (body.view === 'status')
                return { status: aggregate((await deviceList()).filter(d => d.active).map(d => d.status)) };
            if (body.view === 'requests' || body.view === 'requests-recent') {
                const after = body.page ? (await approvals.detail(s, body.page as string)).ordinal : 0;
                const rows = (await approvals.list(s, after, 100, body.view === 'requests' ? 'pending' : 'recent')).requests;
                return { requests: await Promise.all(rows.map(request)), nextPage: rows.length === 100 ? rows.at(-1)!.id : null };
            }
            if (body.view === 'request')
                return request(await approvals.detail(s, body.id as string));
            if (body.view === 'activity')
                return activity((body.page ?? 0) as string | 0, (body.receipt ?? 0) as string | 0);
            if (body.view === 'event') {
                if (!config.checkpointSigner)
                    return { event: null, verification: 'failed' };
                const a = await auditRepository(db, config.checkpointSigner).detail(s, body.id as string, (body.receipt ?? 0) as string | 0), e = a.event;
                return { event: e ? { id: e.id, category: e.event.split('.')[0], action: e.event.split('.')[1], createdAt: e.created_at, deviceId: e.device_id, related: e.reference } : null, verification: a.verification, receipt: a.through };
            }
            if (body.view === 'home') {
                const d = await deviceList(), a = await activity(0, (body.receipt ?? 0) as string | 0);
                return { status: aggregate(d.filter(d => d.active).map(d => d.status)), devices: d, requests: await Promise.all((await approvals.list(s, 0, 10, 'pending')).requests.map(request)), ...a };
            }
            if (body.view === 'history') {
                const page = body.page ? await resolve(body.page) : null;
                if (page && (page.kind !== 'history-page' || page.target !== body.id))
                    throw new ApiError('not_found');
                const rows = await db.prepare('SELECT v.operation_id,v.kind,v.sequence,v.sequence=h.sequence AS current FROM versions v JOIN heads h ON h.tenant_id=v.tenant_id AND h.vault_id=v.vault_id AND h.object_id=v.object_id WHERE v.tenant_id=? AND v.object_id=? AND v.sequence<? AND EXISTS(SELECT 1 FROM vault_devices vd JOIN devices d ON d.tenant_id=vd.tenant_id AND d.id=vd.device_id WHERE vd.tenant_id=v.tenant_id AND vd.vault_id=v.vault_id AND d.account_id=?) ORDER BY v.sequence DESC LIMIT 100').bind(s.tenant_id, body.id, page ? Number(page.action_digest) : Number.MAX_SAFE_INTEGER, s.account_id).all<{
                    operation_id: string;
                    kind: string;
                    sequence: number;
                    current: number;
                }>();
                if (!rows.results.length && !body.page)
                    throw new ApiError('not_found');
                return { nextPage: rows.results.length === 100 ? await action('history-page', body.id as string, String(rows.results.at(-1)!.sequence)) : null, versions: rows.results.map(r => ({ id: r.operation_id, kind: r.kind, current: !!r.current })), requests: await Promise.all((await approvals.list(s, 0, 100)).requests.filter(r => r.object_id === body.id && r.action === 'restore').map(request)) };
            }
            throw new ApiError('not_found');
        },
        async execute(ref: unknown, confirmationRef?: unknown) {
            const a = await resolve(ref);
            if (a.kind === 'approve' || a.kind === 'deny') {
                const current = await approvals.detail(s, a.target);
                if (await decisionDigest(a.kind, current) !== a.action_digest)
                    throw new ApiError('approval_required');
                await approvals.decide(s, a.target, a.kind);
                return request(await approvals.detail(s, a.target));
            }
            if (a.kind === 'remove') {
                const d = (await devices.list(s)).devices.find(d => d.id === a.target);
                if (!d || d.revokeActionDigest !== a.action_digest)
                    throw new ApiError('approval_required');
                await devices.revoke(s, a.target);
                return { removed: (await devices.list(s)).devices.find(d => d.id === a.target)?.active === 0 };
            }
            if (a.kind === 'recovery-cancel') {
                if (typeof confirmationRef !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(confirmationRef)) throw new ApiError('approval_required');
                const repo = recoveryRepository(db, config.recovery ?? {}), r = await repo.detail(s, a.target);
                if (r.cancelDigest !== a.action_digest) throw new ApiError('approval_required');
                const authorization = await db.prepare('SELECT authorization FROM recovery_cancel_confirmations WHERE digest=? AND case_id=? AND account_id=? AND tenant_id=? AND expires_at>unixepoch()').bind(await digest(confirmationRef), a.target, s.account_id, s.tenant_id).first<string>('authorization');
                if (!authorization) throw new ApiError('approval_required');
                await repo.cancel(s, a.target, JSON.parse(authorization));
                const current = await repo.detail(s, a.target);
                return { id: current.id, state: current.state, reviewRequired: current.reviewRequired };
            }
            if (a.kind === 'review') {
                const repo = recoveryRepository(db, config.recovery ?? {}), r = await repo.detail(s, a.target);
                if (r.reviewDigest !== a.action_digest)
                    throw new ApiError('approval_required');
                await repo.review(s, a.target);
                return { reviewRequired: (await repo.detail(s, a.target)).reviewRequired };
            }
            if (a.kind === 'pair') {
                const confirmation = JSON.parse(a.context!) as {
                    canonical: string;
                    signature: string | null;
                };
                await devices.approve(s, confirmation.canonical, confirmation.signature);
                return { approved: (await devices.list(s)).devices.some(d => d.id === a.target && !!d.active) };
            }
            throw new ApiError('not_found');
        },
        async pairing(body: Record<string, unknown>) {
            exactFields(body, ['code']);
            if (typeof body.code !== 'string' || !/^(?:[A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{43})$/.test(body.code))
                throw new ApiError('invalid_request');
            const active = (await devices.list(s)).devices.filter(d => d.active);
            const existing = await db.prepare('SELECT issuer_device_id FROM pairing_confirmations WHERE request_id=(SELECT id FROM device_requests WHERE verification_digest=?) AND account_id=? AND tenant_id=?').bind(await import('../shared/contracts.ts').then(m => m.digest(body.code as string)), s.account_id, s.tenant_id).first<{
                issuer_device_id: string;
            }>();
            const p = await devices.pending(s, await import('../shared/contracts.ts').then(m => m.digest(body.code as string)), existing?.issuer_device_id ?? active[0]?.id ?? null);
            const signed = await db.prepare('SELECT signature FROM pairing_confirmations WHERE request_id=? AND canonical=? AND account_id=? AND tenant_id=?').bind(p.requestId, p.canonical, s.account_id, s.tenant_id).first<{
                signature: string;
            }>();
            return { id: p.requestId, phrase: p.phrase, platform: p.platform, requiresDevice: !!active.length && !signed, confirmRef: active.length && !signed ? null : await action('pair', p.deviceId, p.actionDigest, JSON.stringify({ canonical: p.canonical, signature: signed?.signature ?? null })) };
        },
    };
}
