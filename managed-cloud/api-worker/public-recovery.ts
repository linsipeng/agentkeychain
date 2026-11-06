import { ApiError, digest } from '../shared/contracts.ts';
import { base64, exactFields, identifier } from '../../src/cloud/protocol.ts';
import { recoveryAction, type CancelAuthorization } from '../shared/recovery.ts';
import { recoveryRepository, type StartRequest } from './recovery-repository.ts';
import { emailLookup, type BrowserConfig } from './browser-auth.ts';
import { random } from './webauthn.ts';
import type { SessionRow } from './browser-repository.ts';
export interface RestrictedSession {
    digest: string;
    csrf_digest: string;
    account_id: string | null;
    tenant_id: string | null;
    vault_id: string | null;
    case_id: string;
    request_digest: string;
    target: string | null;
    expires_at: number;
}
const denied = () => new ApiError('unauthorized');
export function publicRecovery(db: D1Database, config: BrowserConfig) {
    return {
        async session(hash: string) {
            return db.prepare('SELECT r.* FROM recovery_sessions r WHERE r.digest=? AND r.revoked=0 AND r.expires_at>unixepoch() AND (r.account_id IS NULL OR EXISTS(SELECT 1 FROM memberships m WHERE m.account_id=r.account_id AND m.tenant_id=r.tenant_id AND m.active=1))').bind(hash).first<RestrictedSession>();
        },
        async verify(body: Record<string, unknown>, bootstrap: string, bootstrapExpires: number) {
            exactFields(body, ['email', 'proof', 'requestRef']);
            if (typeof body.requestRef !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.requestRef))
                throw denied();
            const storedTarget = await db.prepare('SELECT target FROM recovery_targets WHERE digest=? AND expires_at>unixepoch()').bind(await digest(body.requestRef)).first<string>('target');
            if (!storedTarget)
                throw denied();
            const lookup = await emailLookup(config, body.email as string);
            if (typeof body.proof !== 'string' || !body.proof.length || body.proof.length > 2048)
                throw denied();
            const t = JSON.parse(storedTarget) as StartRequest;
            exactFields(t, ['id', 'packageId', 'targetDeviceId', 'signingKey', 'wrappingKey', 'nonce']);
            for (const k of ['id', 'packageId', 'targetDeviceId', 'nonce'] as const)
                identifier(t[k]);
            base64(t.signingKey, 32, 32);
            base64(t.wrappingKey, 32, 32);
            if (!/^[A-Za-z0-9_-]{43}$/.test(t.targetDeviceId) || t.signingKey === t.wrappingKey)
                throw denied();
            const [account, proof] = await Promise.allSettled([
                db.prepare('SELECT e.account_id,p.tenant_id,p.vault_id FROM account_emails e JOIN recovery_packages_v1 p ON p.account_id=e.account_id JOIN memberships m ON m.account_id=e.account_id AND m.tenant_id=p.tenant_id WHERE e.lookup_hash=? AND e.verified=1 AND m.active=1 AND p.id=? LIMIT 2').bind(lookup,t.packageId).all<{
                    account_id: string;
                    tenant_id: string;
                    vault_id: string;
                }>(),
                Promise.resolve().then(() => config.verifyEmail((body.email as string).toLowerCase(), body.proof as string)),
            ]);
            const a = account.status === 'fulfilled' && account.value.results.length === 1 && proof.status === 'fulfilled' && proof.value === true ? account.value.results[0] : undefined;
            const token = 'r.' + random(), csrf = random(), expires = Math.floor(Date.now() / 1000) + 600;
            // Reserve every proof (including decoys) and bootstrap in the same batch.
            // No account existence signal changes the response or database statement count.
            await db.batch([
                db.prepare('INSERT INTO consumed_bootstraps VALUES(?,?)').bind(bootstrap, bootstrapExpires),
                db.prepare('INSERT INTO recovery_sessions(digest,csrf_digest,bootstrap_digest,proof_digest,account_id,tenant_id,vault_id,case_id,request_digest,target,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(await digest(token), await digest(csrf), bootstrap, await digest('recovery-email-proof\0' + lookup + '\0' + body.proof), a?.account_id ?? null, a?.tenant_id ?? null, a?.vault_id ?? null, t.id, await recoveryAction('start', JSON.stringify(t)), JSON.stringify(t), expires),
            ]);
            return { token, csrf };
        },
        async route(s: RestrictedSession, route: string, body: Record<string, unknown>) {
            const repo = recoveryRepository(db, config.recovery ?? {});
            if (!s.account_id || !s.tenant_id)
                throw denied();
            const session = { digest: s.digest, csrf_digest: s.csrf_digest, account_id: s.account_id, tenant_id: s.tenant_id, absolute_expires: s.expires_at, step_up_digest: null, step_up_expires: null } satisfies SessionRow;
            if (route === 'recovery/start') {
                exactFields(body, []);
                if (!s.target) throw denied();
                body = JSON.parse(s.target);
                const p = await db.prepare('SELECT 1 FROM recovery_packages_v1 WHERE id=? AND account_id=? AND tenant_id=? AND vault_id=?').bind(body.packageId, s.account_id, s.tenant_id, s.vault_id).first();
                if (!p)
                    throw denied();
                await repo.start(session, body as unknown as StartRequest);
                await repo.accountVerified(session,s.case_id);
            }
            else {
                if (route === 'recovery/cancel') {
                    exactFields(body, ['id', 'confirmed', 'confirmationRef']);
                    if (typeof body.confirmationRef !== 'string' || body.confirmationRef.length !== 43)
                        throw denied();
                    const authorization = await db.prepare('SELECT authorization FROM recovery_cancel_confirmations WHERE digest=? AND case_id=? AND account_id=? AND tenant_id=? AND expires_at>unixepoch()').bind(await digest(body.confirmationRef), s.case_id, s.account_id, s.tenant_id).first<string>('authorization');
                    if (!authorization)
                        throw denied();
                    body = { id: body.id, confirmed: body.confirmed, authorization: JSON.parse(authorization) };
                }
                exactFields(body, route === 'recovery/cancel' ? ['id', 'confirmed', 'authorization'] : ['id']);
                if (body.id !== s.case_id)
                    throw denied();
                if (route === 'recovery/cancel') {
                    if (body.confirmed !== true)
                        throw denied();
                    await repo.cancel(session, s.case_id, body.authorization as CancelAuthorization);
                }
            }
            const r = await repo.detail(session, s.case_id);
            return { id: r.id, state: r.state, reviewRequired: r.reviewRequired };
        },
    };
}
