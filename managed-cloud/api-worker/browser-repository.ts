export interface SessionRow {
    digest: string;
    csrf_digest: string;
    account_id: string;
    tenant_id: string;
    absolute_expires: number;
    step_up_digest: string | null;
    step_up_expires: number | null;
}
export interface ChallengeRow {
    id: string;
    challenge_digest: string;
    purpose: string;
    session_digest: string;
    identity_hash: string;
    account_id: string | null;
    verification_id: string | null;
    request_digest: string;
    auth_expires: number;
}
export interface KeyRow {
    id: string;
    account_id: string;
    public_key: string;
    counter: number;
}
export interface VerificationRow {
    id: string;
    email_lookup: string;
    encrypted_email: string;
}
/** Only this factory owns raw D1; browser services cannot supply arbitrary SQL. */
export function browserRepository(db: D1Database) {
    return {
        async cleanup() {
            // One atomic bounded sweep. Expired auth artifacts retain 24 hours;
            // rejected audit events retain 30 days; all other events are permanent.
            // Remove acceptance children before their expired challenge parents.
            const expiredChallenges = 'SELECT id FROM webauthn_challenges WHERE expires_at<unixepoch()-86400 ORDER BY expires_at,id LIMIT 32';
            await db.batch([
                db.prepare(`DELETE FROM auth_acceptances WHERE challenge_id IN(${expiredChallenges})`),
                db.prepare(`DELETE FROM webauthn_challenges WHERE id IN(${expiredChallenges})`),
                db.prepare(`DELETE FROM account_verifications WHERE id IN(SELECT v.id FROM account_verifications v WHERE v.expires_at<unixepoch()-86400 AND NOT EXISTS(SELECT 1 FROM webauthn_challenges c WHERE c.verification_id=v.id) ORDER BY v.expires_at,v.id LIMIT 32)`),
                db.prepare(`DELETE FROM browser_sessions WHERE digest IN(SELECT digest FROM browser_sessions WHERE absolute_expires<unixepoch()-86400 OR last_seen<unixepoch()-88200 ORDER BY absolute_expires,digest LIMIT 32)`),
                db.prepare(`DELETE FROM consumed_bootstraps WHERE digest IN(SELECT digest FROM consumed_bootstraps WHERE expires_at<unixepoch()-86400 ORDER BY expires_at,digest LIMIT 32)`),
                db.prepare(`DELETE FROM auth_audit WHERE id IN(SELECT id FROM auth_audit WHERE event='rejected' AND created_at<unixepoch()-2592000 ORDER BY created_at,id LIMIT 32)`),
            ]);
        },
        async rate(kind: 'source' | 'identity', hash: string, limit: number) {
            // Independent durable counters. Saturation bounds numeric growth; denied
            // requests do not roll back other dimensions or create per-request rows.
            const row = await db.prepare(`INSERT INTO auth_rate_windows VALUES(?,?,unixepoch()/60,1) ON CONFLICT(kind,digest,window) DO UPDATE SET hits=min(hits+1,1001) RETURNING hits`).bind(kind, hash).first<{
                hits: number;
            }>();
            await db.prepare('DELETE FROM auth_rate_windows WHERE rowid IN(SELECT rowid FROM auth_rate_windows WHERE window<unixepoch()/60-2 LIMIT 32)').run();
            return row!.hits <= limit;
        },
        async session(hash: string) {
            return db.prepare(`SELECT s.* FROM browser_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id WHERE s.digest=? AND s.revoked=0 AND s.last_seen>unixepoch()-1800 AND s.absolute_expires>unixepoch() AND m.active=1`).bind(hash).first<SessionRow>();
        },
        async bootstrapUsed(hash: string) { return !!await db.prepare('SELECT 1 FROM consumed_bootstraps WHERE digest=?').bind(hash).first(); },
        async invitation(hash: string, emailHash: string) { return !!await db.prepare('SELECT 1 FROM invitations WHERE digest=? AND email_lookup=? AND expires_at>unixepoch() AND consumed_at IS NULL').bind(hash, emailHash).first(); },
        async saveVerification(id: string, invite: string, session: string, emailHash: string, encrypted: string) {
            const inserted = await db.prepare(`INSERT INTO account_verifications SELECT ?,digest,?,?,?,unixepoch()+300,NULL FROM invitations WHERE digest=? AND email_lookup=? AND expires_at>unixepoch() AND consumed_at IS NULL RETURNING id`).bind(id, session, emailHash, encrypted, invite, emailHash).all<{ id: string }>();
            if (inserted.results.length !== 1)
                throw new Error('unauthorized');
        },
        async verification(id: string, session: string) {
            return db.prepare(`SELECT v.* FROM account_verifications v JOIN invitations i ON i.digest=v.invitation_digest WHERE v.id=? AND v.session_digest=? AND v.expires_at>unixepoch() AND v.consumed_at IS NULL AND i.expires_at>unixepoch() AND i.consumed_at IS NULL`).bind(id, session).first<VerificationRow>();
        },
        async identity(account: string) {
            return db.prepare('SELECT lookup_hash FROM account_emails WHERE account_id=? AND verified=1').bind(account).first<{
                lookup_hash: string;
            }>();
        },
        async challenge(row: ChallengeRow) {
            await db.prepare('INSERT INTO webauthn_challenges(id,challenge_digest,purpose,session_digest,identity_hash,account_id,verification_id,request_digest,auth_expires,expires_at) VALUES(?,?,?,?,?,?,?,?,?,unixepoch()+300)').bind(row.id, row.challenge_digest, row.purpose, row.session_digest, row.identity_hash, row.account_id, row.verification_id, row.request_digest, row.auth_expires).run();
        },
        async attempt(id: string, session: string, purpose: string) {
            // Persist failed attempts too. RETURNING is an atomic attempt reservation.
            return db.prepare(`UPDATE webauthn_challenges SET attempts=attempts+1 WHERE id=? AND session_digest=? AND purpose=? AND consumed_at IS NULL AND expires_at>unixepoch() AND attempts<5 RETURNING *`).bind(id, session, purpose).first<ChallengeRow>();
        },
        async key(id: string, identity: string) {
            return db.prepare('SELECT p.* FROM passkeys p JOIN account_emails e ON e.account_id=p.account_id WHERE p.id=? AND e.lookup_hash=? AND p.active=1 AND e.verified=1').bind(id, identity).first<KeyRow>();
        },
        async membership(account: string) {
            return db.prepare('SELECT tenant_id FROM memberships WHERE account_id=? AND active=1 ORDER BY tenant_id LIMIT 1').bind(account).first<{
                tenant_id: string;
            }>();
        },
        async accept(input: {
            challenge: ChallengeRow;
            account: string;
            tenant: string;
            key: KeyRow;
            sessionDigest: string;
            csrfDigest: string;
            absoluteExpiry: number;
            actionDigest: string | null;
            verification?: VerificationRow;
        }) {
            const { challenge: c, account, tenant, key, verification: v } = input;
            const statements = [db.prepare('INSERT INTO accept_browser_auth VALUES(?,?,?,?,?,?)').bind(c.id, c.session_digest, c.purpose, c.request_digest, key.id, account)];
            if (c.purpose === 'registration') {
                if (!v)
                    throw new Error('unauthorized');
                statements.push(db.prepare('INSERT INTO accounts(id) VALUES(?)').bind(account), db.prepare('INSERT INTO tenants(id) VALUES(?)').bind(tenant), db.prepare('INSERT INTO memberships VALUES(?,?,1)').bind(tenant, account), db.prepare('INSERT INTO vaults(tenant_id,id) VALUES(?,?)').bind(tenant, crypto.randomUUID()), db.prepare('INSERT INTO account_emails VALUES(?,?,?,1)').bind(account, v.encrypted_email, v.email_lookup), db.prepare('INSERT INTO passkeys(id,account_id,public_key,counter) VALUES(?,?,?,?)').bind(key.id, account, key.public_key, key.counter));
            }
            else {
                statements.push(db.prepare(`INSERT INTO auth_audit(event,account_id,tenant_id) SELECT 'counter_risk',?,? FROM passkeys WHERE id=? AND (counter>0 OR ?>0) AND ?>=0 AND ?<=counter`).bind(account,tenant,key.id, key.counter, key.counter, key.counter), db.prepare('UPDATE passkeys SET counter=max(counter,?) WHERE id=?').bind(key.counter, key.id));
            }
            statements.push(db.prepare('UPDATE browser_sessions SET revoked=1 WHERE digest=?').bind(c.session_digest), db.prepare('INSERT INTO browser_sessions(digest,csrf_digest,account_id,tenant_id,absolute_expires,step_up_digest,step_up_expires) VALUES(?,?,?,?,?,?,?)').bind(input.sessionDigest, input.csrfDigest, account, tenant, input.absoluteExpiry, input.actionDigest, input.actionDigest ? Math.floor(Date.now() / 1000) + 300 : null), db.prepare('INSERT INTO auth_audit(event,account_id,tenant_id) VALUES(?,?,?)').bind(c.purpose === 'registration' ? 'registered' : c.purpose === 'authentication' ? 'authenticated' : 'step_up',account,tenant));
            await db.batch(statements);
        },
        async rejected() { await db.prepare("INSERT INTO auth_audit(event) VALUES('rejected')").run(); },
        async logout(hash: string) {
            await db.batch([db.prepare('UPDATE browser_sessions SET revoked=1 WHERE digest=?').bind(hash), db.prepare("INSERT INTO auth_audit(event,account_id,tenant_id) SELECT 'logout',account_id,tenant_id FROM browser_sessions WHERE digest=?").bind(hash)]);
        },
        async touch(hash: string) {
            const result = await db.prepare(`UPDATE browser_sessions SET last_seen=unixepoch() WHERE digest=? AND revoked=0 AND last_seen>unixepoch()-1800 AND absolute_expires>unixepoch() RETURNING digest`).bind(hash).first();
            return !!result;
        },
    };
}
