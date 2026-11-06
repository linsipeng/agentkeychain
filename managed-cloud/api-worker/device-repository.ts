import { ApiError, verify } from '../shared/contracts.ts';
import { actionDigest, canonicalGrant, canonicalPackage, type EnrollmentGrant, type KeyPackage } from '../shared/device-protocol.ts';
import type { SessionRow } from './browser-repository.ts';
import type { DeviceContext } from './auth.ts';
import { random } from './webauthn.ts';
interface Pairing {
    id: string;
    device_id: string;
    signing_key: string;
    wrapping_key: string;
    platform: string;
    phrase: string;
    expires_at: number;
    state: string;
    account_id: string;
    tenant_id: string;
    vault_id: string;
    key_epoch: number;
}
const fail = () => new ApiError('not_found');
export function deviceRepository(db: D1Database) {
    const nonce = (c: DeviceContext) => db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest, c.tenantId, c.vaultId, c.deviceId, c.accountId, c.nonce, c.timestamp);
    async function removal(tenant:string,id:string,active=true){
        const rows=(await db.prepare('SELECT vault_id,package_id FROM last_device_vaults WHERE tenant_id=? AND device_id=? ORDER BY vault_id').bind(tenant,id).all<{vault_id:string;package_id:string|null}>()).results;
        return {lastDevice:rows.length>0,recoveryReady:rows.length>0&&rows.every(r=>r.package_id!==null),canRemove:active&&rows.every(r=>r.package_id!==null)};
    }
    return {
        async rejected() { await db.prepare("INSERT INTO device_audit(event) VALUES('rejected')").run(); },
        async cleanup() {
            // A nonce survives its entire session lifetime. Bounded scans never
            // delete replay protection from a live (even revoked) session.
            await db.prepare("DELETE FROM device_requests WHERE id IN(SELECT id FROM device_requests WHERE state IN('pending','bound','denied') AND expires_at<unixepoch()-86400 LIMIT 32)").run();
            await db.batch([db.prepare('DELETE FROM device_session_issues WHERE challenge_id IN(SELECT id FROM device_challenges WHERE expires_at<unixepoch()-86400 LIMIT 32)'), db.prepare('DELETE FROM device_challenges WHERE id IN(SELECT id FROM device_challenges WHERE expires_at<unixepoch()-86400 LIMIT 32)')]);
            await db.prepare('DELETE FROM device_nonces WHERE rowid IN(SELECT n.rowid FROM device_nonces n JOIN device_sessions s ON s.digest=n.session_digest WHERE s.expires_at<unixepoch()-300 LIMIT 64)').run();
        },
        async request(input: {
            code: string;
            verification: string;
            phrase: string;
            signing: string;
            wrapping: string;
            platform: string;
        }) {
            const id = random(), device = random();
            await db.batch([db.prepare('INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at) VALUES(?,?,?,?,?,?,?,?,unixepoch()+600)').bind(id, input.code, input.verification, input.phrase, device, input.signing, input.wrapping, input.platform), db.prepare("INSERT INTO device_audit(event) VALUES('requested')")]);
            return { requestId: id, deviceId: device };
        },
        async poll(code: string) {
            const results = await db.batch([
                db.prepare("UPDATE device_requests SET poll_after=unixepoch()+5,state=CASE WHEN state='approved' THEN 'delivered' ELSE state END WHERE code_digest=? AND state<>'delivered' AND expires_at>unixepoch() AND poll_after<=unixepoch() RETURNING state,device_id,vault_id,id").bind(code),
                db.prepare("INSERT INTO device_audit(event,account_id,tenant_id,device_id) SELECT 'delivered',account_id,tenant_id,device_id FROM device_requests WHERE code_digest=? AND state='delivered' AND changes()=1").bind(code),
            ]);
            const row = results[0]!.results[0] as {
                state: string;
                device_id: string;
                vault_id: string;
                id: string;
            } | undefined;
            if (!row)
                throw new ApiError('unauthorized');
            return { state: row.state === 'bound' ? 'pending' : row.state === 'delivered' ? 'approved' : row.state, ...(row.state === 'delivered' ? { deviceId: row.device_id, vaultId: row.vault_id, requestId: row.id } : {}) };
        },
        async pending(s: SessionRow, verification: string, issuer: string | null) {
            // Registration creates one vault. Ambiguous membership never selects a
            // caller-supplied vault and fails closed until a dedicated selection flow.
            const rows = await db.batch([
                db.prepare(`UPDATE device_requests SET account_id=?,tenant_id=?,vault_id=(SELECT id FROM vaults WHERE tenant_id=?),state='bound' WHERE verification_digest=? AND state='pending' AND expires_at>unixepoch() AND (SELECT count(*) FROM vaults WHERE tenant_id=?)=1 AND EXISTS(SELECT 1 FROM browser_sessions s JOIN memberships m ON m.account_id=s.account_id AND m.tenant_id=s.tenant_id WHERE s.digest=? AND s.revoked=0 AND s.absolute_expires>unixepoch() AND s.last_seen>unixepoch()-1800 AND m.active=1) RETURNING id`).bind(s.account_id, s.tenant_id, s.tenant_id, verification, s.tenant_id, s.digest),
                db.prepare("INSERT INTO device_audit(event,account_id,tenant_id) SELECT 'bound',?,? WHERE changes()=1").bind(s.account_id, s.tenant_id),
                db.prepare("SELECT * FROM device_requests WHERE verification_digest=? AND account_id=? AND tenant_id=? AND state='bound' AND expires_at>unixepoch()").bind(verification, s.account_id, s.tenant_id),
            ]);
            const r = rows[2]!.results[0] as unknown as Pairing | undefined;
            if (!r)
                throw fail();
            const canonical = canonicalGrant({ version: 1, requestId: r.id, accountId: s.account_id, tenantId: s.tenant_id, vaultId: r.vault_id, deviceId: r.device_id, signingKey: r.signing_key, wrappingKey: r.wrapping_key, issuerDeviceId: issuer, keyEpoch: r.key_epoch, expiresAt: r.expires_at });
            return { requestId: r.id, deviceId: r.device_id, platform: r.platform, phrase: r.phrase, canonical, actionDigest: await actionDigest('approve', canonical), denyActionDigest: await actionDigest('deny', r.id) };
        },
        async approve(s: SessionRow, canonical: string, signature: string | null) {
            let g: EnrollmentGrant;
            try {
                g = JSON.parse(canonical) as EnrollmentGrant;
                if (canonicalGrant(g) !== canonical)
                    throw fail();
            }
            catch {
                throw new ApiError('invalid_request');
            }
            const r = await db.prepare("SELECT * FROM device_requests WHERE id=? AND account_id=? AND tenant_id=? AND state='bound' AND expires_at>unixepoch()").bind(g.requestId, s.account_id, s.tenant_id).first<Pairing>();
            if (!r || canonicalGrant({ version: 1, requestId: r.id, accountId: s.account_id, tenantId: s.tenant_id, vaultId: r.vault_id, deviceId: r.device_id, signingKey: r.signing_key, wrappingKey: r.wrapping_key, issuerDeviceId: g.issuerDeviceId, keyEpoch: r.key_epoch, expiresAt: r.expires_at }) !== canonical)
                throw fail();
            if (g.issuerDeviceId === null) {
                if (signature !== null)
                    throw new ApiError('invalid_request');
            }
            else {
                const key = await db.prepare('SELECT public_key FROM devices WHERE tenant_id=? AND account_id=? AND id=? AND active=1').bind(s.tenant_id, s.account_id, g.issuerDeviceId).first<string>('public_key');
                if (!key || !signature || !await verify(key, signature, canonical))
                    throw new ApiError('invalid_signature');
            }
            await db.prepare('INSERT INTO device_actions(id,session_digest,account_id,tenant_id,action,target,action_digest,canonical,signature,issuer_device_id) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(random(), s.digest, s.account_id, s.tenant_id, 'approve', r.id, await actionDigest('approve', canonical), canonical, signature, g.issuerDeviceId).run();
            return { approved: true, deviceId: r.device_id };
        },
        async deny(s: SessionRow, id: string) {
            await db.prepare("INSERT INTO device_actions(id,session_digest,account_id,tenant_id,action,target,action_digest,canonical) VALUES(?,?,?,?,'deny',?,?,?)").bind(random(), s.digest, s.account_id, s.tenant_id, id, await actionDigest('deny', id), id).run();
            return { denied: true };
        },
        async list(s: SessionRow) {
            const rows = await db.prepare('SELECT d.id,d.public_key,k.wrapping_key,d.active FROM devices d JOIN device_keys k ON k.tenant_id=d.tenant_id AND k.device_id=d.id WHERE d.tenant_id=? AND d.account_id=? ORDER BY d.id LIMIT 100').bind(s.tenant_id, s.account_id).all<{
                id: string;
                public_key: string;
                wrapping_key: string;
                active: number;
            }>();
            return { devices: await Promise.all(rows.results.map(async (r) => ({ id:r.id,active:r.active,...await removal(s.tenant_id,r.id,!!r.active), revocationComplete:r.active===0&&!(await db.prepare("SELECT 1 FROM device_revocation_boundaries b WHERE b.tenant_id=? AND b.device_id=? AND NOT EXISTS(SELECT 1 FROM signed_rosters r JOIN roster_witness_sagas w ON w.tenant_id=r.tenant_id AND w.vault_id=r.vault_id AND w.revision=r.revision WHERE r.tenant_id=b.tenant_id AND r.vault_id=b.vault_id AND w.state='acknowledged' AND r.revision=(SELECT max(revision) FROM signed_rosters WHERE tenant_id=b.tenant_id AND vault_id=b.vault_id) AND EXISTS(SELECT 1 FROM json_each(r.canonical,'$.revoked') j WHERE json_extract(j.value,'$.deviceId')=b.device_id)) LIMIT 1").bind(s.tenant_id,r.id).first()), revokeActionDigest: await actionDigest('revoke', JSON.stringify([s.tenant_id, s.account_id, r.id, r.public_key, r.wrapping_key,...((await removal(s.tenant_id,r.id)).lastDevice?['Access will require recovery']:[])])) }))) };
        },
        async revoke(s: SessionRow, id: string) {
            const row = await db.prepare('SELECT d.public_key,k.wrapping_key FROM devices d JOIN device_keys k ON k.tenant_id=d.tenant_id AND k.device_id=d.id WHERE d.tenant_id=? AND d.account_id=? AND d.id=? AND d.active=1').bind(s.tenant_id, s.account_id, id).first<{
                public_key: string;
                wrapping_key: string;
            }>();
            if (!row)
                throw fail();
            const canonical = JSON.stringify([s.tenant_id, s.account_id, id, row.public_key, row.wrapping_key,...((await removal(s.tenant_id,id)).lastDevice?['Access will require recovery']:[])]);
            await db.prepare("INSERT INTO device_actions(id,session_digest,account_id,tenant_id,action,target,action_digest,canonical) VALUES(?,?,?,?,'revoke',?,?,?)").bind(random(), s.digest, s.account_id, s.tenant_id, id, await actionDigest('revoke', canonical), canonical).run();
            return { revoked: false, enforced: true, witnessPending: true };
        },
        async challenge(deviceId: string, challengeDigest: string) {
            const id = random();
            const results = await db.batch([
                db.prepare(`INSERT INTO device_challenges(id,challenge_digest,request_id,expires_at) SELECT ?,?,r.id,unixepoch()+60 FROM device_requests r JOIN devices d ON d.tenant_id=r.tenant_id AND d.id=r.device_id WHERE r.device_id=? AND r.state IN('approved','delivered') AND d.active=1 RETURNING expires_at,request_id`).bind(id, challengeDigest, deviceId),
                db.prepare("INSERT INTO device_audit(event) SELECT 'challenge' WHERE changes()=1"),
                db.prepare("SELECT device_id,vault_id FROM device_requests WHERE device_id=? AND state IN('approved','delivered')").bind(deviceId),
            ]);
            const c = results[0]!.results[0] as {
                expires_at: number;
            } | undefined, r = results[2]!.results[0] as {
                device_id: string;
                vault_id: string;
            } | undefined;
            if (!c || !r)
                throw fail();
            return { challengeId: id, deviceId: r.device_id, vaultId: r.vault_id, expiresAt: c.expires_at };
        },
        async attempt(id: string) {
            const c = await db.prepare('UPDATE device_challenges SET attempts=attempts+1 WHERE id=? AND consumed=0 AND expires_at>unixepoch() AND attempts<5 RETURNING *').bind(id).first<{
                id: string;
                challenge_digest: string;
                request_id: string;
                expires_at: number;
            }>();
            if (!c)
                throw new ApiError('unauthorized');
            const r = await db.prepare('SELECT signing_key,device_id,vault_id FROM device_requests WHERE id=?').bind(c.request_id).first<{
                signing_key: string;
                device_id: string;
                vault_id: string;
            }>();
            if (!r)
                throw fail();
            return { ...c, ...r };
        },
        async issue(id: string, digest: string) { await db.prepare('INSERT INTO device_session_issues(challenge_id,digest) VALUES(?,?)').bind(id, digest).run(); },
        async putPackage(c: DeviceContext, canonical: string, signature: string) {
            const p = JSON.parse(canonical) as KeyPackage;
            if (canonicalPackage(p) !== canonical || p.vaultId !== c.vaultId || p.issuerDeviceId !== c.deviceId)
                throw fail();
            if (!await verify(c.publicKey, signature, canonical))
                throw new ApiError('invalid_signature');
            await db.batch([nonce(c), db.prepare('INSERT INTO device_key_packages VALUES(?,?,?,?,?,?,?,?)').bind(c.tenantId, c.vaultId, p.targetDeviceId, p.keyEpoch, c.deviceId, p.grantId, canonical, signature)]);
            return { accepted: true };
        },
        async ownPackage(c: DeviceContext) {
            const results = await db.batch([nonce(c), db.prepare('SELECT canonical,signature FROM device_key_packages WHERE tenant_id=? AND vault_id=? AND target_device_id=? ORDER BY key_epoch DESC LIMIT 1').bind(c.tenantId, c.vaultId, c.deviceId), db.prepare("INSERT INTO device_audit(event,account_id,tenant_id,device_id) VALUES('package_fetched',?,?,?)").bind(c.accountId, c.tenantId, c.deviceId)]);
            const row = results[1]!.results[0] as {
                canonical: string;
                signature: string;
            } | undefined;
            if (!row)
                throw fail();
            return row;
        },
    };
}
