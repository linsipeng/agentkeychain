import { digest } from '../shared/contracts.ts';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { manifest, packageContext, recoveryCase, releaseContext, type CancelAuthorization, type RecoveryAuthority, type RecoveryEvidence, type RecoveryKeys } from '../shared/recovery.ts';
import type { SealedShare } from '../shared/recovery-crypto.ts';
interface Env {
    CUSTODIAN: D1Database;
    RECOVERY_AUTH?: RecoveryAuthority;
    RECOVERY_KEYS?: RecoveryKeys;
}
export class Custodian extends WorkerEntrypoint<Env> {
    override async fetch() { return new Response(null, { status: 404 }); }
    async describe() { return { component: 'custodian', protocol: 1, recoveryEnabled: !!this.env.RECOVERY_AUTH && !!this.env.RECOVERY_KEYS, bindings: Object.keys(this.env).sort() }; }
    async key() {
        if (!this.env.RECOVERY_KEYS)
            throw new Error('unavailable');
        return this.env.RECOVERY_KEYS.key();
    }
    async enroll(canonical: string, signature: string) {
        const m = manifest(canonical);
        if (!this.env.RECOVERY_AUTH || !this.env.RECOVERY_KEYS || !await this.env.RECOVERY_AUTH.enrollment(canonical, signature))
            throw new Error('unauthorized');
        if ((await this.key()).keyId !== m.custodianKeyId)
            throw new Error('wrong_key');
        const old = await this.env.CUSTODIAN.prepare('SELECT canonical,signature FROM recovery_packages WHERE id=?').bind(m.packageId).first<{
            canonical: string;
            signature: string;
        }>();
        if (old) {
            if (old.canonical !== canonical || old.signature !== signature)
                throw new Error('idempotency_conflict');
            return { packageId: m.packageId };
        }
        await this.env.CUSTODIAN.prepare('INSERT INTO recovery_packages VALUES(?,?,?,?,?,?,?)').bind(m.packageId, canonical, signature, m.accountId, m.tenantId, m.vaultId, m.keyEpoch).run();
        return { packageId: m.packageId };
    }
    async prepare(canonical: string) {
        const c = recoveryCase(canonical), now = Math.floor(Date.now() / 1000);
        if (c.createdAt > now + 60 || c.expiresAt <= now)
            throw new Error('expired');
        const p = await this.env.CUSTODIAN.prepare('SELECT canonical FROM recovery_packages WHERE id=? AND account_id=? AND tenant_id=? AND vault_id=? AND key_epoch=? AND key_epoch=(SELECT max(key_epoch) FROM recovery_packages WHERE tenant_id=? AND vault_id=?)').bind(c.packageId, c.accountId, c.tenantId, c.vaultId, c.keyEpoch, c.tenantId, c.vaultId).first<{
            canonical: string;
        }>();
        if (!p)
            throw new Error('not_found');
        const old = await this.env.CUSTODIAN.prepare('SELECT canonical,state FROM recovery_sagas WHERE id=?').bind(c.id).first<{
            canonical: string;
            state: string;
        }>();
        if (old) {
            if (old.canonical !== canonical || old.state === 'cancelled')
                throw new Error('invalid_transition');
            return { id: c.id };
        }
        await this.env.CUSTODIAN.prepare("INSERT INTO recovery_sagas VALUES(?,?,?,'prepared',?,?,NULL)").bind(c.id, c.packageId, canonical, c.notBefore, c.expiresAt).run();
        return { id: c.id };
    }
    async release(canonical: string, evidence: RecoveryEvidence): Promise<SealedShare> {
        const c = recoveryCase(canonical);
        if (!this.env.RECOVERY_AUTH || !this.env.RECOVERY_KEYS || !await this.env.RECOVERY_AUTH.authorize(canonical, evidence))
            throw new Error('unauthorized');
        if (evidence.mode !== 'device' && evidence.mode !== 'cooldown')
            throw new Error('unauthorized');
        if (evidence.mode === 'cooldown' && c.notBefore > Math.floor(Date.now() / 1000))
            throw new Error('cooldown');
        const row = await this.env.CUSTODIAN.prepare("SELECT s.*,p.canonical AS package FROM recovery_sagas s JOIN recovery_packages p ON p.id=s.package_id WHERE s.id=? AND s.canonical=? AND s.state IN('prepared','released') AND s.expires_at>unixepoch() AND p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages WHERE tenant_id=? AND vault_id=?)").bind(c.id, canonical, c.tenantId, c.vaultId).first<{
            release: string | null;
            package: string;
        }>();
        if (!row)
            throw new Error('not_found');
        if (row.release)
            return JSON.parse(row.release) as SealedShare;
        const m = manifest(row.package), box = await this.env.RECOVERY_KEYS.rewrap(m.custodianKeyId, m.custodianShare, packageContext(m, 'custodian'), c.wrappingKey, releaseContext(canonical, 'custodian'));
        if (!await this.env.RECOVERY_AUTH.authorize(canonical, evidence))
            throw new Error('unauthorized');
        const accepted = await this.env.CUSTODIAN.prepare("UPDATE recovery_sagas SET release=COALESCE(release,?),state='released' WHERE id=? AND canonical=? AND state IN('prepared','released') AND expires_at>unixepoch() AND package_id IN(SELECT id FROM recovery_packages p WHERE p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages WHERE tenant_id=p.tenant_id AND vault_id=p.vault_id)) RETURNING release").bind(JSON.stringify(box), c.id, canonical).first<{
            release: string;
        }>();
        if (!accepted)
            throw new Error('not_found');
        return JSON.parse(accepted.release) as SealedShare;
    }
    async cancel(canonical: string, authorization?: CancelAuthorization) {
        const c = recoveryCase(canonical);
        if (!authorization || !this.env.RECOVERY_AUTH)
            throw new Error('unauthorized');
        const hash = await digest(JSON.stringify([canonical, authorization]));
        const used = await this.env.CUSTODIAN.prepare('SELECT case_id,digest FROM recovery_cancellations WHERE nonce=?').bind(authorization.nonce).first<{
            case_id: string;
            digest: string;
        }>();
        // Exact committed retry is a receipt, not another authorization use.
        if (used) {
            if (used.case_id !== c.id || used.digest !== hash)
                throw new Error('unauthorized');
            return;
        }
        if (!await this.env.RECOVERY_AUTH.cancel(canonical, authorization))
            throw new Error('unauthorized');
        await this.env.CUSTODIAN.batch([
            this.env.CUSTODIAN.prepare('INSERT INTO recovery_cancellations VALUES(?,?,?,?)').bind(authorization.nonce, c.id, canonical, hash),
            this.env.CUSTODIAN.prepare("INSERT INTO recovery_sagas SELECT ?,?,?,'cancelled',?,?,NULL WHERE NOT EXISTS(SELECT 1 FROM recovery_sagas WHERE id=?)").bind(c.id, c.packageId, canonical, c.notBefore, c.expiresAt, c.id),
            this.env.CUSTODIAN.prepare("UPDATE recovery_sagas SET state='cancelled',release=NULL WHERE id=? AND canonical=? AND state IN('prepared','released')").bind(c.id, canonical)
        ]);
    }
    async complete(canonical: string, proof: string, signature: string) {
        const c = recoveryCase(canonical);
        if (!this.env.RECOVERY_AUTH || !await this.env.RECOVERY_AUTH.complete(canonical, proof, signature))
            throw new Error('unauthorized');
        const row = await this.env.CUSTODIAN.prepare('SELECT state FROM recovery_sagas WHERE id=? AND canonical=?').bind(c.id, canonical).first<{
            state: string;
        }>();
        if (row?.state === 'completed')
            return;
        if (row?.state !== 'released')
            throw new Error('invalid_transition');
        // Release and Main activation established eligibility; expiry cannot strand an intent.
        await this.env.CUSTODIAN.prepare("UPDATE recovery_sagas SET state='completed' WHERE id=? AND canonical=? AND state='released'").bind(c.id, canonical).run();
        if (await this.env.CUSTODIAN.prepare('SELECT state FROM recovery_sagas WHERE id=?').bind(c.id).first('state') !== 'completed')
            throw new Error('invalid_transition');
    }
}
export default { fetch() { return new Response(null, { status: 404 }); } };
