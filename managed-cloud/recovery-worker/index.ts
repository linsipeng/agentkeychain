import {parseRecoveryRevocation} from '../shared/revocation-witness.ts';
import {trustActivationBinding,activationMessage,type TrustActivationMaterial,type TrustActivationBinding} from '../shared/trust-activation.ts';
import {rosterDigest,parseRoster} from '../shared/roster.ts';
import {rosterWitness,type WitnessRequest} from '../shared/roster-witness.ts';
import type {ReleaseTrustManifest} from '../../src/cloud/config.ts';
import {issueRecoveryTrust} from '../shared/recovery-trust.ts';
import type {Checkpoint,CheckpointSigner} from '../shared/checkpoints.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {signRecoveryRelease,type RecoveryReleaseSigner} from '../shared/recovery-release.ts';
import { rpcData } from '../shared/rpc-data.ts';
import { digest,verify } from '../shared/contracts.ts';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { manifest, packageContext, recoveryCase, releaseContext, type CancelAuthorization, type RecoveryAuthority, type RecoveryEvidence, type RecoveryKeys } from '../shared/recovery.ts';
import type { SealedShare } from '../shared/recovery-crypto.ts';
interface Env {
    CUSTODIAN: D1Database;
    ROSTER_WITNESS_SIGNER?:CheckpointSigner;
    RECOVERY_TRUST_SIGNER?:CheckpointSigner;
    RECOVERY_TRUST_POLICY?:{manifest():Promise<string>};
    RECOVERY_AUTH?: RecoveryAuthority;
    RECOVERY_KEYS?: RecoveryKeys;
    RECOVERY_RELEASE_SIGNER?: RecoveryReleaseSigner;
}
export class Custodian extends WorkerEntrypoint<Env> {
    override async fetch() { return new Response(null, { status: 404 }); }
    async describe() { return { component: 'custodian', protocol: 1, recoveryEnabled: !!this.env.RECOVERY_AUTH && !!this.env.RECOVERY_KEYS, bindings: Object.keys(this.env).sort() }; }
    async key() {
        if (!this.env.RECOVERY_KEYS)
            throw new Error('unavailable');
        return rpcData(this.env.RECOVERY_KEYS.key());
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
        const m = manifest(row.package), box = await rpcData(this.env.RECOVERY_KEYS.rewrap(m.custodianKeyId, m.custodianShare, packageContext(m, 'custodian'), c.wrappingKey, releaseContext(canonical, 'custodian')));
        if (!await this.env.RECOVERY_AUTH.authorize(canonical, evidence))
            throw new Error('unauthorized');
        const accepted = await this.env.CUSTODIAN.prepare("UPDATE recovery_sagas SET release=COALESCE(release,?),state='released' WHERE id=? AND canonical=? AND state IN('prepared','released') AND expires_at>unixepoch() AND package_id IN(SELECT id FROM recovery_packages p WHERE p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages WHERE tenant_id=p.tenant_id AND vault_id=p.vault_id)) RETURNING release").bind(JSON.stringify(box), c.id, canonical).first<{
            release: string;
        }>();
        if (!accepted)
            throw new Error('not_found');
        return JSON.parse(accepted.release) as SealedShare;
    }
    async authenticatedRelease(canonical:string,evidence:RecoveryEvidence){
        if(!this.env.RECOVERY_RELEASE_SIGNER)throw new Error('unavailable');
        const box=await this.release(canonical,evidence),c=recoveryCase(canonical);
        const packageCanonical=await this.env.CUSTODIAN.prepare('SELECT canonical FROM recovery_packages WHERE id=?').bind(c.packageId).first<string>('canonical');
        if(!packageCanonical)throw new Error('not_found');
        return signRecoveryRelease('custodian',canonical,packageCanonical,evidence,box,this.env.RECOVERY_RELEASE_SIGNER);
    }
    private async witnessStore(){
        if(!this.env.ROSTER_WITNESS_SIGNER||!this.env.RECOVERY_TRUST_POLICY||!this.env.RECOVERY_AUTH?.rosterGenesis)throw new Error('witness_unavailable');
        const policy=JSON.parse(await this.env.RECOVERY_TRUST_POLICY.manifest()) as ReleaseTrustManifest,key=await this.env.ROSTER_WITNESS_SIGNER.key();
        if(!policy.witnessKeys?.some(p=>p.keyId===key.keyId&&p.publicKey===key.publicKey)||policy.checkpointKeys.some(p=>p.publicKey===key.publicKey)||policy.recoveryAuthorities?.some(p=>p.publicKey===key.publicKey))throw new Error('invalid_witness_authority');
        return rosterWitness(this.env.CUSTODIAN,this.env.ROSTER_WITNESS_SIGNER,policy.checkpointKeys,s=>this.env.RECOVERY_AUTH!.rosterGenesis!(s),policy.recoveryAuthorities??[]);
    }
    async witnessHead(tenant:string,vault:string){const h=await (await this.witnessStore()).head(tenant,vault);return h?JSON.parse(h.receipt) as SignedManagedOperation:null;}
    async witness(input:WitnessRequest){return (await this.witnessStore()).accept(input);}
    async witnessRevocation(canonical:string){
        const r=parseRecoveryRevocation(canonical),db=this.env.CUSTODIAN;
        const old=await db.prepare('SELECT canonical,receipt FROM recovery_revocation_witness WHERE tenant_id=? AND vault_id=? AND device_id=?').bind(r.tenantId,r.vaultId,r.deviceId).first<{canonical:string;receipt:string}>();
        if(old){if(old.canonical!==canonical)throw new Error('idempotency_conflict');return JSON.parse(old.receipt) as SignedManagedOperation;}
        if(!await this.env.RECOVERY_AUTH?.rosterRevocation?.(canonical))throw new Error('unauthorized');
        const h=await (await this.witnessStore()).head(r.tenantId,r.vaultId);
        const p=await db.prepare('SELECT canonical FROM recovery_packages WHERE id=? AND tenant_id=? AND vault_id=? AND account_id=?').bind(r.packageId,r.tenantId,r.vaultId,r.accountId).first<string>('canonical');
        if(!h||!p||h.checkpoint!==JSON.stringify(r.acceptedThrough))throw new Error('witness_not_latest');
        const roster=parseRoster(JSON.parse(h.roster)),a=JSON.parse(r.actionCanonical);
        if(roster.accountId!==r.accountId||!roster.active.some(d=>d.deviceId===r.deviceId&&d.signingKey===a[3]&&d.wrappingKey===a[4]))throw new Error('invalid_revocation');
        const receipt={canonical,signature:await this.env.ROSTER_WITNESS_SIGNER!.sign('AgentKeychain-recovery-revocation-v1\0'+canonical)};
        await db.prepare('INSERT INTO recovery_revocation_witness VALUES(?,?,?,?,?,?,?)').bind(r.tenantId,r.vaultId,r.deviceId,r.packageId,JSON.stringify(r.acceptedThrough),canonical,JSON.stringify(receipt)).run();return receipt;
    }
    async committedVersion(canonical:string){const c=recoveryCase(canonical);return this.env.CUSTODIAN.prepare('SELECT version FROM recovery_trust_commits WHERE case_id=?').bind(c.id).first<number>('version');}
    async commitTrust(canonical:string,version:number,hash:string,signature:string){
        const c=recoveryCase(canonical),db=this.env.CUSTODIAN;
        const raw=await db.prepare('SELECT result FROM recovery_trust_versions WHERE case_id=? AND version=?').bind(c.id,version).first<string>('result');
        if(!raw)throw new Error('not_found');const result=JSON.parse(raw) as TrustActivationMaterial & {binding:TrustActivationBinding;witnessEvent:number};
        const binding=await trustActivationBinding(canonical,version,result);
        if(JSON.stringify(binding)!==JSON.stringify(result.binding)||binding.rosterDigest!==hash||!await verify(c.signingKey,signature,activationMessage(binding)))throw new Error('unauthorized');
        const old=await db.prepare('SELECT version,digest FROM recovery_trust_commits WHERE case_id=?').bind(c.id).first<{version:number;digest:string}>();
        if(old){if(old.version!==version||old.digest!==hash)throw new Error('activation_committed');return {committed:true};}
        if(await rosterDigest(result.roster)!==hash)throw new Error('idempotency_conflict');
        const r=parseRoster(result.roster),head=await (await this.witnessStore()).head(c.tenantId,c.vaultId);
        if(!head||head.event!==result.witnessEvent||head.revision!==r.revision||head.digest!==hash)throw new Error('witness_not_latest');
        await db.prepare("INSERT OR IGNORE INTO recovery_trust_commits SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM roster_witness WHERE tenant_id=? AND vault_id=? AND event=(SELECT max(event) FROM roster_witness WHERE tenant_id=? AND vault_id=?) AND event=?) AND NOT EXISTS(SELECT 1 FROM recovery_revocation_witness rw,json_each(?,'$.active') a WHERE rw.tenant_id=? AND rw.vault_id=? AND rw.device_id=json_extract(a.value,'$.deviceId'))").bind(c.id,version,hash,signature,c.tenantId,c.vaultId,c.tenantId,c.vaultId,head.event,result.roster.canonical,c.tenantId,c.vaultId).run();
        const committed=await db.prepare('SELECT version,digest FROM recovery_trust_commits WHERE case_id=?').bind(c.id).first<{version:number;digest:string}>();
        if(committed?.version!==version||committed.digest!==hash)throw new Error('witness_not_latest');return {committed:true};
    }
    async trustBundle(canonical:string,rosters:SignedManagedOperation[],checkpoint:Checkpoint,revocations:{deviceId:string;acceptedThrough:Checkpoint}[]=[],receiptVersion=1){
        const c=recoveryCase(canonical),db=this.env.CUSTODIAN;
        if(!Number.isSafeInteger(receiptVersion)||receiptVersion<1)throw new Error('idempotency_conflict');
        if(!this.env.RECOVERY_TRUST_SIGNER||!this.env.RECOVERY_TRUST_POLICY)throw new Error('unavailable');
        // A receipt is immutable. After a response loss the original chain wins.
        const requestDigest=await digest(JSON.stringify([canonical,rosters,checkpoint,revocations]));
        const old=await db.prepare('SELECT request_digest,result FROM recovery_trust_versions WHERE case_id=? AND version=?').bind(c.id,receiptVersion).first<{request_digest:string;result:string}>();
        if(old&&old.request_digest!==requestDigest)throw new Error('idempotency_conflict');
        const p=await db.prepare("SELECT p.canonical FROM recovery_sagas s JOIN recovery_packages p ON p.id=s.package_id WHERE s.id=? AND s.canonical=? AND s.state='completed' AND p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages WHERE tenant_id=? AND vault_id=?)").bind(c.id,canonical,c.tenantId,c.vaultId).first<string>('canonical');
        if(!p)throw new Error('not_found');
        const witness=await this.witnessStore();
        if(old){const result=JSON.parse(old.result) as {sealed:SealedShare;refreshDigest:string;roster:SignedManagedOperation};if(await this.committedVersion(canonical)===receiptVersion)return result;if(await db.prepare("SELECT 1 FROM recovery_revocation_witness rw,json_each(?,'$.active') a WHERE rw.tenant_id=? AND rw.vault_id=? AND rw.device_id=json_extract(a.value,'$.deviceId') LIMIT 1").bind(result.roster.canonical,c.tenantId,c.vaultId).first())throw new Error('witness_not_latest');await witness.requireLatest([result.roster],checkpoint);return result;}
        await db.prepare('INSERT OR IGNORE INTO recovery_trust_intents VALUES(?,?,?)').bind(c.id,receiptVersion,requestDigest).run();
        if(await db.prepare('SELECT request_digest FROM recovery_trust_intents WHERE case_id=? AND version=?').bind(c.id,receiptVersion).first<string>('request_digest')!==requestDigest)throw new Error('idempotency_conflict');
        let issuanceRosters=rosters;
        try{await witness.requireLatest(rosters,checkpoint);}catch(error){
            // Resume a witness-committed / trust-receipt-pending saga after response loss.
            const h=await witness.head(c.tenantId,c.vaultId),last=rosters.at(-1);
            if(!h||!last||h.checkpoint!==JSON.stringify(checkpoint))throw error;
            const successor=JSON.parse(h.roster) as SignedManagedOperation,r=parseRoster(successor);
            if(r.revision!==parseRoster(last).revision+1||r.previousDigest!==await rosterDigest(last)||!r.recovery||JSON.parse(r.recovery.canonical).caseId!==c.id)throw error;
            issuanceRosters=[...rosters,successor];
        }
        const latest=parseRoster(rosters.at(-1)!);
        const independentlyRevoked=await db.prepare('SELECT device_id,checkpoint FROM recovery_revocation_witness WHERE tenant_id=? AND vault_id=?').bind(c.tenantId,c.vaultId).all<{device_id:string;checkpoint:string}>();
        for(const row of independentlyRevoked.results)if(!revocations.some(d=>d.deviceId===row.device_id&&JSON.stringify(d.acceptedThrough)===row.checkpoint))throw new Error('witness_revocation_mismatch');
        for(const d of latest.revoked)if(!revocations.some(v=>v.deviceId===d.deviceId&&JSON.stringify(v.acceptedThrough)===JSON.stringify(d.acceptedThrough)))throw new Error('witness_revocation_mismatch');
        for(const d of revocations.filter(v=>!latest.revoked.some(r=>r.deviceId===v.deviceId))){
            const recorded=await db.prepare('SELECT checkpoint FROM recovery_revocation_witness WHERE tenant_id=? AND vault_id=? AND device_id=? AND package_id=?').bind(c.tenantId,c.vaultId,d.deviceId,c.packageId).first<string>('checkpoint');
            if(recorded!==JSON.stringify(d.acceptedThrough))throw new Error('witness_revocation_mismatch');
        }
        // Exact request freshness is checked again by the independent append CAS.
        const packageSignature=await db.prepare('SELECT signature FROM recovery_packages WHERE id=?').bind(c.packageId).first<string>('signature');
        if(!packageSignature)throw new Error('not_found');
        const issued=await issueRecoveryTrust({caseCanonical:canonical,manifestCanonical:p,packageSignature,rosters:issuanceRosters,checkpoint,revocations},await this.env.RECOVERY_TRUST_POLICY.manifest(),this.env.RECOVERY_TRUST_SIGNER,async rows=>{const h=await witness.head(c.tenantId,c.vaultId);if(!h)throw new Error('witness_missing');return witness.accept({prior:JSON.parse(h.receipt),rosters:rows.filter(row=>parseRoster(row).revision>=h.revision),checkpoints:[checkpoint]});},receiptVersion);
        const material={signedDigest:issued.signedDigest,checkpoint,witness:issued.bundle.witness!,sealed:issued.sealed,refreshDigest:issued.bundle.refreshDigest,roster:issued.bundle.rosters.at(-1)!,witnessEvent:JSON.parse(issued.bundle.witness!.canonical).event as number};
        const result={...material,binding:await trustActivationBinding(canonical,receiptVersion,material)};
        await db.prepare('INSERT OR IGNORE INTO recovery_trust_versions SELECT ?,?,?,? WHERE (SELECT max(event) FROM roster_witness WHERE tenant_id=? AND vault_id=?)=?').bind(c.id,receiptVersion,requestDigest,JSON.stringify(result),c.tenantId,c.vaultId,result.witnessEvent).run();
        if(receiptVersion===1)await db.prepare('INSERT OR IGNORE INTO recovery_trust_receipts VALUES(?,?,?)').bind(c.id,requestDigest,JSON.stringify(result)).run();
        const stored=await db.prepare('SELECT request_digest,result FROM recovery_trust_versions WHERE case_id=? AND version=?').bind(c.id,receiptVersion).first<{request_digest:string;result:string}>();
        if(stored?.request_digest!==requestDigest)throw new Error('idempotency_conflict');
        return JSON.parse(stored.result) as typeof result;
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
