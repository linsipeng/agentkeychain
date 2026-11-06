import {acknowledgeLastDeviceRevocation} from './revocation-witness.ts';
import {trustActivationBinding,activationMessage,type TrustActivationMaterial,type TrustActivationBinding} from '../shared/trust-activation.ts';
import {acknowledgeRoster} from './roster-witness.ts';
import {checkpoint,genesisRoot,type CheckpointSigner,type Checkpoint} from '../shared/checkpoints.ts';
import {parseRoster,verifyRoster,rosterDigest} from '../shared/roster.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {signRecoveryRelease,type RecoveryReleaseSigner} from '../shared/recovery-release.ts';
import { rpcData } from '../shared/rpc-data.ts';
import { ApiError, digest, verify } from '../shared/contracts.ts';
import { manifest, packageContext, recoveryAction, recoveryCase, releaseContext, type CancelAuthorization, type RecoveryAuthority, type RecoveryCase, type RecoveryEvidence, type RecoveryKeys, type RecoveryRPC } from '../shared/recovery.ts';
import { encode64, seal, type SealedShare } from '../shared/recovery-crypto.ts';
import type { DeviceContext } from './auth.ts';
import type { SessionRow } from './browser-repository.ts';
import { base64, exactFields, identifier } from '../../src/cloud/protocol.ts';
export interface RecoveryBindings {
    CHECKPOINT_SIGNER?:CheckpointSigner;
    RECOVERY_ACCOUNT_ATTESTER?:{attest(canonical:string):Promise<string>};
    RECOVERY?: RecoveryRPC;
    RECOVERY_AUTH?: RecoveryAuthority;
    RECOVERY_KEYS?: RecoveryKeys;
    RECOVERY_RELEASE_SIGNER?: RecoveryReleaseSigner;
}
interface Row {
    id: string;
    canonical: string;
    state: string;
    request_digest: string;
    proof_digest: string;
    challenge: string;
    api_release: string | null;
    custodian_release: string | null;
    confirmer_id: string | null;
    expires_at: number;
    review_required: number;
    cancel_authorization: string | null;
}
export interface StartRequest {
    id: string;
    packageId: string;
    targetDeviceId: string;
    signingKey: string;
    wrappingKey: string;
    nonce: string;
}
export function recoveryRepository(db: D1Database, bindings: RecoveryBindings) {
    const remote = () => {
        if (!bindings.RECOVERY || !bindings.RECOVERY_AUTH || !bindings.RECOVERY_KEYS)
            throw new ApiError('internal_error');
        return { rpc: bindings.RECOVERY, auth: bindings.RECOVERY_AUTH, keys: bindings.RECOVERY_KEYS };
    };
    const nonce = (c: DeviceContext) => db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest, c.tenantId, c.vaultId, c.deviceId, c.accountId, c.nonce, c.timestamp);
    const get = async (s: SessionRow, id: string) => {
        const r = await db.prepare('SELECT * FROM recovery_sagas WHERE id=? AND tenant_id=? AND account_id=?').bind(id, s.tenant_id, s.account_id).first<Row>();
        if (!r)
            throw new ApiError('not_found');
        return r;
    };
    const browserAction = (s: SessionRow, hash: string) => db.prepare('INSERT INTO recovery_browser_actions VALUES(?,?,?,?,?)').bind(crypto.randomUUID(), s.digest, s.tenant_id, s.account_id, hash);
    async function live(r: Row) {
        const c = recoveryCase(r.canonical);
        const valid = await db.prepare("SELECT 1 FROM recovery_sagas s JOIN recovery_packages_v1 p ON p.id=s.package_id JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id WHERE s.id=? AND s.state NOT IN('cancelled','completed') AND s.expires_at>unixepoch() AND m.active=1 AND p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages_v1 WHERE tenant_id=s.tenant_id AND vault_id=s.vault_id)").bind(c.id).first();
        if (!valid)
            throw new ApiError('not_found');
        return c;
    }
    return {
        async keys() { const b = remote(); return { api: await rpcData(b.keys.key()), custodian: await rpcData(b.rpc.key()) }; },
        async enroll(c: DeviceContext, canonical: string, signature: string) {
            const m = manifest(canonical), b = remote();
            if (m.tenantId !== c.tenantId || m.accountId !== c.accountId || m.vaultId !== c.vaultId || m.issuerDeviceId !== c.deviceId)
                throw new ApiError('not_found');
            if (!await verify(c.publicKey, signature, canonical) || !await b.auth.enrollment(canonical, signature))
                throw new ApiError('invalid_signature');
            if ((await rpcData(b.keys.key())).keyId !== m.apiKeyId)
                throw new ApiError('invalid_request');
            const old = await db.prepare('SELECT canonical,signature FROM recovery_packages_v1 WHERE id=?').bind(m.packageId).first<{
                canonical: string;
                signature: string;
            }>();
            if (old && (old.canonical !== canonical || old.signature !== signature))
                throw new ApiError('idempotency_conflict');
            await db.batch([nonce(c), db.prepare('INSERT INTO recovery_packages_v1 SELECT ?,?,?,?,?,?,?,0 WHERE NOT EXISTS(SELECT 1 FROM recovery_packages_v1 WHERE id=?)').bind(m.packageId, c.tenantId, c.vaultId, c.accountId, m.keyEpoch, canonical, signature, m.packageId)]);
            await rpcData(b.rpc.enroll(canonical, signature));
            await db.batch([db.prepare('UPDATE recovery_packages_v1 SET ready=1 WHERE id=?').bind(m.packageId),db.prepare('INSERT INTO recovery_readiness VALUES(?,unixepoch()+2592000,0) ON CONFLICT(package_id) DO UPDATE SET valid_until=excluded.valid_until WHERE revoked=0').bind(m.packageId)]);
            return { packageId: m.packageId };
        },
        async start(s: SessionRow, input: StartRequest) {
            exactFields(input, ['id', 'packageId', 'targetDeviceId', 'signingKey', 'wrappingKey', 'nonce']);
            for (const f of ['id', 'packageId', 'targetDeviceId', 'nonce'] as const)
                identifier(input[f]);
            base64(input.signingKey, 32, 32);
            base64(input.wrappingKey, 32, 32);
            if (!/^[A-Za-z0-9_-]{43}$/.test(input.targetDeviceId) || input.signingKey === input.wrappingKey)
                throw new ApiError('invalid_request');
            const request = JSON.stringify(input), hash = await recoveryAction('start', request), b = remote();
            const old = await db.prepare('SELECT * FROM recovery_sagas WHERE id=? AND tenant_id=? AND account_id=?').bind(input.id, s.tenant_id, s.account_id).first<Row>();
            if (old) {
                if (old.request_digest !== hash || old.state === 'cancelled' || old.state === 'completed')
                    throw new ApiError('idempotency_conflict');
                await rpcData(b.rpc.prepare(old.canonical));
                return { canonical: old.canonical, challenge: JSON.parse(old.challenge) as SealedShare, state: old.state };
            }
            const p = await db.prepare('SELECT * FROM recovery_packages_v1 WHERE id=? AND tenant_id=? AND account_id=? AND ready=1 AND key_epoch=(SELECT max(key_epoch) FROM recovery_packages_v1 WHERE tenant_id=? AND vault_id=recovery_packages_v1.vault_id)').bind(input.packageId, s.tenant_id, s.account_id, s.tenant_id).first<{
                vault_id: string;
                key_epoch: number;
            }>();
            if (!p)
                throw new ApiError('not_found');
            const now = Math.floor(Date.now() / 1000), c: RecoveryCase = { version: 1, id: input.id, packageId: input.packageId, accountId: s.account_id, tenantId: s.tenant_id, vaultId: p.vault_id, keyEpoch: p.key_epoch, targetDeviceId: input.targetDeviceId, signingKey: input.signingKey, wrappingKey: input.wrappingKey, createdAt: now, notBefore: now + 86400, expiresAt: now + 172800, nonce: input.nonce };
            const canonical = JSON.stringify(c), proof = crypto.getRandomValues(new Uint8Array(32)), challenge = await seal(c.wrappingKey, proof, releaseContext(canonical, 'api') + 'proof');
            await db.batch([browserAction(s, hash), db.prepare("INSERT INTO recovery_sagas(id,tenant_id,vault_id,account_id,package_id,canonical,request_digest,session_digest,state,not_before,expires_at,proof_digest,challenge) VALUES(?,?,?,?,?,?,?,?,'prepared',?,?,?,?)").bind(c.id, c.tenantId, c.vaultId, c.accountId, c.packageId, canonical, hash, s.digest, c.notBefore, c.expiresAt, await digest(encode64(proof)), JSON.stringify(challenge)), db.prepare('UPDATE recovery_sessions SET cancel_digest=? WHERE digest=? AND case_id=? AND request_digest=?').bind(await recoveryAction('cancel', canonical),s.digest,c.id,hash)]);
            proof.fill(0);
            await rpcData(b.rpc.prepare(canonical));
            return { canonical, challenge, state: 'prepared' };
        },
        async detail(s: SessionRow, id: string,native=false) {
            const r=await get(s,id),c=recoveryCase(r.canonical);
            let state=r.expires_at<=Math.floor(Date.now()/1000)&&!['activating','completed','cancelled'].includes(r.state)?'expired':r.state;
            if(native&&!['activating','completed','cancelled','expired'].includes(state)){
                const eligible=await db.prepare('SELECT 1 FROM recovery_packages_v1 p JOIN memberships m ON m.tenant_id=p.tenant_id AND m.account_id=p.account_id WHERE p.id=? AND m.active=1 AND p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages_v1 WHERE tenant_id=? AND vault_id=?)').bind(c.packageId,c.tenantId,c.vaultId).first();
                if(!eligible)state='conflict';
            }
            return {id:r.id,canonical:r.canonical,state,challenge:JSON.parse(r.challenge) as SealedShare,reviewRequired:!!r.review_required,cancelDigest:await recoveryAction('cancel',r.canonical),reviewDigest:await recoveryAction('review',r.canonical)};
        },
        async review(s: SessionRow, id: string) {
            const r = await get(s, id);
            if (r.state !== 'completed')
                throw new ApiError('invalid_transition');
            await db.batch([browserAction(s, await recoveryAction('review', r.canonical)), db.prepare("UPDATE recovery_sagas SET review_required=0 WHERE id=? AND state='completed'").bind(id)]);
            return { reviewRequired: false };
        },
        async notifications(s: SessionRow, after: number) {
            if (!Number.isSafeInteger(after) || after < 0)
                throw new ApiError('invalid_request');
            return { notifications: (await db.prepare('SELECT id,case_id,device_id,event,created_at FROM recovery_notifications WHERE tenant_id=? AND account_id=? AND id>? ORDER BY id LIMIT 100').bind(s.tenant_id, s.account_id, after).all()).results };
        },
        async release(s: SessionRow, id: string, evidence: RecoveryEvidence) {
            exactFields(evidence, ['mode', 'confirmerId', 'signature', 'proof']);
            const r = await get(s, id), c = await live(r), b = remote();
            if (evidence.mode !== 'device' && evidence.mode !== 'cooldown')
                throw new ApiError('invalid_request');
            if (evidence.mode === 'cooldown' && (c.notBefore > Math.floor(Date.now() / 1000) || evidence.confirmerId !== null || evidence.signature !== null))
                throw new ApiError('approval_required');
            if (evidence.mode === 'device') {
                const d = await db.prepare('SELECT d.public_key FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id WHERE d.tenant_id=? AND d.account_id=? AND d.id=? AND d.active=1 AND v.vault_id=? AND v.active=1').bind(c.tenantId, c.accountId, evidence.confirmerId, c.vaultId).first<{
                    public_key: string;
                }>();
                if (!d || !evidence.signature || !await verify(d.public_key, evidence.signature, JSON.stringify(['AgentKeychain-recovery-confirm-v1', r.canonical])))
                    throw new ApiError('invalid_signature');
            }
            if (!await b.auth.authorize(r.canonical, evidence))
                throw new ApiError('approval_required');
            const confirmed = await db.prepare("UPDATE recovery_sagas SET state='confirmed' WHERE id=? AND state='prepared' AND expires_at>unixepoch() RETURNING id").bind(id).first();
            if (!confirmed && !['confirmed', 'released'].includes((await get(s, id)).state))
                throw new ApiError('not_found');
            await rpcData(b.rpc.prepare(r.canonical));
            const custody = await rpcData(b.rpc.release(r.canonical, evidence));
            const p = await db.prepare('SELECT canonical FROM recovery_packages_v1 WHERE id=?').bind(c.packageId).first<{
                canonical: string;
            }>();
            const m = manifest(p!.canonical), api = r.api_release ? JSON.parse(r.api_release) as SealedShare : await rpcData(b.keys.rewrap(m.apiKeyId, m.apiShare, packageContext(m, 'api'), c.wrappingKey, releaseContext(r.canonical, 'api')));
            const result = await db.prepare("UPDATE recovery_sagas SET state='released',api_release=COALESCE(api_release,?),custodian_release=COALESCE(custodian_release,?),confirmer_id=? WHERE id=? AND state IN('prepared','confirmed','released') AND expires_at>unixepoch() AND (? IS NULL OR EXISTS(SELECT 1 FROM devices WHERE tenant_id=? AND account_id=? AND id=? AND active=1)) AND EXISTS(SELECT 1 FROM memberships WHERE tenant_id=? AND account_id=? AND active=1) RETURNING api_release,custodian_release").bind(JSON.stringify(api), JSON.stringify(custody), evidence.confirmerId, c.id, evidence.confirmerId, c.tenantId, c.accountId, evidence.confirmerId, c.tenantId, c.accountId).first<{
                api_release: string;
                custodian_release: string;
            }>();
            if (!result)
                throw new ApiError('not_found');
            return { api: JSON.parse(result.api_release) as SealedShare, custodian: JSON.parse(result.custodian_release) as SealedShare, wrappedVDK: m.wrappedVDK };
        },
        async authenticatedRelease(s:SessionRow,id:string,evidence:RecoveryEvidence){
            const b=remote();
            if(!bindings.RECOVERY_RELEASE_SIGNER||!b.rpc.authenticatedRelease)throw new ApiError('internal_error');
            const released=await this.release(s,id,evidence),r=await get(s,id),c=await live(r);
            const manifestCanonical=await db.prepare('SELECT canonical FROM recovery_packages_v1 WHERE id=?').bind(c.packageId).first<string>('canonical');
            if(!manifestCanonical)throw new ApiError('not_found');
            const custodian=await rpcData(b.rpc.authenticatedRelease(r.canonical,evidence));
            // Recheck cancellation/epoch/expiry after the independent service round trip.
            await live(await get(s,id));
            const api=await signRecoveryRelease('api',r.canonical,manifestCanonical,evidence,released.api,bindings.RECOVERY_RELEASE_SIGNER);
            return {caseCanonical:r.canonical,manifestCanonical,api,custodian};
        },
        async accountVerified(s:SessionRow,id:string){
            if(!bindings.RECOVERY_ACCOUNT_ATTESTER)return;
            const r=await get(s,id);await live(r);
            const proof=await bindings.RECOVERY_ACCOUNT_ATTESTER.attest(r.canonical);
            base64(proof,64,64);
            const evidence:RecoveryEvidence={mode:'cooldown',confirmerId:null,signature:null,proof};
            await db.prepare('INSERT OR IGNORE INTO recovery_authorizations VALUES(?,?)').bind(id,JSON.stringify(evidence)).run();
        },
        async confirm(c:DeviceContext,id:string,signature:string){
            const s={account_id:c.accountId,tenant_id:c.tenantId} as SessionRow,r=await get(s,id),rc=await live(r);
            if(rc.vaultId!==c.vaultId||!await verify(c.publicKey,signature,JSON.stringify(['AgentKeychain-recovery-confirm-v1',r.canonical])))throw new ApiError('invalid_signature');
            const evidence:RecoveryEvidence={mode:'device',confirmerId:c.deviceId,signature,proof:null};
            if(!await remote().auth.authorize(r.canonical,evidence))throw new ApiError('approval_required');
            await db.batch([nonce(c),db.prepare('INSERT INTO recovery_authorizations VALUES(?,?) ON CONFLICT(case_id) DO UPDATE SET evidence=excluded.evidence').bind(id,JSON.stringify(evidence))]);return {confirmed:true};
        },
        async evidence(s:SessionRow,id:string){
            const r=await get(s,id);await live(r);
            const raw=await db.prepare('SELECT evidence FROM recovery_authorizations WHERE case_id=?').bind(id).first<string>('evidence');
            if(!raw)throw new ApiError('approval_required');
            const evidence=JSON.parse(raw) as RecoveryEvidence;
            if(!await remote().auth.authorize(r.canonical,evidence))throw new ApiError('approval_required');return {evidence};
        },
        async trustBundle(s:SessionRow,id:string){
            const r=await get(s,id),c=recoveryCase(r.canonical),b=remote();
            if(r.state!=='completed'||!b.rpc.trustBundle||!bindings.CHECKPOINT_SIGNER)throw new ApiError('approval_required');
            const current=await db.prepare('SELECT canonical,signature FROM signed_rosters WHERE tenant_id=? AND vault_id=? ORDER BY revision DESC LIMIT 1').bind(c.tenantId,c.vaultId).all<SignedManagedOperation>();
            const rows=current.results;
            if(!rows.length)throw new ApiError('not_found');
            const head=await db.prepare('SELECT canonical,signature FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? ORDER BY sequence DESC LIMIT 1').bind(c.tenantId,c.vaultId).first<Checkpoint>();
            const cp=head??await checkpoint(bindings.CHECKPOINT_SIGNER,c.tenantId,c.vaultId,0,await genesisRoot(c.tenantId,c.vaultId),null,null);
            const boundaries=await db.prepare('SELECT device_id,sequence FROM device_revocation_boundaries WHERE tenant_id=? AND vault_id=? ORDER BY device_id').bind(c.tenantId,c.vaultId).all<{device_id:string;sequence:number}>();
            const revocations=[];
            for(const row of boundaries.results){const acceptedThrough=row.sequence===0?await checkpoint(bindings.CHECKPOINT_SIGNER,c.tenantId,c.vaultId,0,await genesisRoot(c.tenantId,c.vaultId),null,null):await db.prepare('SELECT canonical,signature FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? AND sequence=?').bind(c.tenantId,c.vaultId,row.sequence).first<Checkpoint>();if(!acceptedThrough)throw new ApiError('not_found');revocations.push({deviceId:row.device_id,acceptedThrough});}
            for(const revoked of revocations)await acknowledgeLastDeviceRevocation(db,c.tenantId,revoked.deviceId,b.rpc,bindings.CHECKPOINT_SIGNER);
            type Request={rows:SignedManagedOperation[];cp:Checkpoint;revocations:{deviceId:string;acceptedThrough:Checkpoint}[]};
            type Result=TrustActivationMaterial & {binding:TrustActivationBinding;witness?:SignedManagedOperation;sealed:import('../shared/recovery-crypto.ts').SealedShare;refreshDigest:string;roster:SignedManagedOperation};
            let saga=await db.prepare('SELECT version,request,result FROM recovery_trust_requests q WHERE case_id=? AND NOT EXISTS(SELECT 1 FROM recovery_trust_superseded x WHERE x.case_id=q.case_id AND x.version=q.version) ORDER BY version DESC LIMIT 1').bind(id).first<{version:number;request:string;result:string|null}>();
            const committed=b.rpc.committedVersion?await b.rpc.committedVersion(r.canonical):null;
            if(committed)saga=await db.prepare('SELECT version,request,result FROM recovery_trust_requests WHERE case_id=? AND version=?').bind(id,committed).first<{version:number;request:string;result:string|null}>();
            if(saga?.result&&!committed){const request=JSON.parse(saga.request) as Request,result=JSON.parse(saga.result) as Result;
                if(await rosterDigest(rows.at(-1)!)!==await rosterDigest(result?.roster??request.rows.at(-1)!)||JSON.stringify(cp)!==JSON.stringify(request.cp)||JSON.stringify(revocations)!==JSON.stringify(request.revocations))saga=null;
            }
            if(!saga){
                if(!b.rpc.witness)throw new ApiError('internal_error');
                await acknowledgeRoster(db,c.tenantId,c.vaultId,{head:(t,v)=>b.rpc.witnessHead!(t,v),witness:i=>b.rpc.witness!(i)},bindings.CHECKPOINT_SIGNER);
                const version=(await db.prepare('SELECT max(version) v FROM recovery_trust_requests WHERE case_id=?').bind(id).first<number>('v')??0)+1;
                const request=JSON.stringify({rows,cp,revocations} satisfies Request);
                const statements=[db.prepare('INSERT OR IGNORE INTO recovery_trust_requests VALUES(?,?,?,NULL)').bind(id,version,request)];
                if(revocations.some(v=>!parseRoster(rows.at(-1)!).revoked.some(d=>d.deviceId===v.deviceId))||!parseRoster(rows.at(-1)!).active.some(d=>d.deviceId===c.targetDeviceId&&d.signingKey===c.signingKey&&d.wrappingKey===c.wrappingKey))statements.unshift(db.prepare('INSERT OR IGNORE INTO recovery_roster_reservations VALUES(?,?,?,?)').bind(c.tenantId,c.vaultId,parseRoster(rows.at(-1)!).revision+1,id));
                await db.batch(statements);
                saga=await db.prepare('SELECT version,request,result FROM recovery_trust_requests WHERE case_id=? AND version=?').bind(id,version).first<{version:number;request:string;result:string|null}>();
                if(saga?.request!==request)throw new ApiError('idempotency_conflict');
            }
            const request=JSON.parse(saga!.request) as Request;
            let result:Result;
            try{result=await rpcData(b.rpc.trustBundle(r.canonical,request.rows,request.cp,request.revocations,saga!.version));}
            catch(error){
                if(!saga!.result&&error instanceof Error&&/witness_not_latest|witness_stale_checkpoint/.test(error.message))await db.prepare('INSERT OR IGNORE INTO recovery_trust_superseded VALUES(?,?)').bind(id,saga!.version).run();
                throw error;
            }
            if(JSON.stringify(result.binding)!==JSON.stringify(await trustActivationBinding(r.canonical,saga!.version,result)))throw new ApiError('idempotency_conflict');
            const roster=parseRoster(result.roster);
            const same=request.rows.find(s=>s.canonical===result.roster.canonical&&s.signature===result.roster.signature);
            const prior=request.rows.find(s=>parseRoster(s).revision===roster.revision-1);
            if(!same){if(!prior)throw new ApiError('idempotency_conflict');await verifyRoster(result.roster,prior);}
            if(roster.accountId!==c.accountId||roster.tenantId!==c.tenantId||roster.vaultId!==c.vaultId||roster.keyEpoch!==c.keyEpoch||!roster.active.some(d=>d.deviceId===c.targetDeviceId&&d.signingKey===c.signingKey&&d.wrappingKey===c.wrappingKey))throw new ApiError('idempotency_conflict');
            if(!/^[a-f0-9]{64}$/.test(result.refreshDigest))throw new ApiError('invalid_request');
            const statements=[];
            if(!same)statements.push(db.prepare('INSERT INTO signed_rosters VALUES(?,?,?,?,?,?,?,?,?)').bind(c.tenantId,c.vaultId,c.accountId,roster.revision,await rosterDigest(result.roster),roster.previousDigest,null,result.roster.canonical,result.roster.signature));
            statements.push(db.prepare('INSERT OR IGNORE INTO recovery_refresh_versions VALUES(?,?,?,?)').bind(c.id,saga!.version,c.targetDeviceId,result.refreshDigest),db.prepare('UPDATE recovery_trust_requests SET result=? WHERE case_id=? AND version=? AND (result IS NULL OR result=?)').bind(JSON.stringify(result),id,saga!.version,JSON.stringify(result)));
            if(!result.witness)throw new ApiError('internal_error');
            const witnessed=JSON.parse(result.witness.canonical) as {revision:number;digest:string};
            if(witnessed.revision!==roster.revision||witnessed.digest!==await rosterDigest(result.roster))throw new ApiError('idempotency_conflict');
            statements.push(db.prepare("UPDATE roster_witness_sagas SET state='acknowledged',receipt=? WHERE tenant_id=? AND vault_id=? AND revision=? AND digest=?").bind(JSON.stringify(result.witness),c.tenantId,c.vaultId,roster.revision,witnessed.digest));
            await db.batch(statements);
            return {sealed:result.sealed,receiptVersion:saga!.version,binding:result.binding};
        },
        async commitTrust(s:SessionRow,id:string,version:number,hash:string,signature:string){
            const r=await get(s,id),b=remote();if(!b.rpc.commitTrust||r.state!=='completed')throw new ApiError('not_found');
            const raw=await db.prepare('SELECT result FROM recovery_trust_requests WHERE case_id=? AND version=?').bind(id,version).first<string>('result');
            if(!raw)throw new ApiError('not_found');
            const selected=JSON.parse(raw) as TrustActivationMaterial & {binding:TrustActivationBinding};
            const binding=await trustActivationBinding(r.canonical,version,selected);
            if(JSON.stringify(binding)!==JSON.stringify(selected.binding)||binding.rosterDigest!==hash||!await verify(recoveryCase(r.canonical).signingKey,signature,activationMessage(binding)))throw new ApiError('idempotency_conflict');
            const result=await rpcData(b.rpc.commitTrust(r.canonical,version,hash,signature));
            await db.prepare('INSERT OR IGNORE INTO recovery_activation VALUES(?,?,?)').bind(id,version,hash).run();return result;
        },
        async readback(s:SessionRow,id:string){
            const r=await get(s,id),c=recoveryCase(r.canonical);
            const ready=await db.prepare("SELECT f.digest FROM recovery_refresh f JOIN devices d ON d.id=f.device_id JOIN device_keys k ON k.tenant_id=d.tenant_id AND k.device_id=d.id JOIN memberships m ON m.tenant_id=d.tenant_id AND m.account_id=d.account_id JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id WHERE f.case_id=? AND d.tenant_id=? AND d.account_id=? AND v.vault_id=? AND d.public_key=? AND k.wrapping_key=? AND d.active=1 AND m.active=1 AND v.active=1").bind(id,c.tenantId,c.accountId,c.vaultId,c.signingKey,c.wrappingKey).first<string>('digest');
            const activation=await db.prepare('SELECT digest FROM recovery_activation WHERE case_id=?').bind(id).first<string>('digest');
            const head=activation??await db.prepare('SELECT digest FROM signed_rosters WHERE tenant_id=? AND vault_id=? ORDER BY revision DESC LIMIT 1').bind(c.tenantId,c.vaultId).first<string>('digest');
            if(r.state!=='completed'||!ready||!head)throw new ApiError('not_found');return {completed:true,caseCanonical:r.canonical,refreshDigest:ready,rosterDigest:head};
        },
        async cancel(s: SessionRow, id: string, authorization?: CancelAuthorization, device?: DeviceContext) {
            const r = await get(s, id), b = remote();
            if (device && recoveryCase(r.canonical).vaultId !== device.vaultId)
                throw new ApiError('not_found');
            if (['activating', 'completed'].includes(r.state))
                return { cancelled: false, state: r.state };
            if (r.state !== 'cancelled') {
                if (!authorization || !await b.auth.cancel(r.canonical, authorization))
                    throw new ApiError('approval_required');
                try {
                    await db.batch([device ? nonce(device) : browserAction(s, await recoveryAction('cancel', r.canonical)), db.prepare("UPDATE recovery_sagas SET state='cancelled',cancel_authorization=?,api_release=NULL,custodian_release=NULL WHERE id=? AND state IN('prepared','confirmed','released','proven')").bind(JSON.stringify(authorization), id)]);
                }
                catch (error) {
                    // Finish may have revoked the session after this call read the case.
                    // The durable decision, not a stale authorization error, wins.
                    const latest = await get(s, id);
                    if (['activating', 'completed'].includes(latest.state))
                        return { cancelled: false, state: latest.state };
                    if (latest.state !== 'cancelled')
                        throw error;
                }
            }
            if (r.state === 'cancelled' && authorization) {
                if (!await b.auth.cancel(r.canonical, authorization))
                    throw new ApiError('approval_required');
                await db.prepare("UPDATE recovery_sagas SET cancel_authorization=? WHERE id=? AND state='cancelled'").bind(JSON.stringify(authorization), id).run();
            }
            const current = await get(s, id);
            if (current.state !== 'cancelled')
                return { cancelled: false, state: current.state };
            await rpcData(b.rpc.cancel(r.canonical, JSON.parse(current.cancel_authorization!) as CancelAuthorization));
            return { cancelled: true };
        },
        async finish(s: SessionRow, id: string, proof: string, signature: string) {
            base64(proof, 32, 32);
            base64(signature, 64, 64);
            const r = await get(s, id), c = recoveryCase(r.canonical), b = remote();
            if (await digest(proof) !== r.proof_digest || !await verify(c.signingKey, signature, JSON.stringify(['AgentKeychain-recovery-proof-v1', r.canonical, proof])))
                throw new ApiError('invalid_signature');
            if (r.state === 'completed')
                return { completed: true, reviewRequired: !!r.review_required };
            if (r.state !== 'activating') {
                await live(r);
                const accepted = await db.prepare("UPDATE recovery_sagas SET state='activating' WHERE id=? AND state IN('released','proven') AND api_release IS NOT NULL AND custodian_release IS NOT NULL AND expires_at>unixepoch() AND proof_digest=? RETURNING id").bind(id, await digest(proof)).first();
                if (!accepted)
                    throw new ApiError('invalid_transition');
            }
            await rpcData(b.rpc.complete(r.canonical, proof, signature));
            await db.prepare("UPDATE recovery_sagas SET state='completed' WHERE id=? AND state='activating'").bind(id).run();
            const end = await get(s, id);
            if (end.state !== 'completed')
                throw new ApiError('invalid_transition');
            return { completed: true, reviewRequired: true };
        }
    };
}
