/** Unwired same-device Main observation. Never a Custody proof or a write authorization. */
import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisRoot,type CheckpointKey,type CheckpointSigner} from '../shared/checkpoints.ts';
import {ApiError,digest,verify} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {rosterDigest,verifyRoster} from '../shared/roster.ts';
import {verifyWitness} from '../shared/roster-witness.ts';
import type {DeviceContext} from './auth.ts';

const missing=()=>new ApiError('not_found');
function fields(input:unknown){
 exactFields(input,['nonce','requestId','grantDigest','rosterDigest']);
 const {nonce,requestId,grantDigest,rosterDigest}=input;
 if(typeof nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(nonce)||typeof requestId!=='string'||
    typeof grantDigest!=='string'||!/^[a-f0-9]{64}$/.test(grantDigest)||
    typeof rosterDigest!=='string'||!/^[a-f0-9]{64}$/.test(rosterDigest))throw missing();
 identifier(requestId);
 return {nonce,requestId,grantDigest,rosterDigest};
}
export function canonicalGenesisPackageAbsence(input:unknown){return JSON.stringify(fields(input));}

async function lookupGenesisPackageAbsence(db:D1Database,scope:DeviceContext,input:unknown,witnessPins:readonly CheckpointKey[]){
 try{
  const request=fields(input),fresh=()=>Math.abs(Math.floor(Date.now()/1000)-scope.timestamp)<=30;
  if(!fresh()||await digest(JSON.stringify(request))!==scope.bodyDigest)throw missing();
  const lookup=()=>db.prepare(`SELECT g.canonical AS grant_canonical,d.public_key,k.wrapping_key,g.key_epoch,
      r.canonical AS roster_canonical,r.signature AS roster_signature,w.receipt
   FROM enrollment_grants g
   JOIN device_requests q ON q.id=g.id AND q.tenant_id=g.tenant_id AND q.vault_id=g.vault_id AND q.device_id=g.device_id
    AND q.key_epoch=g.key_epoch AND q.state IN ('approved','delivered')
   JOIN memberships m ON m.tenant_id=g.tenant_id AND m.account_id=q.account_id AND m.active=1
   JOIN devices d ON d.tenant_id=g.tenant_id AND d.id=g.device_id AND d.account_id=q.account_id AND d.public_key=q.signing_key AND d.active=1
   JOIN device_keys k ON k.tenant_id=g.tenant_id AND k.device_id=g.device_id AND k.wrapping_key=q.wrapping_key
   JOIN vault_devices v ON v.tenant_id=g.tenant_id AND v.vault_id=g.vault_id AND v.device_id=g.device_id AND v.active=1
   JOIN device_sessions s ON s.tenant_id=g.tenant_id AND s.vault_id=g.vault_id AND s.device_id=g.device_id AND s.account_id=q.account_id
    AND s.active=1 AND s.expires_at>unixepoch() AND s.digest=?
   JOIN signed_rosters r ON r.tenant_id=g.tenant_id AND r.vault_id=g.vault_id AND r.account_id=q.account_id AND r.issuer_device_id=g.device_id AND r.revision=1 AND r.digest=?
   JOIN roster_witness_sagas w ON w.tenant_id=r.tenant_id AND w.vault_id=r.vault_id AND w.revision=r.revision AND w.digest=r.digest AND w.state='acknowledged'
   WHERE g.id=? AND q.account_id=? AND g.tenant_id=? AND g.vault_id=? AND g.device_id=? AND d.public_key=? AND g.issuer_device_id IS NULL
    AND NOT EXISTS(SELECT 1 FROM signed_rosters n WHERE n.tenant_id=r.tenant_id AND n.vault_id=r.vault_id AND n.revision>1)
    AND NOT EXISTS(SELECT 1 FROM device_revocation_boundaries b WHERE b.tenant_id=g.tenant_id AND b.vault_id=g.vault_id AND b.device_id=g.device_id)
    AND NOT EXISTS(SELECT 1 FROM device_key_packages p WHERE p.tenant_id=g.tenant_id AND p.vault_id=g.vault_id AND p.target_device_id=g.device_id)
    AND NOT EXISTS(SELECT 1 FROM genesis_package_continuations c WHERE c.tenant_id=g.tenant_id AND c.vault_id=g.vault_id AND c.device_id=g.device_id)
   `).bind(scope.sessionDigest,request.rosterDigest,request.requestId,scope.accountId,scope.tenantId,scope.vaultId,scope.deviceId,scope.publicKey)
   .first<{grant_canonical:string;public_key:string;wrapping_key:string;key_epoch:number;roster_canonical:string;roster_signature:string;receipt:string|null}>();
  const row=await lookup();
  if(!row||!row.receipt||row.receipt.length>8192||row.grant_canonical.length>4096||row.roster_canonical.length>16384)throw missing();
  const grant=JSON.parse(row.grant_canonical) as EnrollmentGrant;
  const signedRoster={canonical:row.roster_canonical,signature:row.roster_signature};
  const roster=await verifyRoster(signedRoster,null,Math.floor(Date.now()/1000)),d=roster.active[0];
  if(canonicalGrant(grant)!==row.grant_canonical||await digest(row.grant_canonical)!==request.grantDigest||
     grant.issuerDeviceId!==null||grant.requestId!==request.requestId||grant.accountId!==scope.accountId||grant.tenantId!==scope.tenantId||
     grant.vaultId!==scope.vaultId||grant.deviceId!==scope.deviceId||grant.signingKey!==scope.publicKey||grant.wrappingKey!==row.wrapping_key||
     grant.keyEpoch!==row.key_epoch||roster.keyEpoch!==row.key_epoch||roster.accountId!==scope.accountId||roster.tenantId!==scope.tenantId||
     roster.vaultId!==scope.vaultId||roster.issuer.kind!=='device'||roster.issuer.id!==scope.deviceId||
     roster.active.length!==1||!d||d.deviceId!==scope.deviceId||d.signingKey!==scope.publicKey||d.wrappingKey!==row.wrapping_key||
     await rosterDigest(signedRoster)!==request.rosterDigest)throw missing();
  const value:unknown=JSON.parse(row.receipt);
  exactFields(value,['canonical','signature']);
  if(typeof value.canonical!=='string'||typeof value.signature!=='string')throw missing();
  base64(value.signature,64,64);
  const w=await verifyWitness({canonical:value.canonical,signature:value.signature},witnessPins,
   {accountId:scope.accountId,tenantId:scope.tenantId,vaultId:scope.vaultId,revision:1,digest:request.rosterDigest});
  if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(scope.tenantId,scope.vaultId)||!fresh()||
     JSON.stringify(await lookup())!==JSON.stringify(row))throw missing();
  return {observation:{version:1,source:'main-local-observation',...request,rosterRevision:1,keyEpoch:row.key_epoch,
   witnessDigest:await digest(JSON.stringify([value.canonical,value.signature])),packagePresent:false} as const,
   wrappingKey:row.wrapping_key,validThrough:Math.min(roster.expiresAt,scope.timestamp+30),checkpointKeys:roster.checkpointKeys,
   recoveryAuthorities:roster.recoveryAuthorities};
 }catch{throw missing();}
}

export async function observeGenesisPackageAbsence(db:D1Database,scope:DeviceContext,input:unknown,witnessPins:readonly CheckpointKey[]){
 return (await lookupGenesisPackageAbsence(db,scope,input,witnessPins)).observation;
}

export const MAIN_GENESIS_PACKAGE_ABSENCE_DOMAIN='AgentKeychain-enrollment-continuation-package-absence-v1';
interface AbsencePins {
 /** Explicitly resolved from reviewed release policy, not request data. */
 readonly mainAbsenceAuthority:CheckpointKey;
 readonly witnesses:readonly CheckpointKey[];
 /** All other role pins, including Auth, Main commit and Custody's absence-current signer. */
 readonly otherReleaseKeys:readonly CheckpointKey[];
}

/** Inert Main-only issuer. This proves a temporary observation, never activation
 * or independent freshness. Production ingress must use primary-consistent D1. */
export async function proveGenesisPackageAbsence(db:D1Database,scope:DeviceContext,input:unknown,
 pins:AbsencePins,localSigner:CheckpointSigner):Promise<SignedManagedOperation>{
 try{
  const now=()=>Math.floor(Date.now()/1000),before=await lookupGenesisPackageAbsence(db,scope,input,pins.witnesses),a=before.observation;
  const key=await localSigner.key(),authority=pins.mainAbsenceAuthority;
  identifier(key.keyId);base64(key.publicKey,32,32);
  if(key.keyId!==authority.keyId||key.publicKey!==authority.publicKey||key.keyId!==await digest(key.publicKey)||
     key.publicKey===scope.publicKey||key.publicKey===before.wrappingKey||
     [...pins.witnesses,...before.checkpointKeys,...before.recoveryAuthorities,...pins.otherReleaseKeys]
      .some(p=>p.keyId===key.keyId||p.publicKey===key.publicKey))throw missing();
  const issuedAt=now(),expiresAt=Math.min(issuedAt+30,before.validThrough);
  if(expiresAt<=issuedAt)throw missing();
  const canonical=JSON.stringify({version:1,domain:MAIN_GENESIS_PACKAGE_ABSENCE_DOMAIN,keyId:key.keyId,
   nonce:a.nonce,requestId:a.requestId,grantDigest:a.grantDigest,rosterDigest:a.rosterDigest,
   accountId:scope.accountId,tenantId:scope.tenantId,vaultId:scope.vaultId,deviceId:scope.deviceId,keyEpoch:a.keyEpoch,
   rosterRevision:1,witnessDigest:a.witnessDigest,status:'absent',issuedAt,expiresAt});
  const signature=await localSigner.sign(canonical);
  if(!await verify(key.publicKey,signature,canonical))throw missing();
  const after=await lookupGenesisPackageAbsence(db,scope,input,pins.witnesses);
  if(now()>=expiresAt||JSON.stringify(after)!==JSON.stringify(before))throw missing();
  return {canonical,signature};
 }catch{throw missing();}
}
