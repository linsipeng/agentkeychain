import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {DeviceContext} from './auth.ts';
import {ApiError,digest,verify} from '../shared/contracts.ts';
import {canonicalGrant,canonicalPackage,type EnrollmentGrant,type KeyPackage} from '../shared/device-protocol.ts';
import {canonicalContinuationIntent,canonicalContinuationReceipt} from '../shared/enrollment-continuation.ts';
import {genesisRoot,type CheckpointKey,type CheckpointSigner} from '../shared/checkpoints.ts';
import {verifyWitness} from '../shared/roster-witness.ts';
import {CONTINUATION_HEAD_DOMAIN,MAIN_CONTINUATION_COMMIT_DOMAIN} from '../shared/continuation-fresh-head.ts';
export { MAIN_CONTINUATION_COMMIT_DOMAIN };

interface Expectation {
 readonly continuationId:string;
 readonly requestId:string;
 readonly intentDigest:string;
 readonly approvalDigest:string;
 readonly payloadDigest:string;
}
interface StoredCommit {
 old_grant:string;
 signed_intent:string;
 signed_approval:string;
 package_canonical:string;
 package_signature:string;
 witness:string;
 roster_digest:string;
 key_epoch:number;
}

const notFound=()=>new ApiError('not_found');
const envelope=(raw:string,max:number):SignedManagedOperation=>{
 if(raw.length>max)throw notFound();
 const v:unknown=JSON.parse(raw);
 exactFields(v,['canonical','signature']);
 if(typeof v.canonical!=='string'||!v.canonical)throw notFound();
 base64(v.signature,64,64);
 return {canonical:v.canonical,signature:v.signature};
};

export function canonicalGenesisCommitExpectation(input:unknown):string{
 exactFields(input,['continuationId','requestId','intentDigest','approvalDigest','payloadDigest']);
 const {continuationId,requestId,intentDigest,approvalDigest,payloadDigest}=input;
 if(typeof continuationId!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(continuationId)||
    ![intentDigest,approvalDigest,payloadDigest].every(d=>typeof d==='string'&&/^[a-f0-9]{64}$/.test(d)))throw notFound();
 identifier(requestId);
 return JSON.stringify({continuationId,requestId,intentDigest,approvalDigest,payloadDigest});
}

async function lookupGenesisPackageCommit(db:D1Database,scope:DeviceContext,input:Expectation){
  const row=await db.prepare(`SELECT c.old_grant,c.signed_intent,c.signed_approval,c.witness,c.roster_digest,c.key_epoch,
    p.canonical AS package_canonical,p.signature AS package_signature FROM genesis_package_continuations c
   JOIN enrollment_grants g ON g.id=c.request_id AND g.canonical=c.old_grant AND g.tenant_id=c.tenant_id
    AND g.vault_id=c.vault_id AND g.device_id=c.device_id AND g.key_epoch=c.key_epoch AND g.issuer_device_id IS NULL
   JOIN device_requests q ON q.id=g.id AND q.account_id=c.account_id AND q.tenant_id=c.tenant_id
    AND q.vault_id=c.vault_id AND q.device_id=c.device_id AND q.state IN('approved','delivered')
   JOIN memberships m ON m.tenant_id=c.tenant_id AND m.account_id=c.account_id AND m.active=1
   JOIN devices d ON d.tenant_id=c.tenant_id AND d.account_id=c.account_id AND d.id=c.device_id AND d.active=1 AND d.public_key=q.signing_key
   JOIN device_keys k ON k.tenant_id=d.tenant_id AND k.device_id=d.id AND k.wrapping_key=q.wrapping_key
   JOIN vault_devices v ON v.tenant_id=c.tenant_id AND v.vault_id=c.vault_id AND v.device_id=c.device_id AND v.active=1
   JOIN device_sessions s ON s.tenant_id=c.tenant_id AND s.vault_id=c.vault_id AND s.device_id=c.device_id
    AND s.account_id=c.account_id AND s.digest=? AND s.active=1 AND s.expires_at>unixepoch()
   JOIN device_key_packages p ON p.tenant_id=c.tenant_id AND p.vault_id=c.vault_id AND p.target_device_id=c.device_id
    AND p.issuer_device_id=c.device_id AND p.key_epoch=c.key_epoch AND p.grant_id=c.request_id
    AND p.canonical=c.package_canonical AND p.signature=c.package_signature
   JOIN signed_rosters original ON original.tenant_id=c.tenant_id AND original.vault_id=c.vault_id AND original.account_id=c.account_id
    AND original.revision=1 AND original.digest=c.roster_digest AND original.canonical=c.roster_canonical AND original.signature=c.roster_signature
   JOIN signed_rosters latest ON latest.tenant_id=c.tenant_id AND latest.vault_id=c.vault_id AND latest.account_id=c.account_id
    AND latest.revision=(SELECT max(r.revision) FROM signed_rosters r WHERE r.tenant_id=c.tenant_id AND r.vault_id=c.vault_id)
    AND json_extract(latest.canonical,'$.keyEpoch')=c.key_epoch
    AND EXISTS(SELECT 1 FROM json_each(latest.canonical,'$.active') a WHERE json_extract(a.value,'$.deviceId')=d.id
     AND json_extract(a.value,'$.signingKey')=d.public_key AND json_extract(a.value,'$.wrappingKey')=k.wrapping_key)
   WHERE c.id=? AND c.request_id=? AND c.account_id=? AND c.tenant_id=? AND c.vault_id=? AND c.device_id=? AND d.public_key=?
    AND NOT EXISTS(SELECT 1 FROM device_revocation_boundaries r WHERE r.tenant_id=c.tenant_id AND r.vault_id=c.vault_id AND r.device_id=c.device_id)
    AND NOT EXISTS(SELECT 1 FROM device_key_packages newer WHERE newer.tenant_id=c.tenant_id AND newer.vault_id=c.vault_id
      AND newer.target_device_id=c.device_id AND newer.key_epoch>c.key_epoch)`)
   .bind(scope.sessionDigest,input.continuationId,input.requestId,scope.accountId,scope.tenantId,scope.vaultId,scope.deviceId,scope.publicKey).first<StoredCommit>();
  if(!row||row.old_grant.length>4096||row.package_canonical.length>4096)throw notFound();
  const target=envelope(row.signed_intent,8192),approval=envelope(row.signed_approval,4096),witness=envelope(row.witness,8192);
  const g=JSON.parse(row.old_grant) as EnrollmentGrant,p=JSON.parse(row.package_canonical) as KeyPackage;
  const intent=JSON.parse(target.canonical),accepted=JSON.parse(approval.canonical);
  if(canonicalGrant(g)!==row.old_grant||canonicalPackage(p)!==row.package_canonical||
     canonicalContinuationIntent(intent)!==target.canonical||canonicalContinuationReceipt(accepted)!==approval.canonical)throw notFound();
  const intentDigest=await digest(target.canonical),approvalDigest=await digest(JSON.stringify([approval.canonical,approval.signature]));
  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',row.package_canonical,row.package_signature]));
  if(intentDigest!==input.intentDigest||approvalDigest!==input.approvalDigest||payloadDigest!==input.payloadDigest||
     accepted.intentDigest!==intentDigest||intent.id!==input.continuationId||intent.requestId!==input.requestId||
     intent.originalGrantDigest!==await digest(row.old_grant)||intent.rosterDigest!==row.roster_digest||
     intent.witnessHead?.revision!==1||intent.witnessHead.digest!==row.roster_digest||
     intent.payloadDigest!==payloadDigest||intent.stage!=='put-key-package'||intent.keyEpoch!==row.key_epoch||
     g.requestId!==input.requestId||g.issuerDeviceId!==null||g.keyEpoch!==row.key_epoch||
     g.accountId!==scope.accountId||g.tenantId!==scope.tenantId||g.vaultId!==scope.vaultId||g.deviceId!==scope.deviceId||g.signingKey!==scope.publicKey||
     p.vaultId!==scope.vaultId||p.issuerDeviceId!==scope.deviceId||p.targetDeviceId!==scope.deviceId||p.grantId!==input.requestId||p.keyEpoch!==row.key_epoch||
     !await verify(scope.publicKey,target.signature,target.canonical)||!await verify(scope.publicKey,row.package_signature,row.package_canonical))throw notFound();
  return {commit:{version:1,stage:'put-key-package',committed:true,source:'main-transaction',
   continuationId:input.continuationId,requestId:input.requestId,keyEpoch:row.key_epoch,
   intentDigest,approvalDigest,payloadDigest,witnessDigest:await signedDigest(witness)} as const,
   signedApproval:approval, approval:accepted as {approvedAt:number;expiresAt:number;authorityKeyId:string},
   rosterDigest:row.roster_digest,grant:g};
}

/** A read-only view owned by the Main transaction that wrote both immutable
 * records. This is a local projection, not a signed attestation. */
export async function readGenesisPackageCommit(db:D1Database,scope:DeviceContext,input:Expectation){
 try{
  if(await digest(canonicalGenesisCommitExpectation(input))!==scope.bodyDigest)throw notFound();
  return (await lookupGenesisPackageCommit(db,scope,input)).commit;
 }catch{throw notFound();}
}

const signedDigest=(value:SignedManagedOperation)=>digest(JSON.stringify([value.canonical,value.signature]));
const nowSeconds=()=>Math.floor(Date.now()/1000);
interface ProofExpectation {readonly commit:Expectation;readonly nonce:string;readonly custodyFreshHeadDigest:string}
interface ProofPins {
 readonly mainCommitAuthority:CheckpointKey;
 readonly approvalAuthority:CheckpointKey;
 readonly witnesses:readonly CheckpointKey[];
 /** Release role pins supplied by policy; no caller overrides. */
 readonly otherReleaseKeys:readonly CheckpointKey[];
}

export function canonicalGenesisCommitProofExpectation(input:unknown):string{
 exactFields(input,['commit','nonce','custodyFreshHeadDigest']);
 const {nonce,custodyFreshHeadDigest}=input;
 if(typeof nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(nonce)||
    typeof custodyFreshHeadDigest!=='string'||!/^[a-f0-9]{64}$/.test(custodyFreshHeadDigest))throw notFound();
 return JSON.stringify({commit:JSON.parse(canonicalGenesisCommitExpectation(input.commit)),nonce,custodyFreshHeadDigest});
}

/** Internal readback over already committed storage, not a generic signer or
 * public-facing route. Pins and signer must be sourced by Main's local trusted
 * configuration, while the Custody assertion is generated and signed there.
 * The returned Main claim does not represent independent durability. */
export async function proveGenesisPackageCommit(
 db:D1Database,scope:DeviceContext,input:ProofExpectation,
 custody:{readonly witness:SignedManagedOperation;readonly freshHead:SignedManagedOperation},
 pins:ProofPins, localCommitKey:CheckpointSigner,
):Promise<SignedManagedOperation>{
 try{
  const {commit:request,nonce,custodyFreshHeadDigest}=input;
  if(await digest(canonicalGenesisCommitProofExpectation(input))!==scope.bodyDigest)throw notFound();
  const record=await lookupGenesisPackageCommit(db,scope,request),actual=record.commit;
  const witness=envelope(JSON.stringify(custody.witness),8192),fresh=envelope(JSON.stringify(custody.freshHead),4096);
  if(fresh.canonical.length>2048||await signedDigest(fresh)!==custodyFreshHeadDigest||await signedDigest(witness)!==actual.witnessDigest)throw notFound();
  const w=await verifyWitness(witness,pins.witnesses,{accountId:scope.accountId,tenantId:scope.tenantId,vaultId:scope.vaultId,revision:1,digest:record.rosterDigest});
  const witnessPin=pins.witnesses.find(k=>k.keyId===w.keyId);
  if(!witnessPin||w.event!==1||w.sequence!==0||w.root!==await genesisRoot(scope.tenantId,scope.vaultId))throw notFound();

  const a=record.approval,key=await localCommitKey.key(),approvedAt=a.approvedAt,issuedAt=nowSeconds();
  const reserved=[...pins.witnesses,...pins.otherReleaseKeys,pins.approvalAuthority];
  if(key.keyId!==pins.mainCommitAuthority.keyId||key.publicKey!==pins.mainCommitAuthority.publicKey||
     key.publicKey===record.grant.signingKey||key.publicKey===record.grant.wrappingKey||
     reserved.some(p=>p.publicKey===key.publicKey||p.keyId===key.keyId)||
     witnessPin.publicKey===pins.approvalAuthority.publicKey||witnessPin.publicKey===record.grant.signingKey||witnessPin.publicKey===record.grant.wrappingKey||
     a.authorityKeyId!==pins.approvalAuthority.keyId||a.approvedAt<record.grant.expiresAt||a.expiresAt<=issuedAt||
     !await verify(pins.approvalAuthority.publicKey,record.signedApproval.signature,record.signedApproval.canonical))throw notFound();
  identifier(key.keyId);base64(key.publicKey,32,32);
  const f:unknown=JSON.parse(fresh.canonical);
  exactFields(f,['domain','keyId','nonce','requestId','witnessDigest','approvalDigest','payloadDigest','issuedAt','expiresAt']);
  if(typeof f.issuedAt!=='number'||typeof f.expiresAt!=='number'||!Number.isSafeInteger(f.issuedAt)||!Number.isSafeInteger(f.expiresAt)||
     f.issuedAt<approvedAt||f.issuedAt>issuedAt||f.expiresAt<=issuedAt||f.expiresAt>a.expiresAt||f.expiresAt-f.issuedAt>60||
     fresh.canonical!==JSON.stringify({domain:CONTINUATION_HEAD_DOMAIN,keyId:w.keyId,nonce,requestId:actual.requestId,witnessDigest:actual.witnessDigest,
      approvalDigest:actual.approvalDigest,payloadDigest:actual.payloadDigest,issuedAt:f.issuedAt,expiresAt:f.expiresAt})||
     !await verify(witnessPin.publicKey,fresh.signature,fresh.canonical))throw notFound();
  const expiresAt=Math.min(issuedAt+60,f.expiresAt,a.expiresAt);
  const canonical=JSON.stringify({version:1,domain:MAIN_CONTINUATION_COMMIT_DOMAIN,keyId:key.keyId,nonce,continuationId:actual.continuationId,
   requestId:actual.requestId,accountId:scope.accountId,tenantId:scope.tenantId,vaultId:scope.vaultId,deviceId:scope.deviceId,keyEpoch:actual.keyEpoch,
   stage:actual.stage,intentDigest:actual.intentDigest,approvalDigest:actual.approvalDigest,payloadDigest:actual.payloadDigest,witnessDigest:actual.witnessDigest,
   custodyFreshHeadDigest,issuedAt,expiresAt});
  const signature=await localCommitKey.sign(canonical);
  if(!await verify(key.publicKey,signature,canonical))throw notFound();
  const after=await lookupGenesisPackageCommit(db,scope,request);
  if(JSON.stringify(after.commit)!==JSON.stringify(actual)||nowSeconds()>=expiresAt)throw notFound();
  return {canonical,signature};
 }catch{throw notFound();}
}
