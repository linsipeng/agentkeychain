import {randomBytes} from 'node:crypto';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {verifyContinuationApproval} from '../../managed-cloud/shared/enrollment-continuation.ts';
import {base64,exactFields} from './protocol.ts';
import {rosterDigest} from '../../managed-cloud/shared/roster.ts';
import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';
import sodium from 'libsodium-wrappers-sumo';
import type {SecureStore} from '../platform/secure-store.ts';
import {openKeyPackage,destroyCloudKeys,type CloudKeys} from './crypto.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import {openTrustedEnrollment} from './enrollment.ts';
import type {CloudEnrollment} from './runtime.ts';
import type {CloudStore} from './persistence.ts';
import {assertVerifiedPolicy,verifyContinuationAuthority,verifyContinuationCommitAuthority,type ManagedEndpointPolicy} from './config.ts';
import type {SignedManagedOperation} from './protocol.ts';
import {RosterStore,rosterPins} from './roster.ts';
import {parseRoster,verifyRoster} from '../../managed-cloud/shared/roster.ts';
import {genesisRoot} from '../../managed-cloud/shared/checkpoints.ts';
export interface EnrollmentEvidence {witness?:SignedManagedOperation;grant:EnrollmentGrant;keyPackage:SignedManagedOperation;sealed?:string;phrase?:string;acceptedAt:number}
interface Activation {enrollment:CloudEnrollment;signedRoster:SignedManagedOperation;evidence:EnrollmentEvidence}
interface Intent {version:1;keys:Record<keyof CloudKeys,string>;activation?:Activation;continuation?:ContinuationJournal}
const encode=(keys:CloudKeys)=>Object.fromEntries(Object.entries(keys).map(([k,v])=>[k,Buffer.from(v).toString('base64')])) as Intent['keys'];
async function load(secure:SecureStore):Promise<Intent|null>{
 const raw=await secure.get('enrollment-intent');if(!raw)return null;
 try{const value=JSON.parse(Buffer.from(raw).toString()) as Intent;if(value.version!==1||!value.keys)throw new Error();return value;}catch{throw new Error('cloud_enrollment_intent_conflict');}finally{raw.fill(0);}
}
async function save(secure:SecureStore,intent:Intent){const bytes=Buffer.from(JSON.stringify(intent));try{await secure.put('enrollment-intent',bytes);}finally{bytes.fill(0);}}
/** The protected intent is the durable authority before any individual key slot is written. */
export async function protectEnrollmentKeys(secure:SecureStore,keys:CloudKeys){
 const previous=await load(secure);if(previous&&JSON.stringify(previous.keys)!==JSON.stringify(encode(keys)))throw new Error('cloud_enrollment_intent_conflict');
 if(!previous)await save(secure,{version:1,keys:encode(keys)});
 await restoreEnrollmentKeys(secure);
}
export async function restoreEnrollmentKeys(secure:SecureStore):Promise<CloudKeys|null>{
 const intent=await load(secure);if(!intent)return null;
 await sodium.ready;
 const keys={} as CloudKeys;
 for(const name of ['csk','vdk','signingPublic','signingPrivate','wrappingPublic','wrappingPrivate'] as const){const text=intent.keys[name],bytes=Buffer.from(text??'','base64');if(bytes.toString('base64')!==text||bytes.length!==(name==='signingPrivate'?64:32))throw new Error('cloud_enrollment_intent_conflict');keys[name]=bytes;}
 if(!Buffer.from(sodium.crypto_sign_ed25519_sk_to_pk(keys.signingPrivate)).equals(Buffer.from(keys.signingPublic))||!Buffer.from(sodium.crypto_scalarmult_base(keys.wrappingPrivate)).equals(Buffer.from(keys.wrappingPublic)))throw new Error('cloud_enrollment_intent_conflict');
 const slots=[['signing-private','signingPrivate'],['wrapping-private','wrappingPrivate'],['csk','csk']] as const;
 // Validate all existing slots before repairing any missing one.
 for(const [slot,name] of slots){const value=await secure.get(slot);try{if(value&&!Buffer.from(value).equals(Buffer.from(keys[name])))throw new Error('cloud_enrollment_intent_conflict');}finally{value?.fill(0);}}
 for(const [slot,name] of slots){const value=await secure.get(slot);try{if(!value)await secure.put(slot,keys[name]);}finally{value?.fill(0);}}
 return keys;
}
type GenesisContinuationPreflight = {
  grant:EnrollmentGrant; target:SignedManagedOperation; approval:SignedManagedOperation; authorityAppendix:SignedManagedOperation;
  witness:SignedManagedOperation; freshHead:SignedManagedOperation;
  roster:SignedManagedOperation; keyPackage:SignedManagedOperation;
};
export const newContinuationReadbackNonce=()=>randomBytes(32).toString('base64url');
export const CONTINUATION_HEAD_DOMAIN='AgentKeychain-enrollment-continuation-current-head-v1';
/** Local read-only preflight. It proves independently authorized bytes for the
 * original protected intent, not that a package was committed or this device
 * may become active. There is intentionally no production issuer or caller. */
export async function verifyGenesisContinuationPreflight(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy,nonce:string,input:GenesisContinuationPreflight):Promise<void>{
 await validateGenesisContinuationPreflight(secure,store,policy,nonce,input,Math.floor(Date.now()/1000));
}
async function validateGenesisContinuationPreflight(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy,nonce:string,input:GenesisContinuationPreflight,now:number,reconcileCommitted=false){
 assertVerifiedPolicy(policy);
 const g=input.grant,pins=policy.witnessKeys;
 if(!pins?.length||g.issuerDeviceId!==null||!/^[A-Za-z0-9_-]{43}$/.test(nonce))throw new Error('cloud_continuation_not_provisioned');
 const authority=await verifyContinuationAuthority(policy,input.authorityAppendix);
 const previous=await load(secure),pending=store.get<{requestId:string;deviceId:string}>('state','pending'),approved=store.get<{requestId:string;deviceId:string;vaultId:string}>('state','pending-approved');
 if(!previous||previous.activation||previous.keys.signingPublic!==g.signingKey||previous.keys.wrappingPublic!==g.wrappingKey)throw new Error('cloud_enrollment_intent_conflict');
 if(!reconcileCommitted&&(!pending||!approved||store.get('state','enrollment')||
    pending.requestId!==g.requestId||pending.deviceId!==g.deviceId||approved.requestId!==g.requestId||approved.deviceId!==g.deviceId||approved.vaultId!==g.vaultId||
    JSON.stringify(store.get('state','pending-self-roster'))!==JSON.stringify(input.roster)||
    JSON.stringify(store.get('state','pending-package'))!==JSON.stringify(input.keyPackage)))throw new Error('cloud_enrollment_intent_conflict');
 const r=parseRoster(input.roster),head=await rosterDigest(input.roster);
 if(r.revision!==1||r.accountId!==g.accountId||r.tenantId!==g.tenantId||r.vaultId!==g.vaultId||r.keyEpoch!==g.keyEpoch||
    r.issuer.kind!=='device'||r.issuer.id!==g.deviceId||r.active.length!==1||r.revoked.length||
    r.active[0]?.deviceId!==g.deviceId||r.active[0].signingKey!==g.signingKey||r.active[0].wrappingKey!==g.wrappingKey||
    JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities??[]))
  throw new Error('cloud_enrollment_intent_conflict');
 await verifyRoster(input.roster,null,now,true);
 const w=await verifyWitness(input.witness,pins,{accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:head});
 if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(g.tenantId,g.vaultId))throw new Error('cloud_invalid_continuation_readback');
 const pin=pins.find(k=>k.keyId===w.keyId)!;
 if(pin.publicKey===g.signingKey||pin.publicKey===g.wrappingKey)throw new Error('cloud_continuation_not_provisioned');
 const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',input.keyPackage.canonical,input.keyPackage.signature]));
 await verifyContinuationApproval(input.target,input.approval,{oldGrantCanonical:canonicalGrant(g),stage:'put-key-package',payloadDigest,
  rosterDigest:head,witnessHead:{revision:w.revision,digest:w.digest},authority,issuer:null,now});
 exactFields(input.freshHead,['canonical','signature']);
 if(input.freshHead.canonical.length>2048)throw new Error('cloud_invalid_continuation_readback');
 const fresh:unknown=JSON.parse(input.freshHead.canonical);
 exactFields(fresh,['domain','keyId','nonce','requestId','witnessDigest','approvalDigest','payloadDigest','issuedAt','expiresAt']);
 const approvalWindow=JSON.parse(input.approval.canonical) as {approvedAt:number;expiresAt:number};
 const expected={domain:CONTINUATION_HEAD_DOMAIN,keyId:w.keyId,nonce,requestId:g.requestId,
  witnessDigest:await digest(JSON.stringify([input.witness.canonical,input.witness.signature])),
  approvalDigest:await digest(JSON.stringify([input.approval.canonical,input.approval.signature])),payloadDigest,
  issuedAt:fresh.issuedAt,expiresAt:fresh.expiresAt};
 if(input.freshHead.canonical!==JSON.stringify(expected)||typeof fresh.issuedAt!=='number'||typeof fresh.expiresAt!=='number'||
    !Number.isSafeInteger(fresh.issuedAt)||!Number.isSafeInteger(fresh.expiresAt)||fresh.issuedAt<approvalWindow.approvedAt||fresh.issuedAt>now||now>=fresh.expiresAt||fresh.expiresAt>approvalWindow.expiresAt||
    fresh.expiresAt-fresh.issuedAt>60||!await verify(pin.publicKey,input.freshHead.signature,input.freshHead.canonical))
  throw new Error('cloud_invalid_continuation_readback');
 const wrappingPrivate=Buffer.from(previous.keys.wrappingPrivate,'base64'),wrappingPublic=Buffer.from(previous.keys.wrappingPublic,'base64'),savedVDK=Buffer.from(previous.keys.vdk,'base64');
 try{
  if(wrappingPrivate.length!==32||wrappingPublic.length!==32||savedVDK.length!==32||
     !Buffer.from(sodium.crypto_scalarmult_base(wrappingPrivate)).equals(wrappingPublic))throw new Error('cloud_enrollment_intent_conflict');
  const vdk=openKeyPackage(input.keyPackage,{vaultId:g.vaultId,targetDeviceId:g.deviceId,keyEpoch:g.keyEpoch,issuerDeviceId:g.deviceId,grantId:g.requestId},Buffer.from(g.signingKey,'base64'),wrappingPublic,wrappingPrivate);
  try{if(!Buffer.from(vdk).equals(savedVDK))throw new Error('cloud_enrollment_intent_conflict');}finally{vdk.fill(0);}
 }finally{wrappingPrivate.fill(0);wrappingPublic.fill(0);savedVDK.fill(0);}
}
type ContinuationEvidence=GenesisContinuationPreflight&{commit:SignedManagedOperation;commitAppendix:SignedManagedOperation};
interface ContinuationJournal {kind:'genesis-package-continuation-v1';acceptedAt:number;nonce:string;evidence:ContinuationEvidence}
const commitDomain='AgentKeychain-enrollment-continuation-main-commit-v1';
const denied=()=>new Error('cloud_invalid_continuation_commit');
const bytesDigest=(value:SignedManagedOperation)=>digest(JSON.stringify([value.canonical,value.signature]));
async function validateCommitProof(policy:ManagedEndpointPolicy,nonce:string,input:ContinuationEvidence,now:number){
 const auth=await verifyContinuationAuthority(policy,input.authorityAppendix);
 const owner=await verifyContinuationCommitAuthority(policy,input.commitAppendix);
 const g=input.grant;
 if(owner.keyId===auth.keyId||[auth.publicKey,g.signingKey,g.wrappingKey].includes(owner.publicKey))throw denied();
 exactFields(input.commit,['canonical','signature']);
 if(typeof input.commit.canonical!=='string'||input.commit.canonical.length>3072)throw denied();
 base64(input.commit.signature,64,64);
 const received:unknown=JSON.parse(input.commit.canonical);
 exactFields(received,['version','domain','keyId','nonce','continuationId','requestId','accountId','tenantId','vaultId','deviceId','keyEpoch','stage','intentDigest','approvalDigest','payloadDigest','witnessDigest','custodyFreshHeadDigest','issuedAt','expiresAt']);
 const {id}=JSON.parse(input.target.canonical) as {id:string};
 const fresh=JSON.parse(input.freshHead.canonical) as {issuedAt:number;expiresAt:number};
 const approvalWindow=JSON.parse(input.approval.canonical) as {expiresAt:number};
 const {issuedAt,expiresAt}=received;
 if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
    issuedAt<fresh.issuedAt||issuedAt>now||expiresAt<=now||expiresAt>fresh.expiresAt||expiresAt>approvalWindow.expiresAt||expiresAt-issuedAt>60)
  throw denied();
 const expected={version:1,domain:commitDomain,keyId:owner.keyId,nonce,continuationId:id,requestId:g.requestId,accountId:g.accountId,
  tenantId:g.tenantId,vaultId:g.vaultId,deviceId:g.deviceId,keyEpoch:g.keyEpoch,stage:'put-key-package',intentDigest:await digest(input.target.canonical),
  approvalDigest:await bytesDigest(input.approval),payloadDigest:await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',input.keyPackage.canonical,input.keyPackage.signature])),
  witnessDigest:await bytesDigest(input.witness),custodyFreshHeadDigest:await bytesDigest(input.freshHead),issuedAt,expiresAt};
 if(input.commit.canonical!==JSON.stringify(expected)||!await verify(owner.publicKey,input.commit.signature,input.commit.canonical))throw denied();
}

/** Unwired local phase. The caller must serialize managed enrollment on this
 * store; SecureStore does not offer compare-and-swap across processes. No
 * profile, SQLite activation row, trust anchor or sync permission is written. */
export async function stageGenesisContinuation(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy,nonce:string,evidence:ContinuationEvidence):Promise<void>{
 const old=await load(secure);
 if(!old||old.activation)throw denied();
 if(old.continuation){
  if(old.continuation.nonce!==nonce||JSON.stringify(old.continuation.evidence)!==JSON.stringify(evidence))throw denied();
  if(!await readStagedGenesisContinuation(secure,store,policy))throw denied();
  return;
 }
 // Snapshot caller bytes once across asynchronous checks; don't retain aliases.
 const exact=globalThis.structuredClone(evidence);
 exactFields(exact,['grant','target','approval','authorityAppendix','witness','freshHead','roster','keyPackage','commit','commitAppendix']);
 const acceptedAt=Math.floor(Date.now()/1000);
 const continuation:ContinuationJournal={kind:'genesis-package-continuation-v1',acceptedAt,nonce,evidence:exact};
 if(Buffer.byteLength(JSON.stringify(continuation),'utf8')>24_000)throw denied();
 await validateGenesisContinuationPreflight(secure,store,policy,nonce,exact,acceptedAt);
 await validateCommitProof(policy,nonce,exact,acceptedAt);
 const deadline=(JSON.parse(exact.commit.canonical) as {expiresAt:number}).expiresAt;
 if(Math.floor(Date.now()/1000)>=deadline||JSON.stringify(await load(secure))!==JSON.stringify(old))throw denied();
 await save(secure,{...old,continuation});
}

/** Restart read validates historical evidence at its durably accepted time.
 * This is not renewed authorization: any future activation needs a separate
 * live Custody head and revocation check and an exclusive enrollment lease. */
export async function readStagedGenesisContinuation(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy){
 const verified=await validatedStage(secure,store,policy);
 if(!verified)return null;
 const {stage}=verified;
 return {kind:stage.kind,acceptedAt:stage.acceptedAt,requestId:stage.evidence.grant.requestId,deviceId:stage.evidence.grant.deviceId} as const;
}
const commitMarker='genesis-continuation-local-commit';
const continuationPending=['pending','pending-keys','pending-approved','pending-package','pending-self-roster','enrollment-intent'];
const localConflict=()=>new Error('cloud_enrollment_intent_conflict');
async function validatedStage(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy){
 const intent=await load(secure),stage=intent?.continuation;
 if(!stage||!intent)return null;
 exactFields(stage,['kind','acceptedAt','nonce','evidence']);
 if(intent.activation||stage.kind!=='genesis-package-continuation-v1'||!Number.isSafeInteger(stage.acceptedAt)||stage.acceptedAt<1||
    stage.acceptedAt>Math.floor(Date.now()/1000)||Buffer.byteLength(JSON.stringify(stage),'utf8')>24_000)throw denied();
 exactFields(stage.evidence,['grant','target','approval','authorityAppendix','witness','freshHead','roster','keyPackage','commit','commitAppendix']);
 const stageDigest=await digest(JSON.stringify(stage)),marker=store.get<{stageDigest:string}>('state',commitMarker);
 const profile=store.get<CloudEnrollment>('state','enrollment');
 if((marker&&marker.stageDigest!==stageDigest)||!!profile!==!!marker)throw localConflict();
 await validateGenesisContinuationPreflight(secure,store,policy,stage.nonce,stage.evidence,stage.acceptedAt,!!marker);
 await validateCommitProof(policy,stage.nonce,stage.evidence,stage.acceptedAt);
 return {intent,stage,stageDigest,marker,profile};
}
const postCommitDomain='AgentKeychain-enrollment-continuation-custody-post-commit-v1';
async function validatePostCommit(policy:ManagedEndpointPolicy,e:ContinuationEvidence,nonce:string,proof:SignedManagedOperation){
 exactFields(proof,['canonical','signature']);base64(proof.signature,64,64);
 if(typeof proof.canonical!=='string'||proof.canonical.length>3072)throw denied();
 const input:unknown=JSON.parse(proof.canonical);
 exactFields(input,['version','domain','keyId','nonce','mainCommitDigest','requestId','continuationId','accountId','tenantId','vaultId','deviceId','keyEpoch','witnessDigest','payloadDigest','issuedAt','expiresAt']);
 const g=e.grant,w=JSON.parse(e.witness.canonical) as {keyId:string};
 const main=JSON.parse(e.commit.canonical) as {continuationId:string;issuedAt:number;expiresAt:number;payloadDigest:string};
 const pin=policy.witnessKeys?.find(k=>k.keyId===w.keyId);
 const {issuedAt,expiresAt}=input,now=Math.floor(Date.now()/1000);
 if(!pin||typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
    issuedAt<main.issuedAt||issuedAt>now||expiresAt<=now||expiresAt>main.expiresAt||expiresAt-issuedAt>60)throw denied();
 const expected={version:1,domain:postCommitDomain,keyId:pin.keyId,nonce,mainCommitDigest:await bytesDigest(e.commit),
  requestId:g.requestId,continuationId:main.continuationId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,
  deviceId:g.deviceId,keyEpoch:g.keyEpoch,witnessDigest:await bytesDigest(e.witness),payloadDigest:main.payloadDigest,issuedAt,expiresAt};
 if(JSON.stringify(expected)!==proof.canonical||!await verify(pin.publicKey,proof.signature,proof.canonical))throw denied();
 return expiresAt*1000;
}

/** Isolated continuation activation. No production caller. The supplied transport
 * must obtain a new post-commit Custody response for the generated challenge.
 * Before any wider integration all enrollment writers must honor this lease. */
// eslint-disable-next-line no-unused-vars -- callback argument is a typed transport contract
export async function finalizeGenesisContinuation(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy,obtain:(nonce:string)=>Promise<SignedManagedOperation>):Promise<boolean>{
 const owner=newContinuationReadbackNonce(),leaseMs=30_000;
 store.db.exec('CREATE TABLE IF NOT EXISTS cloud_enrollment_lock(id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires INTEGER NOT NULL)');
 store.transaction(()=>{
  const row=store.db.query('SELECT expires FROM cloud_enrollment_lock WHERE id=1').get() as {expires:number}|null;
  if(row&&row.expires>Date.now())throw new Error('cloud_enrollment_busy');
  store.db.run('INSERT INTO cloud_enrollment_lock VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires',[owner,Date.now()+leaseMs]);
 });
 const fence=()=>{
  const row=store.db.query('SELECT owner,expires FROM cloud_enrollment_lock WHERE id=1').get() as {owner:string;expires:number}|null;
  if(row?.owner!==owner||row.expires<=Date.now()+6000)throw new Error('cloud_lease_lost');
 };
 try{
  const validated=await validatedStage(secure,store,policy);if(!validated)return false;
  const {intent,stage,stageDigest,marker,profile}=validated;
  const {evidence:e}=stage,g=e.grant,s=e.roster,roster=rosterPins(parseRoster(s));
  const expected:CloudEnrollment={accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,deviceId:g.deviceId,keyEpoch:g.keyEpoch,
   signingPublic:g.signingKey,wrappingPublic:g.wrappingKey,vdk:intent.keys.vdk,roster,checkpointKeys:policy.checkpointKeys,releaseId:policy.releaseId,apiOrigin:policy.apiOrigin};
  const anchor={sequence:0,root:await genesisRoot(g.tenantId,g.vaultId)};
  const nextCursor={...anchor,requiredThrough:0},cursor=store.get('state','cursor'),current=store.get('state','roster-current');
  if((profile&&JSON.stringify(profile)!==JSON.stringify(expected))||(cursor&&JSON.stringify(cursor)!==JSON.stringify(nextCursor))||
     (current&&JSON.stringify(current)!==JSON.stringify(s))||(marker&&(!cursor||!current)))throw localConflict();
  const nonce=newContinuationReadbackNonce();
  if(nonce===stage.nonce)throw denied();
  const deadline=await validatePostCommit(policy,e,nonce,await obtain(nonce));
  const stillLive=()=>{fence();if(Date.now()+6000>=deadline)throw denied();};
  stillLive();
  await new RosterStore(store,secure).initialize(s);
  stillLive();
  await store.checkAnchor(secure,anchor,[anchor],true);
  const same=await load(secure);
  if(!same||JSON.stringify(same)!==JSON.stringify(intent))throw localConflict();
  stillLive();
  if(!marker)store.transaction(()=>{
   stillLive();
   if(store.get('state','enrollment')||store.get('state',commitMarker))throw localConflict();
   store.put('state','enrollment',expected);store.put('state','cursor',nextCursor);
   for(const id of continuationPending)store.remove('state',id);
   store.put('state',commitMarker,{stageDigest});store.put('state','health',{state:'idle'});
  });
  // Runtime already refuses to open while this protected intent exists.
  stillLive();
  await secure.remove('enrollment-intent');
  return true;
 }finally{store.db.run('DELETE FROM cloud_enrollment_lock WHERE id=1 AND owner=?',[owner]);}
}
/** Called only after the local SAS/trust/package checks have succeeded. */
export async function prepareEnrollmentActivation(secure:SecureStore,store:CloudStore,keys:CloudKeys,activation:Activation){
 const previous=await load(secure);if(previous?.continuation)throw new Error('cloud_enrollment_intent_conflict');if(previous?.activation&&JSON.stringify(previous.activation)!==JSON.stringify(activation))throw new Error('cloud_enrollment_intent_conflict');
 const intent:Intent={version:1,keys:encode(keys),activation};await save(secure,intent);store.put('state','enrollment-intent',intent);
}
/** No network input is used to repair a partial activation. */
export async function resumeEnrollmentActivation(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy):Promise<boolean>{
 const intent=await load(secure);if(!intent?.activation)return false;
 const {enrollment:e,signedRoster:s}=intent.activation,r=parseRoster(s);
 await verifyRoster(s,null,r.issuedAt,true);
 const evidence=intent.activation.evidence;if(!evidence||!Number.isSafeInteger(evidence.acceptedAt)||evidence.acceptedAt>Math.floor(Date.now()/1000))throw new Error('cloud_enrollment_intent_conflict');
 const grant=evidence.grant;canonicalGrant(grant);
 if(policy.witnessKeys){if(!evidence.witness)throw new Error('cloud_witness_missing');const r=JSON.parse(intent.activation.signedRoster.canonical);await verifyWitness(evidence.witness,policy.witnessKeys,{accountId:e.accountId,tenantId:e.tenantId,vaultId:e.vaultId,revision:r.revision,digest:await rosterDigest(intent.activation.signedRoster)});}
 if(grant.expiresAt<=evidence.acceptedAt||grant.expiresAt>evidence.acceptedAt+600||grant.accountId!==e.accountId||grant.tenantId!==e.tenantId||grant.vaultId!==e.vaultId||grant.deviceId!==e.deviceId||grant.keyEpoch!==e.keyEpoch||grant.signingKey!==e.signingPublic||grant.wrappingKey!==e.wrappingPublic)throw new Error('cloud_enrollment_intent_conflict');
 const keys=await restoreEnrollmentKeys(secure);if(!keys)throw new Error('cloud_enrollment_intent_conflict');
 try{
  let issuer=e.signingPublic;
  if(grant.issuerDeviceId!==null){
   if(!evidence.sealed||!evidence.phrase)throw new Error('cloud_enrollment_intent_conflict');
   const bundle=openTrustedEnrollment(evidence.sealed,keys,{request:grant,phrase:evidence.phrase,phraseConfirmed:true,policy},evidence.acceptedAt);
   if(JSON.stringify(bundle.signedRoster)!==JSON.stringify(s))throw new Error('cloud_enrollment_intent_conflict');issuer=bundle.issuerKey;
  }else if(r.issuer.kind!=='device'||r.issuer.id!==e.deviceId||r.revision!==1)throw new Error('cloud_enrollment_intent_conflict');
  const vdk=openKeyPackage(evidence.keyPackage,{vaultId:grant.vaultId,targetDeviceId:grant.deviceId,keyEpoch:grant.keyEpoch,issuerDeviceId:grant.issuerDeviceId??grant.deviceId,grantId:grant.requestId},Buffer.from(issuer,'base64'),keys.wrappingPublic,keys.wrappingPrivate);
  try{if(Buffer.from(vdk).toString('base64')!==e.vdk)throw new Error('cloud_enrollment_intent_conflict');}finally{vdk.fill(0);}
 }finally{destroyCloudKeys(keys);}

 if(e.apiOrigin!==policy.apiOrigin||e.releaseId!==policy.releaseId||JSON.stringify(e.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities??[])||e.accountId!==r.accountId||e.tenantId!==r.tenantId||e.vaultId!==r.vaultId||e.keyEpoch!==r.keyEpoch||e.vdk!==intent.keys.vdk||e.signingPublic!==intent.keys.signingPublic||e.wrappingPublic!==intent.keys.wrappingPublic||JSON.stringify(e.roster)!==JSON.stringify(rosterPins(r))||!r.active.some(d=>d.deviceId===e.deviceId&&d.signingKey===e.signingPublic&&d.wrappingKey===e.wrappingPublic))throw new Error('cloud_enrollment_intent_conflict');
 const journal=store.get<Intent>('state','enrollment-intent'),profile=store.get<CloudEnrollment>('state','enrollment');
 if((journal&&JSON.stringify(journal)!==JSON.stringify(intent))||(profile&&JSON.stringify(profile)!==JSON.stringify(e)))throw new Error('cloud_enrollment_intent_conflict');
 store.put('state','enrollment-intent',intent);
 await new RosterStore(store,secure).initialize(s);
 const anchor={sequence:0,root:await genesisRoot(e.tenantId,e.vaultId)};
 const cursor=store.get<{sequence:number;root:string}>('state','cursor');if(cursor&&(cursor.sequence!==0||cursor.root!==anchor.root))throw new Error('cloud_enrollment_intent_conflict');
 await store.checkAnchor(secure,anchor,[anchor],true);
 store.transaction(()=>{
  store.put('state','enrollment',e);store.put('state','cursor',{...anchor,requiredThrough:0});
  for(const id of ['pending','pending-keys','pending-approved','pending-package','pending-self-roster','enrollment-intent'])store.remove('state',id);
  store.put('state','health',{state:'idle'});for(const device of e.roster)store.put('pins',device.deviceId,device);
 });
 await secure.remove('enrollment-intent');return true;
}
