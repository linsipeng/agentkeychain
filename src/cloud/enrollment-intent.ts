import {rosterDigest} from '../../managed-cloud/shared/roster.ts';
import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';
import sodium from 'libsodium-wrappers-sumo';
import type {SecureStore} from '../platform/secure-store.ts';
import {openKeyPackage,destroyCloudKeys,type CloudKeys} from './crypto.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import {openTrustedEnrollment} from './enrollment.ts';
import type {CloudEnrollment} from './runtime.ts';
import type {CloudStore} from './persistence.ts';
import type {ManagedEndpointPolicy} from './config.ts';
import type {SignedManagedOperation} from './protocol.ts';
import {RosterStore,rosterPins} from './roster.ts';
import {parseRoster,verifyRoster} from '../../managed-cloud/shared/roster.ts';
import {genesisRoot} from '../../managed-cloud/shared/checkpoints.ts';
export interface EnrollmentEvidence {witness?:SignedManagedOperation;grant:EnrollmentGrant;keyPackage:SignedManagedOperation;sealed?:string;phrase?:string;acceptedAt:number}
interface Activation {enrollment:CloudEnrollment;signedRoster:SignedManagedOperation;evidence:EnrollmentEvidence}
interface Intent {version:1;keys:Record<keyof CloudKeys,string>;activation?:Activation}
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
/** Called only after the local SAS/trust/package checks have succeeded. */
export async function prepareEnrollmentActivation(secure:SecureStore,store:CloudStore,keys:CloudKeys,activation:Activation){
 const previous=await load(secure);if(previous?.activation&&JSON.stringify(previous.activation)!==JSON.stringify(activation))throw new Error('cloud_enrollment_intent_conflict');
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
  for(const id of ['pending','pending-keys','pending-package','pending-self-roster','enrollment-intent'])store.remove('state',id);
  store.put('state','health',{state:'idle'});for(const device of e.roster)store.put('pins',device.deviceId,device);
 });
 await secure.remove('enrollment-intent');return true;
}
