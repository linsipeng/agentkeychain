import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';
import {protectEnrollmentKeys,restoreEnrollmentKeys,prepareEnrollmentActivation,resumeEnrollmentActivation,type EnrollmentEvidence} from './enrollment-intent.ts';
import {RosterStore,enrollmentRoster,refreshRoster,rosterPins,publishRoster} from './roster.ts';
import {parseRoster} from '../../managed-cloud/shared/roster.ts';
import {issuerDelivery,type IssuerDelivery} from './issuer.ts';
import {assertVerifiedPolicy,type ManagedEndpointPolicy} from './config.ts';
import { URL } from "node:url";
/* eslint-disable no-unused-vars -- callback declarations */
import sodium from 'libsodium-wrappers-sumo';
import {randomUUID} from 'node:crypto';
import type {Database} from 'bun:sqlite';
import {createCloudKeys,destroyCloudKeys,openKeyPackage,sealKeyPackage} from './crypto.ts';
import {ManagedHttpClient,CloudHttpError} from './http.ts';
import {CloudStore} from './persistence.ts';
import {canonicalGrant,enrollmentProof,type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import {openTrustedEnrollment,previewEnrollmentPhrase,selfAnchor,type TrustedEnrollmentBundle} from './enrollment.ts';
import {productionComposition,type CloudComposition,type CloudEnrollment,openCloudRuntime} from './runtime.ts';
import {hasCloudState} from './coordinator.ts';
import type {SignedManagedOperation} from './protocol.ts';
const b64=(b:Uint8Array)=>Buffer.from(b).toString('base64');
export interface LoginUI {open(url:string):Promise<void>;showPhrase?(phrase:string):void;confirmPhrase(phrase:string):Promise<boolean>;wait(ms:number):Promise<void>}
/** Both browser entrypoints are owned by the signed Web origin. */
export function authorizationBrowser(policy:ManagedEndpointPolicy,authorization:{browserUri:string;verificationUri:string}):URL {
 assertVerifiedPolicy(policy);
 try {
  const browser=new URL(authorization.browserUri),verification=new URL(authorization.verificationUri);
  for(const [url,path] of [[browser,'/app/devices/add'],[verification,'/v1/auth/devices/verification']] as const){
   if(url.origin!==policy.webOrigin||url.username||url.password||url.hash||url.pathname!==path)throw new Error('cloud_invalid_authorization');
  }
  if(verification.search)throw new Error('cloud_invalid_authorization');
  return browser;
 }catch{throw new Error('cloud_invalid_authorization');}
}
/** Once approval was observed, do not create another remote device or discard the pending trust state. */
function assertCanReplaceEnrollmentRequest(store:CloudStore){
 if(['enrollment','roster-current','pending-approved','pending-self-roster','pending-package'].some(id=>store.get('state',id)))
  throw new Error('cloud_partial_activation_requires_resume');
}
/** New, unapproved requests must never inherit a previous request's state. */
export function replaceEnrollmentRequest(store:CloudStore,authorization:unknown){
 store.transaction(()=>{
  assertCanReplaceEnrollmentRequest(store);
  store.remove('state','pending-package');store.remove('state','pending-self-roster');
  store.put('state','pending',authorization);
 });
}
export async function loginCloud(db:Database,ui:LoginUI,composition:CloudComposition=productionComposition()):Promise<void>{
 const {policy,secure}=composition,keys=await restoreEnrollmentKeys(secure)??await createCloudKeys();let store:CloudStore|undefined;
 try{
  const existing=await secure.get('csk');
  if(existing){
   keys.csk.fill(0);keys.csk=existing;store=new CloudStore(db,keys.csk);
   if(await resumeEnrollmentActivation(secure,store,policy))return;
   if(store.get('state','enrollment'))return;
   const protectedKeys=await restoreEnrollmentKeys(secure);
   if(protectedKeys&&!store.get('state','pending-keys'))store.put('state','pending-keys',{vdk:b64(protectedKeys.vdk),signingPublic:b64(protectedKeys.signingPublic),wrappingPublic:b64(protectedKeys.wrappingPublic)});
   if(protectedKeys)destroyCloudKeys(protectedKeys);
   const pendingKeys=store.get<{vdk:string;signingPublic:string;wrappingPublic:string}>('state','pending-keys');
   const signing=await secure.get('signing-private'),wrapping=await secure.get('wrapping-private');
   if(!pendingKeys||!signing||!wrapping){signing?.fill(0);wrapping?.fill(0);throw new Error('cloud_incomplete_secure_state');}
   keys.signingPrivate.fill(0);keys.wrappingPrivate.fill(0);keys.vdk.fill(0);
   keys.signingPrivate=signing;keys.wrappingPrivate=wrapping;keys.vdk=Buffer.from(pendingKeys.vdk,'base64');
   keys.signingPublic=Buffer.from(pendingKeys.signingPublic,'base64');keys.wrappingPublic=Buffer.from(pendingKeys.wrappingPublic,'base64');
  }else{
   if(hasCloudState(db))throw new Error('cloud_secure_store_locked');
   await protectEnrollmentKeys(secure,keys);
   // The protected intent precedes both SQLite and the individual key slots.
   store=new CloudStore(db,keys.csk);
   store.put('state','pending-keys',{vdk:b64(keys.vdk),signingPublic:b64(keys.signingPublic),wrappingPublic:b64(keys.wrappingPublic)});
   await secure.put('signing-private',keys.signingPrivate);await secure.put('wrapping-private',keys.wrappingPrivate);await secure.put('csk',keys.csk);
  }
  store.put('state','health',{state:'enrolling'});
  const identity={record:{vaultId:'pending',deviceId:'pending',publicKey:b64(keys.signingPublic),revoked:false},privateKey:keys.signingPrivate};
  const http=new ManagedHttpClient(policy,identity,composition.network),platform=process.platform==='darwin'?'macos':process.platform==='linux'?'linux':'other';
  type PendingAuthorization={deviceCode:string;deviceId:string;requestId:string;browserUri:string;verificationUri:string;phrase:string;interval:number;expiresIn:number;deadline:number};
  let authorization=store.get<PendingAuthorization>('state','pending');
  if(authorization&&authorization.deadline<=Date.now()){
   assertCanReplaceEnrollmentRequest(store);
   // An expired request cannot prove it was never approved: the current
   // signed resume endpoint no longer returns its state after expiry.
   throw new Error('cloud_enrollment_expired_requires_reconcile');
  }
  if(!authorization){
  assertCanReplaceEnrollmentRequest(store);
  const result=await http.publicCall('/v1/devices/authorize',{signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),platform,proof:b64(sodium.crypto_sign_detached(enrollmentProof(b64(keys.signingPublic),b64(keys.wrappingPublic),platform),keys.signingPrivate))}) as Omit<PendingAuthorization,'deadline'>;
  authorization={...result,deadline:Date.now()+result.expiresIn*1000};
  replaceEnrollmentRequest(store,authorization);
  }
  const browser=authorizationBrowser(policy,authorization);
  if(!/^[a-z]+(?: [a-z]+){2}$/.test(authorization.phrase)||authorization.phrase.length>128||!Number.isFinite(authorization.interval)||authorization.interval<5||authorization.interval>60||!Number.isFinite(authorization.expiresIn)||authorization.expiresIn<1||authorization.expiresIn>600)throw new Error('cloud_invalid_authorization');
  store.put('state','pending',authorization);
  const timestamp=Math.floor(Date.now()/1000);
  const initial=await http.publicCall('/v1/devices/resume',{requestId:authorization.requestId,deviceId:authorization.deviceId,timestamp,signature:b64(sodium.crypto_sign_detached(JSON.stringify(['AgentKeychain-enrollment-resume-v1',authorization.requestId,authorization.deviceId,timestamp]),keys.signingPrivate))}) as {state:string;deviceId?:string;requestId?:string;vaultId?:string};
  if(initial.state==='denied'){assertCanReplaceEnrollmentRequest(store);store.transaction(()=>{for(const id of ['pending','pending-package','pending-self-roster'])store!.remove('state',id);});throw new Error('cloud_authorization_denied');}
  if(initial.state!=='approved'){
   assertCanReplaceEnrollmentRequest(store);
   await ui.open(browser.href);
  }
  ui.showPhrase?.(authorization.phrase);
  const deadline=authorization.deadline;let approved=false;
  while(initial.state==='approved'||Date.now()<deadline){
   if(initial.state!=='approved')await ui.wait(authorization.interval*1000);
   let status:{state:string;deviceId?:string;vaultId?:string;requestId?:string};
   try{status=initial.state==='approved'?initial:await http.publicCall('/v1/devices/status',{deviceCode:authorization.deviceCode}) as typeof status;}catch(error){if(error instanceof CloudHttpError&&error.code==='rate_limited'){await ui.wait(Math.max(error.retryAfter,5000));continue;}throw error;}
   if(status.state==='denied'){assertCanReplaceEnrollmentRequest(store);store.transaction(()=>{for(const id of ['pending','pending-package','pending-self-roster'])store!.remove('state',id);});throw new Error('cloud_authorization_denied');}
   if(status.state!=='approved')continue;
   if(status.deviceId!==authorization.deviceId||status.requestId!==authorization.requestId||!status.vaultId)throw new Error('cloud_invalid_authorization');
   const receipt={requestId:status.requestId,deviceId:status.deviceId,vaultId:status.vaultId};
   const previous=store.get<typeof receipt>('state','pending-approved');
   if(previous&&(previous.requestId!==receipt.requestId||previous.deviceId!==receipt.deviceId||previous.vaultId!==receipt.vaultId))throw new Error('cloud_invalid_authorization');
   store.put('state','pending-approved',receipt);
   identity.record.deviceId=status.deviceId;identity.record.vaultId=status.vaultId;approved=true;break;
  }
  if(!approved||Date.now()>=deadline)throw new Error('cloud_authorization_expired');
  const result=await http.call('/v1/devices/enrollment-grant') as {canonical:string};
  const grant=JSON.parse(result.canonical) as EnrollmentGrant;
  if(canonicalGrant(grant)!==result.canonical||grant.requestId!==authorization.requestId||grant.deviceId!==authorization.deviceId||grant.vaultId!==identity.record.vaultId||grant.signingKey!==b64(keys.signingPublic)||grant.wrappingKey!==b64(keys.wrappingPublic))throw new Error('cloud_invalid_grant');
  let trust:ReturnType<typeof selfAnchor>,evidence:EnrollmentEvidence;
  if(grant.issuerDeviceId===null){
   trust=selfAnchor(grant,keys,policy,true);
   const prepared=store.get<SignedManagedOperation>('state','pending-self-roster');if(prepared)trust={...trust,signedRoster:prepared};else store.put('state','pending-self-roster',trust.signedRoster);
   const witnessed=await publishRoster(http,trust.signedRoster);
   const binding={vaultId:grant.vaultId,targetDeviceId:grant.deviceId,keyEpoch:grant.keyEpoch,issuerDeviceId:grant.deviceId,grantId:grant.requestId};
   let ownPackage=store.get<SignedManagedOperation>('state','pending-package');
   if(!ownPackage||JSON.parse(ownPackage.canonical).grantId!==grant.requestId){ownPackage=sealKeyPackage(keys.vdk,binding,keys.wrappingPublic,keys.signingPrivate);store.put('state','pending-package',ownPackage);}
   await http.call('/v1/devices/enroll',ownPackage);
   evidence={grant,keyPackage:ownPackage,...(witnessed.witness?{witness:witnessed.witness}:{}),acceptedAt:Math.floor(Date.now()/1000)};
  }else{
   let delivery:{sealed:string;canonical:string;witness?:SignedManagedOperation}|undefined;
   while(Date.now()<deadline){try{delivery=await http.call('/v1/devices/trust-bundle-get') as typeof delivery;break;}catch(error){if(!(error instanceof CloudHttpError)||error.code!=='not_found')throw error;await ui.wait(5000);}}
   if(!delivery||delivery.canonical!==result.canonical)throw new Error('cloud_trust_delivery_expired');
   const phrase=previewEnrollmentPhrase(delivery.sealed,keys),phraseConfirmed=await ui.confirmPhrase(phrase);
   const bundle=openTrustedEnrollment(delivery.sealed,keys,{request:grant,phrase,phraseConfirmed,policy});if(!bundle.signedRoster)throw new Error('cloud_signed_roster_required');trust={roster:bundle.roster,checkpointKeys:bundle.checkpointKeys,signedRoster:bundle.signedRoster};
   if(policy.witnessKeys){const r=parseRoster(bundle.signedRoster);if(!delivery.witness)throw new Error('cloud_witness_missing');await verifyWitness(delivery.witness,policy.witnessKeys,{accountId:r.accountId,tenantId:r.tenantId,vaultId:r.vaultId,revision:r.revision,digest:await import('../../managed-cloud/shared/roster.ts').then(m=>m.rosterDigest(bundle.signedRoster))});}
   let signed:SignedManagedOperation|undefined;
   while(Date.now()<deadline){try{signed=await http.call('/v1/devices/key-packages',{},'GET') as SignedManagedOperation;break;}catch(error){if(!(error instanceof CloudHttpError)||error.code!=='not_found')throw error;await ui.wait(5000);}}
   if(!signed)throw new Error('cloud_key_delivery_expired');
   const vdk=openKeyPackage(signed,{vaultId:grant.vaultId,targetDeviceId:grant.deviceId,keyEpoch:grant.keyEpoch,issuerDeviceId:grant.issuerDeviceId,grantId:grant.requestId},Buffer.from(bundle.issuerKey,'base64'),keys.wrappingPublic,keys.wrappingPrivate);keys.vdk.fill(0);keys.vdk=vdk;
   evidence={grant,keyPackage:signed,sealed:delivery.sealed,phrase,...(delivery.witness?{witness:delivery.witness}:{}),acceptedAt:Math.floor(Date.now()/1000)};
  }
  const enrollment:CloudEnrollment={accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,deviceId:grant.deviceId,keyEpoch:grant.keyEpoch,signingPublic:grant.signingKey,wrappingPublic:grant.wrappingKey,vdk:b64(keys.vdk),roster:trust.roster,checkpointKeys:trust.checkpointKeys,releaseId:policy.releaseId,apiOrigin:policy.apiOrigin};
  await prepareEnrollmentActivation(secure,store,keys,{enrollment,signedRoster:trust.signedRoster,evidence});
  await resumeEnrollmentActivation(secure,store,policy);
 }finally{store?.destroy();destroyCloudKeys(keys);}
}
export async function approveDevice(runtime:Awaited<ReturnType<typeof openCloudRuntime>>,requestId:string,ui:LoginUI){
 const owner=randomUUID();if(!runtime.store.acquireLease(owner))throw new Error('cloud_sync_busy');
 let lost=false;const renewal=setInterval(()=>{if(!runtime.store.acquireLease(owner))lost=true;},10000);
 const guardedUI:LoginUI={...ui,wait:async ms=>{await ui.wait(ms);if(lost)throw new Error('cloud_lease_lost');},confirmPhrase:async phrase=>{const confirmed=await ui.confirmPhrase(phrase);runtime.store.assertLease(owner);return confirmed;}};
 try{return await deliverDevice(runtime,requestId,guardedUI);}finally{clearInterval(renewal);runtime.store.releaseLease(owner);}
}
async function deliverDevice(runtime:Awaited<ReturnType<typeof openCloudRuntime>>,requestId:string,ui:LoginUI){
 const receipt=runtime.store.get<{delivered:boolean}>('state','issuer-receipt:'+requestId);if(receipt){if(receipt.delivered)return;throw new Error('cloud_issuer_request_conflict');}
 const previous=runtime.store.get<IssuerDelivery>('state','issuer:'+requestId);
 const retire=()=>runtime.store.transaction(()=>{runtime.store.put('state','issuer-receipt:'+requestId,{requestId,delivered:false});runtime.store.remove('state','issuer:'+requestId);});
 if(previous&&previous.bundle.request.expiresAt<=Math.floor(Date.now()/1000)){retire();throw new Error('cloud_authorization_expired');}
 let detail:{canonical:string};
 try{detail=await runtime.http.call('/v1/devices/pairing-detail',{id:requestId}) as {canonical:string};}catch(error){if(previous&&error instanceof CloudHttpError&&error.code==='not_found'){retire();throw new Error('cloud_issuer_request_conflict',{cause:error});}throw error;}

 const grant=JSON.parse(detail.canonical) as EnrollmentGrant,enrolled=runtime.enrollment;
 if(canonicalGrant(grant)!==detail.canonical||grant.issuerDeviceId!==enrolled.deviceId||grant.vaultId!==enrolled.vaultId||grant.accountId!==enrolled.accountId||grant.tenantId!==enrolled.tenantId||grant.keyEpoch!==enrolled.keyEpoch||grant.expiresAt<=Math.floor(Date.now()/1000))throw new Error('cloud_invalid_grant');
 const previousDelivery=runtime.store.get<IssuerDelivery>('state','issuer:'+requestId);
 if(!previousDelivery)await refreshRoster(runtime.store,runtime.secure,runtime.http,runtime.keys,enrolled.deviceId,false);
 const signedRoster=previousDelivery?.bundle.signedRoster??await enrollmentRoster(runtime.store,runtime.secure,runtime.keys,enrolled.deviceId,{deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey});
 if(!signedRoster)throw new Error('cloud_signed_roster_required');
 const bundle:TrustedEnrollmentBundle={...{},signedRoster,version:1,kind:'enrollment',request:grant,issuerKey:enrolled.signingPublic,roster:rosterPins(parseRoster(signedRoster)),checkpointKeys:runtime.http.policy.checkpointKeys,nonce:randomUUID(),recoveryCase:null};
 const delivery=issuerDelivery(runtime.store,detail.canonical,bundle,runtime.keys),{phrase,sealed,keyPackage}=delivery;
 await runtime.http.call('/v1/devices/pairing-confirm',{id:requestId,signature:b64(sodium.crypto_sign_detached(detail.canonical,runtime.keys.signingPrivate))});
 while(Date.now()<grant.expiresAt*1000){
  try{await publishRoster(runtime.http,signedRoster);await new RosterStore(runtime.store,runtime.secure).accept(signedRoster);await runtime.http.call('/v1/devices/trust-bundle',{requestId,sealed});break;}
  catch(error){if(!(error instanceof CloudHttpError)||!['not_found','cloud_request_failed'].includes(error.code))throw error;await ui.wait(5000);}
 }
 if(Date.now()>=grant.expiresAt*1000)throw new Error('cloud_authorization_expired');
 if(!delivery.confirmed){
  if(!await ui.confirmPhrase(phrase))throw new Error('phrase_confirmation_required');
  runtime.store.transaction(()=>{const current=runtime.store.get<IssuerDelivery>('state','issuer:'+requestId)!;runtime.store.put('state','issuer:'+requestId,{...current,confirmed:true});});
 }
 while(Date.now()<grant.expiresAt*1000){
  try{await runtime.http.call('/v1/devices/enroll',keyPackage);runtime.store.transaction(()=>{runtime.store.put('state','enrollment',{...enrolled,roster:delivery.bundle.roster});for(const device of delivery.bundle.roster)runtime.store.put('pins',device.deviceId,device);runtime.store.put('state','issuer-receipt:'+requestId,{requestId,canonical:delivery.canonical,delivered:true});runtime.store.remove('state','issuer:'+requestId);});return;}
  catch(error){if(!(error instanceof CloudHttpError)||!['not_found','cloud_request_failed'].includes(error.code))throw error;await ui.wait(5000);}
 }
 throw new Error('cloud_authorization_expired');
}
