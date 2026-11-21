import {randomBytes,randomInt} from 'node:crypto';
import {URL} from 'node:url';
import sodium from 'libsodium-wrappers-sumo';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import {canonicalContinuationIntent} from '../../managed-cloud/shared/enrollment-continuation.ts';
import {rosterDigest,verifyRoster} from '../../managed-cloud/shared/roster.ts';
import {canonicalHandoffStage,handoffCodeDigest,handoffPrepareProof,handoffStageDigest,type ContinuationHandoffStage} from '../../managed-cloud/shared/continuation-handoff-wire.ts';
import {restoreEnrollmentKeys} from './enrollment-intent.ts';
import {destroyCloudKeys,openKeyPackage} from './crypto.ts';
import {verifyContinuationHandoffOrigin,type ManagedEndpointPolicy} from './config.ts';
import {exactFields,type SignedManagedOperation} from './protocol.ts';
import type {CloudFetch} from './http.ts';
import type {CloudStore} from './persistence.ts';
import type {SecureStore} from '../platform/secure-store.ts';

const stateKey='pending-continuation-browser-handoff';
const now=()=>Math.floor(Date.now()/1000);
const opaque=()=>randomBytes(32).toString('base64url');
const text=(v:Uint8Array)=>Buffer.from(v).toString('base64');
const conflict=()=>new Error('cloud_enrollment_intent_conflict');
const expired=()=>new Error('cloud_continuation_handoff_expired');
type Saved={authOrigin:string;locator:string;code:string;expiresAt:number;grantDigest:string;codeDigest:string;exactDigest:string;stage:ContinuationHandoffStage};
interface Options {
 secure:SecureStore;store:CloudStore;policy:ManagedEndpointPolicy;authOriginAppendix:SignedManagedOperation;
 oldGrantCanonical:string;roster:SignedManagedOperation;keyPackage:SignedManagedOperation;
 network:CloudFetch;
 // eslint-disable-next-line no-unused-vars -- private local display callback contract
 displayPairCode:(_code:string)=>void;
}
async function readback(response:Response):Promise<unknown>{
 if(!response.ok||!response.body)throw conflict();
 const reader=response.body.getReader(),parts:Uint8Array[]=[];
 try{
  let size=0;
  for(;;){const n=await reader.read();if(n.done)break;size+=n.value.length;if(size>1024){await reader.cancel();throw conflict();}parts.push(n.value);}
  return JSON.parse(Buffer.concat(parts).toString('utf8'));
 }finally{reader.releaseLock();}
}
/** Pilot-only preparation: no default route, transport, or production pin;
 * the one deliberate local display is the only sink for the raw pair code. */
export async function prepareContinuationBrowserHandoff(o:Options):Promise<{browserUrl:string;stage:ContinuationHandoffStage}>{
 const {secure,store,policy,oldGrantCanonical,roster,keyPackage}=o;
 const authOrigin=await verifyContinuationHandoffOrigin(policy,o.authOriginAppendix);
 if(oldGrantCanonical.length>4096||roster.canonical.length>16384||keyPackage.canonical.length>4096)throw conflict();
 const g=JSON.parse(oldGrantCanonical) as EnrollmentGrant;
 if(canonicalGrant(g)!==oldGrantCanonical||g.issuerDeviceId!==null||g.expiresAt>now())throw conflict();
 const assertPending=()=>{
  const p=store.get<{requestId:string;deviceId:string}>('state','pending'),a=store.get<{requestId:string;deviceId:string;vaultId:string}>('state','pending-approved');
  if(store.get('state','enrollment')||p?.requestId!==g.requestId||p.deviceId!==g.deviceId||a?.requestId!==g.requestId||a.deviceId!==g.deviceId||a.vaultId!==g.vaultId||
     JSON.stringify(store.get('state','pending-self-roster'))!==JSON.stringify(roster)||
     JSON.stringify(store.get('state','pending-package'))!==JSON.stringify(keyPackage))throw conflict();
 };
 assertPending();
 const r=await verifyRoster(roster,null,now(),true),d=r.active[0];
 if(r.revision!==1||r.accountId!==g.accountId||r.tenantId!==g.tenantId||r.vaultId!==g.vaultId||r.keyEpoch!==g.keyEpoch||r.active.length!==1||r.revoked.length||
    r.issuer.kind!=='device'||r.issuer.id!==g.deviceId||d?.deviceId!==g.deviceId||d.signingKey!==g.signingKey||d.wrappingKey!==g.wrappingKey||
    JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities??[]))throw conflict();
 const keys=await restoreEnrollmentKeys(secure);if(!keys)throw conflict();
 try{
  if(text(keys.signingPublic)!==g.signingKey||text(keys.wrappingPublic)!==g.wrappingKey)throw conflict();
  const vdk=openKeyPackage(keyPackage,{vaultId:g.vaultId,targetDeviceId:g.deviceId,keyEpoch:g.keyEpoch,issuerDeviceId:g.deviceId,grantId:g.requestId},keys.signingPublic,keys.wrappingPublic,keys.wrappingPrivate);
  try{if(!sodium.memcmp(vdk,keys.vdk))throw conflict();}finally{vdk.fill(0);}
  const grantDigest=await digest(oldGrantCanonical),head=await rosterDigest(roster),sign=(v:string)=>text(sodium.crypto_sign_detached(v,keys.signingPrivate));
  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',keyPackage.canonical,keyPackage.signature]));
  const target=(id:string,expiresAt:number)=>canonicalContinuationIntent({version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id,
   originalGrantDigest:grantDigest,requestId:g.requestId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,deviceId:g.deviceId,signingKey:g.signingKey,
   wrappingKey:g.wrappingKey,issuerDeviceId:null,keyEpoch:g.keyEpoch,stage:'put-key-package',payloadDigest,rosterDigest:head,witnessHead:{revision:1,digest:head},expiresAt});
  const locator=opaque(),code=String(randomInt(100_000_000)).padStart(8,'0'),expiresAt=Math.min(r.expiresAt,now()+120),canonical=target(opaque(),expiresAt);
  const staged=canonicalHandoffStage({oldGrantCanonical,target:{canonical,signature:sign(canonical)},roster,keyPackage});
  const proposal:Saved={authOrigin,locator,code,expiresAt,grantDigest,codeDigest:await handoffCodeDigest(locator,code),exactDigest:await handoffStageDigest(staged),stage:staged};
  const saved=store.transaction(()=>{assertPending();const previous=store.get<Saved>('state',stateKey);if(previous)return previous;
   if(expiresAt<=now())throw expired();store.put('state',stateKey,proposal);return proposal;});
  if(saved.authOrigin!==authOrigin||saved.grantDigest!==grantDigest||!/^[A-Za-z0-9_-]{43}$/.test(saved.locator)||!/^[0-9]{8}$/.test(saved.code)||
     !Number.isSafeInteger(saved.expiresAt)||saved.expiresAt>r.expiresAt||
     saved.stage.oldGrantCanonical!==oldGrantCanonical||JSON.stringify(saved.stage.roster)!==JSON.stringify(roster)||JSON.stringify(saved.stage.keyPackage)!==JSON.stringify(keyPackage)||
     saved.exactDigest!==await handoffStageDigest(saved.stage)||saved.codeDigest!==await handoffCodeDigest(saved.locator,saved.code))throw conflict();
  if(saved.expiresAt<=now())throw expired();
  const expected=target(JSON.parse(saved.stage.target.canonical).id,saved.expiresAt);
  if(expected!==saved.stage.target.canonical||!await verify(g.signingKey,saved.stage.target.signature,expected))throw conflict();
  try{
   const reply=await readback(await o.network(new URL('/v1/auth/continuation-handoff/prepare',authOrigin).href,{method:'POST',headers:{'content-type':'application/json'},
    credentials:'omit',redirect:'error',cache:'no-store',signal:globalThis.AbortSignal.timeout(15000),body:JSON.stringify({locator:saved.locator,codeDigest:saved.codeDigest,
     expiresAt:saved.expiresAt,stage:saved.stage,signature:sign(handoffPrepareProof(saved.locator,saved.codeDigest,saved.exactDigest,saved.expiresAt))})}));
   exactFields(reply,['locator']);if(reply.locator!==saved.locator)throw conflict();
  }catch{throw new Error('cloud_continuation_handoff_unavailable');}
  store.transaction(()=>{assertPending();if(JSON.stringify(store.get('state',stateKey))!==JSON.stringify(saved))throw conflict();if(saved.expiresAt<=now())throw expired();});
  o.displayPairCode(saved.code);
  return {browserUrl:new URL('/continuation/approve#handoff='+saved.locator,authOrigin).href,stage:saved.stage};
 }finally{destroyCloudKeys(keys);}
}
