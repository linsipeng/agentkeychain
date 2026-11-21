import {URL,URLSearchParams} from 'node:url';
import {digest} from '../../managed-cloud/shared/contracts.ts';
import {type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import type {ContinuationHandoffStage} from '../../managed-cloud/shared/continuation-handoff-wire.ts';
import {assertSyntheticContinuationIntent,assertSyntheticContinuationScope,verifySyntheticContinuationRollout} from './continuation-rollout.ts';
import {verifyContinuationHandoffOrigin,type ManagedEndpointPolicy} from './config.ts';
import {pollContinuationBrowserApproval,prepareContinuationBrowserHandoff} from './continuation-handoff.ts';
import {assertContinuationLease,finalizeGenesisContinuationLocked,newContinuationReadbackNonce,readStagedGenesisContinuation,stageGenesisContinuation,verifyGenesisContinuationPreflight,withContinuationEnrollmentLease} from './enrollment-intent.ts';
import type {CloudStore} from './persistence.ts';
import type {SignedManagedOperation} from './protocol.ts';
import type {SecureStore} from '../platform/secure-store.ts';
import type {CloudFetch} from './http.ts';

type SignedRollout=Parameters<typeof verifySyntheticContinuationRollout>[1];
type Fresh={witness:SignedManagedOperation;freshHead:SignedManagedOperation};
type Handoff={locator:string;stage:ContinuationHandoffStage;browserUrl:string};
type OwnerProof={nonce:string;stage:ContinuationHandoffStage;approval:SignedManagedOperation;fresh:Fresh};
/* eslint-disable no-unused-vars -- synthetic transport contract arguments */
export interface SyntheticContinuationFlow {
 authOriginAppendix:SignedManagedOperation;
 oldGrantCanonical:string;roster:SignedManagedOperation;keyPackage:SignedManagedOperation;
 // Explicit distinct handlers. No URL/role fallback, no ambient session.
 prepareNetwork:CloudFetch;
 authorize:(targetDigest:string)=>Promise<SignedRollout>;
 open:(browserUrl:string)=>Promise<void>;
 displayPairCode:(code:string)=>void;
 pollNetwork:CloudFetch;
 custodyHead:(owner:Omit<OwnerProof,'fresh'>)=>Promise<Fresh>;
 commitOrRead:(apiOrigin:string,owner:OwnerProof)=>Promise<SignedManagedOperation>;
 custodyPost:(nonce:string,commit:SignedManagedOperation)=>Promise<SignedManagedOperation>;
}
/* eslint-enable no-unused-vars */
type Saved={handoff:Handoff;signed:SignedRollout;published:boolean;approval?:SignedManagedOperation;commitNonce?:string;commit?:SignedManagedOperation};
const stateKey='pending-continuation-machine';
const blocked=()=>new Error('cloud_continuation_not_provisioned');

export function assertSyntheticContinuationFlow(flow:SyntheticContinuationFlow){
 if(!flow.authOriginAppendix||!flow.oldGrantCanonical||!flow.roster||!flow.keyPackage||
   ['prepareNetwork','authorize','open','displayPairCode','pollNetwork','custodyHead','commitOrRead','custodyPost'].some(k=>typeof flow[k as keyof SyntheticContinuationFlow]!=='function'))throw blocked();
}
/** One finite attempt. Persist exact evidence before each fallible remote step.
 * It does not implement/enable production transport or print sensitive data. */
export async function advanceSyntheticContinuation(secure:SecureStore,store:CloudStore,policy:ManagedEndpointPolicy,flow:SyntheticContinuationFlow):Promise<'waiting-for-approval'|'active'>{
 assertSyntheticContinuationFlow(flow);
 const authOrigin=await verifyContinuationHandoffOrigin(policy,flow.authOriginAppendix);
 return withContinuationEnrollmentLease(store,async lease=>{
  const fence=()=>assertContinuationLease(store,lease);
  const put=(entry:Saved)=>store.transaction(()=>{fence();store.put('state',stateKey,entry);});
  let saved=store.get<Saved>('state',stateKey);
  const obtain=async(nonce:string)=>{fence();if(!saved?.commit)throw blocked();const result=await flow.custodyPost(nonce,saved.commit);fence();return result;};
  if(await readStagedGenesisContinuation(secure,store,policy)){
   if(!saved?.commit)throw blocked();
   const permit=await verifySyntheticContinuationRollout(policy,saved.signed);
   if(!await finalizeGenesisContinuationLocked(secure,store,policy,obtain,lease,permit))throw blocked();
   store.transaction(()=>{fence();store.remove('state',stateKey);store.remove('state','pending-continuation-browser-handoff');});return 'active';
  }
  if(!saved?.published){
   let code:string|undefined;
   const result=await prepareContinuationBrowserHandoff({secure,store,policy,authOriginAppendix:flow.authOriginAppendix,
    oldGrantCanonical:flow.oldGrantCanonical,roster:flow.roster,keyPackage:flow.keyPackage,
    network:async(url,init)=>{fence();if(new URL(url).origin!==authOrigin)throw blocked();return flow.prepareNetwork(url,init);},
    displayPairCode:value=>{code=value;},
    authorizeBeforePublish:async(stage,browserUrl)=>{
     fence();
     const intentDigest=await digest(stage.target.canonical),u=new URL(browserUrl),locator=new URLSearchParams(u.hash.slice(1)).get('handoff');
     if(u.origin!==authOrigin||u.pathname!=='/continuation/approve'||!locator||!/^[A-Za-z0-9_-]{43}$/.test(locator))throw blocked();
     const handoff={locator,stage,browserUrl};
     const signed=saved?.signed??await flow.authorize(intentDigest);
     const permit=await verifySyntheticContinuationRollout(policy,signed);await assertSyntheticContinuationIntent(policy,permit,stage.target);
     if(saved&&JSON.stringify(saved.handoff)!==JSON.stringify(handoff))throw blocked();
     saved={handoff,signed,published:false};put(saved);
    }});
   if(!saved||saved.handoff.browserUrl!==result.browserUrl||JSON.stringify(saved.handoff.stage)!==JSON.stringify(result.stage)||!code)throw blocked();
   put({...saved,published:true});
   // Mark first; a terminated process never automatically opens a second tab.
   flow.displayPairCode(code);
   await flow.open(result.browserUrl);
   return 'waiting-for-approval';
  }
  const stage=saved.handoff.stage;
  if(stage.oldGrantCanonical!==flow.oldGrantCanonical||JSON.stringify(stage.roster)!==JSON.stringify(flow.roster)||
    JSON.stringify(stage.keyPackage)!==JSON.stringify(flow.keyPackage)||new URL(saved.handoff.browserUrl).origin!==authOrigin)throw blocked();
  const permit=await verifySyntheticContinuationRollout(policy,saved.signed);
  await assertSyntheticContinuationIntent(policy,permit,stage.target);
  const reply=saved.approval?{status:'approved' as const,approval:saved.approval}:await pollContinuationBrowserApproval({secure,store,policy,authOriginAppendix:flow.authOriginAppendix,authAuthorityAppendix:saved.signed.authAppendix,
   locator:saved.handoff.locator,stage,network:async(url,init)=>{fence();if(new URL(url).origin!==authOrigin)throw blocked();return flow.pollNetwork(url,init);}});
  fence();
  if(reply.status==='pending')return 'waiting-for-approval';
  if(reply.status!=='approved')throw blocked();
  const {approval}=reply,nonce=saved.commitNonce??newContinuationReadbackNonce();
  const request={nonce,stage,approval},fresh=await flow.custodyHead(request);fence();
  const grant=JSON.parse(stage.oldGrantCanonical) as EnrollmentGrant;
  const evidence={grant,target:stage.target,approval,authorityAppendix:saved.signed.authAppendix,commitAppendix:saved.signed.commitAppendix,roster:stage.roster,keyPackage:stage.keyPackage,witness:fresh.witness,freshHead:fresh.freshHead};
  await assertSyntheticContinuationScope(policy,permit,evidence);
  await verifyGenesisContinuationPreflight(secure,store,policy,nonce,evidence);
  fence();
  put({...saved,approval,commitNonce:nonce});
  const commit=await flow.commitOrRead(policy.apiOrigin,{...request,fresh});fence();
  // Keep the exact readback before crossing the protected write boundary.
  // It cannot authorize anything until stageGenesisContinuation verifies it.
  saved={...saved,approval,commitNonce:nonce,commit};put(saved);
  await stageGenesisContinuation(secure,store,policy,nonce,{...evidence,commit},lease);fence();
  // Obtain a distinct post-commit nonce; this is not the preflight head.
  if(!await finalizeGenesisContinuationLocked(secure,store,policy,obtain,lease,permit))throw blocked();
  store.transaction(()=>{fence();store.remove('state',stateKey);store.remove('state','pending-continuation-browser-handoff');});
  return 'active';
 });
}

/** Explicit resume display only; everything remains local and lease-bound. */
// eslint-disable-next-line no-unused-vars -- explicit local-only presenter
export async function showSyntheticContinuationHandoff(store:CloudStore,policy:ManagedEndpointPolicy,flow:SyntheticContinuationFlow,display:(url:string,code:string)=>void){
 const authOrigin=await verifyContinuationHandoffOrigin(policy,flow.authOriginAppendix);
 return withContinuationEnrollmentLease(store,async lease=>{
  const saved=store.get<Saved>('state',stateKey);
  if(!saved?.published||saved.approval||saved.commit||typeof display!=='function')throw blocked();
  const {stage,locator,browserUrl}=saved.handoff;
  if(stage.oldGrantCanonical!==flow.oldGrantCanonical||JSON.stringify(stage.roster)!==JSON.stringify(flow.roster)||
    JSON.stringify(stage.keyPackage)!==JSON.stringify(flow.keyPackage))throw blocked();
  const permit=await verifySyntheticContinuationRollout(policy,saved.signed);
  await assertSyntheticContinuationIntent(policy,permit,stage.target);
  const {displayPreparedContinuationHandoff}=await import('./continuation-handoff.ts');
  await displayPreparedContinuationHandoff(store,authOrigin,locator,browserUrl,stage,()=>{
   assertContinuationLease(store,lease);
   if(Math.floor(Date.now()/1000)>=permit.expiresAt||JSON.stringify(store.get('state',stateKey))!==JSON.stringify(saved))throw blocked();
  },display);
 });
}
