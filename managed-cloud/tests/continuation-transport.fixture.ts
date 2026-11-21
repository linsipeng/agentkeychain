/** Synthetic-only graph, never imported by production Worker entrypoints. */
import {WorkerEntrypoint} from 'cloudflare:workers';
import {exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {authenticate} from '../api-worker/auth.ts';
import {canonicalGenesisCommitProofExpectation,proveGenesisPackageCommit} from '../api-worker/genesis-package-continuation-readback.ts';
import type {CheckpointKey} from '../shared/checkpoints.ts';
import {digest} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {proveContinuationAuthReadiness,proveFreshContinuationHead,provePostCommitContinuationHead,type ContinuationFreshHeadRequest} from '../shared/continuation-fresh-head.ts';
import {rosterWitness,type WitnessRequest} from '../shared/roster-witness.ts';
import {rpcData} from '../shared/rpc-data.ts';
import type {ContinuationAuthReadinessRequest} from '../shared/continuation-auth-readiness.ts';

import {canonicalFixturePost,fixtureTransportOrigin,type PostExpectation} from './continuation-transport-contract.ts';
const unavailable=()=>new Error('fixture_continuation_unavailable');
type PinPolicy={main:CheckpointKey;witness:CheckpointKey;approval:CheckpointKey;checkpoint:CheckpointKey};
type CommitExpectation=Parameters<typeof proveGenesisPackageCommit>[2];
type Fresh=Awaited<ReturnType<typeof proveFreshContinuationHead>>;
type Headers={authorization:string;'x-device-nonce':string;'x-device-proof':string;'x-device-timestamp':string};
interface MainEnv {MAIN:D1Database;ROLE_KEY:string;PINS:string;CUSTODY:CustodyContinuationTransport}
interface CustodyEnv {CUSTODIAN:D1Database;ROLE_KEY:string;PINS:string}

async function localSigner(raw:string,pin:CheckpointKey){
 const key=await crypto.subtle.importKey('pkcs8',Uint8Array.from(atob(raw),c=>c.charCodeAt(0)),'Ed25519',false,['sign']);
 return {key:async()=>pin,sign:async(message:string)=>btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(message)))))};
}
function request(path:string,headers:Headers,body:string){
 exactFields(headers,['authorization','x-device-nonce','x-device-proof','x-device-timestamp']);
 if(typeof body!=='string'||body.length>4096||Object.values(headers).some(v=>typeof v!=='string'||v.length>512))throw unavailable();
 return new Request(fixtureTransportOrigin+path,{method:'POST',headers:{...headers,'content-type':'application/json'},body});
}
const signedDigest=(s:SignedManagedOperation)=>digest(JSON.stringify([s.canonical,s.signature]));
export class CustodyContinuationTransport extends WorkerEntrypoint<CustodyEnv>{
 override async fetch(_request?:Request|string){return new Response(null,{status:404});}
 /** Test graph only: synthetic roster state for real scoped-proof fixtures. */
 async fixtureInitialWitness(input:WitnessRequest){
  const p=JSON.parse(this.env.PINS) as PinPolicy;
  return rosterWitness(this.env.CUSTODIAN,await localSigner(this.env.ROLE_KEY,p.witness),[p.checkpoint],async()=>true,[]).accept(input);
 }
 async fresh(input:ContinuationFreshHeadRequest){
  const p=JSON.parse(this.env.PINS) as PinPolicy;
  return proveFreshContinuationHead(this.env.CUSTODIAN,input,{authority:p.approval,witnessKeys:[p.witness],checkpointKeys:[p.checkpoint],recoveryAuthorities:[]},await localSigner(this.env.ROLE_KEY,p.witness));
 }
 async post(input:ContinuationFreshHeadRequest,prior:SignedManagedOperation,main:SignedManagedOperation){
  const p=JSON.parse(this.env.PINS) as PinPolicy;
  return provePostCommitContinuationHead(this.env.CUSTODIAN,input,prior,main,{mainCommitAuthority:p.main,authority:p.approval,witnessKeys:[p.witness],checkpointKeys:[p.checkpoint],recoveryAuthorities:[],otherReleaseKeys:[]},await localSigner(this.env.ROLE_KEY,p.witness));
 }
}

/** Auth gets only this private synthetic service entrypoint. */
export class CustodyContinuationReadinessTransport extends WorkerEntrypoint<CustodyEnv>{
 override async fetch(_request?:Request|string){return new Response(null,{status:404});}
 async readiness(input:ContinuationAuthReadinessRequest){
  const p=JSON.parse(this.env.PINS) as PinPolicy;
  return proveContinuationAuthReadiness(this.env.CUSTODIAN,input,
   {authority:p.approval,witnessKeys:[p.witness],checkpointKeys:[p.checkpoint],recoveryAuthorities:[]},await localSigner(this.env.ROLE_KEY,p.witness));
 }
}

export class MainContinuationTransport extends WorkerEntrypoint<MainEnv>{
 override async fetch(_request?:Request|string){return new Response(null,{status:404});}
 async commitProof(headers:Headers,body:string,custody:Fresh){
  try{
   const req=request('/commit-proof',headers,body),expectation=JSON.parse(body) as CommitExpectation;
   if(canonicalGenesisCommitProofExpectation(expectation)!==body)throw unavailable();
   const scope=await authenticate(this.env.MAIN,req,null,body),p=JSON.parse(this.env.PINS) as PinPolicy;
   return await proveGenesisPackageCommit(this.env.MAIN,scope,expectation,custody,{mainCommitAuthority:p.main,approvalAuthority:p.approval,witnesses:[p.witness],otherReleaseKeys:[p.checkpoint]},await localSigner(this.env.ROLE_KEY,p.main));
  }catch{throw unavailable();}
 }
 async postProof(headers:Headers,body:string,input:ContinuationFreshHeadRequest,prior:SignedManagedOperation,main:SignedManagedOperation){
  try{
   const req=request('/post-commit-proof',headers,body),parsed:unknown=JSON.parse(body);
   exactFields(parsed,['nonce','requestDigest','mainCommitDigest','priorFreshHeadDigest']);
   const exactRequest=JSON.stringify(input);
   if(exactRequest.length>96*1024||main.canonical.length>4096||prior.canonical.length>2048)throw unavailable();
   const expected:PostExpectation={nonce:input.nonce,requestDigest:await digest(exactRequest),mainCommitDigest:await signedDigest(main),priorFreshHeadDigest:await signedDigest(prior)};
   if(canonicalFixturePost(expected)!==body)throw unavailable();
   const scope=await authenticate(this.env.MAIN,req,null,body),g=JSON.parse(input.grant) as EnrollmentGrant;
   if(canonicalGrant(g)!==input.grant||g.accountId!==scope.accountId||g.tenantId!==scope.tenantId||
      g.vaultId!==scope.vaultId||g.deviceId!==scope.deviceId||g.signingKey!==scope.publicKey)throw unavailable();
   const response=await rpcData(this.env.CUSTODY.post(input,prior,main));
   // Never release the response if the requesting device lost access midflight.
   const live=await authenticate(this.env.MAIN,request('/post-commit-proof',headers,body),scope.vaultId,body);
   if(live.accountId!==scope.accountId||live.tenantId!==scope.tenantId||live.deviceId!==scope.deviceId||live.publicKey!==scope.publicKey)throw unavailable();
   return response;
  }catch{throw unavailable();}
 }
}
