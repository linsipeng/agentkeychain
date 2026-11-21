/** Explicit private continuation-only pilot Worker; no public route or signer RPC. */
import {WorkerEntrypoint} from 'cloudflare:workers';
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {digest} from '../shared/contracts.ts';
import {readExactMainGenesisAdmission} from '../shared/genesis-main-binding.ts';
import {proveContinuationAuthReadiness,proveFreshContinuationHead,provePostCommitContinuationHead,type ContinuationFreshHeadRequest} from '../shared/continuation-fresh-head.ts';
import type {ContinuationAuthReadinessRequest} from '../shared/continuation-auth-readiness.ts';

interface Env {CUSTODIAN?:D1Database;PILOT_CUSTODY_MODE?:string;PILOT_CUSTODY_EXPIRES_AT?:string;
 PILOT_CUSTODY_PINS?:string;PILOT_CUSTODY_WITNESS_PKCS8_B64?:string;
 PILOT_CUSTODY_GENESIS_BIND_MODE?:string;PILOT_CUSTODY_GENESIS_BIND_EXPIRES_AT?:string;PILOT_CUSTODY_GENESIS_BIND_PINS?:string}
const denied=()=>new Error('pilot_custody_unavailable');
const now=()=>Math.floor(Date.now()/1000);
async function pin(v:unknown){
 exactFields(v,['keyId','publicKey']);
 if(typeof v.keyId!=='string'||typeof v.publicKey!=='string')throw denied();
 base64(v.publicKey,32,32);
 if(v.keyId!==await digest(v.publicKey))throw denied();
 return {keyId:v.keyId,publicKey:v.publicKey};
}
async function configure(e:Env){
 const {CUSTODIAN:database,PILOT_CUSTODY_EXPIRES_AT:end,PILOT_CUSTODY_PINS:raw,PILOT_CUSTODY_WITNESS_PKCS8_B64:secret}=e;
 if(e.PILOT_CUSTODY_MODE!=='continuation-v1'||!database||!end||!/^[0-9]{10}$/.test(end)||
    Number(end)<=now()||Number(end)-now()>604800||!raw||raw.length>16384||!secret)throw denied();
 const p:unknown=JSON.parse(raw);
 exactFields(p,['authority','witness','mainCommitAuthority','checkpointKeys','recoveryAuthorities','otherReleaseKeys']);
 const list=(x:unknown)=>{if(!Array.isArray(x)||x.length>16)throw denied();return Promise.all(x.map(pin));};
 const [authority,witness,mainCommitAuthority,checkpointKeys,recoveryAuthorities,otherReleaseKeys]=await Promise.all(
  [pin(p.authority),pin(p.witness),pin(p.mainCommitAuthority),list(p.checkpointKeys),list(p.recoveryAuthorities),list(p.otherReleaseKeys)]);
 const all=[authority,witness,mainCommitAuthority,...checkpointKeys,...recoveryAuthorities,...otherReleaseKeys];
 if(!checkpointKeys.length||new Set(all.map(k=>k.keyId)).size!==all.length)throw denied();
 base64(secret,48,48);
 const key=await crypto.subtle.importKey('pkcs8',Uint8Array.from(atob(secret),c=>c.charCodeAt(0)),'Ed25519',false,['sign']);
 const live=()=>{if(now()>=Number(end))throw denied();};
 const db={prepare:(sql:string)=>{live();return database.withSession('first-primary').prepare(sql);}};
 const signer={key:async()=>witness,sign:async(canonical:string)=>{live();
  return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(canonical)))));
 }};
 return {db,policy:{authority,witnessKeys:[witness],mainCommitAuthority,checkpointKeys,recoveryAuthorities,otherReleaseKeys},signer,live};
}
class Private extends WorkerEntrypoint<Env>{
 override async fetch(_request?:Request|string){return new Response(null,{status:404});}
}
export class PilotCustodyReadiness extends Private{
 async readiness(input:ContinuationAuthReadinessRequest){
  try{const {db,policy,signer,live}=await configure(this.env),result=await proveContinuationAuthReadiness(db,input,policy,signer);
   live();return result;}catch{throw denied();}
 }
}
export class PilotCustodyFresh extends Private{
 async fresh(input:ContinuationFreshHeadRequest){
  try{const {db,policy,signer,live}=await configure(this.env),result=await proveFreshContinuationHead(db,input,policy,signer);
   live();return result;}catch{throw denied();}
 }
}
export class PilotCustodyPost extends Private{
 async post(input:ContinuationFreshHeadRequest,prior:SignedManagedOperation,main:SignedManagedOperation){
  try{const {db,policy,signer,live}=await configure(this.env),result=await provePostCommitContinuationHead(db,input,prior,main,policy,signer);
   live();return result;}catch{throw denied();}
 }
}
/** Configure only as a private service binding of the exact isolated Pilot
 * Main. This entrypoint has no public route or signer; the caller cannot
 * supply pins or replace proof of original-device possession. */
export class PilotCustodyGenesisBindingReadback extends Private{
 async read(raw:unknown){
  try{
   const {CUSTODIAN:database,PILOT_CUSTODY_GENESIS_BIND_MODE:mode,
    PILOT_CUSTODY_GENESIS_BIND_EXPIRES_AT:end,PILOT_CUSTODY_GENESIS_BIND_PINS:encoded}=this.env;
   if(mode!=='main-binding-v1'||!database||!end||!/^\d{10}$/.test(end)||!encoded||encoded.length>8192)throw denied();
   const expiresAt=Number(end),start=now();
   if(expiresAt<=start||expiresAt-start>604800)throw denied();
   const fields:unknown=JSON.parse(encoded);
   exactFields(fields,['authority','witness','checkpointKeys','recoveryAuthorities']);
   const pins=(v:unknown)=>{if(!Array.isArray(v)||v.length>16)throw denied();return Promise.all(v.map(pin));};
   const [authority,witness,checkpointKeys,recoveryAuthorities]=await Promise.all(
    [pin(fields.authority),pin(fields.witness),pins(fields.checkpointKeys),pins(fields.recoveryAuthorities)]);
   const all=[authority,witness,...checkpointKeys,...recoveryAuthorities];
   if(!checkpointKeys.length||new Set(all.map(key=>key.publicKey)).size!==all.length||now()>=expiresAt)throw denied();
   const result=await readExactMainGenesisAdmission(database,raw,{authority,witness,checkpointKeys,recoveryAuthorities});
   const validUntil=Math.min(expiresAt,result.validUntil);
   if(now()>=validUntil)throw denied();
   return {...result,validUntil};
  }catch{throw denied();}
 }
}
export default {fetch(){return new Response(null,{status:404});}};
