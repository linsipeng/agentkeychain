/** Private ingress for an isolated staging graph. Not exported by any live worker. */
import {WorkerEntrypoint} from 'cloudflare:workers';
import {base64,exactFields} from '../../src/cloud/protocol.ts';
import type {CheckpointKey} from '../shared/checkpoints.ts';
import type {ContinuationAuthReadinessRequest} from '../shared/continuation-auth-readiness.ts';
import {proveContinuationAuthReadiness} from '../shared/continuation-fresh-head.ts';
import {digest} from '../shared/contracts.ts';

const closed=()=>new Error('continuation_head_rejected');
interface Env {
 CUSTODIAN:D1Database;
 CONTINUATION_READINESS_PINS:string;
 CONTINUATION_WITNESS_PKCS8_B64:string;
}
export interface CustodyReadinessPort {
 readiness(input:ContinuationAuthReadinessRequest):ReturnType<typeof proveContinuationAuthReadiness>;
}

async function pin(value:unknown):Promise<CheckpointKey>{
 exactFields(value,['keyId','publicKey']);
 if(typeof value.keyId!=='string'||typeof value.publicKey!=='string')throw closed();
 base64(value.publicKey,32,32);
 if(value.keyId!==await digest(value.publicKey))throw closed();
 return {keyId:value.keyId,publicKey:value.publicKey};
}

export class CustodyContinuationReadinessTransport extends WorkerEntrypoint<Env> implements CustodyReadinessPort {
 override async fetch(_request?:Request|string){return new Response(null,{status:404});}
 async readiness(input:ContinuationAuthReadinessRequest){
  try{
   const raw=this.env.CONTINUATION_READINESS_PINS;
   if(typeof raw!=='string'||raw.length>16*1024)throw closed();
   const config:unknown=JSON.parse(raw);
   exactFields(config,['authority','witness','checkpointKeys','recoveryAuthorities']);
   if(!Array.isArray(config.checkpointKeys)||!config.checkpointKeys.length||!Array.isArray(config.recoveryAuthorities))throw closed();
   const authority=await pin(config.authority),witness=await pin(config.witness),
    checkpointKeys=await Promise.all(config.checkpointKeys.map(pin)),recoveryAuthorities=await Promise.all(config.recoveryAuthorities.map(pin));
   const all=[authority,witness,...checkpointKeys,...recoveryAuthorities];
   if(new Set(all.map(k=>k.keyId)).size!==all.length)throw closed();
   const encoded=this.env.CONTINUATION_WITNESS_PKCS8_B64;
   base64(encoded,48,48); // Raw Ed25519 PKCS#8 from the Custody secret store.
   const privateKey=await crypto.subtle.importKey('pkcs8',Uint8Array.from(atob(encoded),c=>c.charCodeAt(0)),'Ed25519',false,['sign']);
   return await proveContinuationAuthReadiness(this.env.CUSTODIAN,input,{authority,witnessKeys:[witness],checkpointKeys,recoveryAuthorities},{
    key:async()=>witness,
    sign:async canonical=>btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(canonical))))),
   });
  }catch{throw closed();}
 }
}

export default {fetch(){return new Response(null,{status:404});}};
