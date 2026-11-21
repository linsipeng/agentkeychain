/** Closed synthetic Worker preview. Never part of a production build graph. */
import {WorkerEntrypoint} from 'cloudflare:workers';
import {continuationApprovalUi} from '../auth-trust-worker/experimental/continuation-ui.ts';
import {continuationIssuer} from '../auth-trust-worker/experimental/continuation-issuer.ts';
import type {CheckpointKey} from '../shared/checkpoints.ts';
import type {CustodyContinuationReadinessTransport} from './continuation-transport.fixture.ts';
import {rpcData} from '../shared/rpc-data.ts';

const origin='https://continuation-auth.fixture.invalid';
const identity={origin,rpId:'continuation-auth.fixture.invalid'};
interface Env {
 AUTH:D1Database;
 ROLE_KEY:string;
 PINS:string;
 CUSTODY_READY:CustodyContinuationReadinessTransport;
}
interface Pins {genesis:CheckpointKey;approval:CheckpointKey;checkpoint:CheckpointKey;witness:CheckpointKey}

export class AuthContinuationPreview extends WorkerEntrypoint<Env>{
 override async fetch(_req?:Request|string){return new Response(null,{status:404});}
 async preview(step:'begin'|'complete',headers:Record<string,string>,body:string){
  if(step!=='begin'&&step!=='complete')throw new Error('fixture_continuation_unavailable');
  const {AUTH:db,PINS,ROLE_KEY,CUSTODY_READY}=this.env,p=JSON.parse(PINS) as Pins;
  const privateKey=await crypto.subtle.importKey('pkcs8',Uint8Array.from(atob(ROLE_KEY),c=>c.charCodeAt(0)),'Ed25519',false,['sign']);
  const signature=async (value:string)=>btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(value)))));
  const issuer=continuationIssuer(db,identity,{
   genesis:{authority:p.genesis,checkpointKeys:[p.checkpoint],recoveryAuthorities:[]},authority:p.approval,witnesses:[p.witness],
  },{key:async()=>p.approval,sign:signature},request=>rpcData(CUSTODY_READY.readiness(request)));
  return continuationApprovalUi(origin,issuer)(new Request(origin+'/v1/auth/continuation-approval/'+step,{method:'POST',headers,body}));
 }
}
