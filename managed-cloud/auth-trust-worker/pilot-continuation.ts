/** Separate continuation-only Worker. The normal Auth entrypoint does not import it. */
import {base64,exactFields} from '../../src/cloud/protocol.ts';
import {digest} from '../shared/contracts.ts';
import type {CheckpointKey,CheckpointSigner} from '../shared/checkpoints.ts';
import {rpcData} from '../shared/rpc-data.ts';
import type {CustodyReadinessPort} from '../custody-trust-worker/continuation-readiness.ts';
import {continuationIssuer} from './experimental/continuation-issuer.ts';
import {continuationApprovalUi} from './experimental/continuation-ui.ts';
import {continuationApprovalSurface} from './experimental/continuation-page.ts';
import {continuationHandoff} from './experimental/continuation-handoff.ts';
import {continuationReadback} from './experimental/continuation-readback.ts';
import {continuationDevicePoll} from './experimental/continuation-device-poll.ts';

declare const AKC_PILOT_BROWSER_BUNDLE:string;

interface Env {
 AUTH:D1Database;
 PILOT_AUTH_MODE:string;
 PILOT_AUTH_ORIGIN:string;
 PILOT_AUTH_EXPIRES_AT:string;
 PILOT_AUTH_PINS:string;
 PILOT_APPROVAL_SIGNER:CheckpointSigner;
 PILOT_CUSTODY_READINESS:CustodyReadinessPort;
 PILOT_HANDOFF_HMAC:string;
}
const paths=new Map([
 ['/continuation/approve','GET'],['/continuation/approve/browser.js','GET'],
 ['/v1/auth/continuation-handoff/prepare','POST'],['/v1/auth/continuation-handoff/browser','POST'],
 ['/v1/auth/continuation-handoff/claim','POST'],['/v1/auth/continuation-handoff/poll','POST'],
 ['/v1/auth/continuation-approval/begin','POST'],['/v1/auth/continuation-approval/complete','POST'],
 ['/v1/auth/continuation-receipt','POST'],
]);
const reject=()=>new Error('pilot_continuation_unavailable');
const closed=()=>new Response(null,{status:404,headers:{'cache-control':'no-store','referrer-policy':'no-referrer'}});
const now=()=>Math.floor(Date.now()/1000);

async function pin(value:unknown):Promise<CheckpointKey>{
 exactFields(value,['keyId','publicKey']);
 base64(value.publicKey,32,32);
 if(value.keyId!==await digest(value.publicKey))throw reject();
 return {keyId:value.keyId,publicKey:value.publicKey};
}
async function pins(raw:string){
 if(typeof raw!=='string'||raw.length>16*1024)throw reject();
 const p:unknown=JSON.parse(raw);
 exactFields(p,['genesis','approval','checkpointKeys','recoveryAuthorities','witnesses']);
 const list=async(value:unknown,min:number)=>{
  if(!Array.isArray(value)||value.length<min||value.length>16)throw reject();
  return Promise.all(value.map(pin));
 };
 const [genesis,approval,checkpointKeys,recoveryAuthorities,witnesses]=await Promise.all([
  pin(p.genesis),pin(p.approval),list(p.checkpointKeys,1),list(p.recoveryAuthorities,0),list(p.witnesses,1),
 ]);
 const all=[genesis,approval,...checkpointKeys,...recoveryAuthorities,...witnesses];
 if(new Set(all.map(x=>x.keyId)).size!==all.length)throw reject();
 return {genesis:{authority:genesis,checkpointKeys,recoveryAuthorities},authority:approval,witnesses};
}

export default {
 async fetch(req:Request,env:Env):Promise<Response>{
  try{
   if(env.PILOT_AUTH_MODE!=='continuation-v1'||!/^\d{10}$/.test(env.PILOT_AUTH_EXPIRES_AT))return closed();
   const deadline=Number(env.PILOT_AUTH_EXPIRES_AT),seconds=now();
   if(deadline<=seconds||deadline-seconds>7*86400)return closed();
   const u=new URL(req.url),origin=env.PILOT_AUTH_ORIGIN;
   if(u.protocol!=='https:'||u.origin!==origin||u.port||u.search||req.url.includes('?')||
      !/^auth-pilot-[a-z0-9]+(?:-[a-z0-9]+)*\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(u.hostname)||
      paths.get(u.pathname)!==req.method)return closed();
   if(!env.AUTH||typeof env.AUTH.prepare!=='function'||
      typeof env.PILOT_APPROVAL_SIGNER?.key!=='function'||typeof env.PILOT_APPROVAL_SIGNER?.sign!=='function'||
      typeof env.PILOT_CUSTODY_READINESS?.readiness!=='function')return closed();
   const policy=await pins(env.PILOT_AUTH_PINS),signer=env.PILOT_APPROVAL_SIGNER;
   const signerPin=await pin(await rpcData(signer.key()));
   if(signerPin.keyId!==policy.authority.keyId||signerPin.publicKey!==policy.authority.publicKey||now()>=deadline)return closed();
   base64(env.PILOT_HANDOFF_HMAC,32,32);
   const secret=Uint8Array.from(atob(env.PILOT_HANDOFF_HMAC),c=>c.charCodeAt(0));
   let macKey:CryptoKey;
   try{macKey=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-256'},false,['sign']);}
   finally{secret.fill(0);}
   const issuer=continuationIssuer(env.AUTH,{origin,rpId:u.hostname},policy,{
    key:async()=>signerPin,
    sign:async(value)=>{if(now()>=deadline)throw reject();return signer.sign(value);},
   },input=>{if(now()>=deadline)throw reject();return rpcData(env.PILOT_CUSTODY_READINESS.readiness(input));});
   if(now()>=deadline)return closed();
   return await continuationApprovalSurface(origin,AKC_PILOT_BROWSER_BUNDLE,
    continuationApprovalUi(origin,issuer),
    continuationReadback(env.AUTH,origin,policy.authority),
    continuationHandoff(env.AUTH,origin,macKey,issuer.assertStageForHandoff),
    continuationDevicePoll(env.AUTH,origin,policy.authority,issuer.assertStageForHandoff))(req);
  }catch{return closed();}
 },
};
