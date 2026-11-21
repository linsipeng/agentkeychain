import type {RegistrationResponseJSON,AuthenticationResponseJSON} from '@simplewebauthn/server';
import {exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {random} from '../../api-worker/webauthn.ts';
import {boundedBody,digest} from '../../shared/contracts.ts';
import type {pilotGenesisRegistration} from './pilot-genesis-registration.ts';

import type {pilotGenesisConsent} from './pilot-genesis-consent.ts';

export const PILOT_GENESIS_CONSENT_PATH='/v1/auth/pilot-genesis/consent';
export const PILOT_GENESIS_REGISTER_PATH='/v1/auth/pilot-genesis/registration';
const cookie='__Host-akc_pilot_genesis_registration';
const opaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const headers={'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};
const deny=()=>Response.json({error:{code:'pilot_genesis_registration_unavailable'}},{status:401,headers});
function operation(v:unknown):SignedManagedOperation{
 exactFields(v,['canonical','signature']);
 if(typeof v.canonical!=='string'||typeof v.signature!=='string')throw new Error('invalid_stage');
 return {canonical:v.canonical,signature:v.signature};
}

/** Scoped invitation registration, not login, consent, credential recovery or
 * GenesisApproval issuance. No invitation in the URL, no cookie accepted on
 * begin, and completion binds both the server-generated cookie and CSRF token. */
export function pilotGenesisRegistrationHttp(origin:string,deadline:number,kernel:ReturnType<typeof pilotGenesisRegistration>,consent?:ReturnType<typeof pilotGenesisConsent>){
 const initial=new URL(origin);
 if(initial.protocol!=='https:'||origin!==initial.origin||initial.port||!initial.hostname.startsWith('auth-pilot-')||
    !Number.isSafeInteger(deadline))throw new Error('invalid_pilot_origin');
 return async(req:Request):Promise<Response>=>{
  try{
   const unixNow=()=>Math.floor(Date.now()/1000),u=new URL(req.url);
   const begin=u.pathname===PILOT_GENESIS_REGISTER_PATH+'/begin',complete=u.pathname===PILOT_GENESIS_REGISTER_PATH+'/complete';
   const start=u.pathname===PILOT_GENESIS_CONSENT_PATH+'/begin',finish=u.pathname===PILOT_GENESIS_CONSENT_PATH+'/complete',
    read=u.pathname===PILOT_GENESIS_CONSENT_PATH+'/readback';
   if(unixNow()>=deadline||req.method!=='POST'||u.origin!==origin||u.search||req.url.includes('?')||(!begin&&!complete&&(!consent||(!start&&!finish&&!read)))||
      req.headers.get('origin')!==origin||req.headers.get('sec-fetch-site')!=='same-origin'||
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers.get('content-type')??'')||req.headers.has('authorization'))return deny();
   const body:unknown=JSON.parse(await boundedBody(req,60_000));
   exactFields(body,['invite','oldGrantCanonical','roster',...(complete||finish?['response']:[]),...(finish||read?['id']:[])]);
   if(typeof body.oldGrantCanonical!=='string')return deny();
   const invite=operation(body.invite),roster=operation(body.roster),grant=body.oldGrantCanonical;
   const browser=(req.headers.get('cookie')??'').split(';').map(x=>x.trim()).filter(x=>x.startsWith(cookie+'='));
   if(begin){
    if(browser.length||req.headers.has('x-csrf-token'))return deny();
    const session=random(),csrf=random();
    const options=await kernel.begin(invite,grant,roster,await digest(JSON.stringify([session,csrf])));
    if(unixNow()>=deadline)return deny();
    options.timeout=Math.min(options.timeout??120_000,120_000);
    return Response.json({options,csrf},{headers:{...headers,'set-cookie':cookie+'='+session+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=120'}});
   }
   const session=browser[0]?.slice(cookie.length+1),csrf=req.headers.get('x-csrf-token');
   if(browser.length!==1||!opaque(session)||!opaque(csrf))return deny();
   const browserDigest=await digest(JSON.stringify([session,csrf]));
   if(unixNow()>=deadline)return deny();
   if(start&&consent)return Response.json(await consent.begin(invite,grant,roster,browserDigest),{headers});
   if(finish||read){
    if(!consent||!opaque(body.id))return deny();
    const proof=finish?await consent.complete(invite,grant,roster,browserDigest,body.id,body.response as AuthenticationResponseJSON):
     await consent.readback(invite,grant,roster,browserDigest,body.id);
    return Response.json(proof,{headers});
   }
   await kernel.complete(invite,grant,roster,browserDigest,body.response as RegistrationResponseJSON);
   return new Response(null,{status:204,headers});
  }catch{return deny();}
 };
}
