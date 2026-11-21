import type {SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import {exactFields} from '../../../src/cloud/protocol.ts';
import {boundedBody,digest,verify} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {canonicalContinuationIntent} from '../../shared/enrollment-continuation.ts';
import {random} from '../../api-worker/webauthn.ts';
import type {StageInput} from './continuation-issuer.ts';

const prefix='/v1/auth/continuation-handoff/';
const browserCookie='__Host-akc_handoff',csrfCookie='__Host-akc_handoff_csrf';
const opaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const unavailable=()=>Response.json({error:{code:'continuation_handoff_unavailable'}},{status:401,headers:{'cache-control':'no-store'}});
function cookie(headers:Headers,name:string){
 const tokens=(headers.get('cookie')??'').split(';').map(x=>x.trim()).filter(x=>x.startsWith(name+'='));
 const value=tokens[0]?.slice(name.length+1);
 if(tokens.length!==1||!opaque(value))throw new Error('not_available');
 return value;
}
export const handoffCodeDigest=(locator:string,code:string)=>digest(JSON.stringify(['AgentKeychain-continuation-handoff-code-v1',locator,code]));
export const handoffPrepareProof=(locator:string,codeDigest:string,stageDigest:string,expiresAt:number)=>
 JSON.stringify(['AgentKeychain-continuation-handoff-prepare-v1',locator,codeDigest,stageDigest,expiresAt]);
function signed(value:unknown,cap:number):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||value.canonical.length>cap||typeof value.signature!=='string'||value.signature.length>100)throw new Error('not_available');
 return {canonical:value.canonical,signature:value.signature};
}
function stage(value:unknown):StageInput{
 exactFields(value,['oldGrantCanonical','target','roster','keyPackage']);
 if(typeof value.oldGrantCanonical!=='string'||value.oldGrantCanonical.length>4096)throw new Error('not_available');
 return {oldGrantCanonical:value.oldGrantCanonical,target:signed(value.target,4096),roster:signed(value.roster,16384),keyPackage:signed(value.keyPackage,4096)};
}
export const handoffStageDigest=(value:unknown)=>digest(JSON.stringify(stage(value)));
/** Isolated Auth handler only. The operator supplies Auth-owned scope/readiness
 * validation and a purpose-specific HMAC key. The public routing ID grants no
 * access. Browser pairing claims only an exact staged artifact, not Auth login. */
export function continuationHandoff(db:D1Database,authOrigin:string,macKey:CryptoKey,validateStage:(stage:StageInput)=>Promise<void>){
 const origin=new URL(authOrigin);
 const alg=macKey.algorithm as HmacKeyAlgorithm;
 if(origin.protocol!=='https:'||origin.origin!==authOrigin||macKey.type!=='secret'||alg.name!=='HMAC'||alg.hash?.name!=='SHA-256'||alg.length<256||macKey.extractable||!macKey.usages.includes('sign'))
  throw new Error('invalid_handoff_config');
 const codeMac=async(value:string)=>Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',macKey,new TextEncoder().encode(value))),x=>x.toString(16).padStart(2,'0')).join('');
 return async(req:Request)=>{
  try{
   const url=new URL(req.url),route=url.pathname.slice(prefix.length);
   if(url.origin!==authOrigin||url.search||req.method!=='POST'||!url.pathname.startsWith(prefix)||!['prepare','browser','claim'].includes(route)||
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers.get('content-type')??''))return unavailable();
   if(route!=='prepare'&&(req.headers.get('origin')!==authOrigin||req.headers.get('sec-fetch-site')==='cross-site'))return unavailable();
   if(route==='prepare'&&(req.headers.has('origin')||req.headers.has('cookie')))return unavailable();
   const input:unknown=JSON.parse(await boundedBody(req,route==='prepare'?70_000:1024));
   if(route==='prepare'){
    exactFields(input,['locator','codeDigest','stage','expiresAt','signature']);
    const {locator,codeDigest,expiresAt,signature}=input;
    const now=Math.floor(Date.now()/1000);
    if(!opaque(locator)||!hash(codeDigest)||typeof expiresAt!=='number'||!Number.isSafeInteger(expiresAt)||expiresAt<=now||expiresAt>now+120||
       typeof signature!=='string'||signature.length>100)return unavailable();
    const view=stage(input.stage),g=JSON.parse(view.oldGrantCanonical) as EnrollmentGrant,t=JSON.parse(view.target.canonical);
    const grantDigest=await digest(view.oldGrantCanonical),intent=await digest(view.target.canonical),exact=await handoffStageDigest(view);
    if(canonicalGrant(g)!==view.oldGrantCanonical||canonicalContinuationIntent(t)!==view.target.canonical||g.issuerDeviceId!==null||g.expiresAt>now||
       t.stage!=='put-key-package'||t.originalGrantDigest!==grantDigest||expiresAt>t.expiresAt||
       !await verify(g.signingKey,view.target.signature,view.target.canonical)||
       !await verify(g.signingKey,signature,handoffPrepareProof(locator,codeDigest,exact,expiresAt)))return unavailable();
    await validateStage(view);
    const mac=await codeMac(codeDigest);
    const [,res]=await db.batch<{exact_digest:string;code_mac:string;expires:number}>([
     db.prepare(`INSERT INTO auth_continuation_handoffs(locator,intent_digest,exact_digest,code_mac,stage_json,expires)
      SELECT ?,?,?,?,?,? WHERE ?>unixepoch() ON CONFLICT(locator) DO NOTHING`).bind(locator,intent,exact,mac,JSON.stringify(view),expiresAt,expiresAt),
     db.prepare('SELECT exact_digest,code_mac,expires FROM auth_continuation_handoffs WHERE locator=? AND intent_digest=? AND expires>unixepoch()').bind(locator,intent),
    ]);
    const row=res?.results[0];
    if(!row||row.exact_digest!==exact||row.code_mac!==mac||row.expires!==expiresAt)return unavailable();
    return Response.json({locator},{headers:{'cache-control':'no-store'}});
   }
   if(route==='browser'){
    exactFields(input,['locator']);
    if(!opaque(input.locator))return unavailable();
    try{
     const token=await digest(cookie(req.headers,browserCookie)),anti=await digest(cookie(req.headers,csrfCookie));
     const known=await db.prepare(`SELECT 1 FROM auth_continuation_handoff_browsers b JOIN auth_continuation_handoffs h ON h.locator=b.locator
      WHERE b.locator=? AND b.session_digest=? AND b.csrf_digest=? AND min(b.expires,h.expires)>unixepoch()
       AND (h.claimed_session IS NULL OR h.claimed_session=b.session_digest)`).bind(input.locator,token,anti).first();
     if(known)return Response.json({ready:true},{headers:{'cache-control':'no-store'}});
    }catch{/* No staged cookies yet; create server-generated browser scope. */}
    const token=random(),anti=random();
    const row=await db.prepare(`INSERT INTO auth_continuation_handoff_browsers
     SELECT ?,?,locator,expires FROM auth_continuation_handoffs WHERE locator=? AND expires>unixepoch() AND claimed_session IS NULL
     RETURNING locator`).bind(await digest(token),await digest(anti),input.locator).first();
    if(!row)return unavailable();
    const headers=new Headers({'cache-control':'no-store'});
    headers.append('set-cookie',browserCookie+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=120');
    headers.append('set-cookie',csrfCookie+'='+anti+'; Path=/; Secure; SameSite=Strict; Max-Age=120');
    return Response.json({ready:true},{headers});
   }
   exactFields(input,['locator','pairCode']);
   const {locator,pairCode}=input;
   if(!opaque(locator)||typeof pairCode!=='string'||!/^[0-9]{8}$/.test(pairCode))return unavailable();
   const anti=cookie(req.headers,csrfCookie);
   if(req.headers.get('x-csrf-token')!==anti)return unavailable();
   const session=await digest(cookie(req.headers,browserCookie)),csrf=await digest(anti),mac=await codeMac(await handoffCodeDigest(locator,pairCode));
   const [,read]=await db.batch<{stage_json:string}>([
    db.prepare(`UPDATE auth_continuation_handoffs SET attempts=attempts+1,claimed_session=CASE WHEN code_mac=? THEN ? ELSE NULL END
     WHERE locator=? AND expires>unixepoch() AND claimed_session IS NULL AND attempts<5 AND EXISTS(
      SELECT 1 FROM auth_continuation_handoff_browsers b WHERE b.locator=? AND b.session_digest=? AND b.csrf_digest=? AND b.expires>unixepoch())`)
     .bind(mac,session,locator,locator,session,csrf),
    db.prepare(`SELECT h.stage_json FROM auth_continuation_handoffs h JOIN auth_continuation_handoff_browsers b
     ON b.locator=h.locator AND b.session_digest=h.claimed_session
     WHERE h.locator=? AND h.code_mac=? AND b.session_digest=? AND b.csrf_digest=? AND min(h.expires,b.expires)>unixepoch()`)
     .bind(locator,mac,session,csrf),
   ]);
   if(!read?.results[0])return unavailable();
   return Response.json({stage:JSON.parse(read.results[0].stage_json)},{headers:{'cache-control':'no-store'}});
  }catch{return unavailable();}
 };
}
