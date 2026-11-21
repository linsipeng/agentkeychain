import {exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import type {CheckpointKey} from '../../shared/checkpoints.ts';
import {boundedBody,digest} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {canonicalContinuationIntent,verifyContinuationApproval} from '../../shared/enrollment-continuation.ts';

const path='/v1/auth/continuation-receipt';
const sessionCookie='__Host-akc_genesis_session';
const csrfCookie='__Host-akc_genesis_csrf';
const headers={'cache-control':'no-store','pragma':'no-cache'};
const reject=()=>Response.json({error:{code:'continuation_receipt_unavailable'}},{status:401,headers});
const isOpaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
function cookie(h:Headers,name:string){
 const candidates=(h.get('cookie')??'').split(';').map(v=>v.trim()).filter(v=>v.startsWith(name+'='));
 const value=candidates[0]?.slice(name.length+1);
 if(candidates.length!==1||!isOpaque(value))throw new Error('invalid');
 return value;
}
/** An independently authenticated Auth UI may pre-scope its own current
 * session to the exact staged ceremony and its pinned credential before the
 * final POST. Readback still requires a committed matching decision. No
 * production mint exists. */
export const continuationReadbackIntent=(id:string,grantDigest:string,intentDigest:string)=>
 digest(JSON.stringify(['AgentKeychain-continuation-receipt-readback-v1',id,grantDigest,intentDigest]));
/** Unwired, read-only Auth receipt recovery. Access to an existing decision
 * never mints an approval or proves current Custodian head/package commitment.
 * No session, grant, approval, signer, or production route is created here. */
export function continuationReadback(db:D1Database,origin:string,authority:CheckpointKey){
 const configured=new URL(origin);
 if(configured.protocol!=='https:'||configured.origin!==origin)throw new Error('invalid_auth_origin');
 return async(req:Request)=>{
  try{
   const url=new URL(req.url);
   if(url.origin!==origin||url.pathname!==path||url.search||req.method!=='POST'||req.headers.get('origin')!==origin||
     req.headers.get('sec-fetch-site')==='cross-site'||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers.get('content-type')??''))return reject();
   const session=await digest(cookie(req.headers,sessionCookie)),csrf=cookie(req.headers,csrfCookie);
   if(req.headers.get('x-csrf-token')!==csrf)return reject();
   const input:unknown=JSON.parse(await boundedBody(req,12288));
   exactFields(input,['decisionId','oldGrantCanonical','target']);
   const {decisionId,oldGrantCanonical,target}=input;
   if(!isOpaque(decisionId)||typeof oldGrantCanonical!=='string'||oldGrantCanonical.length>4096)return reject();
   const g=JSON.parse(oldGrantCanonical) as EnrollmentGrant;
   if(canonicalGrant(g)!==oldGrantCanonical||g.issuerDeviceId!==null)return reject();
   exactFields(target,['canonical','signature']);
   if(typeof target.canonical!=='string'||target.canonical.length>4096||typeof target.signature!=='string'||target.signature.length>100)return reject();
   const intent=JSON.parse(target.canonical);
   if(canonicalContinuationIntent(intent)!==target.canonical||intent.stage!=='put-key-package'||intent.witnessHead?.revision!==1)return reject();
   const intentDigest=await digest(target.canonical),grantDigest=await digest(oldGrantCanonical),csrfDigest=await digest(csrf);
   const action=await continuationReadbackIntent(decisionId,grantDigest,intentDigest);
   const read=()=>db.prepare(`SELECT d.canonical,d.signature FROM auth_continuation_decisions d
    JOIN auth_continuation_challenges c ON c.id=d.id AND c.intent_digest=d.intent_digest
    JOIN auth_genesis_decisions old ON old.id=c.prior_decision_id
    JOIN auth_genesis_pins p USING(account,tenant,vault,credential)
    JOIN auth_genesis_view_sessions s ON s.account=c.account AND s.tenant=c.tenant AND s.vault=c.vault
    JOIN auth_continuation_view_grants v ON v.session_digest=s.session_digest
    WHERE d.id=? AND d.intent_digest=? AND old.grant_digest=? AND c.account=? AND c.tenant=? AND c.vault=?
     AND p.active=1 AND c.expires>unixepoch() AND s.session_digest=? AND s.csrf_digest=?
     AND s.approval_reader=1 AND s.revoked=0 AND s.expires>unixepoch()
     AND v.credential=c.credential AND v.intent_digest=? AND v.issued<=unixepoch() AND v.expires>unixepoch()`)
    .bind(decisionId,intentDigest,grantDigest,g.accountId,g.tenantId,g.vaultId,session,csrfDigest,action)
    .first<SignedManagedOperation>();
   const proof=await read();if(!proof)return reject();
   // The cryptographic check is against the exact recorded stage. Fresh
   // independent current-head checks are mandatory again at actual consumption.
   await verifyContinuationApproval(target as unknown as SignedManagedOperation,proof,{oldGrantCanonical,stage:'put-key-package',
    payloadDigest:intent.payloadDigest,rosterDigest:intent.rosterDigest,witnessHead:intent.witnessHead,authority,issuer:null,now:Math.floor(Date.now()/1000)});
   const current=await read();
   if(!current||current.canonical!==proof.canonical||current.signature!==proof.signature)return reject();
   return Response.json(proof,{headers});
  }catch{return reject();}
 };
}
