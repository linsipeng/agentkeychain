import {exactFields,type SignedManagedOperation} from '../../../src/cloud/protocol.ts';
import type {CheckpointKey} from '../../shared/checkpoints.ts';
import {boundedBody,digest,verify} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {canonicalContinuationIntent,verifyContinuationApproval} from '../../shared/enrollment-continuation.ts';
import {canonicalHandoffStage,CONTINUATION_DEVICE_POLL_SECONDS,handoffDevicePollProof,handoffStageDigest,type ContinuationHandoffStage} from '../../shared/continuation-handoff-wire.ts';
import {continuationReadbackIntent} from './continuation-readback.ts';

const path='/v1/auth/continuation-handoff/poll';
const headers={'cache-control':'no-store','pragma':'no-cache'};
const opaque=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const reject=()=>Response.json({error:{code:'continuation_receipt_unavailable'}},{status:401,headers});
/** Isolated Auth readback for the original device only. A configured,
 * independently current Custody validator is mandatory. No grants, signer,
 * Auth cookies, mutations, or production route are provided by this helper. */
export function continuationDevicePoll(db:D1Database,authOrigin:string,authority:CheckpointKey,validateCurrentStage:(stage:ContinuationHandoffStage)=>Promise<void>){
 const url=new URL(authOrigin);
 if(url.protocol!=='https:'||url.origin!==authOrigin||typeof validateCurrentStage!=='function')throw new Error('invalid_auth_origin');
 return async(req:Request)=>{
  try{
   const u=new URL(req.url);
   if(u.origin!==authOrigin||u.pathname!==path||u.search||req.method!=='POST'||req.headers.has('origin')||req.headers.has('cookie')||
      req.headers.has('authorization')||req.headers.has('sec-fetch-site')||
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers.get('content-type')??''))return reject();
   const input:unknown=JSON.parse(await boundedBody(req,4096));
   exactFields(input,['locator','intentDigest','stageDigest','nonce','timestamp','signature']);
   const {locator,intentDigest,stageDigest,nonce,timestamp,signature}=input;
   const currentTimestamp=()=>Math.floor(Date.now()/1000);
   if(!opaque(locator)||!opaque(nonce)||!hash(intentDigest)||!hash(stageDigest)||typeof timestamp!=='number'||!Number.isSafeInteger(timestamp)||
      Math.abs(timestamp-currentTimestamp())>CONTINUATION_DEVICE_POLL_SECONDS||typeof signature!=='string'||signature.length>100)return reject();
   const stageRow=()=>db.prepare(`SELECT stage_json,claimed_session FROM auth_continuation_handoffs WHERE locator=? AND intent_digest=? AND exact_digest=? AND expires>unixepoch()`)
    .bind(locator,intentDigest,stageDigest).first<{stage_json:string;claimed_session:string|null}>();
   const first=await stageRow();
   if(!first)return reject();
   const stage=canonicalHandoffStage(JSON.parse(first.stage_json)),g=JSON.parse(stage.oldGrantCanonical) as EnrollmentGrant;
   const t=JSON.parse(stage.target.canonical);
   if(canonicalGrant(g)!==stage.oldGrantCanonical||g.issuerDeviceId!==null||canonicalContinuationIntent(t)!==stage.target.canonical||
      t.stage!=='put-key-package'||t.witnessHead?.revision!==1||await handoffStageDigest(stage)!==stageDigest||
      await digest(stage.target.canonical)!==intentDigest||
      !await verify(g.signingKey,signature,handoffDevicePollProof(locator,intentDigest,stageDigest,nonce,timestamp)))return reject();
   await validateCurrentStage(stage); // Fresh independent Custody proof, not historical witness.
   const verifiedStage=await stageRow();
   if(!verifiedStage||verifiedStage.stage_json!==first.stage_json||Math.abs(timestamp-currentTimestamp())>CONTINUATION_DEVICE_POLL_SECONDS)return reject();
   const pending=()=>Response.json({status:'pending'},{status:202,headers});
   if(!verifiedStage.claimed_session)return pending();
   const decision=await db.prepare('SELECT id FROM auth_continuation_decisions WHERE intent_digest=?').bind(intentDigest).first<{id:string}>();
   if(!decision)return pending();
   const grantDigest=await digest(stage.oldGrantCanonical), action=await continuationReadbackIntent(decision.id,grantDigest,intentDigest);
   const read=()=>db.prepare(`SELECT d.canonical,d.signature FROM auth_continuation_decisions d
    JOIN auth_continuation_challenges c ON c.id=d.id AND c.intent_digest=d.intent_digest
    JOIN auth_genesis_decisions old ON old.id=c.prior_decision_id AND old.grant_digest=?
    JOIN auth_genesis_pins p ON p.account=c.account AND p.tenant=c.tenant AND p.vault=c.vault AND p.credential=c.credential
    JOIN auth_continuation_browser_stages b ON b.challenge_id=c.id
    JOIN auth_genesis_view_sessions s ON s.session_digest=b.session_digest AND s.csrf_digest=b.csrf_digest AND s.account=c.account AND s.tenant=c.tenant AND s.vault=c.vault
    JOIN auth_continuation_view_grants v ON v.session_digest=s.session_digest AND v.credential=c.credential
    JOIN auth_continuation_handoffs h ON h.locator=? AND h.intent_digest=d.intent_digest AND h.exact_digest=? AND h.claimed_session=?
    WHERE d.id=? AND c.account=? AND c.tenant=? AND c.vault=? AND p.active=1 AND c.expires>unixepoch()
     AND h.expires>unixepoch() AND s.approval_reader=1 AND s.revoked=0 AND s.expires>unixepoch()
     AND v.intent_digest=? AND v.issued<=unixepoch() AND v.expires>unixepoch()`)
    .bind(grantDigest,locator,stageDigest,verifiedStage.claimed_session,decision.id,g.accountId,g.tenantId,g.vaultId,action).first<SignedManagedOperation>();
   const proof=await read();
   if(!proof)return reject();
   await verifyContinuationApproval(stage.target,proof,{oldGrantCanonical:stage.oldGrantCanonical,stage:'put-key-package',
    payloadDigest:t.payloadDigest,rosterDigest:t.rosterDigest,witnessHead:t.witnessHead,authority,issuer:null,now:currentTimestamp()});
   const again=await read();
   if((JSON.parse(proof.canonical) as {expiresAt:number}).expiresAt<=currentTimestamp()||!again||again.canonical!==proof.canonical||again.signature!==proof.signature||Math.abs(timestamp-currentTimestamp())>CONTINUATION_DEVICE_POLL_SECONDS)return reject();
   return Response.json({status:'approved',approval:proof},{headers});
  }catch{return reject();}
 };
}
