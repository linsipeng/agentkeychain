/** Explicit pilot bundle. No regular API routes or fallback capabilities. */
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {authenticate} from './auth.ts';
import post from './pilot-continuation-post.ts';
import {consumeGenesisPackageContinuation} from './genesis-package-continuation.ts';
import {provePilotGenesisPackageCommit} from './genesis-package-continuation-readback.ts';
import {genesisRoot,type CheckpointKey,type CheckpointSigner} from '../shared/checkpoints.ts';
import {boundedBody,digest,verify} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {CONTINUATION_HEAD_DOMAIN} from '../shared/continuation-fresh-head.ts';
import {verifyContinuationApproval} from '../shared/enrollment-continuation.ts';
import {parseRoster,rosterDigest} from '../shared/roster.ts';
import {verifyWitness} from '../shared/roster-witness.ts';
import {rpcData} from '../shared/rpc-data.ts';
import {PILOT_COMMIT_PATH,PILOT_POST_PROOF_PATH,PILOT_PREFLIGHT_PATH,pilotCommitInput,pilotPreflightInput,pilotProofEnvelope} from '../shared/pilot-continuation-post-wire.ts';

type Exact=ReturnType<typeof pilotPreflightInput>['request'];
type Evidence={witness:SignedManagedOperation;freshHead:SignedManagedOperation};
type Env=Parameters<typeof post.fetch>[1]&{
 PILOT_MAIN_APPROVAL_PIN?:string;PILOT_MAIN_COMMIT_PIN?:string;PILOT_MAIN_SIGNER?:CheckpointSigner;
 PILOT_CUSTODY_FRESH?:{fresh(request:Exact):Promise<Evidence>};
};
const denied=()=>new Response(null,{status:404,headers:{'cache-control':'no-store'}});
const fail=()=>new Error('pilot_continuation_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const signedHash=(s:SignedManagedOperation)=>digest(JSON.stringify([s.canonical,s.signature]));
async function pin(raw:string|undefined):Promise<CheckpointKey>{
 if(!raw||raw.length>1024)throw fail();
 const p:unknown=JSON.parse(raw);exactFields(p,['keyId','publicKey']);
 if(typeof p.keyId!=='string'||typeof p.publicKey!=='string')throw fail();
 base64(p.publicKey,32,32);if(p.keyId!==await digest(p.publicKey))throw fail();
 return {keyId:p.keyId,publicKey:p.publicKey};
}
async function verifiedExact(input:Exact,evidence:unknown,g:EnrollmentGrant,witnessPin:CheckpointKey,authority:CheckpointKey){
 exactFields(evidence,['witness','freshHead']);
 const witness=pilotProofEnvelope(evidence.witness,4096),freshHead=pilotProofEnvelope(evidence.freshHead,2048);
 const rosterHash=await rosterDigest(input.roster),w=await verifyWitness(witness,[witnessPin],
  {accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:rosterHash});
 if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(g.tenantId,g.vaultId))throw fail();
 const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',input.keyPackage.canonical,input.keyPackage.signature]));
 await verifyContinuationApproval(input.target,input.approval,{oldGrantCanonical:input.grant,stage:'put-key-package',
  payloadDigest,rosterDigest:rosterHash,witnessHead:{revision:1,digest:rosterHash},authority,issuer:null,now:now()});
 const a=JSON.parse(input.approval.canonical) as {approvedAt:number;expiresAt:number};
 const f:unknown=JSON.parse(freshHead.canonical);
 exactFields(f,['domain','keyId','nonce','requestId','witnessDigest','approvalDigest','payloadDigest','issuedAt','expiresAt']);
 if(typeof f.issuedAt!=='number'||typeof f.expiresAt!=='number'||!Number.isSafeInteger(f.issuedAt)||!Number.isSafeInteger(f.expiresAt)||
    f.issuedAt<a.approvedAt||f.issuedAt>now()||f.expiresAt<=now()||f.expiresAt>a.expiresAt||f.expiresAt-f.issuedAt>60||
    freshHead.canonical!==JSON.stringify({domain:CONTINUATION_HEAD_DOMAIN,keyId:witnessPin.keyId,nonce:input.nonce,requestId:g.requestId,
     witnessDigest:await signedHash(witness),approvalDigest:await signedHash(input.approval),payloadDigest,issuedAt:f.issuedAt,expiresAt:f.expiresAt})||
    !await verify(witnessPin.publicKey,freshHead.signature,freshHead.canonical))throw fail();
 return {evidence:{witness,freshHead},expiresAt:f.expiresAt};
}
export default {async fetch(request:Request,env:Env):Promise<Response>{
 try{
  const url=new URL(request.url);
  if(url.pathname===PILOT_POST_PROOF_PATH)return post.fetch(request,env);
  const db=env.MAIN,custody=env.PILOT_CUSTODY_FRESH,origin=env.PILOT_MAIN_ORIGIN,end=env.PILOT_MAIN_EXPIRES_AT;
  const isCommit=url.pathname===PILOT_COMMIT_PATH;
  if(env.PILOT_MAIN_MODE!=='continuation-v1'||!db||!custody||typeof custody.fresh!=='function'||!origin||
     !end||!/^[0-9]{10}$/.test(end)||Number(end)<=now()||Number(end)>now()+7*86400||(!isCommit&&url.pathname!==PILOT_PREFLIGHT_PATH))return denied();
  const host=new URL(origin);
  if(host.origin!==origin||host.protocol!=='https:'||host.port||!/^api\.web-pilot-[a-z0-9](?:[a-z0-9-]{0,39}[a-z0-9])?\./.test(host.hostname)||
     url.origin!==origin||url.username||url.password||url.search||url.hash||request.method!=='POST'||request.headers.has('cookie')||request.headers.has('origin')||
     !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type')??''))return denied();
  const raw=await boundedBody(request,64*1024),parsed:unknown=JSON.parse(raw);
  const commit=isCommit?pilotCommitInput(parsed):null,selected=commit??pilotPreflightInput(parsed),input=selected.request;
  if(JSON.stringify(selected)!==raw)return denied();
  const g=JSON.parse(input.grant) as EnrollmentGrant;
  if(canonicalGrant(g)!==input.grant||g.issuerDeviceId!==null||g.expiresAt>now())return denied();
  const witness=await pin(env.PILOT_CUSTODY_WITNESS),authority=await pin(env.PILOT_MAIN_APPROVAL_PIN),main=await pin(env.PILOT_MAIN_COMMIT_PIN);
  const r=parseRoster(input.roster),otherReleaseKeys=[...r.checkpointKeys,...r.recoveryAuthorities];
  const contentKeys=[witness.publicKey,authority.publicKey,main.publicKey,g.signingKey,g.wrappingKey];
  if(new Set(contentKeys).size!==5||otherReleaseKeys.some(p=>contentKeys.includes(p.publicKey)||[witness,authority,main].some(k=>k.keyId===p.keyId)))return denied();
  const primary=()=>db.withSession('first-primary');
  const scoped=async()=>{
   const scope=await authenticate(primary(),request,g.vaultId,raw);
   if(scope.accountId!==g.accountId||scope.tenantId!==g.tenantId||scope.deviceId!==g.deviceId||
      scope.vaultId!==g.vaultId||scope.publicKey!==g.signingKey||Math.abs(now()-scope.timestamp)>=30)throw fail();
   const live=await primary().prepare(`
    SELECT 1 FROM enrollment_grants g
    JOIN device_requests q ON q.id=g.id AND q.tenant_id=g.tenant_id AND q.vault_id=g.vault_id AND q.device_id=g.device_id
     AND q.key_epoch=g.key_epoch AND q.state IN ('approved','delivered')
    JOIN device_keys k ON k.tenant_id=g.tenant_id AND k.device_id=g.device_id AND k.wrapping_key=q.wrapping_key
    WHERE g.id=? AND g.canonical=? AND g.tenant_id=? AND g.vault_id=? AND g.device_id=? AND q.account_id=?
     AND q.signing_key=? AND q.wrapping_key=? AND g.issuer_device_id IS NULL
     AND NOT EXISTS(SELECT 1 FROM device_revocation_boundaries b WHERE b.tenant_id=g.tenant_id AND b.vault_id=g.vault_id AND b.device_id=g.device_id)
   `).bind(g.requestId,input.grant,g.tenantId,g.vaultId,g.deviceId,g.accountId,g.signingKey,g.wrappingKey).first();
   if(!live)throw fail();
   return scope;
  };
  const signer=env.PILOT_MAIN_SIGNER;
  if(isCommit&&(!signer||typeof signer.key!=='function'||typeof signer.sign!=='function'))return denied();
  const first=await scoped();
  if(isCommit){
   const k=await rpcData(signer!.key());
   if(k.keyId!==main.keyId||k.publicKey!==main.publicKey)return denied();
  }
  const expected=commit?await verifiedExact(input,{witness:commit.witness,freshHead:commit.freshHead},g,witness,authority):null;
  const latest=await verifiedExact(input,await rpcData(custody.fresh(input)),g,witness,authority);
  if(expected&&await signedHash(expected.evidence.witness)!==await signedHash(latest.evidence.witness))return denied();
  const same=await scoped();
  if(first.sessionDigest!==same.sessionDigest)return denied();
  const deadline=Math.min(Number(end),latest.expiresAt,expected?.expiresAt??Infinity,same.timestamp+30);
  if(now()>=deadline)return denied();
  let response:SignedManagedOperation|Evidence=latest.evidence;
  if(expected){
   await consumeGenesisPackageContinuation(primary(),{oldGrantCanonical:input.grant,target:input.target,approval:input.approval,
    keyPackage:input.keyPackage,witness:expected.evidence.witness,roster:input.roster},{authority,witnesses:[witness]},
    {scope:same,freshUntil:deadline});
   response=await provePilotGenesisPackageCommit(primary(),same,selected,{mainCommitAuthority:main,approvalAuthority:authority,witnesses:[witness],otherReleaseKeys},
    {key:async()=>main,sign:canonical=>signer!.sign(canonical)});
  }
  if((await scoped()).sessionDigest!==same.sessionDigest||now()>=deadline)return denied();
  return Response.json(response,{headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
 }catch{return denied();}
}};
