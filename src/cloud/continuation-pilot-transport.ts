import {randomBytes} from 'node:crypto';
import {URL} from 'node:url';
import {canonicalPilotPostProof,PILOT_POST_PROOF_PATH,PILOT_PREFLIGHT_PATH,PILOT_COMMIT_PATH,pilotProofEnvelope,pilotPreflightInput,pilotCommitInput} from '../../managed-cloud/shared/pilot-continuation-post-wire.ts';
import {canonicalGrant,requestProof,type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {assertContinuationLease,assertProtectedPilotDraft,newContinuationReadbackNonce,readStagedGenesisContinuation,stageGenesisContinuation,verifyGenesisContinuationPreflight,withContinuationEnrollmentLease,withStagedGenesisPostProof} from './enrollment-intent.ts';
import {prepareContinuationBrowserHandoff,pollContinuationBrowserApproval} from './continuation-handoff.ts';
import {installedContinuationPilotScope,type VerifiedInstalledContinuationPilot} from './continuation-pilot-build.ts';
import {verifyContinuationApproval} from '../../managed-cloud/shared/enrollment-continuation.ts';
import {rosterDigest} from '../../managed-cloud/shared/roster.ts';
import {verifyContinuationAuthority} from './config.ts';
import type {ContinuationHandoffStage} from '../../managed-cloud/shared/continuation-handoff-wire.ts';
import {exactFields,type SignedManagedOperation} from './protocol.ts';
import type {CloudFetch} from './http.ts';
import type {CloudStore} from './persistence.ts';
import type {SecureStore} from '../platform/secure-store.ts';

const preparePath='/v1/auth/continuation-handoff/prepare',pollPath='/v1/auth/continuation-handoff/poll';
const unavailable=()=>new Error('cloud_continuation_pilot_transport_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const jsonMedia=/^application\/json(?:\s*;\s*charset=utf-8)?$/i;
const MaxBody=64*1024;
type Lease=Parameters<typeof assertContinuationLease>[1];
const identityFields=['accountId','tenantId','vaultId','deviceId'] as const;
type ProtectedContext={store:CloudStore;secure:SecureStore;lease:Lease};

export interface PilotMainSession {
 readonly accountId:string;readonly tenantId:string;readonly vaultId:string;readonly deviceId:string;
 readonly token:string;readonly expiresAt:number;
 // eslint-disable-next-line no-unused-vars -- exact signed PoP callback, no signing key exported
 signDeviceProof:(message:string)=>Promise<string>;
}
type PrepareOptions=Omit<Parameters<typeof prepareContinuationBrowserHandoff>[0],'policy'|'authOriginAppendix'|'network'|'authorizeBeforePublish'> & {
 // An explicit pilot scoped authorization must run before publishing; the installed command does not implement it yet.
 authorizeBeforePublish:NonNullable<Parameters<typeof prepareContinuationBrowserHandoff>[0]['authorizeBeforePublish']>;
};
type PollOptions=Omit<Parameters<typeof pollContinuationBrowserApproval>[0],'policy'|'authOriginAppendix'|'authAuthorityAppendix'|'network'>;

const roundKey='installed-pilot-commit-round-v1';
const envelopeDigest=(x:SignedManagedOperation)=>digest(JSON.stringify([x.canonical,x.signature]));
type Fresh={witness:SignedManagedOperation;freshHead:SignedManagedOperation};
type Round={scopeDigest:string;nonce:string;fresh?:Fresh;commit?:SignedManagedOperation};
type PilotInvocation={secure:SecureStore;store:CloudStore;session:PilotMainSession;permit:SignedManagedOperation;
 stage:ContinuationHandoffStage;approval:SignedManagedOperation};

/** A narrow port, not a rollout switch. No default state, token issuer,
 * runtime trust overrides or activation. */
export function installedContinuationPilotTransport(gate:VerifiedInstalledContinuationPilot,network:CloudFetch=fetch){
 const scope=installedContinuationPilotScope(gate);
 const ensure=()=>installedContinuationPilotScope(gate);
 const authNetwork=(path:typeof preparePath|typeof pollPath):CloudFetch=>async(url,init)=>{
  ensure();
  const expected=new URL(path,scope.authOrigin).href;
  const headers=init.headers;
  exactFields(headers,['content-type']);
  if(url!==expected||init.method!=='POST'||headers['content-type']!=='application/json'||init.credentials!=='omit'||
     init.redirect!=='error'||typeof init.body!=='string'||Buffer.byteLength(init.body)>MaxBody)throw unavailable();
  // Rebuild the request: no ambient cookies, bearer, Origin, or user-set headers.
  const response=await network(expected,{method:'POST',headers:{'content-type':'application/json'},body:init.body,
   credentials:'omit',redirect:'error',cache:'no-store',signal:globalThis.AbortSignal.timeout(10000)});
  ensure();
  if(response.redirected||response.url!==expected||!jsonMedia.test(response.headers.get('content-type')??'')||
    !(path===preparePath?response.status===200:[200,202].includes(response.status)))throw unavailable();
  return response;
 };
 const mainNetwork=async(o:ProtectedContext,g:EnrollmentGrant,s:PilotMainSession,
  path:typeof PILOT_PREFLIGHT_PATH|typeof PILOT_COMMIT_PATH|typeof PILOT_POST_PROOF_PATH,body:string,guard:()=>unknown)=>{
     const {token,expiresAt}=s;
     if(!/^[A-Za-z0-9_-]{1,256}$/.test(token)||!Number.isSafeInteger(expiresAt)||expiresAt<=now()||
      expiresAt-now()>900||identityFields.some(k=>s[k]!==g[k]))throw unavailable();
     const url=new URL(path,scope.policy.apiOrigin);
     if(Buffer.byteLength(body)>MaxBody)throw unavailable();
     const nonce=randomBytes(24).toString('base64url'),timestamp=now();
     const challenge=requestProof('POST',url,await digest(body),timestamp,nonce,await digest(token));
     const signature=await s.signDeviceProof(challenge);
     if(!/^[A-Za-z0-9+/]{86}==$/.test(signature)||!await verify(g.signingKey,signature,challenge)||
      now()>=Math.min(timestamp+30,expiresAt))throw unavailable();
     guard();assertContinuationLease(o.store,o.lease);
     const response=await network(url.href,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token,
      'x-device-nonce':nonce,'x-device-timestamp':String(timestamp),'x-device-proof':signature},body,credentials:'omit',
      redirect:'error',cache:'no-store',signal:globalThis.AbortSignal.timeout(10000)});
     if(response.status!==200||response.redirected||response.url!==url.href||!response.body||
      !jsonMedia.test(response.headers.get('content-type')??''))throw unavailable();
     const reader=response.body.getReader(),parts:Uint8Array[]=[];
     try{
      let size=0;
      for(;;){const result=await reader.read();if(result.done)break;size+=result.value.byteLength;
       if(size>8192){await reader.cancel();throw unavailable();}parts.push(result.value);}
     }finally{reader.releaseLock();}
     guard();
     if(now()>=Math.min(timestamp+30,expiresAt))throw unavailable();
     return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts))) as unknown;
 };
 return Object.freeze({
  get state(){ensure();return 'transport_unavailable' as const;},
  async prepare(o:PrepareOptions&{lease:Lease}){
   try{
    ensure();assertContinuationLease(o.store,o.lease);
    if(typeof o.authorizeBeforePublish!=='function')throw unavailable();
    return await prepareContinuationBrowserHandoff({...o,policy:scope.policy,authOriginAppendix:scope.authOriginAppendix,
     network:authNetwork(preparePath),authorizeBeforePublish:async(stage,url)=>{
      await o.authorizeBeforePublish(stage,url);ensure();assertContinuationLease(o.store,o.lease);
     },displayPairCode:code=>{ensure();assertContinuationLease(o.store,o.lease);o.displayPairCode(code);}});
   }catch{throw unavailable();}
  },
  async poll(o:PollOptions&{lease:Lease}){
   try{
    ensure();assertContinuationLease(o.store,o.lease);
    const result=await pollContinuationBrowserApproval({...o,policy:scope.policy,authOriginAppendix:scope.authOriginAppendix,
     authAuthorityAppendix:scope.authAppendix,network:authNetwork(pollPath)});
    ensure();assertContinuationLease(o.store,o.lease);
    return result;
   }catch{throw unavailable();}
  },
  /** Explicit composition only: never dispatch this via the normal or standalone CLI until pilot-native storage exists. */
  async commitApprovedStage(o:PilotInvocation):Promise<'commit-verified-not-active'>{
   try{
    ensure();
    const stage=globalThis.structuredClone(o.stage),approval=pilotProofEnvelope(o.approval,1024),permit=pilotProofEnvelope(o.permit,2048);
    const grant=JSON.parse(stage.oldGrantCanonical) as EnrollmentGrant;
    if(canonicalGrant(grant)!==stage.oldGrantCanonical||grant.issuerDeviceId!==null||grant.expiresAt>now())throw unavailable();
    const subject=JSON.parse(permit.canonical) as {issuedAt:number;expiresAt:number};
    const {issuedAt,expiresAt}=subject,intentDigest=await digest(stage.target.canonical),approvalDigest=await envelopeDigest(approval);
    if(!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||issuedAt<1||issuedAt>now()||expiresAt<=now()||
       expiresAt>gate.expiresAt||expiresAt-issuedAt>300)throw unavailable();
    if(permit.canonical!==JSON.stringify({version:1,domain:'AgentKeychain-installed-continuation-pilot-commit-v1',keyId:scope.rollout.keyId,
      installationDigest:scope.installationDigest,intentDigest,approvalDigest,issuedAt,expiresAt})||
      !await verify(scope.rollout.publicKey,permit.signature,permit.canonical))throw unavailable();
    const guard=()=>{ensure();if(now()>=expiresAt)throw unavailable();};
    const scopeDigest=await digest(JSON.stringify([scope.installationDigest,intentDigest,approvalDigest]));
    const authority=await verifyContinuationAuthority(scope.policy,scope.authAppendix);
    const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',stage.keyPackage.canonical,stage.keyPackage.signature]));
    const rosterHash=await rosterDigest(stage.roster);
    await verifyContinuationApproval(stage.target,approval,{oldGrantCanonical:stage.oldGrantCanonical,stage:'put-key-package',
     payloadDigest,rosterDigest:rosterHash,witnessHead:{revision:1,digest:rosterHash},authority,issuer:null,now:now()});
    guard();
    return await withContinuationEnrollmentLease(o.store,async lease=>{
     const bound={secure:o.secure,store:o.store,lease};
     const fence=()=>{guard();assertContinuationLease(o.store,lease);};
     const exact={grant,target:stage.target,approval,authorityAppendix:scope.authAppendix,commitAppendix:scope.commitAppendix,
      roster:stage.roster,keyPackage:stage.keyPackage};
     await assertProtectedPilotDraft(o.secure,o.store,lease,exact);fence();
     let round=o.store.get<Round>('state',roundKey);
     if(round&&round.scopeDigest!==scopeDigest)throw unavailable();
     const save=(value:Round)=>o.store.transaction(()=>{fence();o.store.put('state',roundKey,value);return value;});
     round??=save({scopeDigest,nonce:newContinuationReadbackNonce()});
     const request={nonce:round.nonce,grant:stage.oldGrantCanonical,target:stage.target,approval,roster:stage.roster,keyPackage:stage.keyPackage};
     if(!round.fresh){
      const result=await mainNetwork(bound,grant,o.session,PILOT_PREFLIGHT_PATH,JSON.stringify(pilotPreflightInput({request})),fence);
      exactFields(result,['witness','freshHead']);
      const fresh={witness:pilotProofEnvelope(result.witness,4096),freshHead:pilotProofEnvelope(result.freshHead,2048)};
      await verifyGenesisContinuationPreflight(o.secure,o.store,scope.policy,round.nonce,{...exact,...fresh});
      round=save({...round,fresh});
     }
     const {fresh,nonce}=round;if(!fresh)throw unavailable();
     const evidence={...exact,...fresh};
     if(!await readStagedGenesisContinuation(o.secure,o.store,scope.policy)){
      // Keep the original lease-fenced nonce and preflight bytes before the
      // atomic Main write. Retrying a lost response retransmits the same body.
      await verifyGenesisContinuationPreflight(o.secure,o.store,scope.policy,nonce,evidence);
      fence();
      const commit=round.commit??pilotProofEnvelope(await mainNetwork(bound,grant,o.session,PILOT_COMMIT_PATH,
       JSON.stringify(pilotCommitInput({request,...fresh})),fence),4096);
      await stageGenesisContinuation(o.secure,o.store,scope.policy,nonce,{...evidence,commit},lease);
      round=save({...round,commit});
     }
     const postNonce=newContinuationReadbackNonce();
     await withStagedGenesisPostProof(o.secure,o.store,scope.policy,postNonce,lease,async e=>{
      if(JSON.stringify(e.target)!==JSON.stringify(stage.target)||await envelopeDigest(e.approval)!==approvalDigest||
        JSON.stringify(e.freshHead)!==JSON.stringify(fresh.freshHead)||JSON.stringify(e.witness)!==JSON.stringify(fresh.witness))throw unavailable();
      const raw=canonicalPilotPostProof({request:{...request,nonce:postNonce},prior:e.freshHead,main:e.commit});
      return pilotProofEnvelope(await mainNetwork(bound,grant,o.session,PILOT_POST_PROOF_PATH,raw,fence),4096);
     });
     fence();
     return 'commit-verified-not-active' as const;
    });
   }catch{throw unavailable();}
  },
  async postFromProtectedStage(o:ProtectedContext&{nonce:string;session:PilotMainSession}){
   try{
    ensure();
    const postNonce=o.nonce;
    const proof=await withStagedGenesisPostProof(o.secure,o.store,scope.policy,postNonce,o.lease,async e=>{
     if(JSON.stringify(e.authorityAppendix)!==JSON.stringify(scope.authAppendix)||
        JSON.stringify(e.commitAppendix)!==JSON.stringify(scope.commitAppendix))throw unavailable();
     const g=e.grant;
     const body=canonicalPilotPostProof({request:{nonce:postNonce,grant:canonicalGrant(g),target:e.target,approval:e.approval,
      roster:e.roster,keyPackage:e.keyPackage},prior:e.freshHead,main:e.commit});
     return pilotProofEnvelope(await mainNetwork(o,g,o.session,PILOT_POST_PROOF_PATH,body,ensure),4096);
    });
    ensure();
    return proof;
   }catch{throw unavailable();}
  },
 });
}
