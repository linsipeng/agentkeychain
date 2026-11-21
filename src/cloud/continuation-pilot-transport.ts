import {randomBytes} from 'node:crypto';
import {URL} from 'node:url';
import {canonicalPilotPostProof,PILOT_POST_PROOF_PATH,pilotProofEnvelope} from '../../managed-cloud/shared/pilot-continuation-post-wire.ts';
import {canonicalGrant,requestProof} from '../../managed-cloud/shared/device-protocol.ts';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {assertContinuationLease,withStagedGenesisPostProof} from './enrollment-intent.ts';
import {prepareContinuationBrowserHandoff,pollContinuationBrowserApproval} from './continuation-handoff.ts';
import {installedContinuationPilotScope,type VerifiedInstalledContinuationPilot} from './continuation-pilot-build.ts';
import {exactFields} from './protocol.ts';
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

/** A narrow port, not a rollout switch. No default state, token issuer,
 * runtime trust overrides, preflight, commit, or activation. */
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
  async postFromProtectedStage(o:ProtectedContext&{nonce:string;session:PilotMainSession}){
   try{
    ensure();
    const postNonce=o.nonce;
    const proof=await withStagedGenesisPostProof(o.secure,o.store,scope.policy,postNonce,o.lease,async e=>{
     const s=o.session,{grant:g}=e;
     const {token,expiresAt}=s;
     if(!/^[A-Za-z0-9_-]{1,256}$/.test(token)||!Number.isSafeInteger(expiresAt)||expiresAt<=now()||
      expiresAt-now()>900||identityFields.some(k=>s[k]!==g[k])||
      JSON.stringify(e.authorityAppendix)!==JSON.stringify(scope.authAppendix)||
      JSON.stringify(e.commitAppendix)!==JSON.stringify(scope.commitAppendix))throw unavailable();
     const url=new URL(PILOT_POST_PROOF_PATH,scope.policy.apiOrigin);
     const body=canonicalPilotPostProof({request:{nonce:postNonce,grant:canonicalGrant(g),target:e.target,approval:e.approval,
      roster:e.roster,keyPackage:e.keyPackage},prior:e.freshHead,main:e.commit});
     if(Buffer.byteLength(body)>MaxBody)throw unavailable();
     const nonce=randomBytes(24).toString('base64url'),timestamp=now();
     const challenge=requestProof('POST',url,await digest(body),timestamp,nonce,await digest(token));
     const signature=await s.signDeviceProof(challenge);
     if(!/^[A-Za-z0-9+/]{86}==$/.test(signature)||!await verify(g.signingKey,signature,challenge)||
      now()>=Math.min(timestamp+30,expiresAt))throw unavailable();
     ensure();assertContinuationLease(o.store,o.lease);
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
     ensure();
     if(now()>=Math.min(timestamp+30,expiresAt))throw unavailable();
     return pilotProofEnvelope(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts))),4096);
    });
    ensure();
    return proof;
   }catch{throw unavailable();}
  },
 });
}
