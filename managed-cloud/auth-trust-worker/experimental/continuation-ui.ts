import type {AuthenticationResponseJSON} from '@simplewebauthn/server';
import {exactFields} from '../../../src/cloud/protocol.ts';
import {boundedBody,digest} from '../../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../shared/device-protocol.ts';
import {random} from '../../api-worker/webauthn.ts';
import type {continuationIssuer,StageInput} from './continuation-issuer.ts';

const path='/v1/auth/continuation-approval';
const session='__Host-akc_genesis_session', csrf='__Host-akc_genesis_csrf';
const reject=()=>Response.json({error:{code:'continuation_approval_unavailable'}},{status:401,headers:{'cache-control':'no-store'}});
function cookie(headers:Headers,name:string){
 const matches=(headers.get('cookie')??'').split(';').map(v=>v.trim()).filter(v=>v.startsWith(name+'='));
 const value=matches[0]?.slice(name.length+1);
 if(matches.length!==1||!/^[A-Za-z0-9_-]{43}$/.test(value??''))throw new Error('invalid');
 return value!;
}
function stage(value:unknown):StageInput {
 exactFields(value,['oldGrantCanonical','target','roster','keyPackage']);
 for(const k of ['target','roster','keyPackage'])exactFields(value[k],['canonical','signature']);
 return value as unknown as StageInput;
}
/** Local Auth transport only. No browser stages may be selected by the caller
 * or accepted outside an independently provisioned HTTPS Auth RP. A historical
 * witness is not a live revocation check; never deploy this fixture without
 * independently current Custody validation and protected Auth state. */
export function continuationApprovalUi(origin:string,issuer:ReturnType<typeof continuationIssuer>){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.origin!==origin)throw new Error('invalid_auth_origin');
 return async(req:Request)=>{
  try{
   const url=new URL(req.url);
   if(url.origin!==origin||!([path+'/begin',path+'/complete'].includes(url.pathname))||url.search||req.method!=='POST'||
     req.headers.get('origin')!==origin||req.headers.get('sec-fetch-site')==='cross-site'||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers.get('content-type')??''))
    return reject();
   const input:unknown=JSON.parse(await boundedBody(req,70_000));
   if(url.pathname===path+'/begin'){
    exactFields(input,['stage']);
    const proposal=stage(input.stage),g=JSON.parse(proposal.oldGrantCanonical) as EnrollmentGrant;
    if(canonicalGrant(g)!==proposal.oldGrantCanonical)return reject();
    // Keep browser tokens across lost completion responses, but no authenticated
    // session or readback grant exists before a valid UV ceremony commits.
    const token=random(),anti=random();
    const challenge=await issuer.begin(proposal,{sessionDigest:await digest(token),csrfDigest:await digest(anti)});
    const headers=new Headers({'cache-control':'no-store'});
    headers.append('set-cookie',session+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=120');
    headers.append('set-cookie',csrf+'='+anti+'; Path=/; Secure; SameSite=Strict; Max-Age=120');
    return Response.json({...challenge,display:{purpose:'continue-original-device-key-package',deviceId:g.deviceId,accountId:g.accountId,vaultId:g.vaultId}},{headers});
   }
   exactFields(input,['id','stage','assertion']);
   if(typeof input.id!=='string')return reject();
   const token=cookie(req.headers,session),anti=cookie(req.headers,csrf);
   if(req.headers.get('x-csrf-token')!==anti)return reject();
   const proof=await issuer.complete(input.id,stage(input.stage),input.assertion as AuthenticationResponseJSON,{sessionDigest:await digest(token),csrfDigest:await digest(anti)});
   return Response.json(proof,{headers:{'cache-control':'no-store'}});
  }catch{return reject();}
 };
}
