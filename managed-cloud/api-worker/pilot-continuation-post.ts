/** Separate, default-disabled pilot entrypoint. No mutations or signing key. */
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {authenticate,type DeviceContext} from './auth.ts';
import type {CheckpointKey} from '../shared/checkpoints.ts';
import {boundedBody,digest,verify} from '../shared/contracts.ts';
import {CUSTODY_CONTINUATION_POST_COMMIT_DOMAIN,type ContinuationFreshHeadRequest} from '../shared/continuation-fresh-head.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {rpcData} from '../shared/rpc-data.ts';

import {canonicalPilotPostProof,PILOT_POST_PROOF_PATH,pilotProofEnvelope} from '../shared/pilot-continuation-post-wire.ts';
interface PostCommitPort {
 post(input:ContinuationFreshHeadRequest,previous:SignedManagedOperation,main:SignedManagedOperation):Promise<SignedManagedOperation>;
}
interface Env {
 MAIN?:D1Database;
 PILOT_MAIN_MODE?:string;
 PILOT_MAIN_ORIGIN?:string;
 PILOT_MAIN_EXPIRES_AT?:string;
 PILOT_CUSTODY_WITNESS?:string;
 PILOT_CUSTODY_POST?:PostCommitPort;
}
const deny=()=>new Response(null,{status:404,headers:{'cache-control':'no-store'}});
const rejected=()=>new Error('pilot_continuation_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const digestEnvelope=(x:SignedManagedOperation)=>digest(JSON.stringify([x.canonical,x.signature]));
export default {async fetch(request:Request,env:Env):Promise<Response>{
 try{
  const {MAIN:db,PILOT_CUSTODY_POST:custody,PILOT_MAIN_ORIGIN:origin,PILOT_MAIN_EXPIRES_AT:end,PILOT_CUSTODY_WITNESS:pinText}=env;
  if(env.PILOT_MAIN_MODE!=='continuation-v1'||!db||!custody||typeof custody.post!=='function'||!origin||
     !end||!/^[0-9]{10}$/.test(end)||Number(end)<=now()||Number(end)-now()>7*86400||!pinText||pinText.length>1024)return deny();
  const configured=new URL(origin),u=new URL(request.url);
  if(configured.origin!==origin||configured.protocol!=='https:'||configured.port||
     !/^api\.web-pilot-[a-z0-9](?:[a-z0-9-]{0,39}[a-z0-9])?\./.test(configured.hostname)||
     u.origin!==origin||u.username||u.password||u.pathname!==PILOT_POST_PROOF_PATH||u.search||u.hash||
     request.method!=='POST'||request.headers.has('cookie')||request.headers.has('origin')||
     !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type')??''))return deny();
  const witness:unknown=JSON.parse(pinText);
  exactFields(witness,['keyId','publicKey']);
  if(typeof witness.keyId!=='string'||typeof witness.publicKey!=='string')return deny();
  base64(witness.publicKey,32,32);
  if(witness.keyId!==await digest(witness.publicKey))return deny();
  const pin:CheckpointKey={keyId:witness.keyId,publicKey:witness.publicKey};
  const body=await boundedBody(request,64*1024),parsed:unknown=JSON.parse(body);
  if(canonicalPilotPostProof(parsed)!==body)return deny();
  const input=parsed as {request:ContinuationFreshHeadRequest;prior:SignedManagedOperation;main:SignedManagedOperation};
  const g=JSON.parse(input.request.grant) as EnrollmentGrant;
  if(canonicalGrant(g)!==input.request.grant||g.issuerDeviceId!==null||g.expiresAt>now()||
     pin.publicKey===g.signingKey||pin.publicKey===g.wrappingKey)return deny();
  const scope=async():Promise<DeviceContext>=>{
   const ctx=await authenticate(db.withSession('first-primary'),request,g.vaultId,body);
   if(Math.abs(now()-ctx.timestamp)>=30||ctx.accountId!==g.accountId||ctx.tenantId!==g.tenantId||
      ctx.vaultId!==g.vaultId||ctx.deviceId!==g.deviceId||ctx.publicKey!==g.signingKey)throw rejected();
   const active=await db.withSession('first-primary').prepare(`
     SELECT 1 FROM enrollment_grants g
     JOIN device_requests q ON q.id=g.id AND q.tenant_id=g.tenant_id AND q.vault_id=g.vault_id AND q.device_id=g.device_id
       AND q.key_epoch=g.key_epoch AND q.state IN('approved','delivered')
     JOIN device_keys k ON k.tenant_id=g.tenant_id AND k.device_id=g.device_id AND k.wrapping_key=q.wrapping_key
     WHERE g.id=? AND g.canonical=? AND g.tenant_id=? AND g.vault_id=? AND g.device_id=? AND q.account_id=?
       AND q.signing_key=? AND q.wrapping_key=? AND g.issuer_device_id IS NULL
       AND NOT EXISTS(SELECT 1 FROM device_revocation_boundaries r WHERE r.tenant_id=g.tenant_id AND r.vault_id=g.vault_id AND r.device_id=g.device_id)
    `).bind(g.requestId,input.request.grant,g.tenantId,g.vaultId,g.deviceId,g.accountId,g.signingKey,g.wrappingKey).first();
   if(!active)throw rejected();
   return ctx;
  };
  const authorized=await scope();
  const result=pilotProofEnvelope(await rpcData(custody.post(input.request,input.prior,input.main)),4096);
  const proof:unknown=JSON.parse(result.canonical);
  exactFields(proof,['version','domain','keyId','nonce','mainCommitDigest','requestId','continuationId','accountId','tenantId','vaultId','deviceId','keyEpoch','witnessDigest','payloadDigest','issuedAt','expiresAt']);
  if(proof.version!==1||proof.domain!==CUSTODY_CONTINUATION_POST_COMMIT_DOMAIN||proof.keyId!==pin.keyId||
     proof.nonce!==input.request.nonce||proof.mainCommitDigest!==await digestEnvelope(input.main)||proof.requestId!==g.requestId||
     proof.accountId!==g.accountId||proof.tenantId!==g.tenantId||proof.vaultId!==g.vaultId||proof.deviceId!==g.deviceId||
     proof.keyEpoch!==g.keyEpoch||typeof proof.issuedAt!=='number'||typeof proof.expiresAt!=='number'||
     !Number.isSafeInteger(proof.issuedAt)||!Number.isSafeInteger(proof.expiresAt)||proof.issuedAt>now()||
     proof.expiresAt-proof.issuedAt>60||!await verify(pin.publicKey,result.signature,result.canonical))return deny();
  const live=await scope();
  if(live.sessionDigest!==authorized.sessionDigest||now()>=Math.min(Number(end),proof.expiresAt))return deny();
  return Response.json(result,{headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
 }catch{return deny();}
}};
