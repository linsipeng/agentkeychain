/* global RequestInit */
import { URL } from "node:url";
/* eslint-disable no-unused-vars -- interface and parameter properties */
import sodium from 'libsodium-wrappers-sumo';
import {randomBytes} from 'node:crypto';
import {assertVerifiedPolicy,type ManagedEndpointPolicy} from './config.ts';
import type {DeviceIdentity} from './device.ts';
import {challengeProof,requestProof} from '../../managed-cloud/shared/device-protocol.ts';
import {digest} from '../../managed-cloud/shared/contracts.ts';
await sodium.ready;
export type CloudFetch=(url:string,init:RequestInit)=>Promise<Response>;
export class CloudHttpError extends Error {
 constructor(readonly code:string,readonly retryAfter=0){super(code);}
}
export class ManagedHttpClient {
 private token:string|null=null;
 private expires=0;
 private refresh:Uint8Array|null=null;
 setRefreshCredential(value:Uint8Array){if(value.length!==43||!/^[A-Za-z0-9_-]{43}$/.test(Buffer.from(value).toString()))throw new Error('cloud_invalid_refresh');this.refresh?.fill(0);this.refresh=new Uint8Array(value);}
 constructor(readonly policy:ManagedEndpointPolicy,private identity:DeviceIdentity,private network:CloudFetch=fetch){assertVerifiedPolicy(policy);}
 private async request(path:string,body:unknown,authenticated:boolean,method='POST'):Promise<unknown>{
  if(!path.startsWith('/v1/')||path.includes('\\')||new URL(path,this.policy.apiOrigin).origin!==this.policy.apiOrigin)throw new Error('cloud_invalid_path');
  const url=new URL(path,this.policy.apiOrigin),raw=method==='GET'?'':JSON.stringify(body);
  if(Buffer.byteLength(raw)>(['/v1/devices/roster-put','/v1/devices/trust-bundle'].includes(path)?600:384)*1024)throw new Error('cloud_request_too_large');
  const headers:Record<string,string>={'content-type':'application/json'};
  if(authenticated){
   await this.session();const nonce=randomBytes(24).toString('base64url'),timestamp=Math.floor(Date.now()/1000);
   headers.authorization='Bearer '+this.token;headers['x-device-nonce']=nonce;headers['x-device-timestamp']=String(timestamp);
   headers['x-device-proof']=Buffer.from(sodium.crypto_sign_detached(requestProof(method,url,await digest(raw),timestamp,nonce,await digest(this.token!)),this.identity.privateKey)).toString('base64');
  }
  let response:Response;
  try{response=await this.network(url.href,{method,headers,...(method==='GET'?{}:{body:raw}),redirect:'error',credentials:'omit',signal:globalThis.AbortSignal.timeout(15000)});}catch{throw new CloudHttpError('cloud_network_unavailable');}
  if(response.status>=300&&response.status<400)throw new CloudHttpError('cloud_redirect_rejected');
  const reader=response.body?.getReader();let size=0;const chunks:Uint8Array[]=[];
  try{if(reader)for(;;){const r=await reader.read();if(r.done)break;size+=r.value.byteLength;if(size>1024*1024){await reader.cancel();throw new CloudHttpError('cloud_response_too_large');}chunks.push(r.value);}}
  finally{reader?.releaseLock();}
  let value:unknown;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new CloudHttpError('cloud_invalid_response');}
  if(!response.ok){
   if(response.status===401){this.token=null;this.expires=0;}
   const code=(value as {error?:{code?:unknown}})?.error?.code;
   const safe=typeof code==='string'&&['revoked','unauthorized','not_found','approval_required','incompatible','rate_limited','generation_conflict','tombstone','key_epoch','idempotency_conflict'].includes(code)?code:'cloud_request_failed';
   throw new CloudHttpError(safe,Math.min(300,Math.max(0,Number(response.headers.get('retry-after'))||0))*1000);
  }
  return value;
 }
 async session(){
  if(this.token&&this.expires>Date.now()+30000)return;
  if(this.refresh){
   const credential=Buffer.from(this.refresh).toString(),sessionToken=Buffer.from(sodium.crypto_generichash(32,JSON.stringify(['AgentKeychain-recovery-session-v1',credential]),null)).toString('base64url');
   const body={deviceId:this.identity.record.deviceId,credential,sessionToken,timestamp:Math.floor(Date.now()/1000)};
   const t=await this.publicCall('/v1/devices/recovery-refresh',{...body,signature:Buffer.from(sodium.crypto_sign_detached(JSON.stringify(['AgentKeychain-recovery-refresh-v1',body]),this.identity.privateKey)).toString('base64')}) as {token:string;tokenType:string;expiresIn:number;deviceId:string;vaultId:string};
   if(t.token!==sessionToken||t.deviceId!==this.identity.record.deviceId||t.vaultId!==this.identity.record.vaultId||t.tokenType!=='DeviceProof'||!Number.isSafeInteger(t.expiresIn)||t.expiresIn<1||t.expiresIn>900)throw new Error('cloud_invalid_session');
   this.token=t.token;this.expires=Date.now()+t.expiresIn*1000;return;
  }
  const c=await this.publicCall('/v1/devices/challenge',{deviceId:this.identity.record.deviceId}) as {challengeId:string;challenge:string;deviceId:string;vaultId:string;expiresAt:number};
  if(c.deviceId!==this.identity.record.deviceId||c.vaultId!==this.identity.record.vaultId||!Number.isSafeInteger(c.expiresAt)||c.expiresAt<=Math.floor(Date.now()/1000)||c.expiresAt>Math.floor(Date.now()/1000)+120)throw new CloudHttpError('cloud_invalid_challenge');
  const signature=Buffer.from(sodium.crypto_sign_detached(challengeProof(c.challengeId,await digest(c.challenge),c.deviceId,c.vaultId,c.expiresAt),this.identity.privateKey)).toString('base64');
  const t=await this.publicCall('/v1/devices/token',{challengeId:c.challengeId,signature}) as {token:string;expiresIn:number;deviceId:string;vaultId:string;tokenType:string};
  if(t.deviceId!==c.deviceId||t.vaultId!==c.vaultId||t.tokenType!=='DeviceProof'||typeof t.token!=='string'||! /^[A-Za-z0-9_-]{1,256}$/.test(t.token)||!Number.isSafeInteger(t.expiresIn)||t.expiresIn<1||t.expiresIn>900)throw new CloudHttpError('cloud_invalid_session');
  this.token=t.token;this.expires=Date.now()+t.expiresIn*1000;
 }
 publicCall(path:string,body:unknown){return this.request(path,body,false);}
 call(path:string,body:unknown={},method='POST'){return this.request(path,body,true,method);}
 logout(){this.token=null;this.expires=0;this.refresh?.fill(0);this.refresh=null;}
}
export function retryDelay(attempt:number,retryAfter=0,random:()=>number=Math.random){return Math.max(Math.min(300000,Math.max(0,retryAfter)),Math.floor(random()*Math.min(300000,1000*2**Math.min(18,Math.max(0,attempt)))));}
