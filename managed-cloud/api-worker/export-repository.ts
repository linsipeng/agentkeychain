import {canonicalExport,type ExportIntent} from '../shared/export.ts';
import {ApiError,digest,verify} from '../shared/contracts.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {DeviceContext} from './auth.ts';
export const exportSelect=`SELECT (SELECT ordinal FROM approval_order WHERE tenant_id=e.tenant_id AND account_id=e.account_id AND request_id=e.id) AS ordinal,tenant_id,vault_id,id,account_id,device_id,'export' AS action,'vault-export' AS object_id,request_digest,created_at,expires_at,decided_at,consumed_at AS consumed_sequence,signature AS intent_signature,NULL AS summary_digest,CASE WHEN state='pending' AND expires_at<=unixepoch() THEN 'expired' ELSE state END AS state FROM export_requests e`;
export function exportRepository(db:D1Database){
 const nonce=(c:DeviceContext)=>db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest,c.tenantId,c.vaultId,c.deviceId,c.accountId,c.nonce,c.timestamp);
 async function validate(c:DeviceContext,s:SignedManagedOperation){
  let i:ExportIntent;try{i=JSON.parse(s.canonical);if(canonicalExport(i)!==s.canonical)throw new Error();}catch{throw new ApiError('invalid_request');}
  if(i.accountId!==c.accountId||i.tenantId!==c.tenantId||i.vaultId!==c.vaultId||i.deviceId!==c.deviceId)throw new ApiError('not_found');
  if(!await verify(c.publicKey,s.signature,s.canonical))throw new ApiError('invalid_signature');return i;
 }
 const previous=(c:DeviceContext,id:string)=>db.prepare('SELECT canonical,signature,state,consumed_at,expires_at FROM export_requests WHERE tenant_id=? AND account_id=? AND id=?').bind(c.tenantId,c.accountId,id).first<{canonical:string;signature:string;state:string;consumed_at:number|null;expires_at:number}>();
 return {
  async request(c:DeviceContext,s:SignedManagedOperation){
   const i=await validate(c,s),old=await previous(c,i.requestId);
   if(old&&(old.canonical!==s.canonical||old.signature!==s.signature))throw new ApiError('idempotency_conflict');
   if(!old&&(i.expiresAt<=Math.floor(Date.now()/1000)||i.expiresAt>Math.floor(Date.now()/1000)+900))throw new ApiError('invalid_request');
   await db.batch([nonce(c),db.prepare('INSERT INTO export_requests(tenant_id,vault_id,id,account_id,device_id,canonical,signature,request_digest,expires_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,account_id,id) DO NOTHING').bind(c.tenantId,c.vaultId,i.requestId,c.accountId,c.deviceId,s.canonical,s.signature,await digest(s.canonical),i.expiresAt)]);
   const stored=await previous(c,i.requestId);if(stored?.canonical!==s.canonical||stored.signature!==s.signature)throw new ApiError('idempotency_conflict');return {requestId:i.requestId};
  },
  async consume(c:DeviceContext,s:SignedManagedOperation){
   const i=await validate(c,s),old=await previous(c,i.requestId);
   if(!old||old.canonical!==s.canonical||old.signature!==s.signature||old.state!=='approved'||(old.consumed_at===null&&old.expires_at<=Math.floor(Date.now()/1000)))throw new ApiError('approval_required');
   await db.batch([nonce(c),db.prepare('UPDATE export_requests SET consumed_at=unixepoch() WHERE tenant_id=? AND account_id=? AND id=? AND consumed_at IS NULL').bind(c.tenantId,c.accountId,i.requestId)]);
   return {accepted:true,requestId:i.requestId};
  }
 };
}
