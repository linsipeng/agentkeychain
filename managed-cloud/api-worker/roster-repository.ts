import {ApiError,verify} from '../shared/contracts.ts';
import {parseRoster,verifyRoster,rosterDigest} from '../shared/roster.ts';
import {checkpoint,genesisRoot,type CheckpointSigner} from '../shared/checkpoints.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {DeviceContext} from './auth.ts';
export function rosterRepository(db:D1Database){
 const nonce=(c:DeviceContext)=>db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest,c.tenantId,c.vaultId,c.deviceId,c.accountId,c.nonce,c.timestamp);
 return {
 async put(c:DeviceContext,s:SignedManagedOperation){
  const r=parseRoster(s);if(r.accountId!==c.accountId||r.tenantId!==c.tenantId||r.vaultId!==c.vaultId||(r.issuer.kind==='device'&&r.issuer.id!==c.deviceId))throw new ApiError('not_found');
  const same=await db.prepare('SELECT canonical,signature FROM signed_rosters WHERE tenant_id=? AND vault_id=? AND revision=?').bind(c.tenantId,c.vaultId,r.revision).first<SignedManagedOperation>();
  if(same){const latest=await db.prepare('SELECT max(revision) revision FROM signed_rosters WHERE tenant_id=? AND vault_id=?').bind(c.tenantId,c.vaultId).first<number>('revision');if(latest!==r.revision)throw new ApiError('idempotency_conflict');if(same.canonical!==s.canonical||same.signature!==s.signature)throw new ApiError('idempotency_conflict');await nonce(c).run();return {accepted:true};}
  const prior=await db.prepare('SELECT canonical,signature FROM signed_rosters WHERE tenant_id=? AND vault_id=? ORDER BY revision DESC LIMIT 1').bind(c.tenantId,c.vaultId).first<SignedManagedOperation>();
  const migrated=!prior&&!!await db.prepare('SELECT 1 FROM device_revocation_boundaries WHERE tenant_id=? AND vault_id=? LIMIT 1').bind(c.tenantId,c.vaultId).first();
  await verifyRoster(s,prior,Math.floor(Date.now()/1000),migrated);
  if(r.issuer.kind==='recovery'){
   const e=JSON.parse(r.recovery!.canonical) as {caseId:string;targetDeviceId:string};
   if(e.targetDeviceId!==c.deviceId||!await db.prepare("SELECT 1 FROM recovery_sagas WHERE id=? AND account_id=? AND tenant_id=? AND vault_id=? AND state='completed'").bind(e.caseId,c.accountId,c.tenantId,c.vaultId).first())throw new ApiError('approval_required');
  }
  const rows=await db.prepare('SELECT d.id,d.public_key,k.wrapping_key,CASE WHEN d.active=1 AND v.active=1 THEN 1 ELSE 0 END AS active FROM devices d JOIN device_keys k ON k.tenant_id=d.tenant_id AND k.device_id=d.id JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id WHERE d.tenant_id=? AND d.account_id=? AND v.vault_id=?').bind(c.tenantId,c.accountId,c.vaultId).all<{id:string;public_key:string;wrapping_key:string;active:number}>();
  for(const d of [...r.active,...r.revoked]){const row=rows.results.find(v=>v.id===d.deviceId);if(!row)throw new ApiError('not_found');if(row.public_key!==d.signingKey||row.wrapping_key!==d.wrappingKey||!!row.active!==r.active.includes(d))throw new ApiError('idempotency_conflict');}
  // A revision cannot hide an already registered device, including revoked historical identities.
  if(rows.results.length!==r.active.length+r.revoked.length)throw new ApiError('idempotency_conflict');
  for(const d of r.revoked){const boundary=await db.prepare('SELECT sequence FROM device_revocation_boundaries WHERE tenant_id=? AND vault_id=? AND device_id=?').bind(c.tenantId,c.vaultId,d.deviceId).first<number>('sequence');if(boundary===null||boundary!==(JSON.parse(d.acceptedThrough.canonical) as {sequence:number}).sequence)throw new ApiError('idempotency_conflict');}
  const hash=await rosterDigest(s);
  await db.batch([nonce(c),db.prepare('INSERT INTO signed_rosters VALUES(?,?,?,?,?,?,?,?,?)').bind(c.tenantId,c.vaultId,c.accountId,r.revision,hash,r.previousDigest,r.issuer.kind==='device'?c.deviceId:null,s.canonical,s.signature)]);
  return {accepted:true};
 },
 async pending(c:DeviceContext,signer:CheckpointSigner){
  const rows=await db.prepare('SELECT b.device_id,b.sequence,p.canonical,p.signature FROM device_revocation_boundaries b LEFT JOIN sync_checkpoints p ON p.tenant_id=b.tenant_id AND p.vault_id=b.vault_id AND p.sequence=b.sequence WHERE b.tenant_id=? AND b.vault_id=? ORDER BY b.device_id LIMIT 1000').bind(c.tenantId,c.vaultId).all<{device_id:string;sequence:number;canonical:string|null;signature:string|null}>();
  const revocations=[];for(const row of rows.results){const cp=row.canonical?{canonical:row.canonical,signature:row.signature!}:row.sequence===0?await checkpoint(signer,c.tenantId,c.vaultId,0,await genesisRoot(c.tenantId,c.vaultId),null,null):null;if(!cp)throw new ApiError('not_found');revocations.push({deviceId:row.device_id,acceptedThrough:cp});}
  await nonce(c).run();return {revocations};
 },
 /** Possession-only, read-only channel remains available to revoked devices. No session or write permission is issued. */
 async fetch(b:{accountId:string;tenantId:string;vaultId:string;deviceId:string;after:number;timestamp:number;signature:string}){
  if(!Number.isSafeInteger(b.after)||b.after<0||!Number.isSafeInteger(b.timestamp)||Math.abs(Math.floor(Date.now()/1000)-b.timestamp)>120)throw new ApiError('unauthorized');
  const key=await db.prepare('SELECT public_key FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id WHERE d.tenant_id=? AND d.account_id=? AND d.id=? AND v.vault_id=?').bind(b.tenantId,b.accountId,b.deviceId,b.vaultId).first<string>('public_key');
  const {signature,...body}=b;if(!key||!await verify(key,signature,JSON.stringify(['AgentKeychain-roster-fetch-v1',body])))throw new ApiError('unauthorized');
  const rows=await db.prepare('SELECT canonical,signature FROM signed_rosters WHERE tenant_id=? AND vault_id=? AND account_id=? AND revision>? ORDER BY revision LIMIT 32').bind(b.tenantId,b.vaultId,b.accountId,b.after).all<SignedManagedOperation>();
  const head=await db.prepare('SELECT revision,digest FROM signed_rosters WHERE tenant_id=? AND vault_id=? AND account_id=? ORDER BY revision DESC LIMIT 1').bind(b.tenantId,b.vaultId,b.accountId).first<{revision:number;digest:string}>();
  let size=0;const revisions=[];for(const row of rows.results){const length=JSON.stringify(row).length;if(size+length>768*1024)break;size+=length;revisions.push(row);}return {revisions,head};
 }
 };
}
