import type {DeviceContext} from './auth.ts';
import {ApiError} from '../shared/contracts.ts';
import {base64,identifier} from '../../src/cloud/protocol.ts';
export function trustRepository(db:D1Database){
 const nonce=(c:DeviceContext)=>db.prepare('INSERT INTO accept_device_nonce VALUES(?,?,?,?,?,?,?)').bind(c.sessionDigest,c.tenantId,c.vaultId,c.deviceId,c.accountId,c.nonce,c.timestamp);
 return {
  async put(c:DeviceContext,requestId:string,sealed:string){
   identifier(requestId);base64(sealed,48);if(sealed.length>512*1024)throw new ApiError('payload_too_large');
   const grant=await db.prepare('SELECT device_id FROM enrollment_grants WHERE id=? AND tenant_id=? AND vault_id=? AND issuer_device_id=?').bind(requestId,c.tenantId,c.vaultId,c.deviceId).first<{device_id:string}>();
   if(!grant)throw new ApiError('not_found');
   await db.batch([nonce(c),db.prepare('INSERT INTO trusted_enrollment_bundles VALUES(?,?,?,?,?,?)').bind(requestId,c.tenantId,c.vaultId,grant.device_id,c.deviceId,sealed)]);
   return {accepted:true};
  },
  async own(c:DeviceContext){
   const r=await db.prepare('SELECT b.sealed,g.canonical FROM trusted_enrollment_bundles b JOIN enrollment_grants g ON g.id=b.request_id WHERE b.tenant_id=? AND b.vault_id=? AND b.target_device_id=? ORDER BY g.key_epoch DESC LIMIT 1').bind(c.tenantId,c.vaultId,c.deviceId).first<{sealed:string;canonical:string}>();
   if(!r)throw new ApiError('not_found');await nonce(c).run();return r;
  },
  async grant(c:DeviceContext){
   const r=await db.prepare('SELECT canonical FROM enrollment_grants WHERE tenant_id=? AND vault_id=? AND device_id=? ORDER BY key_epoch DESC LIMIT 1').bind(c.tenantId,c.vaultId,c.deviceId).first<{canonical:string}>();
   if(!r)throw new ApiError('not_found');await nonce(c).run();return r;
  }
 };
}
