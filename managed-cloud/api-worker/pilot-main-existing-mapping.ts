/** Unwired, read-only Main resolver for one operator-allowlisted pilot link. */
import {URL} from 'node:url';
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {CheckpointKey} from '../shared/checkpoints.ts';
import {digest,verify} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import type {ExistingMainMapping} from '../shared/pilot-main-invite-link.ts';

export const PILOT_MAIN_MAPPING_ALLOWLIST='AgentKeychain-pilot-main-existing-mapping-allowlist-v1';
const denied=()=>new Error('pilot_main_existing_mapping_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const digestShape=(s:unknown):s is string=>typeof s==='string'&&s.length===64&&/^[a-f0-9]{64}$/.test(s);
type Configuration=Readonly<{
 mode:'existing-mapping-v1';operator:Readonly<CheckpointKey>;reservedRolePins:readonly Readonly<CheckpointKey>[];
 // Independently verified from the pilot installation or explicitly reviewed
 // provisioning policy. Never populate this from an applicant or the invite.
 installation:Readonly<Omit<ExistingMainMapping,'grantCanonical'>>;
 allowlist:Readonly<SignedManagedOperation>;
}>;
type Row={
 grant:string;custodyReceipt:string;requestId:string;accountId:string;tenantId:string;vaultId:string;deviceId:string;
 signingKey:string;wrappingKey:string;keyEpoch:number;grantExpiresAt:number;
};

/** Call only with trusted owner configuration. There is no input selector,
 * account creation, write, fallback or credential issuer. A successful lookup
 * is evidence of existing scoped mapping, not authorization to act. */
export async function resolvePilotMainExistingMapping(
 db:Pick<D1Database,'withSession'>,config?:Configuration,
):Promise<ExistingMainMapping>{
 try{
  if(config?.mode!=='existing-mapping-v1')throw denied();
  const {operator,reservedRolePins,installation,allowlist:{canonical,signature}}=config;
  const {installationDigest,profileDigest,installationExpiresAt,authOrigin,rpId}=installation,at=now();
  const u=new URL(authOrigin);
  if(u.origin!==authOrigin||u.protocol!=='https:'||u.port||u.hostname!==rpId||
     !/^auth-pilot-[a-z0-9]+(?:-[a-z0-9]+)*\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(rpId)||
     !digestShape(installationDigest)||!digestShape(profileDigest)||!Number.isSafeInteger(installationExpiresAt)||installationExpiresAt<=at||
     typeof canonical!=='string'||canonical.length>2048||!reservedRolePins.length||reservedRolePins.length>16)throw denied();
  for(const p of [operator,...reservedRolePins]){base64(p.publicKey,32,32);if(p.keyId!==await digest(p.publicKey))throw denied();}
  if(reservedRolePins.some(p=>p.publicKey===operator.publicKey||p.keyId===operator.keyId))throw denied();
  base64(signature,64,64);
  const claim:unknown=JSON.parse(canonical);
  exactFields(claim,['version','domain','keyId','attemptDigest','grantDigest','custodyReceiptDigest','installationDigest','profileDigest',
   'authOrigin','rpId','installationExpiresAt','issuedAt','expiresAt']);
  const {attemptDigest,grantDigest,custodyReceiptDigest,issuedAt,expiresAt}=claim;
  if(!digestShape(attemptDigest)||!digestShape(grantDigest)||!digestShape(custodyReceiptDigest)||
     typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
     issuedAt<1||issuedAt>at||expiresAt<=at||expiresAt>installationExpiresAt||expiresAt-issuedAt>600||
     canonical!==JSON.stringify({version:1,domain:PILOT_MAIN_MAPPING_ALLOWLIST,keyId:operator.keyId,attemptDigest,grantDigest,custodyReceiptDigest,
      installationDigest,profileDigest,authOrigin,rpId,installationExpiresAt,issuedAt,expiresAt})||
     !await verify(operator.publicKey,signature,canonical))throw denied();

  const read=()=>db.withSession('first-primary').prepare(`
   SELECT s.grant,s.custody_receipt AS custodyReceipt,q.id AS requestId,q.account_id AS accountId,q.tenant_id AS tenantId,
    q.vault_id AS vaultId,q.device_id AS deviceId,q.signing_key AS signingKey,q.wrapping_key AS wrappingKey,q.key_epoch AS keyEpoch,
    q.expires_at AS grantExpiresAt
   FROM pilot_genesis_main_binding_stage s JOIN pilot_genesis_main_binding_eligible q ON q.id=s.request_id
    AND q.account_id=s.account_id AND q.tenant_id=s.tenant_id AND q.vault_id=s.vault_id AND q.device_id=s.device_id
   WHERE s.attempt_digest=? AND unixepoch()>=? AND unixepoch()<?
  `).bind(attemptDigest,issuedAt,expiresAt).first<Row>();
  const row=await read();
  if(!row||typeof row.grant!=='string'||row.grant.length>4096||typeof row.custodyReceipt!=='string'||row.custodyReceipt.length>8192)throw denied();
  const {requestId,accountId,tenantId,vaultId,deviceId,signingKey,wrappingKey,keyEpoch,grantExpiresAt}=row;
  const g:EnrollmentGrant={version:1,requestId,accountId,tenantId,vaultId,deviceId,signingKey,wrappingKey,
   issuerDeviceId:null,keyEpoch,expiresAt:grantExpiresAt};
  if(row.grant!==canonicalGrant(g)||expiresAt>grantExpiresAt||[signingKey,wrappingKey].includes(operator.publicKey)||
     await digest(row.grant)!==grantDigest||await digest(row.custodyReceipt)!==custodyReceiptDigest||
     JSON.stringify(await read())!==JSON.stringify(row)||now()>=expiresAt)throw denied();
  // ExistingMainMapping's expiry is a ceiling for subsequent verification.
  // Narrow it to the operator grant; never extend the signed installation.
  return Object.freeze({grantCanonical:row.grant,installationDigest,profileDigest,installationExpiresAt:expiresAt,authOrigin,rpId});
 }catch{throw denied();}
}
