import {parseRoster} from '../../managed-cloud/shared/roster.ts';
import {signRoster,rosterPins} from './roster.ts';
import sodium from 'libsodium-wrappers-sumo';
import { createHash } from 'node:crypto';
import { canonicalGrant, type EnrollmentGrant } from '../../managed-cloud/shared/device-protocol.ts';
import { assertVerifiedPolicy, type ManagedEndpointPolicy } from './config.ts';
import { base64, exactFields, identifier, type DeviceRecord, type SignedManagedOperation } from './protocol.ts';
import type { CloudKeys } from './crypto.ts';
import type { CheckpointKey } from '../../managed-cloud/shared/checkpoints.ts';
await sodium.ready;
export interface TrustedEnrollmentBundle {
  signedRoster:SignedManagedOperation;
  version:1;
  kind:'enrollment'|'recovery';
  request:EnrollmentGrant;
  issuerKey:string;
  roster:DeviceRecord[];
  checkpointKeys:readonly CheckpointKey[];
  nonce:string;
  recoveryCase:string|null;
}
export function canonicalEnrollment(b:TrustedEnrollmentBundle):string {
  exactFields(b,['version','kind','request','issuerKey','roster','checkpointKeys','nonce','recoveryCase','signedRoster']);
  if(b.version!==1 || !['enrollment','recovery'].includes(b.kind))throw new Error('invalid_trust_bundle');
  const request=JSON.parse(canonicalGrant(b.request)) as EnrollmentGrant;
  identifier(b.nonce);base64(b.issuerKey,32,32);
  if(b.kind==='recovery')identifier(b.recoveryCase);else if(b.recoveryCase!==null)throw new Error('invalid_recovery_binding');
  if(!Array.isArray(b.roster)||b.roster.length<1||b.roster.length>1000)throw new Error('invalid_roster');
  const ids=new Set<string>();
  const roster=b.roster.map(r=>{
    exactFields(r,['vaultId','deviceId','publicKey','revoked']);identifier(r.deviceId);base64(r.publicKey,32,32);
    if(r.vaultId!==request.vaultId||typeof r.revoked!=='boolean'||ids.has(r.deviceId))throw new Error('invalid_roster');
    ids.add(r.deviceId);return {vaultId:r.vaultId,deviceId:r.deviceId,publicKey:r.publicKey,revoked:r.revoked};
  }).sort((a,b)=>a.deviceId<b.deviceId?-1:a.deviceId>b.deviceId?1:0);
  const target=roster.find(r=>r.deviceId===request.deviceId);
  if(!target||target.revoked||target.publicKey!==request.signingKey)throw new Error('invalid_target');
  if(b.kind==='enrollment'){
    const issuer=roster.find(r=>r.deviceId===request.issuerDeviceId);
    if(!issuer||issuer.revoked||issuer.publicKey!==b.issuerKey)throw new Error('invalid_issuer');
  }
  const pins=new Set<string>();
  if(!Array.isArray(b.checkpointKeys)||!b.checkpointKeys.length||b.checkpointKeys.length>16)throw new Error('invalid_pins');
  const checkpointKeys=b.checkpointKeys.map(p=>{
    exactFields(p,['keyId','publicKey']);identifier(p.keyId);base64(p.publicKey,32,32);
    if(pins.has(p.keyId))throw new Error('duplicate_pin');pins.add(p.keyId);return {keyId:p.keyId,publicKey:p.publicKey};
  }).sort((a,b)=>a.keyId<b.keyId?-1:a.keyId>b.keyId?1:0);
  {const r=parseRoster(b.signedRoster);if(r.accountId!==request.accountId||r.tenantId!==request.tenantId||r.vaultId!==request.vaultId||r.keyEpoch!==request.keyEpoch||JSON.stringify(rosterPins(r).sort((a,b)=>a.deviceId<b.deviceId?-1:1))!==JSON.stringify(roster)||JSON.stringify(r.checkpointKeys)!==JSON.stringify(checkpointKeys)||!r.active.some(d=>d.deviceId===request.deviceId&&d.wrappingKey===request.wrappingKey)||(b.kind==='enrollment'?(r.issuer.kind!=='device'||r.issuer.id!==request.issuerDeviceId||r.active.find(d=>d.deviceId===r.issuer.id)?.signingKey!==b.issuerKey):(r.issuer.kind!=='recovery'||r.recoveryAuthorities.find(k=>k.keyId===r.issuer.id)?.publicKey!==b.issuerKey||!r.recovery||(JSON.parse(r.recovery.canonical) as {caseId:string}).caseId!==b.recoveryCase)))throw new Error('invalid_roster_bundle');}
  return JSON.stringify({signedRoster:b.signedRoster,version:1,kind:b.kind,request,issuerKey:b.issuerKey,roster,checkpointKeys,nonce:b.nonce,recoveryCase:b.recoveryCase});
}
/** Both devices display this locally computed commitment, never a server-selected phrase.
 * 80 bits shown in five groups. Confirmation applies to this exact transcript. */
export function enrollmentPhrase(bundle:TrustedEnrollmentBundle):string {
  return createHash('sha256').update('AgentKeychain-enrollment-SAS-v1\0').update(canonicalEnrollment(bundle)).digest('hex').slice(0,20).match(/.{4}/g)!.join(' ');
}
export function sealTrustedEnrollment(bundle:TrustedEnrollmentBundle,signingPrivate:Uint8Array):string {
  const canonical=canonicalEnrollment(bundle);
  const signed:SignedManagedOperation={canonical,signature:Buffer.from(sodium.crypto_sign_detached('AgentKeychain-trust-bundle-v1\0'+canonical,signingPrivate)).toString('base64')};
  const plain=Buffer.from(JSON.stringify(signed));
  try{return Buffer.from(sodium.crypto_box_seal(plain,Buffer.from(bundle.request.wrappingKey,'base64'))).toString('base64');}
  finally{plain.fill(0);}
}
export interface EnrollmentAcceptance {
  request:EnrollmentGrant;
  phraseConfirmed:boolean;
  phrase:string;
  policy:ManagedEndpointPolicy;
  recovery?:{completedCase:string;authorityPublicKey:string};
}
export function openTrustedEnrollment(sealed:string,keys:Pick<CloudKeys,'wrappingPublic'|'wrappingPrivate'|'signingPublic'>,local:EnrollmentAcceptance,verifiedAt=Math.floor(Date.now()/1000)):TrustedEnrollmentBundle {
  assertVerifiedPolicy(local.policy);
  if(local.phraseConfirmed!==true||sealed.length>512*1024)throw new Error('phrase_confirmation_required');
  let plaintext:Uint8Array|undefined;
  try{
    base64(sealed,48);
    plaintext=sodium.crypto_box_seal_open(Buffer.from(sealed,'base64'),keys.wrappingPublic,keys.wrappingPrivate);
    const signed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plaintext)) as SignedManagedOperation;
    exactFields(signed,['canonical','signature']);base64(signed.signature,64,64);
    const b=JSON.parse(signed.canonical) as TrustedEnrollmentBundle;
    if(canonicalEnrollment(b)!==signed.canonical||canonicalGrant(b.request)!==canonicalGrant(local.request)||
      b.request.expiresAt<=verifiedAt||b.request.expiresAt>verifiedAt+600||
      b.request.signingKey!==Buffer.from(keys.signingPublic).toString('base64')||b.request.wrappingKey!==Buffer.from(keys.wrappingPublic).toString('base64')||
      enrollmentPhrase(b)!==local.phrase||JSON.stringify(b.checkpointKeys)!==JSON.stringify(local.policy.checkpointKeys))throw new Error();
    if(b.signedRoster&&JSON.stringify(parseRoster(b.signedRoster).recoveryAuthorities)!==JSON.stringify(local.policy.recoveryAuthorities??[]))throw new Error();
    if(b.kind==='recovery'&&(!local.recovery||b.recoveryCase!==local.recovery.completedCase||b.issuerKey!==local.recovery.authorityPublicKey))throw new Error();
    if(b.kind==='enrollment'&&local.recovery)throw new Error();
    if(!sodium.crypto_sign_verify_detached(Buffer.from(signed.signature,'base64'),'AgentKeychain-trust-bundle-v1\0'+signed.canonical,Buffer.from(b.issuerKey,'base64')))throw new Error();
    return b;
  }catch{throw new Error('invalid_trusted_enrollment');}finally{plaintext?.fill(0);}
}
export function selfAnchor(request:EnrollmentGrant,keys:CloudKeys,policy:ManagedEndpointPolicy,passkeyApproved:boolean){
  assertVerifiedPolicy(policy);canonicalGrant(request);
  if(!passkeyApproved||request.issuerDeviceId!==null||request.signingKey!==Buffer.from(keys.signingPublic).toString('base64')||request.wrappingKey!==Buffer.from(keys.wrappingPublic).toString('base64')||request.expiresAt<=Math.floor(Date.now()/1000))throw new Error('invalid_first_device_approval');
  const now=Math.floor(Date.now()/1000);
  const signedRoster=signRoster({version:1,accountId:request.accountId,tenantId:request.tenantId,vaultId:request.vaultId,revision:1,previousDigest:null,keyEpoch:request.keyEpoch,active:[{deviceId:request.deviceId,signingKey:request.signingKey,wrappingKey:request.wrappingKey}],revoked:[],issuer:{kind:'device',id:request.deviceId},issuedAt:now,expiresAt:now+2592000,checkpointKeys:[...policy.checkpointKeys],recoveryAuthorities:[...(policy.recoveryAuthorities??[])],recovery:null},keys.signingPrivate);
  return {signedRoster,roster:[{vaultId:request.vaultId,deviceId:request.deviceId,publicKey:request.signingKey,revoked:false}],checkpointKeys:policy.checkpointKeys};
}
/** Preview is display-only. It establishes no pin and cannot activate a device. */
export function previewEnrollmentPhrase(sealed:string,keys:Pick<CloudKeys,'wrappingPublic'|'wrappingPrivate'>):string {
 if(sealed.length>512*1024)throw new Error('invalid_trusted_enrollment');base64(sealed,48);
 const bytes=sodium.crypto_box_seal_open(Buffer.from(sealed,'base64'),keys.wrappingPublic,keys.wrappingPrivate);
 try{const signed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as SignedManagedOperation;return enrollmentPhrase(JSON.parse(signed.canonical) as TrustedEnrollmentBundle);}finally{bytes.fill(0);}
}
