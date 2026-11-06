import {WorkerEntrypoint} from 'cloudflare:workers';
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {recoveryAuthority} from './recovery-authorization.ts';
import {recoveryKeyring} from './recovery-keyring.ts';
import {manifest,packageContext,recoveryCase,type CancelAuthorization,type RecoveryEvidence} from './recovery.ts';
import {parseRoster,verifyRoster} from './roster.ts';
import {parseRecoveryRevocation} from './revocation-witness.ts';
import {digest} from './contracts.ts';
import {domainSigner,loadKeyrings,validateRewrap,type Party,type SigningPurpose} from './trust-support.ts';
import type {SealedShare} from './recovery-crypto.ts';
export interface TrustEnv {
 TRUST_DB:D1Database;
 CHECKPOINT_KEYRING?:string;ACCOUNT_KEYRING?:string;WRAP_KEYRING:string;RELEASE_KEYRING:string;WITNESS_KEYRING?:string;TRUST_KEYRING?:string;
 PEER_PUBLIC_KEYS:string;RELEASE_POLICY:string;
}
// Helpers are module functions, never RPC methods. TypeScript access modifiers
// alone do not hide a WorkerEntrypoint method from a service binding caller.
async function safe<T>(call:()=>Promise<T>):Promise<T>{try{return await call();}catch{throw new Error('trust_operation_rejected');}}
async function rings(env:TrustEnv,party:Party){
 const peers:unknown=JSON.parse(env.PEER_PUBLIC_KEYS);if(!Array.isArray(peers)||!peers.length||peers.length>64)throw new Error('unavailable');
 for(const p of peers)base64(p,32,32);
 return loadKeyrings({wrap:env.WRAP_KEYRING,release:env.RELEASE_KEYRING,...(party==='api'?{checkpoint:env.CHECKPOINT_KEYRING!,account:env.ACCOUNT_KEYRING!}:{witness:env.WITNESS_KEYRING!,trust:env.TRUST_KEYRING!})},peers);
}
async function signer(env:TrustEnv,party:Party,purpose:SigningPurpose){const ring=(await rings(env,party))[purpose];if(!ring)throw new Error('unavailable');return domainSigner(ring,purpose,party);}
function registry(env:TrustEnv,party:Party){const db=env.TRUST_DB;return {
 device:async(a:string,t:string,v:string,d:string)=>{
  const revoked=await db.prepare('SELECT 1 FROM trust_devices WHERE account_id=? AND tenant_id=? AND vault_id=? AND device_id=? AND revoked=1').bind(a,t,v,d).first();if(revoked)return null;
  if(party==='api')return db.prepare('SELECT d.public_key FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id JOIN memberships m ON m.account_id=d.account_id AND m.tenant_id=d.tenant_id WHERE d.account_id=? AND d.tenant_id=? AND v.vault_id=? AND d.id=? AND d.active=1 AND v.active=1 AND m.active=1').bind(a,t,v,d).first<string>('public_key');
  const raw=await db.prepare('SELECT roster FROM roster_witness WHERE tenant_id=? AND vault_id=? ORDER BY event DESC LIMIT 1').bind(t,v).first<string>('roster');
  if(raw){const r=parseRoster(JSON.parse(raw));if(r.accountId!==a||r.expiresAt<=Math.floor(Date.now()/1000))return null;
   if(await db.prepare('SELECT 1 FROM recovery_revocation_witness WHERE tenant_id=? AND vault_id=? AND device_id=?').bind(t,v,d).first())return null;
   return r.active.find(x=>x.deviceId===d)?.signingKey??null;
  }
  return db.prepare('SELECT signing_key FROM trust_devices WHERE account_id=? AND tenant_id=? AND vault_id=? AND device_id=? AND revoked=0 AND expires_at>unixepoch()').bind(a,t,v,d).first<string>('signing_key');
 },
 accountVerifier:async(a:string)=>db.prepare('SELECT public_key FROM trust_accounts WHERE account_id=? AND revoked=0 AND expires_at>unixepoch()').bind(a).first<string>('public_key')
};}
const authority=(env:TrustEnv,party:Party)=>recoveryAuthority(registry(env,party));
class Private extends WorkerEntrypoint<TrustEnv>{override async fetch(){return new Response(null,{status:404});}}
export function authorityEntrypoint(party:Party){return class extends Private{
 async cancel(c:string,a:CancelAuthorization){return safe(async()=>{await rings(this.env,party);return authority(this.env,party).cancel(c,a);});}
 async complete(c:string,p:string,s:string){return safe(async()=>{await rings(this.env,party);return authority(this.env,party).complete(c,p,s);});}
 async enrollment(c:string,s:string){return safe(async()=>{await rings(this.env,party);return authority(this.env,party).enrollment(c,s);});}
 async authorize(c:string,e:RecoveryEvidence){return safe(async()=>{
  await rings(this.env,party);if(!await authority(this.env,party).authorize(c,e))return false;
  await this.env.TRUST_DB.prepare('DELETE FROM trust_authorizations WHERE expires_at<=unixepoch()').run();
  await this.env.TRUST_DB.prepare('INSERT INTO trust_authorizations VALUES(?,?,unixepoch()+60) ON CONFLICT(digest) DO UPDATE SET evidence=excluded.evidence,expires_at=excluded.expires_at').bind(await digest(c),JSON.stringify(e)).run();return true;
 });}
 async rosterRevocation(c:string){return safe(async()=>{await rings(this.env,party);parseRecoveryRevocation(c);return !!await this.env.TRUST_DB.prepare('SELECT 1 FROM trust_revocations WHERE digest=? AND expires_at>unixepoch()').bind(await digest(c)).first();});}
 async rosterGenesis(s:SignedManagedOperation){return safe(async()=>{await rings(this.env,party);const r=await verifyRoster(s,null),key=await registry(this.env,party).device(r.accountId,r.tenantId,r.vaultId,r.issuer.id);return r.issuer.kind==='device'&&r.active.find(d=>d.deviceId===r.issuer.id)?.signingKey===key;});}
};}
export function keysEntrypoint(party:Party){return class extends Private{
 async key(){return safe(async()=>{const r=(await rings(this.env,party)).wrap!;return {keyId:r.active.keyId,publicKey:r.active.publicKey};});}
 async rewrap(id:string,box:SealedShare,source:string,target:string,context:string){return safe(async()=>{
  const c=validateRewrap(party,id,source,target,context),db=this.env.TRUST_DB,canonical=JSON.stringify(c);
  const table=party==='api'?'recovery_packages_v1':'recovery_packages';
  const row=await db.prepare(`SELECT p.canonical FROM recovery_sagas s JOIN ${table} p ON p.id=s.package_id WHERE s.id=? AND s.canonical=? AND s.state IN('prepared','confirmed','released') AND s.expires_at>unixepoch() AND p.key_epoch=(SELECT max(key_epoch) FROM ${table} WHERE tenant_id=p.tenant_id AND vault_id=p.vault_id)`).bind(c.id,canonical).first<{canonical:string}>();
  const evidence=await db.prepare('SELECT evidence FROM trust_authorizations WHERE digest=? AND expires_at>unixepoch()').bind(await digest(canonical)).first<string>('evidence');
  if(!row||!evidence||!await authority(this.env,party).authorize(canonical,JSON.parse(evidence)))throw new Error('unauthorized');
  const m=manifest(row.canonical);if(source!==packageContext(m,party)||JSON.stringify(box)!==JSON.stringify(party==='api'?m.apiShare:m.custodianShare))throw new Error('unauthorized');
  const r=(await rings(this.env,party)).wrap!,keyring=await recoveryKeyring(new Map([...r.keys].map(([id,k])=>[id,k.pair!])),r.active.keyId);
  return keyring.rewrap(id,box,source,target,context);
 });}
};}
export function signerEntrypoint(party:Party,purpose:SigningPurpose){return class extends Private{
 async key(){return safe(async()=>{return (await signer(this.env,party,purpose)).key();});}
 async publicKeys(){return safe(async()=>{const r=(await rings(this.env,party))[purpose]!;return [...r.keys.values()].map(k=>({keyId:k.keyId,publicKey:k.publicKey}));});}
 async sign(message:string){return safe(async()=>{return (await signer(this.env,party,purpose)).sign(message);});}
};}
export class AccountAttesterBase extends Private {
 async attest(canonical:string){return safe(async()=>{
  const c=recoveryCase(canonical),s=await signer(this.env,'api','account'),pin=await s.key();
  if(await registry(this.env,'api').accountVerifier(c.accountId)!==pin.publicKey)throw new Error('unauthorized');
  const verified=await this.env.TRUST_DB.prepare('SELECT 1 FROM recovery_sessions WHERE account_id=? AND tenant_id=? AND vault_id=? AND case_id=? AND expires_at>unixepoch() AND revoked=0').bind(c.accountId,c.tenantId,c.vaultId,c.id).first();
  const saga=await this.env.TRUST_DB.prepare("SELECT 1 FROM recovery_sagas WHERE id=? AND canonical=? AND state IN('prepared','confirmed','released') AND expires_at>unixepoch()").bind(c.id,canonical).first();
  if(!verified||!saga)throw new Error('unauthorized');return s.sign(JSON.stringify(['AgentKeychain-recovery-account-verified-v1',canonical]));
 });}
}
export class RecoveryTrustPolicyBase extends Private {
 async manifest(){return safe(async()=>{
  const local=await rings(this.env,'custodian');const raw=this.env.RELEASE_POLICY,p=JSON.parse(raw) as Required<import('../../src/cloud/config.ts').ReleaseTrustManifest>;exactFields(p,['version','releaseId','apiOrigin','protocolMin','protocolMax','checkpointKeys','witnessKeys','recoveryAuthorities','recoveryServices']);
  if(JSON.stringify(p)!==raw||p.version!==1||new URL(p.apiOrigin).origin!==p.apiOrigin||!p.apiOrigin.startsWith('https://')||p.protocolMin!==2||p.protocolMax!==2)throw new Error('unavailable');
  const pins=[...p.checkpointKeys,...p.witnessKeys,...p.recoveryAuthorities,p.recoveryServices.api,p.recoveryServices.custodian];
  if(!p.checkpointKeys.length||!p.witnessKeys.length||!p.recoveryAuthorities.length||new Set(pins.map(k=>k.publicKey)).size!==pins.length)throw new Error('unavailable');
  for(const pin of pins){exactFields(pin,['keyId','publicKey']);base64(pin.publicKey,32,32);if(pin.keyId!==await digest(pin.publicKey))throw new Error('unavailable');}
  const peers:unknown=JSON.parse(this.env.PEER_PUBLIC_KEYS);if(!Array.isArray(peers)||!peers.length||peers.some(k=>typeof k!=='string'))throw new Error('unavailable');
  for(const pin of [...p.checkpointKeys,p.recoveryServices.api])if(!peers.includes(pin.publicKey))throw new Error('unavailable');
  const localOwn=(purpose:'witness'|'trust'|'release')=>new Set([...local[purpose]!.keys.values()].map(k=>k.publicKey));
  for(const pin of p.witnessKeys)if(!localOwn('witness').has(pin.publicKey))throw new Error('unavailable');
  for(const pin of p.recoveryAuthorities)if(!localOwn('trust').has(pin.publicKey))throw new Error('unavailable');
  if(!localOwn('release').has(p.recoveryServices.custodian.publicKey))throw new Error('unavailable');
  for(const [purpose,pins] of [['witness',p.witnessKeys],['trust',p.recoveryAuthorities],['release',[p.recoveryServices.custodian]]] as const){const key=await (await signer(this.env,'custodian',purpose)).key();if(!pins.some(p=>p.keyId===key.keyId&&p.publicKey===key.publicKey))throw new Error('unavailable');}
  return raw;
 });}
}
