import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {digest,verify} from './contracts.ts';
import {verifyCheckpoint,type Checkpoint,type CheckpointKey} from './checkpoints.ts';
export const ROSTER_DOMAIN='AgentKeychain-trusted-roster-v1\0';
export interface RosterDevice {deviceId:string;signingKey:string;wrappingKey:string}
export interface RevokedRosterDevice extends RosterDevice {revokedRevision:number;acceptedThrough:Checkpoint}
export interface TrustedDeviceRoster {
 version:1;accountId:string;tenantId:string;vaultId:string;revision:number;previousDigest:string|null;keyEpoch:number;
 active:RosterDevice[];revoked:RevokedRosterDevice[];issuer:{kind:'device'|'recovery';id:string};issuedAt:number;expiresAt:number;
 checkpointKeys:CheckpointKey[];recoveryAuthorities:CheckpointKey[];recovery:SignedManagedOperation|null;
}
const sort=<T>(items:T[],key:(item:T)=>string)=>[...items].sort((a,b)=>key(a)<key(b)?-1:key(a)>key(b)?1:0);
const integer=(n:number,min=0)=>{if(!Number.isSafeInteger(n)||n<min)throw new Error('invalid_roster_integer');};
export function canonicalRoster(r:TrustedDeviceRoster):string{
 exactFields(r,['version','accountId','tenantId','vaultId','revision','previousDigest','keyEpoch','active','revoked','issuer','issuedAt','expiresAt','checkpointKeys','recoveryAuthorities','recovery']);
 if(r.version!==1)throw new Error('invalid_roster_version');for(const id of [r.accountId,r.tenantId,r.vaultId])identifier(id);
 integer(r.revision,1);integer(r.keyEpoch,1);integer(r.issuedAt);integer(r.expiresAt);
 if(r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>2592000||(r.revision===1?r.previousDigest!==null:typeof r.previousDigest!=='string'||!/^[a-f0-9]{64}$/.test(r.previousDigest)))throw new Error('invalid_roster');
 exactFields(r.issuer,['kind','id']);identifier(r.issuer.id);if(!['device','recovery'].includes(r.issuer.kind))throw new Error('invalid_roster_issuer');
 if(!Array.isArray(r.active)||!Array.isArray(r.revoked)||r.active.length+r.revoked.length<1||r.active.length+r.revoked.length>1000)throw new Error('invalid_roster_size');
 const ids=new Set<string>(),keys=new Set<string>();
 const device=(d:RosterDevice|RevokedRosterDevice,revoked:boolean)=>{
  exactFields(d,['deviceId','signingKey','wrappingKey',...(revoked?['revokedRevision','acceptedThrough']:[])]);identifier(d.deviceId);base64(d.signingKey,32,32);base64(d.wrappingKey,32,32);
  if(ids.has(d.deviceId)||keys.has(d.signingKey)||keys.has(d.wrappingKey)||d.signingKey===d.wrappingKey)throw new Error('invalid_roster_duplicate');ids.add(d.deviceId);keys.add(d.signingKey);keys.add(d.wrappingKey);
  const value={deviceId:d.deviceId,signingKey:d.signingKey,wrappingKey:d.wrappingKey};if(!revoked)return value;
  const v=d as RevokedRosterDevice;integer(v.revokedRevision,1);if(v.revokedRevision>r.revision)throw new Error('invalid_revocation_revision');exactFields(v.acceptedThrough,['canonical','signature']);base64(v.acceptedThrough.signature,64,64);
  return {...value,revokedRevision:v.revokedRevision,acceptedThrough:{canonical:v.acceptedThrough.canonical,signature:v.acceptedThrough.signature}};
 };
 const active=sort(r.active.map(d=>device(d,false)),d=>d.deviceId),revoked=sort(r.revoked.map(d=>device(d,true)),d=>d.deviceId);
 const pins=(p:CheckpointKey[],required:boolean)=>{if(!Array.isArray(p)||p.length>16||(required&&!p.length))throw new Error('invalid_roster_pins');const ids=new Set<string>(),values=new Set<string>();return sort(p.map(k=>{exactFields(k,['keyId','publicKey']);identifier(k.keyId);base64(k.publicKey,32,32);if(ids.has(k.keyId)||values.has(k.publicKey))throw new Error('invalid_roster_pins');ids.add(k.keyId);values.add(k.publicKey);return {keyId:k.keyId,publicKey:k.publicKey};}),k=>k.keyId);};
 if(r.recovery!==null){exactFields(r.recovery,['canonical','signature']);base64(r.recovery.signature,64,64);if(typeof r.recovery.canonical!=='string'||r.recovery.canonical.length>8192)throw new Error('invalid_recovery_evidence');}
 if((r.issuer.kind==='recovery')!==(r.recovery!==null))throw new Error('invalid_recovery_evidence');
 const canonical=JSON.stringify({version:1,accountId:r.accountId,tenantId:r.tenantId,vaultId:r.vaultId,revision:r.revision,previousDigest:r.previousDigest,keyEpoch:r.keyEpoch,active,revoked,issuer:{kind:r.issuer.kind,id:r.issuer.id},issuedAt:r.issuedAt,expiresAt:r.expiresAt,checkpointKeys:pins(r.checkpointKeys,true),recoveryAuthorities:pins(r.recoveryAuthorities,false),recovery:r.recovery?{canonical:r.recovery.canonical,signature:r.recovery.signature}:null});
 if(canonical.length>512*1024)throw new Error('invalid_roster_size');return canonical;
}
export function parseRoster(s:SignedManagedOperation):TrustedDeviceRoster{exactFields(s,['canonical','signature']);base64(s.signature,64,64);if(typeof s.canonical!=='string'||s.canonical.length>512*1024)throw new Error('invalid_roster_size');const r=JSON.parse(s.canonical) as TrustedDeviceRoster;if(canonicalRoster(r)!==s.canonical)throw new Error('invalid_roster_canonical');return r;}
export const rosterDigest=(s:SignedManagedOperation)=>digest(JSON.stringify(['AgentKeychain-roster-digest-v1',s.canonical,s.signature]));
/** Callers must independently authenticate the first bundle. A server response is never an anchor. */
async function validateRoster(s:SignedManagedOperation,previous:SignedManagedOperation|null,now=Math.floor(Date.now()/1000),bootstrap=false){
 const r=parseRoster(s),p=previous?parseRoster(previous):null;
 if(r.issuedAt>now+120||r.expiresAt<=now)throw new Error('invalid_roster_expiry');
 if(p){
  if(r.accountId!==p.accountId||r.tenantId!==p.tenantId||r.vaultId!==p.vaultId||r.revision!==p.revision+1||r.previousDigest!==await rosterDigest(previous!)||r.keyEpoch!==p.keyEpoch||r.issuedAt<p.issuedAt||JSON.stringify(r.checkpointKeys)!==JSON.stringify(p.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(p.recoveryAuthorities))throw new Error('invalid_roster_chain');
  for(const old of [...p.active,...p.revoked]){const next=[...r.active,...r.revoked].find(d=>d.deviceId===old.deviceId);if(!next||next.signingKey!==old.signingKey||next.wrappingKey!==old.wrappingKey)throw new Error('invalid_roster_key_substitution');}
  for(const old of p.revoked)if(JSON.stringify(r.revoked.find(d=>d.deviceId===old.deviceId))!==JSON.stringify(old))throw new Error('invalid_roster_reactivation');
  for(const d of r.revoked)if(!p.revoked.some(v=>v.deviceId===d.deviceId)&&(!p.active.some(v=>v.deviceId===d.deviceId)||d.revokedRevision!==r.revision))throw new Error('invalid_roster_revocation');
 }else if(!bootstrap&&(r.revision!==1||r.revoked.length||r.active.length!==1))throw new Error('invalid_roster_genesis');
 let key:string|undefined;
 if(r.issuer.kind==='device')key=(p??r).active.find(d=>d.deviceId===r.issuer.id)?.signingKey;
 else {
  key=(p??r).recoveryAuthorities.find(k=>k.keyId===r.issuer.id)?.publicKey;
  const e=r.recovery!,c=JSON.parse(e.canonical) as {version:number;caseId:string;accountId:string;tenantId:string;vaultId:string;revision:number;previousDigest:string;targetDeviceId:string;signingKey:string;wrappingKey:string;completedAt:number};
  exactFields(c,['version','caseId','accountId','tenantId','vaultId','revision','previousDigest','targetDeviceId','signingKey','wrappingKey','completedAt']);identifier(c.caseId);integer(c.completedAt);
  if(e.canonical!==JSON.stringify({version:c.version,caseId:c.caseId,accountId:c.accountId,tenantId:c.tenantId,vaultId:c.vaultId,revision:c.revision,previousDigest:c.previousDigest,targetDeviceId:c.targetDeviceId,signingKey:c.signingKey,wrappingKey:c.wrappingKey,completedAt:c.completedAt}))throw new Error('invalid_roster_recovery_canonical');
  const target=r.active.find(d=>d.deviceId===c.targetDeviceId);
  if(c.version!==1||c.accountId!==r.accountId||c.tenantId!==r.tenantId||c.vaultId!==r.vaultId||c.revision!==r.revision||c.previousDigest!==r.previousDigest||c.completedAt>r.issuedAt||!target||target.signingKey!==c.signingKey||target.wrappingKey!==c.wrappingKey||!key||!await verify(key,e.signature,'AgentKeychain-roster-recovery-completed-v1\0'+e.canonical))throw new Error('invalid_roster_recovery');
 }
 if(!key)throw new Error('invalid_roster_issuer');
 for(const d of r.revoked){const id=(JSON.parse(d.acceptedThrough.canonical) as {keyId:string}).keyId,pin=r.checkpointKeys.find(k=>k.keyId===id);if(!pin)throw new Error('invalid_roster_checkpoint');await verifyCheckpoint(pin,r.tenantId,r.vaultId,d.acceptedThrough);}
 return {r,key};
}
export async function verifyRoster(s:SignedManagedOperation,previous:SignedManagedOperation|null,now=Math.floor(Date.now()/1000),bootstrap=false):Promise<TrustedDeviceRoster>{
 const {r,key}=await validateRoster(s,previous,now,bootstrap);if(!await verify(key,s.signature,ROSTER_DOMAIN+s.canonical))throw new Error('invalid_roster_issuer');return r;
}
/** Independent recovery-authority signer. The API server stores the result and has no signing key.
 * Completed evidence is an authority-signed certificate, never a caller's boolean/state label. */
export async function issueRecoveryRoster(previous:SignedManagedOperation,next:TrustedDeviceRoster,signer:{key():Promise<CheckpointKey>;sign(message:string):Promise<string>}):Promise<SignedManagedOperation>{
 if(next.issuer.kind!=='recovery'||!next.recovery)throw new Error('invalid_roster_recovery');
 const pin=await signer.key(),prior=parseRoster(previous);
 if(pin.keyId!==next.issuer.id||!prior.recoveryAuthorities.some(k=>k.keyId===pin.keyId&&k.publicKey===pin.publicKey))throw new Error('invalid_roster_authority');
 // Verify the completion certificate before asking an authority to sign a new revision.
 if(!await verify(pin.publicKey,next.recovery.signature,'AgentKeychain-roster-recovery-completed-v1\0'+next.recovery.canonical))throw new Error('invalid_roster_recovery');
 const canonical=canonicalRoster(next);await validateRoster({canonical,signature:btoa('\0'.repeat(64))},previous);
 const signed={canonical,signature:await signer.sign(ROSTER_DOMAIN+canonical)};
 await verifyRoster(signed,previous);return signed;
}
