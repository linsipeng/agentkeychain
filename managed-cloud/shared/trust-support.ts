import {base64,exactFields,identifier} from '../../src/cloud/protocol.ts';
import {decode64,encode64} from './recovery-crypto.ts';
import {digest} from './contracts.ts';
import {genesisRoot} from './checkpoints.ts';
import {canonicalRecoveryRelease,RECOVERY_RELEASE_DOMAIN} from './recovery-release.ts';
import {canonicalRoster,ROSTER_DOMAIN} from './roster.ts';
import {parseRecoveryRevocation} from './revocation-witness.ts';
import {parseRecoveryTrust,RECOVERY_TRUST_DOMAIN} from './recovery-trust.ts';
import {WITNESS_DOMAIN} from './roster-witness.ts';
import {recoveryCase} from './recovery.ts';
export type Party='api'|'custodian';
export type SigningPurpose='checkpoint'|'release'|'witness'|'trust'|'account';
interface Material {keyId:string;publicKey:string;pair?:CryptoKeyPair}
export interface Keyring {active:Material & {pair:CryptoKeyPair};keys:Map<string,Material>}
const deny=()=>new Error('invalid_trust_configuration');
export async function loadKeyrings(materials:Record<string,string>,peerPublicKeys:readonly string[]):Promise<Record<string,Keyring>>{
 const used=new Set(peerPublicKeys),privateValues=new Set<string>(),result:Record<string,Keyring>={};
 for(const p of peerPublicKeys)base64(p,32,32);
 for(const [purpose,raw] of Object.entries(materials)){
  if(typeof raw!=='string'||raw.length>32768)throw deny();
  const r=JSON.parse(raw);exactFields(r,['activeId','keys']);identifier(r.activeId);
  if(!Array.isArray(r.keys)||!r.keys.length||r.keys.length>16)throw deny();
  const keys=new Map<string,Material>();
  for(const k of r.keys){
   exactFields(k,['keyId','publicKey',...('privateKey' in k?['privateKey']:[])]);base64(k.publicKey,32,32);
   if(!('privateKey' in k)){if(purpose==='wrap'||k.keyId===r.activeId||k.keyId!==await digest(k.publicKey)||used.has(k.publicKey)||keys.has(k.keyId))throw deny();used.add(k.publicKey);keys.set(k.keyId,{keyId:k.keyId,publicKey:k.publicKey});continue;}
   base64(k.privateKey,48,48);
   const privateSeed=encode64(decode64(k.privateKey).slice(-32));
   if(k.keyId!==await digest(k.publicKey)||used.has(k.publicKey)||privateValues.has(privateSeed)||keys.has(k.keyId))throw deny();
   const algorithm=purpose==='wrap'?'X25519':'Ed25519';
   const privateKey=await crypto.subtle.importKey('pkcs8',decode64(k.privateKey),algorithm,false,algorithm==='X25519'?['deriveBits']:['sign']);
   const publicKey=await crypto.subtle.importKey('raw',decode64(k.publicKey),algorithm,true,algorithm==='X25519'?[]:['verify']);
   if(algorithm==='Ed25519'){
    const challenge=crypto.getRandomValues(new Uint8Array(32)),signature=await crypto.subtle.sign('Ed25519',privateKey,challenge);
    if(!await crypto.subtle.verify('Ed25519',publicKey,signature,challenge))throw deny();
   }else{
    const probe=await crypto.subtle.generateKey('X25519',true,['deriveBits']) as CryptoKeyPair;
    const a=new Uint8Array(await crypto.subtle.deriveBits({name:'X25519',public:probe.publicKey},privateKey,256)),b=new Uint8Array(await crypto.subtle.deriveBits({name:'X25519',public:publicKey},probe.privateKey,256));
    const equal=a.every((v,i)=>v===b[i]);a.fill(0);b.fill(0);if(!equal)throw deny();
   }
   used.add(k.publicKey);privateValues.add(privateSeed);keys.set(k.keyId,{keyId:k.keyId,publicKey:k.publicKey,pair:{privateKey,publicKey}});
  }
  const active=keys.get(r.activeId);if(!active?.pair)throw deny();result[purpose]={active:{...active,pair:active.pair},keys};
 }
 return result;
}
function object(message:string,domain:string){if(!message.startsWith(domain))throw deny();const raw=message.slice(domain.length),value=JSON.parse(raw);if(JSON.stringify(value)!==raw)throw deny();return {raw,value};}
const hash=(v:unknown)=>{if(typeof v!=='string'||!/^[a-f0-9]{64}$/.test(v))throw deny();};
const integer=(v:unknown,min=0)=>{if(!Number.isSafeInteger(v)||(v as number)<min)throw deny();};
export async function validateSigning(message:string,purpose:SigningPurpose,party:Party,keyId:string){
 if(typeof message!=='string'||message.length>512*1024)throw deny();
 if(purpose==='checkpoint'){
  const {value:d}=object(message,'');
  if(Array.isArray(d)){
   if(d.length!==7||d[0]!=='AgentKeychain-activity-checkpoint-v2'||d[2]!==keyId||!(d[3]===0||typeof d[3]==='string'&&/^[a-f0-9]{32}$/.test(d[3]))||typeof d[4]!=='string'||!/^[a-f0-9]{32}$/.test(d[4]))throw deny();
   hash(d[1]);integer(d[5],1);hash(d[6]);return;
  }
  exactFields(d,['version','tenantId','vaultId','keyId','sequence','root','previousRoot','operationDigest']);identifier(d.tenantId);identifier(d.vaultId);integer(d.sequence);hash(d.root);
  if(d.version!==1||d.keyId!==keyId||JSON.stringify({version:1,tenantId:d.tenantId,vaultId:d.vaultId,keyId,sequence:d.sequence,root:d.root,previousRoot:d.previousRoot,operationDigest:d.operationDigest})!==message)throw deny();
  if(d.sequence===0){if(d.previousRoot!==null||d.operationDigest!==null||d.root!==await genesisRoot(d.tenantId,d.vaultId))throw deny();}else{hash(d.previousRoot);hash(d.operationDigest);}return;
 }
 if(purpose==='release'){const {raw,value}=object(message,RECOVERY_RELEASE_DOMAIN);if(canonicalRecoveryRelease(value)!==raw||value.party!==party||value.keyId!==keyId||value.expiresAt<=Math.floor(Date.now()/1000))throw deny();return;}
 if(purpose==='account'){
  const {value:a}=object(message,'');if(!Array.isArray(a)||a.length!==2||a[0]!=='AgentKeychain-recovery-account-verified-v1')throw deny();const c=recoveryCase(a[1]);if(JSON.stringify(c)!==a[1]||c.expiresAt<=Math.floor(Date.now()/1000))throw deny();return;
 }
 if(purpose==='witness'){
  if(message.startsWith('AgentKeychain-recovery-revocation-v1\0')){parseRecoveryRevocation(object(message,'AgentKeychain-recovery-revocation-v1\0').raw);return;}
  const {value:d}=object(message,WITNESS_DOMAIN);exactFields(d,['version','keyId','accountId','tenantId','vaultId','event','revision','digest','sequence','root','checkpointDigest']);
  if(d.version!==1||d.keyId!==keyId)throw deny();for(const id of [d.accountId,d.tenantId,d.vaultId])identifier(id);integer(d.event,1);integer(d.revision,1);integer(d.sequence);for(const h of [d.digest,d.root,d.checkpointDigest])hash(h);return;
 }
 if(purpose==='trust'&&party==='custodian'){
  if(message.startsWith(ROSTER_DOMAIN)){const {raw,value:r}=object(message,ROSTER_DOMAIN);if(canonicalRoster(r)!==raw||r.issuer.kind!=='recovery'||r.issuer.id!==keyId)throw deny();return;}
  if(message.startsWith(RECOVERY_TRUST_DOMAIN)){const {raw}=object(message,RECOVERY_TRUST_DOMAIN),b=parseRecoveryTrust({canonical:raw,signature:encode64(new Uint8Array(64))});if(b.authorityKeyId!==keyId)throw deny();recoveryCase(b.caseCanonical);return;}
  const {value:d}=object(message,'AgentKeychain-roster-recovery-completed-v1\0');exactFields(d,['version','caseId','accountId','tenantId','vaultId','revision','previousDigest','targetDeviceId','signingKey','wrappingKey','completedAt']);
  for(const id of [d.caseId,d.accountId,d.tenantId,d.vaultId,d.targetDeviceId])identifier(id);integer(d.revision,2);integer(d.completedAt);hash(d.previousDigest);base64(d.signingKey,32,32);base64(d.wrappingKey,32,32);if(d.version!==1||d.signingKey===d.wrappingKey||(d.completedAt as number)>Math.floor(Date.now()/1000)+60)throw deny();return;
 }
 throw deny();
}
export function domainSigner(ring:Keyring,purpose:SigningPurpose,party:Party){return {
 async key(){return {keyId:ring.active.keyId,publicKey:ring.active.publicKey};},
 async sign(message:string){await validateSigning(message,purpose,party,ring.active.keyId);return encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',ring.active.pair.privateKey,new TextEncoder().encode(message))));}
};}
export function validateRewrap(party:Party,keyId:string,source:string,targetKey:string,targetContext:string){
 const s=JSON.parse(source),t=JSON.parse(targetContext);
 if(!Array.isArray(s)||s.length!==9||JSON.stringify(s)!==source||s[0]!=='AgentKeychain-recovery-share-v1'||s[6]!=='two-party-24h'||s[7]!==party||s[8]!==keyId||!Array.isArray(t)||t.length!==3||JSON.stringify(t)!==targetContext||t[0]!=='AgentKeychain-recovery-release-v1'||t[2]!==party)throw deny();
 const c=recoveryCase(t[1]);if(JSON.stringify(c)!==t[1]||targetKey!==c.wrappingKey||c.expiresAt<=Math.floor(Date.now()/1000)||c.createdAt>Math.floor(Date.now()/1000)+60||JSON.stringify(s.slice(1,6))!==JSON.stringify([c.packageId,c.accountId,c.tenantId,c.vaultId,c.keyEpoch]))throw deny();return c;
}
