import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';
/* eslint-disable no-unused-vars -- parameter properties */
import {randomUUID} from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalRoster,parseRoster,verifyRoster,rosterDigest,ROSTER_DOMAIN,type TrustedDeviceRoster,type RosterDevice} from '../../managed-cloud/shared/roster.ts';
import {verifyCheckpoint,type Checkpoint} from '../../managed-cloud/shared/checkpoints.ts';
import {exactFields,type SignedManagedOperation} from './protocol.ts';
import type {CloudStore} from './persistence.ts';
import type {SecureStore} from '../platform/secure-store.ts';
import type {ManagedHttpClient} from './http.ts';
import type {CloudKeys} from './crypto.ts';
await sodium.ready;
export function signRoster(r:TrustedDeviceRoster,key:Uint8Array):SignedManagedOperation{const canonical=canonicalRoster(r);return {canonical,signature:Buffer.from(sodium.crypto_sign_detached(ROSTER_DOMAIN+canonical,key)).toString('base64')};}
export const rosterPins=(r:TrustedDeviceRoster)=>[...r.active.map(d=>({...d,revoked:false})),...r.revoked.map(d=>({...d,revoked:true}))].map(d=>({vaultId:r.vaultId,deviceId:d.deviceId,publicKey:d.signingKey,revoked:d.revoked}));
interface RosterAnchor {revision:number;digest:string}
export class RosterStore {
 private owner:string|null=null;
 constructor(private store:CloudStore,private secure:SecureStore){store.db.exec('CREATE TABLE IF NOT EXISTS cloud_roster_lock(id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires INTEGER NOT NULL)');}
 private async locked<T>(fn:()=>Promise<T>):Promise<T>{
  const owner=randomUUID();this.store.transaction(()=>{const held=this.store.db.query('SELECT expires FROM cloud_roster_lock WHERE id=1').get() as {expires:number}|null;if(held&&held.expires>Date.now())throw new Error('cloud_sync_busy');this.store.db.run('INSERT INTO cloud_roster_lock VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires',[owner,Date.now()+30000]);});
  this.owner=owner;try{return await fn();}finally{this.owner=null;this.store.db.run('DELETE FROM cloud_roster_lock WHERE id=1 AND owner=?',[owner]);}
 }
 private fence(){const held=this.store.db.query('SELECT owner,expires FROM cloud_roster_lock WHERE id=1').get() as {owner:string;expires:number}|null;if(!held||held.owner!==this.owner||held.expires<=Date.now()+6000)throw new Error('cloud_lease_lost');}
 current(){return this.store.get<SignedManagedOperation>('state','roster-current');}
 private async anchor(s:SignedManagedOperation){return {revision:parseRoster(s).revision,digest:await rosterDigest(s)};}
 check(){return this.locked(()=>this.checkLocked());}
 private async checkLocked(){
  const s=this.current();if(!s)throw new Error('cloud_roster_missing');
  const history=this.store.all<SignedManagedOperation>('state').filter(r=>r.id.startsWith('roster-history:')).map(r=>r.value).sort((a,b)=>parseRoster(a).revision-parseRoster(b).revision);
  if(!history.length)throw new Error('cloud_invalid_roster_history');
  for(let i=0;i<history.length;i++){const row=history[i]!,r=parseRoster(row);await verifyRoster(row,i?history[i-1]!:null,r.issuedAt,true);}
  if(await rosterDigest(history.at(-1)!)!==await rosterDigest(s))throw new Error('cloud_invalid_roster_history');
  const raw=await this.secure.get('roster-anchor');if(!raw)throw new Error('cloud_roster_anchor_missing');
  try{const a=JSON.parse(Buffer.from(raw).toString()) as RosterAnchor;exactFields(a,['revision','digest']);const current=await this.anchor(s);
   if(!Number.isSafeInteger(a.revision)||a.revision>current.revision||!await this.contains(history,a))throw new Error('cloud_roster_rollback');
   if(a.revision<current.revision)await this.writeAnchor(current);
  }finally{raw.fill(0);}
  return parseRoster(s);
 }
 private async contains(rows:SignedManagedOperation[],a:RosterAnchor){for(const row of rows)if(parseRoster(row).revision===a.revision&&await rosterDigest(row)===a.digest)return true;return false;}
 private async writeAnchor(a:RosterAnchor){this.fence();const bytes=Buffer.from(JSON.stringify(a));try{await this.secure.put('roster-anchor',bytes);}finally{bytes.fill(0);}}
 /** Called only from the local SAS/recovery or release-verified self-anchor boundary. */
 initialize(s:SignedManagedOperation){return this.locked(()=>this.initializeLocked(s));}
 private async initializeLocked(s:SignedManagedOperation){
  await verifyRoster(s,null,Math.floor(Date.now()/1000),true);
  const old=this.current();if(old){
   if(await rosterDigest(old)!==await rosterDigest(s)){
    const protectedAnchor=await this.secure.get('roster-anchor');
    try{if(!protectedAnchor||Buffer.from(protectedAnchor).toString()!==JSON.stringify(await this.anchor(s)))throw new Error('cloud_invalid_roster_bootstrap');}finally{protectedAnchor?.fill(0);}
    // Validate the complete old history before allowing the protected exact successor.
    try{await this.checkLocked();}catch(error){if(!(error instanceof Error)||error.message!=='cloud_roster_rollback')throw error;}
    await verifyRoster(s,old);this.persist(s);
   }
   await this.checkLocked();return;
  }
  const a=await this.anchor(s),existing=await this.secure.get('roster-anchor');
  try{if(existing&&Buffer.from(existing).toString()!==JSON.stringify(a))throw new Error('cloud_roster_rollback');}finally{existing?.fill(0);}
  // Anchor first. An activation crash can resume only the exact authenticated bundle.
  await this.writeAnchor(a);this.persist(s);
 }
 private persist(s:SignedManagedOperation){this.fence();const r=parseRoster(s);this.store.transaction(()=>{this.store.put('state','roster-history:'+r.revision,s);this.store.put('state','roster-current',s);for(const {id} of this.store.all('pins'))this.store.remove('pins',id);for(const pin of rosterPins(r))this.store.put('pins',pin.deviceId,pin);});}
 accept(s:SignedManagedOperation){return this.locked(()=>this.acceptLocked(s));}
 private async acceptLocked(s:SignedManagedOperation){
  await this.checkLocked();const old=this.current()!;const prior=this.store.get<SignedManagedOperation>('state','roster-history:'+parseRoster(s).revision);if(prior&&await rosterDigest(prior)===await rosterDigest(s))return;
  await verifyRoster(s,old);this.persist(s);await this.writeAnchor(await this.anchor(s));
 }
}
export async function refreshRoster(store:CloudStore,secure:SecureStore,http:ManagedHttpClient,keys:CloudKeys,deviceId:string,issue=true){
 const local=new RosterStore(store,secure);let current=await local.check();
 let promised=store.get<RosterAnchor>('state','roster-required-head')??{revision:current.revision,digest:await rosterDigest(local.current()!)};
 // Bounded pages, exact head continuity. The local anchor forbids a server rollback or fork.
 for(let page=0;;page++){
  if(page>=1024)throw new Error('cloud_invalid_roster_suffix');
  const body={accountId:current.accountId,tenantId:current.tenantId,vaultId:current.vaultId,deviceId,after:current.revision,timestamp:Math.floor(Date.now()/1000)};
  const result=await http.publicCall('/v1/devices/roster-fetch',{...body,signature:Buffer.from(sodium.crypto_sign_detached(JSON.stringify(['AgentKeychain-roster-fetch-v1',body]),keys.signingPrivate)).toString('base64')}) as {revisions:SignedManagedOperation[];head:{revision:number;digest:string}|null;witness?:SignedManagedOperation};
  exactFields(result,['revisions','head',...('witness' in result?['witness']:[])]);if(!result.head||!Array.isArray(result.revisions)||result.revisions.length>32)throw new Error('cloud_invalid_roster_suffix');exactFields(result.head,['revision','digest']);
  if(!Number.isSafeInteger(result.head.revision)||result.head.revision<Math.max(current.revision,promised.revision))throw new Error('cloud_roster_rollback');
  if(result.head.revision===promised.revision&&result.head.digest!==promised.digest)throw new Error('cloud_invalid_roster_suffix');
  if(http.policy?.witnessKeys){if(!result.witness)throw new Error('cloud_witness_missing');await verifyWitness(result.witness,http.policy.witnessKeys,{accountId:current.accountId,tenantId:current.tenantId,vaultId:current.vaultId,...result.head});}
  for(const row of result.revisions){const r=parseRoster(row);if(r.revision===promised.revision&&await rosterDigest(row)!==promised.digest)throw new Error('cloud_invalid_roster_suffix');await local.accept(row);current=r;}
  if(current.revision>=promised.revision){promised=result.head;store.put('state','roster-required-head',promised);}
  if(current.revision===result.head.revision){if(await rosterDigest(local.current()!)!==result.head.digest)throw new Error('cloud_invalid_roster_suffix');break;}
  if(!result.revisions.length||current.revision>result.head.revision)throw new Error('cloud_invalid_roster_suffix');
 }
 if(current.revoked.some(d=>d.deviceId===deviceId)){http.logout();store.put('state','health',{state:'revoked'});throw new Error('revoked');}
 if(current.expiresAt<=Math.floor(Date.now()/1000))throw new Error('cloud_invalid_roster_expiry');
 if(issue){
  const pending=await http.call('/v1/devices/roster-pending') as {revocations:{deviceId:string;acceptedThrough:Checkpoint}[]};exactFields(pending,['revocations']);if(!Array.isArray(pending.revocations)||pending.revocations.length>1000)throw new Error('cloud_invalid_revocations');
  const revoked=[...current.revoked];
  for(const d of pending.revocations){exactFields(d,['deviceId','acceptedThrough']);const old=current.active.find(a=>a.deviceId===d.deviceId);if(!old)continue;
   const cp=JSON.parse(d.acceptedThrough.canonical) as {keyId:string},pin=current.checkpointKeys.find(k=>k.keyId===cp.keyId);if(!pin)throw new Error('cloud_invalid_revocation_checkpoint');await verifyCheckpoint(pin,current.tenantId,current.vaultId,d.acceptedThrough);
   revoked.push({...old,revokedRevision:current.revision+1,acceptedThrough:d.acceptedThrough});
  }
  if(revoked.length!==current.revoked.length||current.expiresAt<Math.floor(Date.now()/1000)+86400){
   const now=Math.floor(Date.now()/1000),next=signRoster({...current,revision:current.revision+1,previousDigest:await rosterDigest(local.current()!),active:current.active.filter(d=>!revoked.some(v=>v.deviceId===d.deviceId)),revoked,issuer:{kind:'device',id:deviceId},issuedAt:now,expiresAt:now+2592000,recovery:null},keys.signingPrivate);
   await publishRoster(http,next);await local.accept(next);current=parseRoster(next);
  }
 }
 return current;
}
export async function enrollmentRoster(store:CloudStore,secure:SecureStore,keys:CloudKeys,issuer:string,target:RosterDevice){
 const local=new RosterStore(store,secure),r=await local.check(),now=Math.floor(Date.now()/1000);
 if(r.active.some(d=>d.deviceId===target.deviceId)||r.revoked.some(d=>d.deviceId===target.deviceId))throw new Error('cloud_invalid_roster_target');
 return signRoster({...r,revision:r.revision+1,previousDigest:await rosterDigest(local.current()!),active:[...r.active,target],issuer:{kind:'device',id:issuer},issuedAt:now,expiresAt:now+2592000,recovery:null},keys.signingPrivate);
}

export async function publishRoster(http:ManagedHttpClient,signed:SignedManagedOperation){
 const result=await http.call('/v1/devices/roster-put',signed) as {accepted:boolean;witness?:SignedManagedOperation};
 if(http.policy?.witnessKeys){const r=parseRoster(signed);if(!result.witness||result.accepted!==true)throw new Error('cloud_witness_missing');await verifyWitness(result.witness,http.policy.witnessKeys,{accountId:r.accountId,tenantId:r.tenantId,vaultId:r.vaultId,revision:r.revision,digest:await rosterDigest(signed)});}
 return result;
}
