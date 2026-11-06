import {randomUUID} from 'node:crypto';
import type {Database} from 'bun:sqlite';
import sodium from 'libsodium-wrappers-sumo';
import {createCloudKeys,destroyCloudKeys,type CloudKeys} from './crypto.ts';
import {CloudStore} from './persistence.ts';
import type {SecureStore} from '../platform/secure-store.ts';
import {identifier} from './protocol.ts';
interface StartRequest {id:string;packageId:string;targetDeviceId:string;signingKey:string;wrappingKey:string;nonce:string}
export type RecoveryStage='created'|'awaiting_verification'|'waiting_for_release'|'released'|'reconstructed'|'activating'|'server_completed'|'local_committed'|'active'|'cancelled'|'expired'|'conflict';
export interface RecoverySnapshot {version:1;revision:number;stage:RecoveryStage;target:StartRequest;data:Record<string,unknown>}
interface Intent {snapshot:RecoverySnapshot;keys:{csk:string;signingPrivate:string;wrappingPrivate:string}}
const b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
const transitions:Record<RecoveryStage,readonly RecoveryStage[]>={created:['awaiting_verification','cancelled','expired','conflict'],awaiting_verification:['waiting_for_release','cancelled','expired','conflict'],waiting_for_release:['released','cancelled','expired','conflict'],released:['reconstructed','cancelled','expired','conflict'],reconstructed:['activating','cancelled','expired','conflict'],activating:['server_completed','cancelled','expired','conflict'],server_completed:['local_committed'],local_committed:['active'],active:[],cancelled:[],expired:[],conflict:[]};
/** A secure-store write is the commit point. SQLite is an encrypted mirror repairable
 * only from that exact secure record. No key is regenerated during resume. */
export class RecoveryJournal {
 private store:CloudStore;
 private timer:ReturnType<typeof setInterval>;
 private closed=false;
 /* eslint-disable no-unused-vars -- TypeScript parameter properties */
 private constructor(private db:Database,private secure:SecureStore,private owner:string,private intent:Intent,readonly keys:CloudKeys){
  this.store=new CloudStore(db,keys.csk);
  this.timer=setInterval(()=>{try{this.fence();db.run('UPDATE cloud_recovery_lease SET expires=? WHERE id=1 AND owner=?',[Date.now()+30000,owner]);}catch{this.close();}},10000);this.timer.unref();
 }
 /* eslint-enable no-unused-vars */
 private static acquire(db:Database){
  db.exec('CREATE TABLE IF NOT EXISTS cloud_recovery_lease(id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires INTEGER NOT NULL)');
  const owner=randomUUID();db.transaction(()=>{const r=db.query('SELECT expires FROM cloud_recovery_lease WHERE id=1').get() as {expires:number}|null;if(r&&r.expires>Date.now())throw new Error('cloud_recovery_busy');db.run('INSERT INTO cloud_recovery_lease VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires',[owner,Date.now()+30000]);}).immediate();return owner;
 }
 private fence(){if(this.closed)throw new Error('cloud_recovery_closed');const r=this.db.query('SELECT owner,expires FROM cloud_recovery_lease WHERE id=1').get() as {owner:string;expires:number}|null;if(!r||r.owner!==this.owner||r.expires<=Date.now())throw new Error('cloud_recovery_busy');}
 /** Explicit restart discards only a key-free terminal receipt, never a live intent. */
 static async clearTerminal(db:Database,secure:SecureStore){
  const owner=this.acquire(db);try{const bytes=await secure.get('recovery-intent');if(!bytes)throw new Error('cloud_recovery_not_terminal');
   try{const intent=JSON.parse(new TextDecoder().decode(bytes)) as Intent;if(!['cancelled','expired','conflict'].includes(intent.snapshot.stage)||Object.values(intent.keys).some(v=>v!==''))throw new Error('cloud_recovery_not_terminal');}finally{bytes.fill(0);}
   if(db.query("SELECT 1 FROM sqlite_master WHERE name='cloud_state'").get())db.run("DELETE FROM cloud_state WHERE id='recovery-intent'");await secure.remove('recovery-intent');
  }finally{db.run('DELETE FROM cloud_recovery_lease WHERE owner=?',[owner]);}
 }
 static async begin(db:Database,secure:SecureStore,packageId:string):Promise<RecoveryJournal>{
  identifier(packageId);
  const existing=await this.resume(db,secure);
  if(existing){if(existing.snapshot().target.packageId!==packageId){existing.close();throw new Error('cloud_recovery_conflict');}return existing;}
  const owner=this.acquire(db);let keys:CloudKeys|undefined;
  try{
   // Recheck under the cross-process fence: another process may have initialized it.
   const pending=await secure.get('recovery-intent'),csk=await secure.get('csk');
   try{if(pending||csk)throw new Error('cloud_recovery_conflict');}finally{pending?.fill(0);csk?.fill(0);}
   if(db.query("SELECT 1 FROM sqlite_master WHERE name='cloud_state'").get()&&db.query('SELECT 1 FROM cloud_state LIMIT 1').get())throw new Error('cloud_recovery_conflict');
   keys=await createCloudKeys();
   const intent:Intent={snapshot:{version:1,revision:1,stage:'created',target:{id:randomUUID(),packageId,targetDeviceId:Buffer.from(sodium.randombytes_buf(32)).toString('base64url'),signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),nonce:randomUUID()},data:{}},keys:{csk:b64(keys.csk),signingPrivate:b64(keys.signingPrivate),wrappingPrivate:b64(keys.wrappingPrivate)}};
   const bytes=Buffer.from(JSON.stringify(intent));try{await secure.put('recovery-intent',bytes);}finally{bytes.fill(0);}
   const journal=new RecoveryJournal(db,secure,owner,intent,keys);try{journal.repair();return journal;}catch(e){journal.close();throw e;}
  }catch(e){if(keys)destroyCloudKeys(keys);db.run('DELETE FROM cloud_recovery_lease WHERE owner=?',[owner]);throw e;}
 }
 static async resume(db:Database,secure:SecureStore):Promise<RecoveryJournal|null>{
  const owner=this.acquire(db);let keys:CloudKeys|undefined;
  try{
   const bytes=await secure.get('recovery-intent');if(!bytes){db.run('DELETE FROM cloud_recovery_lease WHERE owner=?',[owner]);return null;}
   let intent:Intent;try{if(bytes.length>48000)throw new Error('cloud_recovery_invalid_intent');intent=JSON.parse(new TextDecoder().decode(bytes)) as Intent;}finally{bytes.fill(0);}
   const s=intent.snapshot;
   if(s.version!==1||!Number.isSafeInteger(s.revision)||s.revision<1||!Object.hasOwn(transitions,s.stage))throw new Error('cloud_recovery_invalid_intent');
   if(['cancelled','expired','conflict'].includes(s.stage)){if(db.query("SELECT 1 FROM sqlite_master WHERE name='cloud_state'").get())db.run("DELETE FROM cloud_state WHERE id='recovery-intent'");throw new Error('cloud_recovery_'+s.stage);}
   keys={csk:Buffer.from(intent.keys.csk,'base64'),vdk:new Uint8Array(32),signingPrivate:Buffer.from(intent.keys.signingPrivate,'base64'),wrappingPrivate:Buffer.from(intent.keys.wrappingPrivate,'base64'),signingPublic:Buffer.from(s.target.signingKey,'base64'),wrappingPublic:Buffer.from(s.target.wrappingKey,'base64')};
   await sodium.ready;
   if(keys.csk.length!==32||keys.signingPrivate.length!==64||keys.wrappingPrivate.length!==32||b64(sodium.crypto_sign_ed25519_sk_to_pk(keys.signingPrivate))!==s.target.signingKey||b64(sodium.crypto_scalarmult_base(keys.wrappingPrivate))!==s.target.wrappingKey)throw new Error('cloud_recovery_invalid_intent');
   const journal=new RecoveryJournal(db,secure,owner,intent,keys);try{journal.repair();return journal;}catch(e){journal.close();throw e;}
  }catch(e){if(keys)destroyCloudKeys(keys);db.run('DELETE FROM cloud_recovery_lease WHERE owner=?',[owner]);throw e;}
 }
 private repair(){
  this.fence();const old=this.store.get<RecoverySnapshot>('state','recovery-intent'),next=this.intent.snapshot;
  if(old&&(old.revision>next.revision||JSON.stringify(old.target)!==JSON.stringify(next.target)||(old.revision===next.revision&&JSON.stringify(old)!==JSON.stringify(next))))throw new Error('cloud_recovery_rollback');
  if(!old||old.revision<next.revision)this.store.put('state','recovery-intent',next);
 }
 snapshot():RecoverySnapshot{return globalThis.structuredClone(this.intent.snapshot);}
 async advance(stage:RecoveryStage,data:Record<string,unknown>={}){
  this.fence();if(!transitions[this.intent.snapshot.stage].includes(stage))throw new Error('cloud_recovery_invalid_transition');
  await this.write(stage,data);
 }
 async update(data:Record<string,unknown>){
  this.fence();if(['active','cancelled','expired','conflict'].includes(this.intent.snapshot.stage))throw new Error('cloud_recovery_invalid_transition');
  await this.write(this.intent.snapshot.stage,data);
 }
 private async write(stage:RecoveryStage,data:Record<string,unknown>){
  const terminal=['cancelled','expired','conflict'].includes(stage);
  const next:Intent={...this.intent,...(terminal?{keys:{csk:'',signingPrivate:'',wrappingPrivate:''}}:{}),snapshot:{...this.intent.snapshot,revision:this.intent.snapshot.revision+1,stage,data:terminal?{}:{...this.intent.snapshot.data,...data}}};
  const bytes=Buffer.from(JSON.stringify(next));
  try{if(bytes.length>48000)throw new Error('cloud_recovery_intent_too_large');await this.secure.put('recovery-intent',bytes);}catch(error){this.close();throw error;}finally{bytes.fill(0);}
  // If secure put commits but its response is lost, the process must close/resume.
  this.intent=next;this.fence();this.repair();
 }
 close(){if(this.closed)return;this.closed=true;clearInterval(this.timer);this.store.destroy();destroyCloudKeys(this.keys);this.db.run('DELETE FROM cloud_recovery_lease WHERE owner=?',[this.owner]);}
}
