import {lstatSync} from 'node:fs';
import {Database} from 'bun:sqlite';
import sodium from 'libsodium-wrappers-sumo';
import type {SecureStore} from '../platform/secure-store.ts';
await sodium.ready;
const tables=['state','outbox','heads','history','pins','shadow','audit'] as const;
export type CloudTable=typeof tables[number];
export interface Anchor{sequence:number;root:string}
export const CLOUD_SCHEMA=1;
export class CloudStore {
 private key:Uint8Array;
 constructor(readonly db:Database,csk:Uint8Array){
  if(db.filename!==':memory:'&&db.filename){const stat=lstatSync(db.filename);if(stat.isSymbolicLink()||stat.nlink!==1)throw new Error('unsafe_cloud_database');}
  if(csk.length!==32)throw new Error('invalid_csk');this.key=new Uint8Array(csk);
  db.exec('PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;');
  db.exec('CREATE TABLE IF NOT EXISTS cloud_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL)');
  const row=db.query('SELECT version FROM cloud_schema WHERE id=1').get() as {version:number}|null;
  if(row&&row.version!==CLOUD_SCHEMA)throw new Error('cloud_incompatible_schema');
  db.transaction(()=>{
   db.run('INSERT OR IGNORE INTO cloud_schema VALUES(1,?)',[CLOUD_SCHEMA]);
   for(const table of tables)db.exec(`CREATE TABLE IF NOT EXISTS cloud_${table}(id TEXT PRIMARY KEY,nonce BLOB NOT NULL,ciphertext BLOB NOT NULL)`);
   // Lease has no credential/account metadata; token is random process fencing identity.
   db.exec('CREATE TABLE IF NOT EXISTS cloud_lease(id INTEGER PRIMARY KEY CHECK(id IN (1,2)),owner TEXT NOT NULL,expires INTEGER NOT NULL)');
  })();
 }
 private aad(table:CloudTable,id:string){if(!tables.includes(table)||!id||id.length>256)throw new Error('invalid_cloud_row');return JSON.stringify(['AgentKeychain-cloud-row',CLOUD_SCHEMA,table,id]);}
 put(table:CloudTable,id:string,value:unknown){
  const aad=this.aad(table,id),nonce=sodium.randombytes_buf(24),plain=Buffer.from(JSON.stringify(value));
  try{const ciphertext=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain,aad,null,nonce,this.key);this.db.run(`INSERT INTO cloud_${table} VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext`,[id,nonce,ciphertext]);}finally{plain.fill(0);}
 }
 get<T>(table:CloudTable,id:string):T|null{
  const aad=this.aad(table,id),row=this.db.query(`SELECT nonce,ciphertext FROM cloud_${table} WHERE id=?`).get(id) as {nonce:Uint8Array;ciphertext:Uint8Array}|null;
  if(!row)return null;let plain:Uint8Array|undefined;
  try{plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,row.ciphertext,aad,row.nonce,this.key);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain)) as T;}catch{throw new Error('cloud_state_authentication_failed');}finally{plain?.fill(0);}
 }
 all<T>(table:CloudTable):Array<{id:string;value:T}>{this.aad(table,'check');return (this.db.query(`SELECT id FROM cloud_${table} ORDER BY rowid`).all() as {id:string}[]).map(({id})=>({id,value:this.get<T>(table,id)!}));}
 remove(table:CloudTable,id:string){this.aad(table,id);this.db.run(`DELETE FROM cloud_${table} WHERE id=?`,[id]);}
 transaction<T>(fn:()=>T):T{return this.db.transaction(fn).immediate();}
 acquireLease(owner:string,now=Date.now(),ttl=30000,slot=1):boolean{
  return this.transaction(()=>{const r=this.db.query('SELECT owner,expires FROM cloud_lease WHERE id=?').get(slot) as {owner:string;expires:number}|null;if(r&&r.owner!==owner&&r.expires>now)return false;this.db.run('INSERT INTO cloud_lease VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires',[slot,owner,now+ttl]);return true;});
 }
 assertLease(owner:string,now=Date.now(),slot=1) {const r=this.db.query('SELECT owner,expires FROM cloud_lease WHERE id=?').get(slot) as {owner:string;expires:number}|null;if(!r||r.owner!==owner||r.expires<=now)throw new Error('cloud_lease_lost');}
 releaseLease(owner:string,slot=1){this.db.run('DELETE FROM cloud_lease WHERE id=? AND owner=?',[slot,owner]);}
 /** Call only after verifying the signed chain. DB-ahead repair requires proof of the old anchor. */
 async checkAnchor(secure:SecureStore,current:Anchor,verifiedChain:readonly Anchor[],initialize=false){
  const bytes=await secure.get('checkpoint-anchor');
  try{
   if(!bytes&&!initialize)throw new Error('cloud_checkpoint_anchor_missing');
   if(bytes){const previous=JSON.parse(new TextDecoder().decode(bytes)) as Anchor;
    if(!Number.isSafeInteger(previous.sequence)||previous.sequence<0||typeof previous.root!=='string'||previous.sequence>current.sequence||
       (previous.sequence===current.sequence&&previous.root!==current.root)||
       (previous.sequence<current.sequence&&!verifiedChain.some(v=>v.sequence===previous.sequence&&v.root===previous.root)))throw new Error('cloud_rollback_detected');
   }
   const next=Buffer.from(JSON.stringify(current));try{await secure.put('checkpoint-anchor',next);}finally{next.fill(0);}
  }finally{bytes?.fill(0);}
 }
 destroy(){this.key.fill(0);}
}
