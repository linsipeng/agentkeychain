/* eslint-disable no-unused-vars -- parameter properties */
import sodium from 'libsodium-wrappers-sumo';
import {createHash,randomUUID} from 'node:crypto';
import type {Database} from 'bun:sqlite';
import {CloudStore} from './persistence.ts';
import {objectId,sealPayload,openPayload,type CloudKeys,type CloudPayload} from './crypto.ts';
import {canonicalOperation,parseCanonicalOperation,type DeviceRecord,type ManagedOperation,type ManagedVersion,type SignedManagedOperation} from './protocol.ts';
await sodium.ready;
interface LocalRow{name:string;ciphertext:Uint8Array;nonce:Uint8Array;scopes:string;metadata:string|null;version:number;created_at:number;updated_at:number;deleted_at:number|null}
export interface OutboxEntry{signed:SignedManagedOperation;approval:boolean;legacyFingerprint?:string|null;intent?:{action:string;signature:string}}
const fingerprint=(row:LocalRow)=>createHash('sha256').update(JSON.stringify(row)).digest('hex');
interface LegacyEdit {name:string;fingerprint:string|null;action:'rotate'|'scope'|'delete'|'restore';payload:CloudPayload}
const attached=new WeakMap<Database,VaultMutationCoordinator>();
export function coordinatorFor(db:Database){return attached.get(db);}
export function hasCloudState(db:Database){
 if(!db.query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cloud_state'").get())return false;
 const schema=db.query('SELECT version FROM cloud_schema WHERE id=1').get() as {version:number}|null;
 return schema?.version===1;
}
export function guardManagedMutation(db:Database){if(hasCloudState(db)&&!attached.has(db))throw new Error('cloud_unlock_required');}
export class VaultMutationCoordinator {
 constructor(readonly store:CloudStore,private keys:CloudKeys,readonly device:DeviceRecord,private kek:Uint8Array,private keyEpoch:number){attached.set(store.db,this);}
 private row(name:string){return this.store.db.query('SELECT * FROM secrets WHERE name=?').get(name) as LocalRow|null;}
 private sign(op:ManagedOperation):SignedManagedOperation{const canonical=canonicalOperation(op);return {canonical,signature:Buffer.from(sodium.crypto_sign_detached(canonical,this.keys.signingPrivate)).toString('base64')};}
 private operation(payload:CloudPayload,kind:ManagedOperation['kind'],approval:boolean):ManagedOperation{
  const roster=this.store.get<SignedManagedOperation>('state','roster-current');if(roster&&(JSON.parse(roster.canonical) as {expiresAt:number}).expiresAt<=Math.floor(Date.now()/1000))throw new Error('cloud_invalid_roster_expiry');
  const health=this.store.get<{state:string}>('state','health');if(this.device.revoked||health&&['revoked','security_error','auth_required'].includes(health.state))throw new Error('cloud_'+(health?.state??'revoked'));
  const id=objectId(this.keys.vdk,payload.name),head=this.store.get<ManagedVersion>('heads',id),old=head?parseCanonicalOperation(head.signed.canonical):null;
  if(this.store.all<OutboxEntry>('outbox').some(q=>parseCanonicalOperation(q.value.signed.canonical).objectId===id))throw new Error(approval?'approval_required':'cloud_mutation_pending');
  if(kind==='put'&&old?.kind==='delete')throw new Error('restore_required');
  if(kind!=='put'&&!old)throw new Error('cloud_sync_required');
  const header={protocolVersion:2 as const,vaultId:this.device.vaultId,deviceId:this.device.deviceId,objectId:id,operationId:randomUUID(),kind,generation:kind==='restore'?old!.generation+1:old?.generation??1,keyEpoch:this.keyEpoch,approvalRef:approval?randomUUID():null};
  return {...header,envelope:kind==='delete'?null:sealPayload(this.keys.vdk,header,payload)};
 }
 mutate(payload:CloudPayload,kind:ManagedOperation['kind']):void{
  this.store.transaction(()=>{
   const health=this.store.get<{state:string}>('state','health');if(health&&['revoked','security_error','auth_required'].includes(health.state))throw new Error('cloud_'+health.state);
   const old=this.row(payload.name),high=!!old||kind!=='put';
   if(high)throw new Error('approval_required');
   const op=this.operation(payload,kind,false),signed=this.sign(op);
   this.writePayload(payload,false);this.store.put('outbox',op.operationId,{signed,approval:false});this.shadow(payload.name);
  });
 }
 /** Preflight and commit under the same SQLite writer lock. No partial import is visible. */
 mutateBatch(payloads:CloudPayload[]):void{
  this.store.transaction(()=>{
   const names=new Set<string>();
   const prepared=payloads.map(payload=>{
    if(names.has(payload.name))throw new Error('duplicate_import_name');names.add(payload.name);
    const id=objectId(this.keys.vdk,payload.name);
    if(this.row(payload.name)||this.store.get('heads',id)||this.store.get('shadow',id)||this.store.get('state','legacy:'+id))throw new Error('approval_required');
    const op=this.operation(payload,'put',false);return {payload,op,signed:this.sign(op)};
   });
   for(const {payload,op,signed} of prepared){this.writePayload(payload,false);this.store.put('outbox',op.operationId,{signed,approval:false});this.shadow(payload.name);}
   if(prepared.length)this.store.put('audit',randomUUID(),{action:'import',count:prepared.length,at:Date.now()});
  });
 }
 /** Exact approved bytes are queued; local overwrite is delayed until authoritative acceptance. */
 requestApproval(payload:CloudPayload,kind:ManagedOperation['kind'],intent?:'rotate'|'scope'):string{
  return this.store.transaction(()=>{const op=this.operation(payload,kind,true),signed=this.sign(op);const entry:OutboxEntry={signed,approval:true};if(kind==='put'){if(!intent)throw new Error('cloud_approval_intent_required');entry.intent={action:intent,signature:Buffer.from(sodium.crypto_sign_detached(JSON.stringify(['AgentKeychain-approval-intent-v1',signed.canonical,signed.signature,intent]),this.keys.signingPrivate)).toString('base64')};}this.store.put('outbox',op.operationId,entry);return op.approvalRef!;});
 }
 private writePayload(p:CloudPayload,deleted:boolean){
  const nonce=sodium.randombytes_buf(24),plain=Buffer.from(p.value);
  try{
   const cipher=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain,null,null,nonce,this.kek),now=Date.now();
   this.store.db.run(`INSERT INTO secrets(name,ciphertext,nonce,scopes,metadata,created_at,updated_at,version,deleted_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,scopes=excluded.scopes,metadata=excluded.metadata,updated_at=excluded.updated_at,version=MAX(secrets.version+1,excluded.version),deleted_at=excluded.deleted_at`,[p.name,cipher,nonce,JSON.stringify(p.scopes),p.metadata?JSON.stringify(p.metadata):null,now,now,p.localVersion,deleted?now:null]);
  }finally{plain.fill(0);}
 }
 private shadow(name:string){const row=this.row(name);if(row)this.store.put('shadow',objectId(this.keys.vdk,name),{name,fingerprint:fingerprint(row)});}
 /** Invoked inside the page commit transaction, after every page member verifies. */
 apply(version:ManagedVersion){
  const op=parseCanonicalOperation(version.signed.canonical);
  const prior=this.store.get<{name:string;fingerprint:string}>('shadow',op.objectId);
  const queued=this.store.get<OutboxEntry>('outbox',op.operationId);
  const retired=this.store.get<OutboxEntry>('state','retired:'+op.operationId);
  if(retired?.signed.canonical===version.signed.canonical&&retired.signed.signature===version.signed.signature&&prior){
   this.store.put('heads',op.objectId,version);this.store.put('history',String(version.serverSequence),version);
   this.store.remove('state','retired:'+op.operationId);this.stageLegacy(op.objectId,prior.name,this.row(prior.name));return;
  }
  const exact=queued?.signed.canonical===version.signed.canonical&&queued?.signed.signature===version.signed.signature;
  if(prior){const row=this.row(prior.name),actual=row?fingerprint(row):null;
   if(actual!==prior.fingerprint){
    if(exact&&!queued!.approval&&!this.store.get('heads',op.objectId)){
     // The service accepted our original create while an old binary edited it.
     // Advance the authoritative head, retaining the newer local bytes for approval.
     this.store.put('heads',op.objectId,version);this.store.put('history',String(version.serverSequence),version);this.store.remove('outbox',op.operationId);this.stageLegacy(op.objectId,prior.name,row);return;
    }
    if(!(exact&&'legacyFingerprint' in queued!&&actual===queued!.legacyFingerprint)){
     // Verified remote history must not deadlock behind an old-client edit.
     // Keep local bytes, retire superseded intent, then reconcile against the new head.
     for(const pending of this.store.all<OutboxEntry>('outbox'))if(parseCanonicalOperation(pending.value.signed.canonical).objectId===op.objectId){
      if(pending.value.approval)this.retireApproval(pending.id,'stale');else this.store.remove('outbox',pending.id);
     }
     this.store.put('heads',op.objectId,version);this.store.put('history',String(version.serverSequence),version);
     this.store.remove('state','retired:'+op.operationId);this.stageLegacy(op.objectId,prior.name,row);return;
    }
   }}

  if(op.kind==='delete'){
   const shadow=this.store.get<{name:string}>('shadow',op.objectId);
   if(shadow){
    if(!this.row(shadow.name)){const edit=this.store.get<LegacyEdit>('state','legacy:'+op.objectId);if(!edit)throw new Error('cloud_local_conflict');this.writePayload(edit.payload,true);}
    else this.store.db.run('UPDATE secrets SET deleted_at=?,version=version+1 WHERE name=?',[Date.now(),shadow.name]);
    this.shadow(shadow.name);
   }
  }else{
   const payload=openPayload(this.keys.vdk,op);
   if(objectId(this.keys.vdk,payload.name)!==op.objectId)throw new Error('cloud_object_binding');
   // A newer local pending write must not be silently replaced by a remote page.
   const conflict=this.store.all<OutboxEntry>('outbox').some(q=>{const pending=parseCanonicalOperation(q.value.signed.canonical);return pending.objectId===op.objectId&&pending.operationId!==op.operationId;});
   if(conflict)throw new Error('cloud_local_conflict');
   this.writePayload(payload,false);this.shadow(payload.name);
  }
  this.store.put('heads',op.objectId,version);this.store.put('history',String(version.serverSequence),version);
  if(exact){this.store.remove('outbox',op.operationId);this.store.remove('state','legacy:'+op.objectId);this.store.remove('state','legacy-status:'+op.objectId);}
 }
 reconcile(){
  this.store.transaction(()=>{
   const rows=this.store.db.query('SELECT * FROM secrets').all() as LocalRow[];
   const ids=new Set<string>();
   for(const row of rows){
    const id=objectId(this.keys.vdk,row.name);ids.add(id);const shadow=this.store.get<{fingerprint:string}>('shadow',id);
    if(shadow?.fingerprint===fingerprint(row)){
     for(const entry of this.store.all<OutboxEntry>('outbox'))if(parseCanonicalOperation(entry.value.signed.canonical).objectId===id&&'legacyFingerprint' in entry.value&&entry.value.legacyFingerprint!==shadow.fingerprint)this.retireApproval(entry.id,'stale');
     this.store.remove('state','legacy:'+id);this.store.remove('state','legacy-status:'+id);continue;
    }
    if(shadow||row.deleted_at!==null||this.store.get('heads',id)){this.stageLegacy(id,row.name,row);continue;}
    const bytes=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,row.ciphertext,null,row.nonce,this.kek);
    try{const payload={name:row.name,value:new TextDecoder().decode(bytes),scopes:JSON.parse(row.scopes) as string[],metadata:row.metadata?JSON.parse(row.metadata) as Record<string,unknown>:null,localVersion:row.version};const op=this.operation(payload,'put',false);this.store.put('outbox',op.operationId,{signed:this.sign(op),approval:false});this.shadow(row.name);}finally{bytes.fill(0);}
   }
   for(const shadow of this.store.all<{name:string}>('shadow'))if(!ids.has(shadow.id))this.stageLegacy(shadow.id,shadow.value.name,null);
  });
 }
 private stageLegacy(id:string,name:string,row:LocalRow|null){
  this.store.put('state','health',{state:'approval_required'});
  // Pending unaccepted creates cannot be overwritten with an approval for an absent head.
  const head=this.store.get<ManagedVersion>('heads',id);if(!head)return;
  const op=parseCanonicalOperation(head.signed.canonical);
  let payload:CloudPayload;
  if(row){const bytes=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,row.ciphertext,null,row.nonce,this.kek);
   try{payload={name,value:new TextDecoder().decode(bytes),scopes:JSON.parse(row.scopes),metadata:row.metadata?JSON.parse(row.metadata):null,localVersion:row.version};}finally{bytes.fill(0);}
  }else{
   const prior=this.store.all<ManagedVersion>('history').map(x=>x.value).filter(v=>{const o=parseCanonicalOperation(v.signed.canonical);return o.objectId===id&&o.kind!=='delete';}).sort((a,b)=>b.serverSequence-a.serverSequence)[0];
   if(!prior)return;payload=openPayload(this.keys.vdk,parseCanonicalOperation(prior.signed.canonical));
  }
  let action:LegacyEdit['action']=!row||row.deleted_at!==null?'delete':op.kind==='delete'?'restore':'rotate';
  if(action==='rotate'&&op.kind!=='delete'){const previous=openPayload(this.keys.vdk,op);if(JSON.stringify(previous.scopes)!==JSON.stringify(payload.scopes))action='scope';}
  const actual=row?fingerprint(row):null;
  for(const entry of this.store.all<OutboxEntry>('outbox')){
   if(parseCanonicalOperation(entry.value.signed.canonical).objectId===id&&'legacyFingerprint' in entry.value&&entry.value.legacyFingerprint!==actual)this.retireApproval(entry.id,'stale');
  }
  this.store.put('state','legacy:'+id,{name,fingerprint:actual,action,payload} satisfies LegacyEdit);
 }
 retireApproval(operationId:string,state:'stale'|'denied'|'cancelled'|'expired'){
  this.store.transaction(()=>{const entry=this.store.get<OutboxEntry>('outbox',operationId);if(!entry?.approval)return;
   const op=parseCanonicalOperation(entry.signed.canonical);
   this.store.put('state','retired:'+operationId,entry);this.store.remove('outbox',operationId);
   this.store.put('state','legacy-status:'+op.objectId,{state,requestId:op.approvalRef});
  });
 }
 pendingLegacy(){return this.store.all<LegacyEdit>('state').filter(r=>r.id.startsWith('legacy:')).map(r=>({name:r.value.name,action:r.value.action,...this.store.get<{state:string;requestId:string}>('state','legacy-status:'+r.id.slice(7))}));}
 approveLegacy(name:string){return this.store.transaction(()=>{
  const id=objectId(this.keys.vdk,name),edit=this.store.get<LegacyEdit>('state','legacy:'+id),row=this.row(name);
  if(!edit)throw new Error('cloud_no_legacy_edit');
  if((row?fingerprint(row):null)!==edit.fingerprint)throw new Error('cloud_local_conflict');
  const kind=edit.action==='delete'?'delete':edit.action==='restore'?'restore':'put';
  const approval=this.requestApproval(edit.payload,kind,kind==='put'?edit.action as 'scope'|'rotate':undefined);
  const entry=this.store.all<OutboxEntry>('outbox').find(q=>parseCanonicalOperation(q.value.signed.canonical).approvalRef===approval)!;
  this.store.put('outbox',entry.id,{...entry.value,legacyFingerprint:edit.fingerprint});this.store.remove('state','legacy-status:'+id);return approval;
 });}
 detach(){attached.delete(this.store.db);}
}
