import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';
import {rosterDigest} from '../../managed-cloud/shared/roster.ts';
import {refreshRoster,rosterPins} from './roster.ts';
import {type TrustedDeviceRoster} from '../../managed-cloud/shared/roster.ts';
import type {ManagedHttpClient} from './http.ts';
import type {CloudKeys} from './crypto.ts';
/* eslint-disable no-unused-vars -- interface and parameter properties */
import {randomUUID} from 'node:crypto';
import {CloudStore,type Anchor} from './persistence.ts';
import type {SecureStore} from '../platform/secure-store.ts';
import {VaultMutationCoordinator,type OutboxEntry} from './coordinator.ts';
import {assertVerifiedPolicy,type ManagedEndpointPolicy} from './config.ts';
import {verifyOperation} from './device.ts';
import {exactFields,parseCanonicalOperation,type DeviceRecord,type ManagedVersion,type ManagedOperation,type PushReceipt} from './protocol.ts';
import {advanceRoot,genesisRoot,verifyCheckpoint,type Checkpoint} from '../../managed-cloud/shared/checkpoints.ts';
export interface SyncRemote {policy:ManagedEndpointPolicy;call(path:string,body?:unknown,method?:string):Promise<unknown>}
interface Cursor extends Anchor{requiredThrough:number}
interface Page {versions:ManagedVersion[];checkpoint:Checkpoint;pageCheckpoint:Checkpoint;nextCursor:string;hasMore:boolean}
function transition(old:ManagedOperation|undefined,op:ManagedOperation){
 if(!old){if(op.kind!=='put'||op.generation!==1||op.approvalRef!==null)throw new Error('cloud_invalid_transition');}
 else{
  if(op.keyEpoch<old.keyEpoch||!op.approvalRef)throw new Error('cloud_approval_required');
  if(op.kind==='restore'?op.generation<=old.generation:old.kind==='delete'||op.generation!==old.generation)throw new Error('cloud_invalid_transition');
 }
}
export class DurableSync {
 private running:Promise<void>|undefined;
 private pins:DeviceRecord[];
 private roster:TrustedDeviceRoster|undefined;
 constructor(private store:CloudStore,private secure:SecureStore,private coordinator:VaultMutationCoordinator,private remote:SyncRemote,private tenant:string,pins:readonly DeviceRecord[],private rosterRuntime?:{http:ManagedHttpClient;keys:CloudKeys}){
  assertVerifiedPolicy(remote.policy);this.pins=JSON.parse(JSON.stringify(pins)) as DeviceRecord[];
  if(new Set(this.pins.map(p=>p.deviceId)).size!==this.pins.length||!this.pins.some(p=>p.deviceId===coordinator.device.deviceId&&p.publicKey===coordinator.device.publicKey))throw new Error('cloud_invalid_pins');
 }
 sync(){if(this.running)return this.running;this.running=this.run().finally(()=>{this.running=undefined;});return this.running;}
 private async checkpoint(cp:Checkpoint){
  const data=JSON.parse(cp.canonical) as {keyId:string};const pin=this.remote.policy.checkpointKeys.find(p=>p.keyId===data.keyId);if(!pin)throw new Error('cloud_untrusted_checkpoint');
  return verifyCheckpoint(pin,this.tenant,this.coordinator.device.vaultId,cp);
 }
 private async validateHistory(){
  const vault=this.coordinator.device.vaultId,heads=new Map<string,ManagedOperation>(),ids=new Set<string>(),anchors:Anchor[]=[{sequence:0,root:await genesisRoot(this.tenant,vault)}];
  const rows=this.store.all<ManagedVersion>('history').map(v=>v.value).sort((a,b)=>a.serverSequence-b.serverSequence);
  for(const v of rows){const previous=anchors.at(-1)!;await this.validateVersion(v,previous.sequence+1,heads,ids);anchors.push({sequence:v.serverSequence,root:(await advanceRoot(previous.root,v.serverSequence,v.signed)).root});}
  const current=this.store.get<Cursor>('state','cursor')??{...anchors[0]!,requiredThrough:0},last=anchors.at(-1)!;
  if(current.sequence!==last.sequence||current.root!==last.root||!Number.isSafeInteger(current.requiredThrough)||current.requiredThrough<0)throw new Error('cloud_invalid_snapshot');
  const storedHeads=this.store.all<ManagedVersion>('heads');
  if(storedHeads.length!==heads.size||storedHeads.some(v=>JSON.stringify(heads.get(v.id))!==JSON.stringify(parseCanonicalOperation(v.value.signed.canonical))))throw new Error('cloud_invalid_heads');
  this.revocationRoots(anchors);await this.store.checkAnchor(this.secure,current,anchors);return {current,heads,ids,anchors};
 }
 private async validateVersion(v:ManagedVersion,sequence:number,heads:Map<string,ManagedOperation>,ids:Set<string>){
  exactFields(v,['signed','serverSequence']);const op=parseCanonicalOperation(v.signed.canonical),pin=this.pins.find(p=>p.deviceId===op.deviceId);
  const id=JSON.stringify([op.deviceId,op.operationId]);
  if(v.serverSequence!==sequence||op.vaultId!==this.coordinator.device.vaultId||!pin||!await verifyOperation(pin,v.signed)||ids.has(id))throw new Error('cloud_invalid_history');
  const revoked=this.roster?.revoked.find(d=>d.deviceId===op.deviceId);if(revoked&&v.serverSequence>(JSON.parse(revoked.acceptedThrough.canonical) as {sequence:number}).sequence)throw new Error('cloud_invalid_revoked_history');
  transition(heads.get(op.objectId),op);heads.set(op.objectId,op);ids.add(id);
 }
 private revocationRoots(anchors:Anchor[]){const recovery=this.store.get<Anchor>('state','recovery-checkpoint');if(recovery&&recovery.sequence<=anchors.at(-1)!.sequence&&!anchors.some(a=>a.sequence===recovery.sequence&&a.root===recovery.root))throw new Error('cloud_invalid_recovery_checkpoint');for(const d of this.roster?.revoked??[]){const cp=JSON.parse(d.acceptedThrough.canonical) as Anchor;if(cp.sequence<=anchors.at(-1)!.sequence&&!anchors.some(a=>a.sequence===cp.sequence&&a.root===cp.root))throw new Error('cloud_invalid_revocation_checkpoint');}}
 private async run(){
  const owner=randomUUID();if(!this.store.acquireLease(owner))throw new Error('cloud_sync_busy');
  try{
   if(this.rosterRuntime){this.roster=await refreshRoster(this.store,this.secure,this.rosterRuntime.http,this.rosterRuntime.keys,this.coordinator.device.deviceId);this.pins=rosterPins(this.roster);}
   const health=this.store.get<{state:string}>('state','health');if(health&&['revoked','security_error','auth_required','incompatible'].includes(health.state))throw new Error('cloud_'+health.state);
   const {current,heads,ids,anchors}=await this.validateHistory();this.coordinator.reconcile();
   const vault=this.coordinator.device.vaultId;
   for(const {value:entry} of this.store.all<OutboxEntry>('outbox')){
    this.store.assertLease(owner);const op=parseCanonicalOperation(entry.signed.canonical);
    if(!await verifyOperation(this.coordinator.device,entry.signed))throw new Error('cloud_invalid_pending');
    if(entry.approval){
     const approval=await this.remote.call('/v1/devices/approvals',{operation:entry.signed,expiresIn:900,...(entry.intent?{intent:entry.intent}:{})}) as {state?:string};
     if(approval.state&&['denied','cancelled','expired'].includes(approval.state)){
      this.coordinator.retireApproval(op.operationId,approval.state as 'denied'|'cancelled'|'expired');continue;
     }
    }
    // A legacy writer may have changed the row during the approval round trip.
    this.coordinator.reconcile();if(!this.store.get('outbox',op.operationId))continue;
    let receipt:PushReceipt&{checkpoint:Checkpoint;witness?:import('./protocol.ts').SignedManagedOperation};
    try{receipt=await this.remote.call(`/v1/vaults/${vault}/sync/push`,entry.signed) as typeof receipt;}
    catch(error){if(entry.approval&&error instanceof Error&&error.message==='approval_required')continue;throw error;}
    const cp=await this.checkpoint(receipt.checkpoint);
    if(this.remote.policy.witnessKeys){
     if(!receipt.witness||!this.roster)throw new Error('cloud_invalid_witness');
     const witnessed=JSON.parse(receipt.witness.canonical) as {revision:number};
     if(witnessed.revision>this.roster.revision&&this.rosterRuntime){this.roster=await refreshRoster(this.store,this.secure,this.rosterRuntime.http,this.rosterRuntime.keys,this.coordinator.device.deviceId);this.pins=rosterPins(this.roster);}
     const signed=this.store.get<import('./protocol.ts').SignedManagedOperation>('state','roster-current');if(!signed)throw new Error('cloud_roster_missing');
     const w=await verifyWitness(receipt.witness,this.remote.policy.witnessKeys,{accountId:this.roster.accountId,tenantId:this.roster.tenantId,vaultId:vault,revision:this.roster.revision,digest:await rosterDigest(signed)});if(w.sequence<receipt.serverSequence)throw new Error('cloud_invalid_witness_checkpoint');
    }
    if(receipt.vaultId!==vault||receipt.deviceId!==op.deviceId||receipt.operationId!==op.operationId||!Number.isSafeInteger(receipt.serverSequence)||receipt.serverSequence<1||cp.sequence!==receipt.serverSequence)throw new Error('cloud_invalid_receipt');
    // Retain the exact queue bytes until the verified pull commits. Lost replies are safe to retry.
    current.requiredThrough=Math.max(current.requiredThrough,receipt.serverSequence);
    this.store.transaction(()=>{this.store.assertLease(owner);this.store.put('state','cursor',current);});
    if(!this.store.acquireLease(owner))throw new Error('cloud_lease_lost');
   }
   const buffered:ManagedVersion[]=[];let proveThrough=this.store.get<Anchor>('state','recovery-checkpoint')?.sequence??0;
   for(;;){
    this.store.assertLease(owner);
    const cursor=Buffer.from(JSON.stringify([this.tenant,vault,this.coordinator.device.deviceId,current.sequence])).toString('base64');
    const page=await this.remote.call(`/v1/vaults/${vault}/sync/pull?cursor=${encodeURIComponent(cursor)}&limit=100`,{},'GET') as Page;
    exactFields(page,['versions','checkpoint','pageCheckpoint','nextCursor','hasMore']);
    if(!Array.isArray(page.versions)||page.versions.length>100||typeof page.hasMore!=='boolean')throw new Error('cloud_invalid_page');
    const head=await this.checkpoint(page.checkpoint),end=await this.checkpoint(page.pageCheckpoint);
    let root=current.root,sequence=current.sequence;const nextHeads=new Map(heads),nextIds=new Set(ids),newAnchors:Anchor[]=[];
    for(const v of page.versions){await this.validateVersion(v,++sequence,nextHeads,nextIds);root=(await advanceRoot(root,sequence,v.signed)).root;newAnchors.push({sequence,root});}
    if(end.sequence!==sequence||end.root!==root||head.sequence<Math.max(sequence,current.requiredThrough)||page.hasMore!==(sequence<head.sequence)||(!page.hasMore&&head.root!==root)||(page.hasMore&&!page.versions.length))throw new Error('cloud_checkpoint_mismatch');
    this.revocationRoots([...anchors,...newAnchors]);
    const next={sequence,root,requiredThrough:Math.max(current.requiredThrough,head.sequence)};
    buffered.push(...page.versions);
    for(const v of page.versions){const op=parseCanonicalOperation(v.signed.canonical),revoked=this.roster?.revoked.find(d=>d.deviceId===op.deviceId);if(revoked)proveThrough=Math.max(proveThrough,(JSON.parse(revoked.acceptedThrough.canonical) as Anchor).sequence);}
    if(!page.hasMore&&sequence<proveThrough)throw new Error('cloud_invalid_revocation_suffix');
    anchors.push(...newAnchors);
    if(sequence>=proveThrough){this.store.transaction(()=>{
     this.store.assertLease(owner);for(const v of buffered)this.coordinator.apply(v);
     this.store.put('state','cursor',next);this.store.put('state','checkpoint',page.pageCheckpoint);this.store.put('state','health',{state:this.coordinator.pendingLegacy().length?'approval_required':'idle'});
    });
    await this.store.checkAnchor(this.secure,next,anchors);buffered.length=0;}
    Object.assign(current,next);heads.clear();for(const [k,v] of nextHeads)heads.set(k,v);ids.clear();for(const id of nextIds)ids.add(id);
    if(!page.hasMore)break;if(!this.store.acquireLease(owner))throw new Error('cloud_lease_lost');
   }
  if(this.store.all<OutboxEntry>('outbox').some(row=>row.value.approval))throw new Error('approval_required');
  }catch(error){
   const code=error instanceof Error?error.message:'';
   const previousHealth=this.store.get<{state:string}>('state','health')?.state;
   const state=code==='revoked'||code==='cloud_revoked'||previousHealth==='revoked'?'revoked':previousHealth&&['security_error','auth_required','incompatible'].includes(previousHealth)?previousHealth:['unauthorized','not_found'].includes(code)?'auth_required':/invalid|untrusted|rollback|checkpoint|authentication_failed|roster_missing|anchor_missing/.test(code)?'security_error':code==='approval_required'?'approval_required':'backoff';
   this.store.transaction(()=>{this.store.assertLease(owner);this.store.put('state','health',{state});});throw error;
  }finally{this.store.releaseLease(owner);}
 }
}
