import {activationMessage,type TrustActivationBinding} from '../../managed-cloud/shared/trust-activation.ts';
import {digest} from '../../managed-cloud/shared/contracts.ts';
import {rosterDigest} from '../../managed-cloud/shared/roster.ts';
import sodium from 'libsodium-wrappers-sumo';
import type {Database} from 'bun:sqlite';
import {RecoveryJournal} from './recovery-journal.ts';
import {RecoveryTarget} from './recovery-target.ts';
import {recoverVaultKey,recoveryWrappingKey,type RecoveryDelivery} from './recovery.ts';
import {openRecoveryTrust} from './recovery-trust.ts';
import {productionComposition,openCloudRuntime,type CloudComposition,type CloudEnrollment} from './runtime.ts';
import {CloudStore} from './persistence.ts';
import {RosterStore,rosterPins} from './roster.ts';
import {CloudHttpError} from './http.ts';
import {recoveryCase,releaseContext,type RecoveryEvidence} from '../../managed-cloud/shared/recovery.ts';
import {genesisRoot} from '../../managed-cloud/shared/checkpoints.ts';
import {open,type SealedShare} from '../../managed-cloud/shared/recovery-crypto.ts';
import type {SecureAccount} from '../platform/secure-store.ts';
/* eslint-disable no-unused-vars -- callback declarations */
export interface RecoveryUI {open(url:string):Promise<void>;wait(ms:number):Promise<void>;status(state:string,url?:string):void}
/* eslint-enable no-unused-vars */
const b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
interface Detail {canonical:string;state:string;challenge:SealedShare}
export async function activateRecovery(db:Database,kek:Uint8Array,packageId:string|undefined,ui:RecoveryUI,composition:CloudComposition=productionComposition(),restart=false){
 if(!composition.policy.recoveryServices||!composition.policy.recoveryAuthorities?.length)throw new Error('cloud_recovery_not_provisioned');
 if(restart){if(!packageId)throw new Error('cloud_recovery_package_required');await RecoveryJournal.clearTerminal(db,composition.secure);}
 const journal=packageId?await RecoveryJournal.begin(db,composition.secure,packageId):await RecoveryJournal.resume(db,composition.secure);
 if(!journal)throw new Error('cloud_recovery_package_required');
 const target=new RecoveryTarget(journal,composition),store=new CloudStore(db,journal.keys.csk);
 const put=async(account:SecureAccount,value:Uint8Array)=>{const old=await composition.secure.get(account);try{if(old&&!sodium.memcmp(old,value)&&!(journal.snapshot().stage==='server_completed'&&['refresh-credential','recovery-anchor'].includes(account)))throw new Error('cloud_recovery_conflict');if(!old||!sodium.memcmp(old,value))await composition.secure.put(account,value);}finally{old?.fill(0);}};
 try{
  if(journal.snapshot().stage==='created'){
   try{await target.register();}catch(error){if(error instanceof Error&&error.message==='cloud_recovery_expired'){await journal.advance('expired');store.remove('state','recovery-intent');}throw error;}
  }
  const checkDeadline=async()=>{const s=journal.snapshot();if(['created','awaiting_verification','waiting_for_release','released','reconstructed'].includes(s.stage)&&typeof s.data.requestDeadline==='number'&&s.data.requestDeadline<=Date.now()){await journal.advance('expired');store.remove('state','recovery-intent');throw new Error('cloud_recovery_expired');}};
  await checkDeadline();
  if(journal.snapshot().stage==='awaiting_verification'){
   const url=composition.policy.apiOrigin+'/recovery#requestRef='+journal.snapshot().data.requestRef;
   let verified=false;
   try{await target.call('status');verified=true;}catch(error){if(!(error instanceof CloudHttpError)||error.code!=='not_found')throw error;}
   if(!verified){ui.status('awaiting_verification',url);await ui.open(url);}
  }
  for(;;){
   await checkDeadline();
   let snapshot=journal.snapshot();ui.status(snapshot.stage);
   if(snapshot.stage==='active')return;
   if(['cancelled','expired'].includes(snapshot.stage))throw new Error('cloud_recovery_'+snapshot.stage);
   let detail:Detail;
   try{detail=await target.call('status') as Detail;}catch(error){
    if(snapshot.stage==='awaiting_verification'&&error instanceof CloudHttpError&&error.code==='not_found'&&Date.now()<Number(snapshot.data.requestDeadline)){await ui.wait(5000);continue;}throw error;
   }
   const c=recoveryCase(detail.canonical),t=snapshot.target;
   if(c.id!==t.id||c.packageId!==t.packageId||c.targetDeviceId!==t.targetDeviceId||c.signingKey!==t.signingKey||c.wrappingKey!==t.wrappingKey||c.nonce!==t.nonce||(snapshot.data.caseCanonical&&snapshot.data.caseCanonical!==detail.canonical))throw new Error('cloud_recovery_conflict');
   if(['cancelled','expired','conflict'].includes(detail.state)&&!['server_completed','local_committed'].includes(snapshot.stage)){
    await journal.advance(detail.state as 'cancelled'|'expired'|'conflict');
    store.remove('state','recovery-intent');throw new Error('cloud_recovery_'+detail.state);
   }
   if(snapshot.stage==='awaiting_verification'){await journal.advance('waiting_for_release',{caseCanonical:detail.canonical});continue;}
   if(snapshot.stage==='waiting_for_release'){
    try{
     const {evidence}=await target.call('evidence') as {evidence:RecoveryEvidence};
     const delivery=await target.call('delivery',{evidence}) as RecoveryDelivery;
     await journal.advance('released',{delivery,evidence});
    }catch(error){if(error instanceof CloudHttpError&&['approval_required','rate_limited','not_found'].includes(error.code)){await ui.wait(Math.max(5000,error.retryAfter));continue;}throw error;}
    continue;
   }
   if(snapshot.stage==='released'){
    const vdk=await recoverVaultKey(snapshot.data.delivery as RecoveryDelivery,c,snapshot.data.evidence as RecoveryEvidence,journal.keys.wrappingPrivate,composition.policy);
    try{await journal.advance('reconstructed',{vdk:b64(vdk)});}finally{vdk.fill(0);}continue;
   }
   if(snapshot.stage==='reconstructed'){await journal.advance('activating');continue;}
   if(snapshot.stage==='activating'){
    const proof=await open(await recoveryWrappingKey(journal.keys.wrappingPrivate),detail.challenge,releaseContext(detail.canonical,'api')+'proof');
    try{
     const encoded=b64(proof),completionSignature=b64(sodium.crypto_sign_detached(JSON.stringify(['AgentKeychain-recovery-proof-v1',detail.canonical,encoded]),journal.keys.signingPrivate));
     const result=await target.call('finish',{proof:encoded,completionSignature}) as {completed:boolean};if(result.completed!==true)throw new Error('cloud_recovery_not_completed');
    }finally{proof.fill(0);}
    const readback=await target.call('status') as Detail;if(readback.state!=='completed'||readback.canonical!==detail.canonical)throw new Error('cloud_recovery_readback_failed');
    await journal.advance('server_completed');continue;
   }
   if(detail.state!=='completed')throw new Error('cloud_recovery_readback_failed');
   if(snapshot.stage==='server_completed'){
    const delivery=snapshot.data.delivery as RecoveryDelivery,{sealed,receiptVersion,binding}=await target.call('trust') as {sealed:SealedShare;receiptVersion?:number;binding?:TrustActivationBinding};
    const previousRoster=new RosterStore(store,composition.secure).current();
    const trust=await openRecoveryTrust(sealed,{caseCanonical:detail.canonical,manifestCanonical:delivery.manifestCanonical,...(binding?{activation:binding}:{}),...(previousRoster?{rosterAnchor:{revision:JSON.parse(previousRoster.canonical).revision as number,digest:await rosterDigest(previousRoster)}}:{})},journal.keys.wrappingPrivate,composition.policy);
    if(composition.policy.witnessKeys&&(!receiptVersion||!binding||binding.receiptVersion!==receiptVersion))throw new Error('cloud_invalid_recovery_trust');
    if(receiptVersion){
     const hash=await rosterDigest(trust.head),trustSignature=b64(sodium.crypto_sign_detached(activationMessage(binding!),journal.keys.signingPrivate));
     await target.call('commit',{receiptVersion,rosterDigest:hash,trustSignature});
    }
    // Secure slots are idempotent compare-and-stage writes. Enrollment publication
    // is one SQLite transaction; the runtime gate stays closed until final readback.
    await journal.update({refreshDigest:trust.bundle.refreshDigest,rosterDigest:await rosterDigest(trust.head)});
    const refreshBytes=Buffer.from(trust.bundle.refreshCredential);try{await put('refresh-credential',refreshBytes);}finally{refreshBytes.fill(0);}
    const checkpointBytes=Buffer.from(JSON.stringify(trust.checkpoint));try{await put('recovery-anchor',checkpointBytes);}finally{checkpointBytes.fill(0);}
    await put('signing-private',journal.keys.signingPrivate);await put('wrapping-private',journal.keys.wrappingPrivate);await put('csk',journal.keys.csk);
    const localRoster=new RosterStore(store,composition.secure);
    if(previousRoster){for(const row of trust.bundle.rosters)if(JSON.parse(row.canonical).revision>JSON.parse(previousRoster.canonical).revision)await localRoster.accept(row);}else await localRoster.initialize(trust.head);
    const anchor={sequence:0,root:await genesisRoot(c.tenantId,c.vaultId)};
    const cursor=store.get<{sequence:number;root:string}>('state','cursor');
    if(!cursor)await store.checkAnchor(composition.secure,anchor,[anchor],true);
    const enrollment:CloudEnrollment={accountId:c.accountId,tenantId:c.tenantId,vaultId:c.vaultId,deviceId:c.targetDeviceId,keyEpoch:c.keyEpoch,signingPublic:c.signingKey,wrappingPublic:c.wrappingKey,vdk:snapshot.data.vdk as string,roster:rosterPins(trust.roster),checkpointKeys:composition.policy.checkpointKeys,releaseId:composition.policy.releaseId,apiOrigin:composition.policy.apiOrigin};
    store.transaction(()=>{
     store.put('state','enrollment',enrollment);store.put('state','recovery-checkpoint',trust.checkpoint);
     if(!cursor)store.put('state','cursor',{...anchor,requiredThrough:trust.checkpoint.sequence});else store.put('state','cursor',{...cursor,requiredThrough:Math.max(trust.checkpoint.sequence,(cursor as {requiredThrough?:number}).requiredThrough??0)});
     store.put('state','health',{state:'recovering'});
    });
    await journal.advance('local_committed');continue;
   }
   if(snapshot.stage==='local_committed'){
    for(const [account,wanted] of [['csk',journal.keys.csk],['signing-private',journal.keys.signingPrivate],['wrapping-private',journal.keys.wrappingPrivate]] as const){const actual=await composition.secure.get(account);try{if(!actual||!sodium.memcmp(actual,wanted))throw new Error('cloud_recovery_secure_readback_failed');}finally{actual?.fill(0);}}
    const cursor=store.get<{sequence:number;root:string}>('state','cursor'),checkpointBytes=await composition.secure.get('checkpoint-anchor');
    try{if(!cursor||!checkpointBytes||Buffer.from(checkpointBytes).toString()!==JSON.stringify({sequence:cursor.sequence,root:cursor.root}))throw new Error('cloud_recovery_anchor_mismatch');}finally{checkpointBytes?.fill(0);}
    const runtime=await openCloudRuntime(db,kek,composition,true);
    try{if(runtime.enrollment.deviceId!==c.targetDeviceId||runtime.enrollment.signingPublic!==c.signingKey||runtime.enrollment.wrappingPublic!==c.wrappingKey||runtime.enrollment.keyEpoch!==c.keyEpoch||runtime.enrollment.vdk!==snapshot.data.vdk)throw new Error('cloud_recovery_profile_mismatch');const anchor=await composition.secure.get('recovery-anchor');try{if(!anchor||Buffer.from(anchor).toString()!==JSON.stringify(store.get('state','recovery-checkpoint')))throw new Error('cloud_recovery_anchor_mismatch');}finally{anchor?.fill(0);}}finally{runtime.close();}
    const refresh=await composition.secure.get('refresh-credential');try{if(!refresh||await digest(Buffer.from(refresh).toString())!==snapshot.data.refreshDigest)throw new Error('cloud_recovery_secure_readback_failed');}finally{refresh?.fill(0);}
    const final=await target.call('readback') as {completed:boolean;caseCanonical:string;refreshDigest:string;rosterDigest:string};if(final.completed!==true||final.caseCanonical!==detail.canonical||final.refreshDigest!==snapshot.data.refreshDigest||final.rosterDigest!==snapshot.data.rosterDigest)throw new Error('cloud_recovery_readback_failed');
    await journal.advance('active');store.put('state','health',{state:'idle'});ui.status('active');return;
   }
   snapshot=journal.snapshot();throw new Error('cloud_recovery_invalid_stage_'+snapshot.stage);
  }
 }catch(error){
  const stage=journal.snapshot().stage;
  if(error instanceof Error&&['cloud_recovery_conflict','cloud_invalid_recovery_delivery'].includes(error.message)&&['created','awaiting_verification','waiting_for_release','released','reconstructed'].includes(stage)){
   await journal.advance('conflict');store.remove('state','recovery-intent');
  }
  throw error;
 }finally{store.destroy();journal.close();}
}
