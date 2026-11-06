import {cleanupExportStaging} from './export.ts';
import {RosterStore,rosterPins} from './roster.ts';
import {wakeCloud} from './daemon.ts';
import type {Database} from 'bun:sqlite';
import {productionPolicy,type ManagedEndpointPolicy} from './config.ts';
import {platformSecureStore,type SecureStore} from '../platform/secure-store.ts';
import {vaultDir} from '../vault.ts';
import {CloudStore} from './persistence.ts';
import {VaultMutationCoordinator,coordinatorFor,hasCloudState} from './coordinator.ts';
import {ManagedHttpClient,type CloudFetch} from './http.ts';
import {DurableSync} from './durable.ts';
import {destroyCloudKeys,type CloudKeys} from './crypto.ts';
import type {DeviceRecord} from './protocol.ts';
import type {CheckpointKey} from '../../managed-cloud/shared/checkpoints.ts';
export interface CloudEnrollment {accountId:string;tenantId:string;vaultId:string;deviceId:string;keyEpoch:number;signingPublic:string;wrappingPublic:string;vdk:string;roster:DeviceRecord[];checkpointKeys:readonly CheckpointKey[];releaseId:string;apiOrigin:string}
export interface CloudComposition {policy:ManagedEndpointPolicy;secure:SecureStore;network?:CloudFetch}
export function productionComposition():CloudComposition{return {policy:productionPolicy(),secure:platformSecureStore(vaultDir())};}
export async function openCloudRuntime(db:Database,kek:Uint8Array,composition:CloudComposition=productionComposition(),recovering=false){
 const {policy,secure}=composition,csk=await secure.get('csk');if(!csk)throw new Error('cloud_secure_store_locked');
 let signing:Uint8Array|null=null,wrapping:Uint8Array|null=null;
 try{
  const store=new CloudStore(db,csk),enrollment=store.get<CloudEnrollment>('state','enrollment');
  if(!enrollment)throw new Error('cloud_not_enrolled');
  const enrollmentIntent=await secure.get('enrollment-intent');if(enrollmentIntent){enrollmentIntent.fill(0);throw new Error('cloud_enrollment_pending');}
  const recoveryBytes=await secure.get('recovery-intent');
  try{if(recoveryBytes){const recovery=JSON.parse(new TextDecoder().decode(recoveryBytes)) as {snapshot:{stage:string;target:{targetDeviceId:string}}};if(recovery.snapshot.target.targetDeviceId!==enrollment.deviceId||(recovery.snapshot.stage!=='active'&&!(recovering&&recovery.snapshot.stage==='local_committed')))throw new Error('cloud_recovery_pending');}}finally{recoveryBytes?.fill(0);}
  const recoveryAnchor=await secure.get('recovery-anchor');
  try{if(recoveryBytes&&!recoveryAnchor)throw new Error('cloud_recovery_anchor_missing');if(recoveryAnchor&&Buffer.from(recoveryAnchor).toString()!==JSON.stringify(store.get('state','recovery-checkpoint')))throw new Error('cloud_recovery_anchor_mismatch');}finally{recoveryAnchor?.fill(0);}
  if(enrollment.apiOrigin!==policy.apiOrigin)throw new Error('cloud_release_origin_changed');
  // No implicit checkpoint-key rotation policy. A release cannot substitute roster pins.
  if(JSON.stringify(enrollment.checkpointKeys)!==JSON.stringify(policy.checkpointKeys))throw new Error('cloud_release_pin_discontinuity');
  signing=await secure.get('signing-private');wrapping=await secure.get('wrapping-private');
  if(!signing||signing.length!==64||!wrapping||wrapping.length!==32)throw new Error('cloud_secure_store_locked');
  const keys:CloudKeys={csk:new Uint8Array(csk),vdk:Buffer.from(enrollment.vdk,'base64'),signingPrivate:signing,wrappingPrivate:wrapping,signingPublic:Buffer.from(enrollment.signingPublic,'base64'),wrappingPublic:Buffer.from(enrollment.wrappingPublic,'base64')};
  const device={vaultId:enrollment.vaultId,deviceId:enrollment.deviceId,publicKey:enrollment.signingPublic,revoked:false};
  const rosterStore=new RosterStore(store,secure);const roster=await rosterStore.check();
  if(roster.accountId!==enrollment.accountId||roster.tenantId!==enrollment.tenantId||roster.vaultId!==enrollment.vaultId)throw new Error('cloud_invalid_roster_context');
  if(JSON.stringify(roster.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(roster.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities??[]))throw new Error('cloud_invalid_roster_release_pins');
  enrollment.roster=rosterPins(roster);device.revoked=roster.revoked.some(d=>d.deviceId===device.deviceId);if(device.revoked)store.put('state','health',{state:'revoked'});
  const coordinator=new VaultMutationCoordinator(store,keys,device,kek,enrollment.keyEpoch),http=new ManagedHttpClient(policy,{record:device,privateKey:keys.signingPrivate},composition.network);
  const refresh=await secure.get('refresh-credential');try{if(refresh)http.setRefreshCredential(refresh);}finally{refresh?.fill(0);}
  cleanupExportStaging(store);
  const engine=new DurableSync(store,secure,coordinator,http,enrollment.tenantId,enrollment.roster,{http,keys});
  return {store,secure,keys,enrollment,coordinator,http,engine,close(){coordinator.detach();http.logout();store.destroy();destroyCloudKeys(keys);}};
 }catch(error){signing?.fill(0);wrapping?.fill(0);throw error;}finally{csk.fill(0);}
}
/** Shared CRUD entrypoints use this only when managed state exists. Local-only paths never touch cloud keys. */
export async function withCloudMutation<T>(db:Database,kek:Uint8Array,operation:()=>Promise<T>):Promise<T>{
 if(!hasCloudState(db)||coordinatorFor(db))return operation();
 const runtime=await openCloudRuntime(db,kek);try{const result=await operation();try{await wakeCloud(vaultDir());}catch{/* periodic daemon pull remains available */}return result;}finally{runtime.close();}
}
