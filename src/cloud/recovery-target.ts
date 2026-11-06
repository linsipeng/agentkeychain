import sodium from 'libsodium-wrappers-sumo';
import {randomBytes} from 'node:crypto';
import {ManagedHttpClient} from './http.ts';
import type {RecoveryJournal} from './recovery-journal.ts';
import type {CloudComposition} from './runtime.ts';
import {recoveryWrappingKey} from './recovery.ts';
import {open,type SealedShare} from '../../managed-cloud/shared/recovery-crypto.ts';
import {exactFields} from './protocol.ts';
const b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
/** Uses only the isolated journal keys; no enrolled device/session is required. */
export class RecoveryTarget {
 private http:ManagedHttpClient;
 constructor(private journal:RecoveryJournal,composition:CloudComposition){
  const target=journal.snapshot().target;
  this.http=new ManagedHttpClient(composition.policy,{record:{vaultId:'pending',deviceId:target.targetDeviceId,publicKey:target.signingKey,revoked:false},privateKey:journal.keys.signingPrivate},composition.network);
 }
 private sign(value:unknown){return b64(sodium.crypto_sign_detached(JSON.stringify(value),this.journal.keys.signingPrivate));}
 async register(){
  let snapshot=this.journal.snapshot();
  if(snapshot.stage!=='created')return;
  if(!snapshot.data.requestRef){await this.journal.update({requestRef:randomBytes(32).toString('base64url'),requestDeadline:Date.now()+172800000});snapshot=this.journal.snapshot();}
  const target=snapshot.target,requestRef=snapshot.data.requestRef;
  if(typeof requestRef!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(requestRef)||typeof snapshot.data.requestDeadline!=='number'||snapshot.data.requestDeadline<=Date.now())throw new Error('cloud_recovery_expired');
  const challenge=await this.http.publicCall('/v1/devices/recovery-target-challenge',{target,signature:this.sign(['AgentKeychain-recovery-target-v1',target])}) as {challengeRef:string;box:SealedShare};
  exactFields(challenge,['challengeRef','box']);
  if(typeof challenge.challengeRef!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(challenge.challengeRef))throw new Error('cloud_invalid_recovery_target');
  const plaintext=await open(await recoveryWrappingKey(this.journal.keys.wrappingPrivate),challenge.box,'AgentKeychain-recovery-target-possession-v1\0'+challenge.challengeRef+'\0'+JSON.stringify(target));
  try{
   if(plaintext.length!==43)throw new Error('cloud_invalid_recovery_target');
   const result=await this.http.publicCall('/v1/devices/recovery-target',{target,requestRef,signature:this.sign(['AgentKeychain-recovery-target-request-v1',target,requestRef]),challengeRef:challenge.challengeRef,proof:b64(plaintext)}) as {requestRef:string;expiresIn:number};
   exactFields(result,['requestRef','expiresIn']);
   if(result.requestRef!==requestRef||result.expiresIn!==172800)throw new Error('cloud_invalid_recovery_target');
   await this.journal.advance('awaiting_verification');
  }finally{plaintext.fill(0);}
 }
 async call(route:'status'|'delivery'|'finish'|'trust'|'evidence'|'readback'|'commit',extra:Record<string,unknown>={}){
  const name='recovery-target-'+route,body={requestRef:this.journal.snapshot().data.requestRef,...extra};
  return this.http.publicCall('/v1/devices/'+name,{...body,signature:this.sign(['AgentKeychain-recovery-target-call-v1',name,body])});
 }
}
