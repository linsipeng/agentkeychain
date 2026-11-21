import {Buffer} from 'node:buffer';
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {TextDecoder} from 'node:util';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {installedContinuationPilotNativeReaderScope,type VerifiedInstalledContinuationPilot} from './continuation-pilot-build.ts';
import {canonicalPilotBrokerRequest} from './pilot-broker-wire.ts';
import {base64,exactFields} from './protocol.ts';

const denied=()=>new Error('cloud_continuation_pilot_native_inspect_denied');
const clock=()=>Math.floor(Date.now()/1000);
const timeoutMs=5_000;
export const NATIVE_INSPECT_CHALLENGE='AgentKeychain-pilot-native-inspect-challenge-v1';
export const NATIVE_INSPECT_REPLY='AgentKeychain-pilot-native-inspect-reply-v1';
type Ticket=Readonly<{request:string}>;
type Scope=ReturnType<typeof installedContinuationPilotNativeReaderScope>;
const pending=new WeakMap<Ticket,Readonly<{gate:VerifiedInstalledContinuationPilot;scope:Scope;nonce:string;
 profileDigest:string;issuedAt:number;expiresAt:number;end:number}>>();

/** A consumer must obtain profileDigest from independently verified held
 * storage, never from arguments or the remote response. This creates a challenge only. */
export function beginNativeInspectVerification(gate:VerifiedInstalledContinuationPilot,profileDigest:string):Ticket{
 const scope=installedContinuationPilotNativeReaderScope(gate);
 if(typeof profileDigest!=='string'||profileDigest.length!==64||!/^[a-f0-9]{64}$/.test(profileDigest))throw denied();
 const issuedAt=clock(),expiresAt=Math.min(scope.expiresAt,gate.expiresAt,issuedAt+5);
 if(expiresAt<=issuedAt)throw denied();
 const nonce=randomBytes(32).toString('base64url');
 const wire:unknown=JSON.parse(canonicalPilotBrokerRequest({version:1,op:'inspect',profileDigest}));
 const request=JSON.stringify({version:1,domain:NATIVE_INSPECT_CHALLENGE,abi:scope.abi,
  installationDigest:scope.installationDigest,nonce,wire,issuedAt,expiresAt});
 const ticket=Object.freeze({request});
 pending.set(ticket,Object.freeze({gate,scope,nonce,profileDigest,issuedAt,expiresAt,end:performance.now()+timeoutMs}));
 return ticket;
}

/** A signed observation, not proof of peer process, durability, or activation.
 * The responder must derive the observation from its verified local reader. */
export async function verifyNativeInspectObservation(ticket:Ticket,frame:Uint8Array){
 const saved=pending.get(ticket);
 if(!saved)throw denied();
 pending.delete(ticket);
 try{
  const {gate,scope,nonce,profileDigest,issuedAt,expiresAt,end}=saved;
  const live=()=>{
   const now=clock();
   if(now<issuedAt||now>=expiresAt||performance.now()>=end||
      installedContinuationPilotNativeReaderScope(gate)!==scope)throw denied();
   return now;
  };
  live();
  if(!(frame instanceof Uint8Array)||!frame.byteLength||frame.byteLength>2048)throw denied();
  const raw=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(frame);
  const envelope:unknown=JSON.parse(raw);exactFields(envelope,['canonical','signature']);
  if(typeof envelope.canonical!=='string'||Buffer.byteLength(envelope.canonical)>1200)throw denied();
  base64(envelope.signature,64,64);
  const reply:unknown=JSON.parse(envelope.canonical);
  exactFields(reply,['version','domain','keyId','abi','installationDigest','profileDigest','nonce','requestDigest','observedAt','status']);
  const {observedAt,status}=reply;
  if(typeof observedAt!=='number'||!Number.isSafeInteger(observedAt)||observedAt<issuedAt||observedAt>live()||
      (status!=='empty'&&status!=='snapshot-present'&&status!=='rollback-journal-present'))throw denied();
  const canonical=JSON.stringify({version:1,domain:NATIVE_INSPECT_REPLY,keyId:scope.readerPin.keyId,
   abi:scope.abi,installationDigest:scope.installationDigest,profileDigest,nonce,
   requestDigest:await digest(ticket.request),observedAt,status});
  if(canonical!==envelope.canonical||JSON.stringify({canonical,signature:envelope.signature})!==raw||
     !await verify(scope.readerPin.publicKey,envelope.signature,canonical))throw denied();
  live();
  return Object.freeze({status});
 }catch{throw denied();}
}
