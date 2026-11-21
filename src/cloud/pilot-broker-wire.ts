/** Review-only pilot journal IPC contract. Not called by any installed binary.
 * Has no native secret, activation, profile-path or raw SQL capability. */
import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {exactFields} from './protocol.ts';

const domain='AgentKeychain-pilot-journal-broker-request-v1';
const fail=()=>new Error('pilot_broker_request_denied');
const maxFrame=128*1024;
const maxCiphertext=64*1024;
const isDigest=(x:unknown):x is string=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const steps=['pending','handoff-recorded','handoff-published','approval-recorded','preflight-recorded','owner-proof-recorded'] as const;
type Step=(typeof steps)[number];
type Blob={nonce:string;ciphertext:string};

function b64url(value:unknown,min:number,max:number) {
 if(typeof value!=='string'||!value||value.length>Math.ceil(max*4/3)||!/^[A-Za-z0-9_-]+$/.test(value))throw fail();
 const bytes=Buffer.from(value,'base64url');
 if(bytes.length<min||bytes.length>max||bytes.toString('base64url')!==value)throw fail();
 return value;
}
function blob(value:unknown):Blob {
 exactFields(value,['nonce','ciphertext']);
 return {nonce:b64url(value.nonce,24,24),ciphertext:b64url(value.ciphertext,17,maxCiphertext)};
}
export type PilotBrokerRequest=
 | {version:1;op:'inspect';profileDigest:string}
 | {version:1;op:'recover';profileDigest:string;operationDigest:string}
 | {version:1;op:'seed-pending';profileDigest:string;record:Blob}
 | {version:1;op:'advance';profileDigest:string;previousDigest:string;previousGeneration:number;step:Exclude<Step,'pending'>;record:Blob};

/** The peer must derive profileDigest from its own verified installed scope,
 * not accept this caller field as authority. Additional state checks belong
 * in broker: generation+receipt CAS, once-only seed and authenticated peer. */
export function canonicalPilotBrokerRequest(input:unknown):string {
 if(typeof input!=='object'||!input||Array.isArray(input))throw fail();
 const {version,op,profileDigest}=input as Record<string,unknown>;
 if(version!==1||!isDigest(profileDigest))throw fail();
 const base={version:1 as const,op,profileDigest};
 let fixed;
 switch(op){
  case 'inspect':
   exactFields(input,['version','op','profileDigest']);
   fixed=base;break;
  case 'recover':
   exactFields(input,['version','op','profileDigest','operationDigest']);
   if(!isDigest(input.operationDigest))throw fail();
   fixed={...base,operationDigest:input.operationDigest};break;
  case 'seed-pending':
   exactFields(input,['version','op','profileDigest','record']);
   fixed={...base,record:blob(input.record)};break;
  case 'advance':{
   exactFields(input,['version','op','profileDigest','previousDigest','previousGeneration','step','record']);
   const {previousDigest,previousGeneration,step}=input;
   if(!isDigest(previousDigest)||typeof previousGeneration!=='number'||!Number.isSafeInteger(previousGeneration)||
      previousGeneration<1||previousGeneration>=steps.length||steps[previousGeneration]!==step)throw fail();
   fixed={...base,previousDigest,previousGeneration,step,record:blob(input.record)};
   break;
  }
  default:throw fail();
 }
 return JSON.stringify(fixed);
}

export function parsePilotBrokerRequest(bytes:string):Readonly<PilotBrokerRequest> {
 try{
  if(typeof bytes!=='string'||!bytes||Buffer.byteLength(bytes,'utf8')>maxFrame)throw fail();
  const v=JSON.parse(bytes) as PilotBrokerRequest;
  if(canonicalPilotBrokerRequest(v)!==bytes)throw fail();
  if('record' in v)Object.freeze(v.record);
  return Object.freeze(v);
 }catch{throw fail();}
}

/** Recovery only checks an exact local operation; it never retries a network request. */
export function pilotBrokerOperationDigest(canonical:string){
 const request=parsePilotBrokerRequest(canonical);
 if(request.op!=='seed-pending'&&request.op!=='advance')throw fail();
 return createHash('sha256').update(domain+'\0'+canonical).digest('hex');
}

export type PilotBrokerReceipt=Readonly<{
 version:1;kind:'receipt';profileDigest:string;generation:number;step:Step;
 operationDigest:string;previousDigest:string|null;recordDigest:string
}>;
type Response=PilotBrokerReceipt|Readonly<{version:1;kind:'empty';profileDigest:string}>
 |Readonly<{version:1;kind:'snapshot';receipt:PilotBrokerReceipt;record:Readonly<Blob>}>;
export type PilotBrokerReferenceState=Readonly<{
 profileDigest:string;receipts:readonly PilotBrokerReceipt[];current:Readonly<Blob>|null
}>;

function sealedDigest(record:Readonly<Blob>){
 return createHash('sha256').update('AgentKeychain-pilot-journal-broker-record-v1\0'+JSON.stringify(blob(record))).digest('hex');
}
function receipt(value:unknown):PilotBrokerReceipt {
 exactFields(value,['version','kind','profileDigest','generation','step','operationDigest','previousDigest','recordDigest']);
 const {version,kind,profileDigest,generation,step,operationDigest,previousDigest,recordDigest}=value;
 if(version!==1||kind!=='receipt'||!isDigest(profileDigest)||!isDigest(operationDigest)||!isDigest(recordDigest)||
   typeof generation!=='number'||!Number.isSafeInteger(generation)||generation<1||generation>steps.length||
   (generation===1?previousDigest!==null:!isDigest(previousDigest)))throw fail();
 const expectedStep=steps[generation-1];
 if(!expectedStep||expectedStep!==step)throw fail();
 return Object.freeze({version,kind,profileDigest,generation,step:expectedStep,operationDigest,
  previousDigest:previousDigest as string|null,recordDigest});
}
export function canonicalPilotBrokerResponse(value:unknown):string {
 if(typeof value!=='object'||!value||Array.isArray(value)||!('kind' in value))throw fail();
 const candidate=value as Record<string,unknown>;
 if(candidate.kind==='receipt')return JSON.stringify(receipt(value));
 if(candidate.kind==='empty'){
  exactFields(value,['version','kind','profileDigest']);
  if(candidate.version!==1||!isDigest(candidate.profileDigest))throw fail();
  return JSON.stringify({version:1,kind:'empty',profileDigest:candidate.profileDigest});
 }
 if(candidate.kind==='snapshot'){
  exactFields(value,['version','kind','receipt','record']);
  const r=receipt(candidate.receipt),b=blob(candidate.record);
  if(candidate.version!==1||sealedDigest(b)!==r.recordDigest)throw fail();
  return JSON.stringify({version:1,kind:'snapshot',receipt:r,record:b});
 }
 throw fail();
}
export function parsePilotBrokerResponse(bytes:string):Response {
 try{
  if(typeof bytes!=='string'||!bytes||Buffer.byteLength(bytes,'utf8')>maxFrame)throw fail();
  const value=JSON.parse(bytes) as Response;
  if(canonicalPilotBrokerResponse(value)!==bytes)throw fail();
  if(value.kind==='snapshot'){Object.freeze(value.receipt);Object.freeze(value.record);}
  return Object.freeze(value);
 }catch{throw fail();}
}

export function emptyPilotBrokerReference(profileDigest:string):PilotBrokerReferenceState {
 if(!isDigest(profileDigest))throw fail();
 return Object.freeze({profileDigest,receipts:Object.freeze([]),current:null});
}

/** Pure transaction specification only. The profile argument is the
 * independently verified native channel scope, NOT a caller-supplied
 * authentication token. Implement state/receipt changes atomically in the
 * broker; this reference neither authenticates nor persists anything. */
export function transitionPilotBrokerReference(boundProfileDigest:string,state:PilotBrokerReferenceState,bytes:string) {
 const request=parsePilotBrokerRequest(bytes);
 if(!isDigest(boundProfileDigest)||request.profileDigest!==boundProfileDigest||state.profileDigest!==boundProfileDigest||
    !Array.isArray(state.receipts)||state.receipts.length>steps.length)throw fail();
 const receipts:readonly PilotBrokerReceipt[]=state.receipts.map(receipt),seen=new Set<string>();
 let prior:string|null=null;
 for(const [index,entry] of receipts.entries()){
  if(entry.profileDigest!==boundProfileDigest||entry.generation!==index+1||entry.previousDigest!==prior||seen.has(entry.operationDigest))throw fail();
  seen.add(entry.operationDigest);prior=entry.operationDigest;
 }
 const current=receipts.at(-1);
 if(current?(state.current===null||current.recordDigest!==sealedDigest(state.current)):state.current!==null)throw fail();
 const reply=(value:Response,nextState=state)=>Object.freeze({state:nextState,response:canonicalPilotBrokerResponse(value)});
 if(request.op==='inspect')return current&&state.current
  ?reply({version:1,kind:'snapshot',receipt:current,record:state.current})
  :reply({version:1,kind:'empty',profileDigest:boundProfileDigest});
 if(request.op==='recover'){
  const stored=receipts.find(entry=>entry.operationDigest===request.operationDigest);
  if(!stored)throw fail();
  return reply(stored);
 }
 const operationDigest=pilotBrokerOperationDigest(bytes),replayed=receipts.find(entry=>entry.operationDigest===operationDigest);
 if(replayed){
  const step=request.op==='seed-pending'?'pending':request.step;
  const generation=request.op==='seed-pending'?1:request.previousGeneration+1;
  const expected=request.op==='seed-pending'?null:request.previousDigest;
  if(replayed.generation!==generation||replayed.step!==step||replayed.previousDigest!==expected||
     replayed.recordDigest!==sealedDigest(request.record))throw fail();
  return reply(replayed); // Exact previous commit wins before the stale-CAS check.
 }
 if(request.op==='seed-pending'?!!current:(!current||current.generation!==request.previousGeneration||
    current.operationDigest!==request.previousDigest))throw fail();
 const next=receipt({version:1,kind:'receipt',profileDigest:boundProfileDigest,generation:receipts.length+1,
  step:request.op==='seed-pending'?'pending':request.step,operationDigest,previousDigest:prior,recordDigest:sealedDigest(request.record)});
 return reply(next,Object.freeze({profileDigest:boundProfileDigest,receipts:Object.freeze([...receipts,next]),current:request.record}));
}
