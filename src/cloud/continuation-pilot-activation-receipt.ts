/** Canonical local receipt planning only. A parsed record is not authenticated
 * storage, a live lease, fresh Custody approval or active enrollment. */
import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {exactFields} from './protocol.ts';

const basisFields=['profileDigest','stageDigest','commitDigest','slotDigest'] as const;
const dbDomain='AgentKeychain-pilot-activation-db-commit-v1';
const slotDomain='AgentKeychain-pilot-activation-protected-slot-v1';
const denied=()=>new Error('cloud_pilot_activation_receipt_denied');

export type PilotActivationBasis=Readonly<{version:1}&Record<(typeof basisFields)[number],string>>;
type DbCommit=Readonly<{version:1;domain:typeof dbDomain;attemptDigest:string;basis:PilotActivationBasis}>;
type ProtectedSlot=Readonly<{
 version:1;domain:typeof slotDomain;attemptDigest:string;basis:PilotActivationBasis;
 phase:'prepared'|'finalized';previousDigest:string|null;databaseReceiptDigest:string|null;
}>;
type SuccessorPlan=Readonly<{
 kind:'compare-and-record'|'already-recorded';
 expectedPreviousDigest:string;databaseReceiptDigest:string;finalizedCanonical:string;
}>;

function digestText(value:unknown):string {
 if(typeof value!=='string'||value.length!==64||!/^[0-9a-f]{64}$/.test(value))throw denied();
 return value;
}
function basis(value:unknown):PilotActivationBasis {
 exactFields(value,['version',...basisFields]);
 if(value.version!==1)throw denied();
 return Object.freeze({version:1,profileDigest:digestText(value.profileDigest),stageDigest:digestText(value.stageDigest),
  commitDigest:digestText(value.commitDigest),slotDigest:digestText(value.slotDigest)});
}
function exactCanonical<T>(raw:unknown,parse:(input:unknown)=>T):T {
 if(typeof raw!=='string'||!raw||Buffer.byteLength(raw,'utf8')>2048)throw denied();
 const input:unknown=JSON.parse(raw);
 const canonical=parse(input);
 if(JSON.stringify(canonical)!==raw)throw denied();
 return canonical;
}
function dbCommit(value:unknown):DbCommit {
 exactFields(value,['version','domain','attemptDigest','basis']);
 if(value.version!==1||value.domain!==dbDomain)throw denied();
 return Object.freeze({version:1,domain:dbDomain,attemptDigest:digestText(value.attemptDigest),basis:basis(value.basis)});
}
function slot(value:unknown):ProtectedSlot {
 exactFields(value,['version','domain','attemptDigest','basis','phase','previousDigest','databaseReceiptDigest']);
 if(value.version!==1||value.domain!==slotDomain||(value.phase!=='prepared'&&value.phase!=='finalized'))throw denied();
 const phase=value.phase;
 if(phase==='prepared'&&(value.previousDigest!==null||value.databaseReceiptDigest!==null))throw denied();
 return Object.freeze({version:1,domain:slotDomain,attemptDigest:digestText(value.attemptDigest),basis:basis(value.basis),phase,
  previousDigest:phase==='prepared'?null:digestText(value.previousDigest),
  databaseReceiptDigest:phase==='prepared'?null:digestText(value.databaseReceiptDigest)});
}
const sha=(raw:string)=>createHash('sha256').update(raw,'utf8').digest('hex');

/** Text constructors for future trusted adapters, not trust/capability brands. */
export function canonicalPilotActivationDbReceipt(expected:PilotActivationBasis,attemptDigest:string):string {
 return JSON.stringify(dbCommit({version:1,domain:dbDomain,attemptDigest,basis:expected}));
}
export function canonicalPilotActivationPreparedSlot(expected:PilotActivationBasis,attemptDigest:string):string {
 return JSON.stringify(slot({version:1,domain:slotDomain,attemptDigest,basis:expected,phase:'prepared',
  previousDigest:null,databaseReceiptDigest:null}));
}

/** Compare exact observations from the two storage owners. Call only after
 * authenticating them and verifying freshness; callers must retain the same
 * real lease and perform the actual expected-predecessor write/re-read.
 * The predecessor digest must come from trusted prepared continuity (never
 * inferred from a database row or the finalized slot), including on restart.
 * A returned intent does not implement CAS or certify active state. */
export function planPilotActivationSlotSuccessor(expected:PilotActivationBasis,attemptDigest:string,
 expectedPreparedDigest:string,databaseCanonical:unknown,protectedCanonical:unknown):SuccessorPlan {
 try{
  const previous=digestText(expectedPreparedDigest);
  const prepared=canonicalPilotActivationPreparedSlot(expected,attemptDigest);
  if(sha(prepared)!==previous)throw denied();
  exactCanonical(databaseCanonical,dbCommit);
  const database=canonicalPilotActivationDbReceipt(expected,attemptDigest);
  if(databaseCanonical!==database)throw denied();
  const observed=exactCanonical(protectedCanonical,slot);
  const databaseReceiptDigest=sha(database);
  const finalizedCanonical=JSON.stringify(slot({...slot(JSON.parse(prepared)),phase:'finalized',
   previousDigest:previous,databaseReceiptDigest}));
  if(protectedCanonical!==(observed.phase==='prepared'?prepared:finalizedCanonical))throw denied();
  return Object.freeze({kind:observed.phase==='prepared'?'compare-and-record':'already-recorded',
   expectedPreviousDigest:previous,databaseReceiptDigest,finalizedCanonical});
 }catch{throw denied();}
}
