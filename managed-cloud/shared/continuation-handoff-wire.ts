import {exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {digest} from './contracts.ts';
export interface ContinuationHandoffStage {oldGrantCanonical:string;target:SignedManagedOperation;roster:SignedManagedOperation;keyPackage:SignedManagedOperation}
function signed(value:unknown,cap:number):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||value.canonical.length>cap||typeof value.signature!=='string'||value.signature.length>100)throw new Error('invalid_continuation_handoff');
 return {canonical:value.canonical,signature:value.signature};
}
export function canonicalHandoffStage(value:unknown):ContinuationHandoffStage{
 exactFields(value,['oldGrantCanonical','target','roster','keyPackage']);
 if(typeof value.oldGrantCanonical!=='string'||value.oldGrantCanonical.length>4096)throw new Error('invalid_continuation_handoff');
 return {oldGrantCanonical:value.oldGrantCanonical,target:signed(value.target,4096),roster:signed(value.roster,16384),keyPackage:signed(value.keyPackage,4096)};
}
export const handoffCodeDigest=(locator:string,code:string)=>digest(JSON.stringify(['AgentKeychain-continuation-handoff-code-v1',locator,code]));
export const handoffPrepareProof=(locator:string,codeDigest:string,stageDigest:string,expiresAt:number)=>
 JSON.stringify(['AgentKeychain-continuation-handoff-prepare-v1',locator,codeDigest,stageDigest,expiresAt]);
export const handoffStageDigest=(value:unknown)=>digest(JSON.stringify(canonicalHandoffStage(value)));
