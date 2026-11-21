import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
export const PILOT_POST_PROOF_PATH='/v1/pilot/continuation/post-commit-proof';
export function pilotProofEnvelope(value:unknown,limit:number):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||!value.canonical||value.canonical.length>limit||typeof value.signature!=='string')throw new Error('invalid_pilot_post_proof');
 base64(value.signature,64,64);
 return {canonical:value.canonical,signature:value.signature};
}
export function pilotContinuationRequest(input:unknown){
 exactFields(input,['nonce','grant','target','approval','roster','keyPackage']);
 const {nonce,grant,target,approval,roster,keyPackage}=input;
 if(typeof nonce!=='string'||!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(nonce)||
    typeof grant!=='string'||!grant||grant.length>4096)throw new Error('invalid_pilot_post_proof');
 return {nonce,grant,target:pilotProofEnvelope(target,4096),approval:pilotProofEnvelope(approval,4096),
  roster:pilotProofEnvelope(roster,16384),keyPackage:pilotProofEnvelope(keyPackage,4096)};
}
export function canonicalPilotPostProof(input:unknown){
 exactFields(input,['request','prior','main']);
 return JSON.stringify({request:pilotContinuationRequest(input.request),prior:pilotProofEnvelope(input.prior,2048),main:pilotProofEnvelope(input.main,4096)});
}
export const PILOT_PREFLIGHT_PATH='/v1/pilot/continuation/preflight';
export const PILOT_COMMIT_PATH='/v1/pilot/continuation/commit-or-read';
export function pilotPreflightInput(input:unknown){
 exactFields(input,['request']);
 return {request:pilotContinuationRequest(input.request)};
}
export function pilotCommitInput(input:unknown){
 exactFields(input,['request','witness','freshHead']);
 return {request:pilotContinuationRequest(input.request),witness:pilotProofEnvelope(input.witness,4096),freshHead:pilotProofEnvelope(input.freshHead,2048)};
}
