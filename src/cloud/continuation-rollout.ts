import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {type ManagedEndpointPolicy,verifyContinuationAuthority,verifyContinuationCommitAuthority,verifyContinuationRolloutAuthority} from './config.ts';
import {base64,exactFields,type SignedManagedOperation} from './protocol.ts';

const domain='AgentKeychain-continuation-rollout-capability-v1';
const denied=()=>new Error('cloud_continuation_not_provisioned');
const signedDigest=(x:SignedManagedOperation)=>digest(JSON.stringify([x.canonical,x.signature]));
type Inputs={capability:SignedManagedOperation;rolloutAppendix:SignedManagedOperation;authAppendix:SignedManagedOperation;commitAppendix:SignedManagedOperation};
export type VerifiedContinuationRollout=Readonly<{expiresAt:number}>;
const permits=new WeakMap<VerifiedContinuationRollout,{policy:ManagedEndpointPolicy;intentDigest:string;authDigest:string;commitDigest:string;witnessKeyId:string}>();

/** Unwired beyond private synthetic graph injection. The release root
 * delegates to a distinct rollout role; no defaults, env or CLI trust. */
export async function verifySyntheticContinuationRollout(policy:ManagedEndpointPolicy,inputs:Inputs):Promise<VerifiedContinuationRollout>{
 try{
  const {capability,rolloutAppendix,authAppendix,commitAppendix}=inputs;
  const [rollout,auth,main]=await Promise.all([verifyContinuationRolloutAuthority(policy,rolloutAppendix),
   verifyContinuationAuthority(policy,authAppendix),verifyContinuationCommitAuthority(policy,commitAppendix)]);
  if(new Set([rollout.keyId,auth.keyId,main.keyId]).size!==3||new Set([rollout.publicKey,auth.publicKey,main.publicKey]).size!==3)throw denied();
  exactFields(capability,['canonical','signature']);
  if(typeof capability.canonical!=='string'||capability.canonical.length>2048)throw denied();
  base64(capability.signature,64,64);
  const value:unknown=JSON.parse(capability.canonical);
  exactFields(value,['version','domain','mode','manifestDigest','keyId','intentDigest','authAppendixDigest','commitAppendixDigest','witnessKeyId','issuedAt','expiresAt']);
  const {intentDigest,witnessKeyId,issuedAt,expiresAt}=value,now=Math.floor(Date.now()/1000);
  if(typeof intentDigest!=='string'||!/^[a-f0-9]{64}$/.test(intentDigest)||typeof witnessKeyId!=='string'||!policy.witnessKeys?.some(k=>k.keyId===witnessKeyId)||
    typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
    issuedAt>now||issuedAt<1||expiresAt<=now||expiresAt-issuedAt>300)throw denied();
  const authDigest=await signedDigest(authAppendix),commitDigest=await signedDigest(commitAppendix);
  const expected={version:1,domain,mode:'synthetic-only',manifestDigest:JSON.parse(rolloutAppendix.canonical).manifestDigest,keyId:rollout.keyId,
   intentDigest,authAppendixDigest:authDigest,commitAppendixDigest:commitDigest,witnessKeyId,issuedAt,expiresAt};
  if(capability.canonical!==JSON.stringify(expected)||!await verify(rollout.publicKey,capability.signature,capability.canonical))throw denied();
  const permit=Object.freeze({expiresAt});
  permits.set(permit,{policy,intentDigest,authDigest,commitDigest,witnessKeyId});
  return permit;
 }catch{throw denied();}
}
export async function assertSyntheticContinuationIntent(policy:ManagedEndpointPolicy,permit:VerifiedContinuationRollout,target:SignedManagedOperation){
 const scope=permits.get(permit);
 if(!scope||scope.policy!==policy||Math.floor(Date.now()/1000)>=permit.expiresAt||scope.intentDigest!==await digest(target.canonical))throw denied();
}
export async function assertSyntheticContinuationScope(policy:ManagedEndpointPolicy,permit:VerifiedContinuationRollout,input:{
 target:SignedManagedOperation;authorityAppendix:SignedManagedOperation;commitAppendix:SignedManagedOperation;witness:SignedManagedOperation;
}){
 await assertSyntheticContinuationIntent(policy,permit,input.target);
 const scope=permits.get(permit)!;
 if(scope.authDigest!==await signedDigest(input.authorityAppendix)||
    scope.commitDigest!==await signedDigest(input.commitAppendix)||scope.witnessKeyId!==JSON.parse(input.witness.canonical).keyId)throw denied();
}
