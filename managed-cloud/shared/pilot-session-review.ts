/** Synthetic/no-write review of an installed-only session proof.
 * Not a token, issuer, enrollment activation or production trust decision. */
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {CheckpointKey} from './checkpoints.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from './device-protocol.ts';

export const PILOT_SESSION_CHALLENGE='AgentKeychain-pilot-session-review-challenge-v1';
export const PILOT_SESSION_COMPLETION='AgentKeychain-pilot-session-review-completion-v1';
const inviteReadbackDomain='AgentKeychain-pilot-auth-invite-consumption-readback-v1';
const inspectPurpose='inspect-staged-binding';
const denied=()=>new Error('pilot_session_review_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const envelopeDigest=(p:SignedManagedOperation)=>digest(JSON.stringify([p.canonical,p.signature]));
const hex=(x:unknown)=>typeof x==='string'&&x.length===64&&/^[0-9a-f]{64}$/.test(x);
const nonceShape=(x:unknown)=>typeof x==='string'&&x.length===43&&/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(x);
type Pin=Readonly<CheckpointKey>;
/** Expected values come from trusted owner observations: exact staged Main
 * row and previously correlated Auth observation, not a state flag in the
 * completion. The installed pin is a synthetic test role. A real, separately
 * authorized, protected installation proof pin producer does not yet exist. */
type OwnerScope=Readonly<{
 grantCanonical:string;stageAttemptDigest:string;custodyReceiptDigest:string;
 installDigest:string;profileDigest:string;validUntil:number;
 authConsumptionDigest:string;authRequestDigest:string;authNonce:string;inviteDigest:string;authApprovalDigest:string;mainLinkDigest:string;
 challengeAuthority:Pin;authConsumptionAuthority:Pin;installedTestProof:Pin;reservedRolePins:readonly Pin[];
 previousCompletionDigest?:string;
}>;
function operation(value:unknown):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||!value.canonical||new TextEncoder().encode(value.canonical).length>2048)throw denied();
 base64(value.signature,64,64);
 return {canonical:value.canonical,signature:value.signature};
}
function time(fields:Record<string,unknown>,until:number,clock:number){
 const {issuedAt,expiresAt}=fields;
 if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
   issuedAt<1||issuedAt>clock||expiresAt<=clock||expiresAt>until||expiresAt-issuedAt>30)throw denied();
 return {issuedAt,expiresAt};
}
export function pilotSessionReviewCompletion(challengeDigest:string,role:'original-device'|'installed-test'){
 return JSON.stringify({version:1,domain:PILOT_SESSION_COMPLETION,purpose:inspectPurpose,role,challengeDigest});
}
export async function verifySyntheticPilotSessionReview(raw:unknown,owner:OwnerScope){
 try{
  if(typeof raw!=='string'||!raw||new TextEncoder().encode(raw).length>8192)throw denied();
  const issued=now(),{grantCanonical,stageAttemptDigest,custodyReceiptDigest,installDigest,profileDigest,validUntil,
   authConsumptionDigest,authRequestDigest,authNonce,inviteDigest,authApprovalDigest,mainLinkDigest,
   challengeAuthority,authConsumptionAuthority,installedTestProof,reservedRolePins,previousCompletionDigest}=owner;
  if(![stageAttemptDigest,custodyReceiptDigest,installDigest,profileDigest,authConsumptionDigest,authRequestDigest,inviteDigest,
      authApprovalDigest,mainLinkDigest].every(hex)||!nonceShape(authNonce)||!Number.isSafeInteger(validUntil)||validUntil<=issued||
     (previousCompletionDigest!==undefined&&!hex(previousCompletionDigest))||grantCanonical.length>4096||
     !reservedRolePins.length||reservedRolePins.length>16)throw denied();
  const g=JSON.parse(grantCanonical) as EnrollmentGrant;
  if(canonicalGrant(g)!==grantCanonical||g.issuerDeviceId!==null||g.keyEpoch!==1||g.expiresAt<=issued)throw denied();
  const keys=[challengeAuthority,authConsumptionAuthority,installedTestProof,...reservedRolePins];
  const keySet=keys.map(p=>p.publicKey).concat(g.signingKey,g.wrappingKey);
  if(new Set(keySet).size!==keySet.length)throw denied();
  for(const pin of keys){
   base64(pin.publicKey,32,32);
   if(pin.keyId!==await digest(pin.publicKey))throw denied();
  }
  const input:unknown=JSON.parse(raw);
  exactFields(input,['challenge','authConsumption','originalDeviceSignature','installedTestSignature']);
  const challenge=operation(input.challenge),authConsumption=operation(input.authConsumption);
  const {originalDeviceSignature,installedTestSignature}=input;
  base64(originalDeviceSignature,64,64);base64(installedTestSignature,64,64);
  if(raw!==JSON.stringify({challenge,authConsumption,originalDeviceSignature,installedTestSignature})||
     await envelopeDigest(authConsumption)!==authConsumptionDigest)throw denied();
  const auth:unknown=JSON.parse(authConsumption.canonical);
  exactFields(auth,['version','domain','keyId','nonce','requestDigest','inviteDigest','authApprovalDigest','mainLinkDigest',
   'installationDigest','profileDigest','issuedAt','expiresAt']);
  const authTime=time(auth,Math.min(validUntil,g.expiresAt),issued);
  if(authConsumption.canonical!==JSON.stringify({version:1,domain:inviteReadbackDomain,keyId:authConsumptionAuthority.keyId,
    nonce:authNonce,requestDigest:authRequestDigest,inviteDigest,authApprovalDigest,mainLinkDigest,installationDigest:installDigest,
    profileDigest,...authTime})||!await verify(authConsumptionAuthority.publicKey,authConsumption.signature,authConsumption.canonical))throw denied();
  const selected:unknown=JSON.parse(challenge.canonical);
  exactFields(selected,['version','domain','keyId','purpose','nonce','stageAttemptDigest','grantDigest','custodyReceiptDigest',
   'authConsumptionDigest','installationDigest','profileDigest','originalDeviceKeyId','installedTestKeyId','issuedAt','expiresAt']);
  const challengeTime=time(selected,authTime.expiresAt,issued),{nonce}=selected;
  if(!nonceShape(nonce)||nonce===authNonce||challengeTime.issuedAt<authTime.issuedAt||
     challenge.canonical!==JSON.stringify({version:1,domain:PILOT_SESSION_CHALLENGE,keyId:challengeAuthority.keyId,purpose:inspectPurpose,
      nonce,stageAttemptDigest,grantDigest:await digest(grantCanonical),custodyReceiptDigest,authConsumptionDigest,installationDigest:installDigest,
      profileDigest,originalDeviceKeyId:await digest(g.signingKey),installedTestKeyId:installedTestProof.keyId,...challengeTime})||
     !await verify(challengeAuthority.publicKey,challenge.signature,challenge.canonical))throw denied();
  const hash=await envelopeDigest(challenge);
  if(!await verify(g.signingKey,originalDeviceSignature,pilotSessionReviewCompletion(hash,'original-device'))||
     !await verify(installedTestProof.publicKey,installedTestSignature,pilotSessionReviewCompletion(hash,'installed-test'))||
     now()>=challengeTime.expiresAt)throw denied();
  const completionDigest=await digest(raw);
  if((previousCompletionDigest!==undefined&&previousCompletionDigest!==completionDigest)||now()>=challengeTime.expiresAt)throw denied();
  return Object.freeze({state:'pending-installed-pin-provenance' as const,completionDigest,
   replay:previousCompletionDigest===undefined?'not-compared' as const:'exact-match' as const});
 }catch{throw denied();}
}
