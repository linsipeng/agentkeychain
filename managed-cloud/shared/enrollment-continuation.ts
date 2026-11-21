import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from './device-protocol.ts';

export const CONTINUATION_WINDOW_SECONDS=300;
type Stage='publish-roster'|'put-trust-bundle'|'put-key-package';
type WitnessHead={revision:number;digest:string};
interface Intent {
 version:1;domain:'AgentKeychain-enrollment-continuation-intent-v1';id:string;
 originalGrantDigest:string;requestId:string;accountId:string;tenantId:string;vaultId:string;
 deviceId:string;signingKey:string;wrappingKey:string;issuerDeviceId:string|null;keyEpoch:number;
 stage:Stage;payloadDigest:string;rosterDigest:string;witnessHead:WitnessHead|null;expiresAt:number;
}
interface Receipt {
 version:1;domain:'AgentKeychain-enrollment-continuation-approval-v1';intentDigest:string;
 approvedAt:number;expiresAt:number;authorityKeyId:string;
}
const intentKeys=['version','domain','id','originalGrantDigest','requestId','accountId','tenantId','vaultId','deviceId','signingKey','wrappingKey','issuerDeviceId','keyEpoch','stage','payloadDigest','rosterDigest','witnessHead','expiresAt'];
const receiptKeys=['version','domain','intentDigest','approvedAt','expiresAt','authorityKeyId'];
function validHash(value:unknown){if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))throw new Error('invalid_continuation_digest');}
function positive(value:unknown){if(typeof value!=='number'||!Number.isSafeInteger(value)||value<1)throw new Error('invalid_continuation_counter');}
function witness(input:unknown){
 if(input===null)return null;
 exactFields(input,['revision','digest']);positive(input.revision);validHash(input.digest);
 return {revision:input.revision,digest:input.digest};
}
export function canonicalContinuationIntent(input:unknown):string {
 exactFields(input,intentKeys);
 if(input.version!==1||input.domain!=='AgentKeychain-enrollment-continuation-intent-v1')throw new Error('invalid_continuation_intent');
 for(const key of ['id','requestId','accountId','tenantId','vaultId','deviceId'])identifier(input[key]);
 if(typeof input.id!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(input.id))throw new Error('invalid_continuation_id');
 if(input.issuerDeviceId!==null){identifier(input.issuerDeviceId);if(input.issuerDeviceId===input.deviceId)throw new Error('invalid_continuation_issuer');}
 base64(input.signingKey,32,32);base64(input.wrappingKey,32,32);
 if(input.signingKey===input.wrappingKey)throw new Error('invalid_continuation_keys');
 for(const key of ['originalGrantDigest','payloadDigest','rosterDigest'])validHash(input[key]);
 positive(input.keyEpoch);positive(input.expiresAt);
 if(input.stage!=='publish-roster'&&input.stage!=='put-trust-bundle'&&input.stage!=='put-key-package')throw new Error('invalid_continuation_stage');
 const head=witness(input.witnessHead);
 // A pre-genesis witness can only be absent for the first-device roster write.
 if((head===null&&(input.issuerDeviceId!==null||input.stage!=='publish-roster'))||
    (input.stage!=='publish-roster'&&input.rosterDigest!==head?.digest)||
    (input.stage==='put-trust-bundle'&&input.issuerDeviceId===null))
  throw new Error('invalid_continuation_context');
 return JSON.stringify(Object.fromEntries(intentKeys.map(key=>[key,key==='witnessHead'?head:input[key]])));
}
export function canonicalContinuationReceipt(input:unknown):string {
 exactFields(input,receiptKeys);
 if(input.version!==1||input.domain!=='AgentKeychain-enrollment-continuation-approval-v1')throw new Error('invalid_continuation_receipt');
 identifier(input.authorityKeyId);validHash(input.intentDigest);positive(input.approvedAt);positive(input.expiresAt);
 if((input.expiresAt as number)<=(input.approvedAt as number)||(input.expiresAt as number)-(input.approvedAt as number)>CONTINUATION_WINDOW_SECONDS)
  throw new Error('invalid_continuation_window');
 return JSON.stringify(Object.fromEntries(receiptKeys.map(key=>[key,input[key]])));
}
export const continuationIssuerProof=(receiptCanonical:string)=>JSON.stringify(['AgentKeychain-enrollment-continuation-issuer-v1',receiptCanonical]);

interface TrustedContext {
 oldGrantCanonical:string;
 stage:Stage;payloadDigest:string;rosterDigest:string;witnessHead:WitnessHead|null;
 authority:{keyId:string;publicKey:string};
 issuer:{deviceId:string;publicKey:string;signature:string}|null;
 now:number;
}
/** Pure signature/binding validation, not permission to mutate.
 * Callers must supply independently pinned approval authority, current active
 * issuer, actual payload/roster digests, and independent current witness head.
 * The eventual writer must atomically consume an exact receipt while it
 * rechecks membership, revocation, epoch, witness and stage state. */
export async function verifyContinuationApproval(target:SignedManagedOperation,approval:SignedManagedOperation,context:TrustedContext):Promise<void>{
 if(target.canonical.length>4096||approval.canonical.length>1024||context.oldGrantCanonical.length>4096)throw new Error('invalid_continuation_size');
 const intent=JSON.parse(target.canonical) as Intent,receipt=JSON.parse(approval.canonical) as Receipt,grant=JSON.parse(context.oldGrantCanonical) as EnrollmentGrant;
 if(canonicalContinuationIntent(intent)!==target.canonical||canonicalContinuationReceipt(receipt)!==approval.canonical||
    canonicalGrant(grant)!==context.oldGrantCanonical)throw new Error('invalid_continuation_canonical');
 positive(context.now);
 if(intent.originalGrantDigest!==await digest(context.oldGrantCanonical)||receipt.intentDigest!==await digest(target.canonical)||
    intent.requestId!==grant.requestId||intent.accountId!==grant.accountId||intent.tenantId!==grant.tenantId||intent.vaultId!==grant.vaultId||
    intent.deviceId!==grant.deviceId||intent.signingKey!==grant.signingKey||intent.wrappingKey!==grant.wrappingKey||
    intent.issuerDeviceId!==grant.issuerDeviceId||intent.keyEpoch!==grant.keyEpoch||
    intent.stage!==context.stage||intent.payloadDigest!==context.payloadDigest||intent.rosterDigest!==context.rosterDigest||
    JSON.stringify(witness(intent.witnessHead))!==JSON.stringify(witness(context.witnessHead))||
    receipt.authorityKeyId!==context.authority.keyId||receipt.approvedAt<grant.expiresAt||receipt.approvedAt>context.now||
    context.now>=receipt.expiresAt||receipt.expiresAt>intent.expiresAt||intent.expiresAt-receipt.approvedAt>CONTINUATION_WINDOW_SECONDS)
  throw new Error('invalid_continuation_binding');
 const separate=(key:string)=>key!==grant.signingKey&&key!==grant.wrappingKey;
 if(!separate(context.authority.publicKey)||!await verify(grant.signingKey,target.signature,target.canonical)||
    !await verify(context.authority.publicKey,approval.signature,approval.canonical))throw new Error('invalid_continuation_signature');
 if(grant.issuerDeviceId===null){if(context.issuer!==null)throw new Error('invalid_continuation_issuer');}
 else if(!context.issuer||context.issuer.deviceId!==grant.issuerDeviceId||!separate(context.issuer.publicKey)||
         context.issuer.publicKey===context.authority.publicKey||!await verify(context.issuer.publicKey,context.issuer.signature,continuationIssuerProof(approval.canonical)))
  throw new Error('invalid_continuation_issuer');
}
