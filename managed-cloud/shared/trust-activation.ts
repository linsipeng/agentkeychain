import {digest} from './contracts.ts';
import {recoveryCase} from './recovery.ts';
import {parseRoster,rosterDigest} from './roster.ts';
import type {Checkpoint} from './checkpoints.ts';
import type {SealedShare} from './recovery-crypto.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
export interface TrustActivationBinding {
 version:1;caseId:string;receiptVersion:number;signedDigest:string;sealedDigest:string;refreshDigest:string;
 checkpointDigest:string;checkpointRoot:string;checkpointKeyId:string;checkpointSequence:number;
 witnessDigest:string;witnessEvent:number;witnessRevision:number;rosterDigest:string;rosterRevision:number;
 signingKey:string;wrappingKey:string;keyEpoch:number;expiresAt:number;
}
export interface TrustActivationMaterial {signedDigest:string;sealed:SealedShare;refreshDigest:string;roster:SignedManagedOperation;witness:SignedManagedOperation;checkpoint:Checkpoint}
export async function trustActivationBinding(canonical:string,receiptVersion:number,m:TrustActivationMaterial):Promise<TrustActivationBinding>{
 const c=recoveryCase(canonical),r=parseRoster(m.roster),cp=JSON.parse(m.checkpoint.canonical),w=JSON.parse(m.witness.canonical);
 if(!Number.isSafeInteger(receiptVersion)||receiptVersion<1)throw new Error('invalid_activation_binding');
 return {version:1,caseId:c.id,receiptVersion,signedDigest:m.signedDigest,sealedDigest:await digest(JSON.stringify(m.sealed)),refreshDigest:m.refreshDigest,checkpointDigest:await digest(JSON.stringify(m.checkpoint)),checkpointRoot:cp.root,checkpointKeyId:cp.keyId,checkpointSequence:cp.sequence,witnessDigest:await digest(JSON.stringify(m.witness)),witnessEvent:w.event,witnessRevision:w.revision,rosterDigest:await rosterDigest(m.roster),rosterRevision:r.revision,signingKey:c.signingKey,wrappingKey:c.wrappingKey,keyEpoch:c.keyEpoch,expiresAt:Math.min(c.expiresAt,r.expiresAt)};
}
export const activationMessage=(binding:TrustActivationBinding)=>JSON.stringify(['AgentKeychain-recovery-activate-v2',binding]);
