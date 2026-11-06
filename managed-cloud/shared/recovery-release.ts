import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {digest,verify} from './contracts.ts';
import {recoveryCase,type RecoveryEvidence} from './recovery.ts';
import type {SealedShare} from './recovery-crypto.ts';
import type {CheckpointKey} from './checkpoints.ts';
export const RECOVERY_RELEASE_DOMAIN='AgentKeychain-authenticated-recovery-release-v1\0';
export interface RecoveryRelease {
 version:1;party:'api'|'custodian';keyId:string;caseCanonical:string;manifestDigest:string;evidenceDigest:string;expiresAt:number;box:SealedShare;
}
export interface RecoveryReleaseSigner {
 key():Promise<CheckpointKey>;
 sign(message:string):Promise<string>;
}
export function canonicalRecoveryRelease(r:RecoveryRelease):string{
 exactFields(r,['version','party','keyId','caseCanonical','manifestDigest','evidenceDigest','expiresAt','box']);
 identifier(r.keyId);
 if(r.version!==1||!['api','custodian'].includes(r.party)||typeof r.caseCanonical!=='string'||r.caseCanonical.length>8192)throw new Error('invalid_recovery_release');
 const c=recoveryCase(r.caseCanonical);
 if(JSON.stringify(c)!==r.caseCanonical||!Number.isSafeInteger(r.expiresAt)||r.expiresAt>c.expiresAt||r.expiresAt<=c.createdAt||!(/^[a-f0-9]{64}$/).test(r.manifestDigest)||!(/^[a-f0-9]{64}$/).test(r.evidenceDigest))throw new Error('invalid_recovery_release');
 exactFields(r.box,['version','ephemeralKey','nonce','ciphertext']);
 if(r.box.version!==1)throw new Error('invalid_recovery_release');
 base64(r.box.ephemeralKey,32,32);base64(r.box.nonce,12,12);base64(r.box.ciphertext,48,48);
 return JSON.stringify({version:1,party:r.party,keyId:r.keyId,caseCanonical:r.caseCanonical,manifestDigest:r.manifestDigest,evidenceDigest:r.evidenceDigest,expiresAt:r.expiresAt,box:{version:1,ephemeralKey:r.box.ephemeralKey,nonce:r.box.nonce,ciphertext:r.box.ciphertext}});
}
export async function signRecoveryRelease(party:RecoveryRelease['party'],caseCanonical:string,manifestCanonical:string,evidence:RecoveryEvidence,box:SealedShare,signer:RecoveryReleaseSigner):Promise<SignedManagedOperation>{
 const pin=await signer.key(),c=recoveryCase(caseCanonical);
 const canonical=canonicalRecoveryRelease({version:1,party,keyId:pin.keyId,caseCanonical,manifestDigest:await digest(manifestCanonical),evidenceDigest:await digest(JSON.stringify(evidence)),expiresAt:c.expiresAt,box});
 const signature=await signer.sign(RECOVERY_RELEASE_DOMAIN+canonical);
 if(!await verify(pin.publicKey,signature,RECOVERY_RELEASE_DOMAIN+canonical))throw new Error('invalid_recovery_release_signature');
 return {canonical,signature};
}
export async function verifyRecoveryRelease(s:SignedManagedOperation,pin:CheckpointKey,party:RecoveryRelease['party'],caseCanonical:string,manifestCanonical:string,evidence:RecoveryEvidence,now:number):Promise<SealedShare>{
 exactFields(s,['canonical','signature']);base64(s.signature,64,64);
 if(typeof s.canonical!=='string'||s.canonical.length>16384)throw new Error('invalid_recovery_release');
 const r=JSON.parse(s.canonical) as RecoveryRelease;
 if(canonicalRecoveryRelease(r)!==s.canonical||r.party!==party||r.keyId!==pin.keyId||r.caseCanonical!==caseCanonical||r.manifestDigest!==await digest(manifestCanonical)||r.evidenceDigest!==await digest(JSON.stringify(evidence))||r.expiresAt<=now||!await verify(pin.publicKey,s.signature,RECOVERY_RELEASE_DOMAIN+s.canonical))throw new Error('invalid_recovery_release');
 return r.box;
}
