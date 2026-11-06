import {trustActivationBinding,type TrustActivationBinding} from '../../managed-cloud/shared/trust-activation.ts';
import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';
import {assertVerifiedPolicy,canonicalManifest,type ManagedEndpointPolicy} from './config.ts';
import {recoveryWrappingKey} from './recovery.ts';
import {open,type SealedShare} from '../../managed-cloud/shared/recovery-crypto.ts';
import {parseRecoveryTrust,RECOVERY_TRUST_DOMAIN,recoveryTrustContext} from '../../managed-cloud/shared/recovery-trust.ts';
import {verify,digest} from '../../managed-cloud/shared/contracts.ts';
import {recoveryCase} from '../../managed-cloud/shared/recovery.ts';
import {verifyRoster,parseRoster,rosterDigest} from '../../managed-cloud/shared/roster.ts';
import {verifyCheckpoint} from '../../managed-cloud/shared/checkpoints.ts';
import type {SignedManagedOperation} from './protocol.ts';
export async function openRecoveryTrust(sealed:SealedShare,expected:{caseCanonical:string;manifestCanonical:string;activation?:TrustActivationBinding;rosterAnchor?:{revision:number;digest:string};checkpointAnchor?:{sequence:number;root:string}},privateKey:Uint8Array,policy:ManagedEndpointPolicy){
 let bytes:Uint8Array|undefined;
 try{
  assertVerifiedPolicy(policy);const c=recoveryCase(expected.caseCanonical);
  bytes=await open(await recoveryWrappingKey(privateKey),sealed,recoveryTrustContext(expected.caseCanonical),768*1024);
  const signed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as SignedManagedOperation,b=parseRecoveryTrust(signed);
  const pin=policy.recoveryAuthorities?.find(p=>p.keyId===b.authorityKeyId);
  if(!pin||b.refreshDigest!==await digest(b.refreshCredential)||b.caseCanonical!==expected.caseCanonical||b.releaseCanonical!==canonicalManifest(policy)||b.manifestDigest!==await digest(expected.manifestCanonical)||!await verify(pin.publicKey,signed.signature,RECOVERY_TRUST_DOMAIN+signed.canonical))throw new Error();
  for(let i=0;i<b.rosters.length;i++){const row=b.rosters[i]!;await verifyRoster(row,i?b.rosters[i-1]!:null,i===b.rosters.length-1?Math.floor(Date.now()/1000):parseRoster(row).issuedAt,!!policy.witnessKeys&&i===0);}
  const head=b.rosters.at(-1)!,r=parseRoster(head),target=r.active.find(d=>d.deviceId===c.targetDeviceId);
  if((!policy.witnessKeys||!b.witness)&&!b.rosters.some(row=>{const roster=parseRoster(row);return roster.issuer.kind==='recovery'&&roster.issuer.id===pin.keyId&&roster.recovery&&JSON.parse(roster.recovery.canonical).caseId===c.id;})||r.accountId!==c.accountId||r.tenantId!==c.tenantId||r.vaultId!==c.vaultId||r.keyEpoch!==c.keyEpoch||target?.signingKey!==c.signingKey||target.wrappingKey!==c.wrappingKey||JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities))throw new Error();
  if(policy.witnessKeys){if(!b.witness)throw new Error();await verifyWitness(b.witness,policy.witnessKeys,{accountId:c.accountId,tenantId:c.tenantId,vaultId:c.vaultId,revision:r.revision,digest:await rosterDigest(head)},b.checkpoint);}
  const anchor=expected.rosterAnchor;if(anchor){const old=b.rosters.find(s=>parseRoster(s).revision===anchor.revision);if(!old||await rosterDigest(old)!==anchor.digest)throw new Error();}
  const cpPin=policy.checkpointKeys.find(p=>p.keyId===JSON.parse(b.checkpoint.canonical).keyId);if(!cpPin)throw new Error();
  const checkpoint=await verifyCheckpoint(cpPin,c.tenantId,c.vaultId,b.checkpoint),old=expected.checkpointAnchor;
  if(old&&(checkpoint.sequence<old.sequence||(checkpoint.sequence===old.sequence&&checkpoint.root!==old.root)))throw new Error();
  if(expected.activation){if(b.receiptVersion!==expected.activation.receiptVersion||!b.witness)throw new Error();const actual=await trustActivationBinding(expected.caseCanonical,expected.activation.receiptVersion,{signedDigest:await digest(JSON.stringify(signed)),sealed,refreshDigest:b.refreshDigest,roster:head,witness:b.witness,checkpoint:b.checkpoint});if(JSON.stringify(actual)!==JSON.stringify(expected.activation))throw new Error();}
  return {bundle:b,roster:r,head,checkpoint};
 }catch{throw new Error('cloud_invalid_recovery_trust');}finally{bytes?.fill(0);}
}
