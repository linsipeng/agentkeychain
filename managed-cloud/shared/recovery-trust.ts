import {rpcData} from './rpc-data.ts';
import {exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {ReleaseTrustManifest} from '../../src/cloud/config.ts';
import {recoveryCase,manifest} from './recovery.ts';
import {verify,digest} from './contracts.ts';
import {verifyRoster,parseRoster,rosterDigest,issueRecoveryRoster,type TrustedDeviceRoster} from './roster.ts';
import {verifyCheckpoint,type Checkpoint,type CheckpointSigner} from './checkpoints.ts';
import {seal,type SealedShare} from './recovery-crypto.ts';
export const RECOVERY_TRUST_DOMAIN='AgentKeychain-recovery-trust-v1\0';
export interface RecoveryTrustBundle {
 witness?:SignedManagedOperation;
 version:1;receiptVersion:number;caseCanonical:string;releaseCanonical:string;authorityKeyId:string;
 manifestDigest:string;refreshCredential:string;refreshDigest:string;rosters:SignedManagedOperation[];checkpoint:Checkpoint;
}
export const recoveryTrustContext=(canonical:string)=>RECOVERY_TRUST_DOMAIN+canonical;
/** The independent Custodian calls this only after its durable completed decision.
 * The provisioned release policy, never a caller supplied key, selects the authority. */
export async function issueRecoveryTrust(input:{caseCanonical:string;manifestCanonical:string;packageSignature:string;rosters:SignedManagedOperation[];checkpoint:Checkpoint;revocations?:{deviceId:string;acceptedThrough:Checkpoint}[]},releaseCanonical:string,signer:CheckpointSigner,witness?:(rosters:SignedManagedOperation[])=>Promise<SignedManagedOperation>,receiptVersion=1):Promise<{bundle:RecoveryTrustBundle;sealed:SealedShare;signedDigest:string}>{
 const c=recoveryCase(input.caseCanonical),m=manifest(input.manifestCanonical),policy=JSON.parse(releaseCanonical) as ReleaseTrustManifest,pin=await rpcData(signer.key());
 if(m.packageId!==c.packageId||m.accountId!==c.accountId||m.tenantId!==c.tenantId||m.vaultId!==c.vaultId||m.keyEpoch!==c.keyEpoch)throw new Error('invalid_recovery_package');
 if(!policy.recoveryAuthorities?.some(p=>p.keyId===pin.keyId&&p.publicKey===pin.publicKey)||!policy.recoveryServices)throw new Error('invalid_recovery_authority');
 if(!input.rosters.length)throw new Error('invalid_recovery_chain');
 for(let i=0;i<input.rosters.length;i++){const row=input.rosters[i]!;await verifyRoster(row,i?input.rosters[i-1]!:null,parseRoster(row).issuedAt,!!witness&&i===0);}
 const authenticatedIssuer=input.rosters.some(row=>{const roster=parseRoster(row);return roster.issuer.kind==='device'&&roster.issuer.id===m.issuerDeviceId;});
 const recoveryAnchor=input.rosters.some(row=>{const roster=parseRoster(row);return roster.issuer.kind==='recovery'&&policy.recoveryAuthorities?.some(p=>p.keyId===roster.issuer.id&&roster.recoveryAuthorities.some(k=>k.keyId===p.keyId&&k.publicKey===p.publicKey));});
 const prior=input.rosters.at(-1)!,r=parseRoster(prior),issuer=[...r.active,...r.revoked].find(d=>d.deviceId===m.issuerDeviceId),now=Math.floor(Date.now()/1000);
 if((!authenticatedIssuer&&!recoveryAnchor&&!witness)||!issuer||!await verify(issuer.signingKey,input.packageSignature,input.manifestCanonical))throw new Error('invalid_recovery_chain_anchor');
 if(r.accountId!==c.accountId||r.tenantId!==c.tenantId||r.vaultId!==c.vaultId||r.keyEpoch!==c.keyEpoch||JSON.stringify(r.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities)||r.revoked.some(d=>d.deviceId===c.targetDeviceId)||r.active.some(d=>d.deviceId===c.targetDeviceId&&(d.signingKey!==c.signingKey||d.wrappingKey!==c.wrappingKey)))throw new Error('invalid_recovery_chain');
 const cpPin=policy.checkpointKeys.find(p=>p.keyId===(JSON.parse(input.checkpoint.canonical) as {keyId:string}).keyId);
 if(!cpPin)throw new Error('invalid_recovery_checkpoint');await verifyCheckpoint(cpPin,c.tenantId,c.vaultId,input.checkpoint);
 const previousDigest=await rosterDigest(prior),revision=r.revision+1;
 const canonical=JSON.stringify({version:1,caseId:c.id,accountId:c.accountId,tenantId:c.tenantId,vaultId:c.vaultId,revision,previousDigest,targetDeviceId:c.targetDeviceId,signingKey:c.signingKey,wrappingKey:c.wrappingKey,completedAt:now});
 const recovery={canonical,signature:await signer.sign('AgentKeychain-roster-recovery-completed-v1\0'+canonical)};
 const revoked=[...r.revoked];
 for(const item of input.revocations??[]){const old=r.active.find(d=>d.deviceId===item.deviceId);if(old){const boundary=JSON.parse(item.acceptedThrough.canonical) as {sequence:number};if(boundary.sequence>(JSON.parse(input.checkpoint.canonical) as {sequence:number}).sequence)throw new Error('invalid_recovery_checkpoint');revoked.push({...old,revokedRevision:revision,acceptedThrough:item.acceptedThrough});}}
 const next:TrustedDeviceRoster={...r,revision,previousDigest,revoked,active:[...r.active.filter(d=>d.deviceId!==c.targetDeviceId&&!revoked.some(v=>v.deviceId===d.deviceId)),{deviceId:c.targetDeviceId,signingKey:c.signingKey,wrappingKey:c.wrappingKey}],issuer:{kind:'recovery',id:pin.keyId},issuedAt:now,expiresAt:now+2592000,recovery};
 const existingTarget=(input.revocations??[]).every(v=>r.revoked.some(d=>d.deviceId===v.deviceId&&JSON.stringify(d.acceptedThrough)===JSON.stringify(v.acceptedThrough)))&&r.active.some(d=>d.deviceId===c.targetDeviceId)&&(!!witness||input.rosters.some(row=>{const roster=parseRoster(row);return roster.recovery&&JSON.parse(roster.recovery.canonical).caseId===c.id;}));
 const signed=existingTarget?prior:await issueRecoveryRoster(prior,next,signer);
 const resultingRosters=existingTarget?input.rosters:[...input.rosters,signed];
 const refreshCredential=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
 const bundle:RecoveryTrustBundle={...(witness?{witness:await witness(resultingRosters)}:{}),version:1,receiptVersion,caseCanonical:input.caseCanonical,releaseCanonical,authorityKeyId:pin.keyId,manifestDigest:await digest(input.manifestCanonical),refreshCredential,refreshDigest:await digest(refreshCredential),rosters:resultingRosters,checkpoint:input.checkpoint};
 const body=JSON.stringify(bundle),signature=await signer.sign(RECOVERY_TRUST_DOMAIN+body);
 if(!await verify(pin.publicKey,signature,RECOVERY_TRUST_DOMAIN+body))throw new Error('invalid_recovery_authority');
 const bytes=new TextEncoder().encode(JSON.stringify({canonical:body,signature}));
 try{if(bytes.length>512*1024)throw new Error('recovery_trust_too_large');return {bundle,signedDigest:await digest(JSON.stringify({canonical:body,signature})),sealed:await seal(c.wrappingKey,bytes,recoveryTrustContext(input.caseCanonical))};}finally{bytes.fill(0);}
}
export function parseRecoveryTrust(s:SignedManagedOperation):RecoveryTrustBundle{
 exactFields(s,['canonical','signature']);if(typeof s.canonical!=='string'||s.canonical.length>512*1024)throw new Error('invalid_recovery_trust');
 const b=JSON.parse(s.canonical) as RecoveryTrustBundle;
 exactFields(b,[...('witness' in b?['witness']:[]),'version','receiptVersion','caseCanonical','releaseCanonical','authorityKeyId','manifestDigest','refreshCredential','refreshDigest','rosters','checkpoint']);
 if(b.version!==1||!Number.isSafeInteger(b.receiptVersion)||b.receiptVersion<1||typeof b.refreshCredential!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(b.refreshCredential)||typeof b.refreshDigest!=='string'||!/^[a-f0-9]{64}$/.test(b.refreshDigest)||!Array.isArray(b.rosters)||b.rosters.length<1||JSON.stringify(b)!==s.canonical)throw new Error('invalid_recovery_trust');return b;
}
