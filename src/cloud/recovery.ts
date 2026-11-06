import sodium from 'libsodium-wrappers-sumo';
import {assertVerifiedPolicy,type ManagedEndpointPolicy} from './config.ts';
import {manifest,recoveryCase,releaseContext,vaultKeyContext,type RecoveryCase,type RecoveryEvidence} from '../../managed-cloud/shared/recovery.ts';
import {joinRecoveryKey,open,unwrapVaultKey} from '../../managed-cloud/shared/recovery-crypto.ts';
import {verifyRecoveryRelease} from '../../managed-cloud/shared/recovery-release.ts';
import {exactFields,type SignedManagedOperation} from './protocol.ts';
export interface RecoveryDelivery {caseCanonical:string;manifestCanonical:string;api:SignedManagedOperation;custodian:SignedManagedOperation}
/** Imports only locally stored raw X25519 material. The temporary PKCS8 buffer is erased. */
export async function recoveryWrappingKey(privateKey:Uint8Array):Promise<globalThis.CryptoKey>{
 if(privateKey.length!==32)throw new Error('invalid_recovery_wrapping_key');
 const der=Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),privateKey]);
 try{return await globalThis.crypto.subtle.importKey('pkcs8',der,'X25519',false,['deriveBits']);}finally{der.fill(0);}
}
/** No share or recovery key escapes this function. Caller owns and must erase the returned VDK. */
export async function recoverVaultKey(delivery:RecoveryDelivery,expected:RecoveryCase,evidence:RecoveryEvidence,privateKey:Uint8Array,policy:ManagedEndpointPolicy,now=Math.floor(Date.now()/1000)):Promise<Uint8Array>{
 let api:Uint8Array|undefined,custodian:Uint8Array|undefined,key:Uint8Array|undefined;
 try{
  assertVerifiedPolicy(policy);if(!policy.recoveryServices)throw new Error();
  exactFields(delivery,['caseCanonical','manifestCanonical','api','custodian']);
  const c=recoveryCase(delivery.caseCanonical),m=manifest(delivery.manifestCanonical);
  if(delivery.caseCanonical!==JSON.stringify(expected)||JSON.stringify(c)!==delivery.caseCanonical||c.expiresAt<=now||c.createdAt>now+120||m.packageId!==c.packageId||m.accountId!==c.accountId||m.tenantId!==c.tenantId||m.vaultId!==c.vaultId||m.keyEpoch!==c.keyEpoch)throw new Error();
  await sodium.ready;
  if(Buffer.from(sodium.crypto_scalarmult_base(privateKey)).toString('base64')!==c.wrappingKey)throw new Error();
  exactFields(evidence,['mode','confirmerId','signature','proof']);
  if(evidence.mode==='cooldown'){if(now<c.notBefore||evidence.confirmerId!==null||evidence.signature!==null)throw new Error();}
  else if(evidence.mode!=='device'||!evidence.confirmerId||!evidence.signature)throw new Error();
  const a=await verifyRecoveryRelease(delivery.api,policy.recoveryServices.api,'api',delivery.caseCanonical,delivery.manifestCanonical,evidence,now);
  const b=await verifyRecoveryRelease(delivery.custodian,policy.recoveryServices.custodian,'custodian',delivery.caseCanonical,delivery.manifestCanonical,evidence,now);
  const wrapping=await recoveryWrappingKey(privateKey);
  api=await open(wrapping,a,releaseContext(delivery.caseCanonical,'api'));
  custodian=await open(wrapping,b,releaseContext(delivery.caseCanonical,'custodian'));
  key=joinRecoveryKey(api,custodian);
  return await unwrapVaultKey(key,m.wrappedVDK,vaultKeyContext(m));
 }catch{throw new Error('cloud_invalid_recovery_delivery');}
 finally{api?.fill(0);custodian?.fill(0);key?.fill(0);}
}
