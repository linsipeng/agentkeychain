import type {CloudStore} from './persistence.ts';
import {sealKeyPackage,type CloudKeys} from './crypto.ts';
import {sealTrustedEnrollment,enrollmentPhrase,type TrustedEnrollmentBundle} from './enrollment.ts';
import type {SignedManagedOperation} from './protocol.ts';
import type {EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
export interface IssuerDelivery {canonical:string;sealed:string;phrase:string;keyPackage:SignedManagedOperation;bundle:TrustedEnrollmentBundle;confirmed:boolean}
/** Persist randomized ciphertext before any network I/O. Concurrent issuers use the same journal. */
export function issuerDelivery(store:CloudStore,canonical:string,bundle:TrustedEnrollmentBundle,keys:CloudKeys,now=Date.now()):IssuerDelivery{
 const grant=JSON.parse(canonical) as EnrollmentGrant;
 if(grant.expiresAt*1000<=now)throw new Error('cloud_authorization_expired');
 return store.transaction(()=>{
  const id='issuer:'+grant.requestId,previous=store.get<IssuerDelivery>('state',id);
  if(previous){if(previous.canonical!==canonical)throw new Error('cloud_issuer_request_conflict');return previous;}
  const delivery:IssuerDelivery={canonical,bundle,sealed:sealTrustedEnrollment(bundle,keys.signingPrivate),phrase:enrollmentPhrase(bundle),keyPackage:sealKeyPackage(keys.vdk,{vaultId:grant.vaultId,targetDeviceId:grant.deviceId,keyEpoch:grant.keyEpoch,issuerDeviceId:grant.issuerDeviceId!,grantId:grant.requestId},Buffer.from(grant.wrappingKey,'base64'),keys.signingPrivate),confirmed:false};
  store.put('state',id,delivery);return delivery;
 });
}
