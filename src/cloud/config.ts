import {validateReleaseOrigins} from '../../managed-cloud/shared/release-origins.mjs';
import sodium from 'libsodium-wrappers-sumo';
import { base64, exactFields, identifier, type SignedManagedOperation } from './protocol.ts';
import type { CheckpointKey } from '../../managed-cloud/shared/checkpoints.ts';
import {digest} from '../../managed-cloud/shared/contracts.ts';
import { releaseArtifact } from './release.generated.ts';
await sodium.ready;
export interface ReleaseTrustManifest {
  version: 1;
  releaseId: string;
  apiOrigin: string;
  webOrigin: string;
  protocolMin: number;
  protocolMax: number;
  checkpointKeys: readonly CheckpointKey[];
  witnessKeys?: readonly CheckpointKey[];
  recoveryAuthorities?: readonly CheckpointKey[];
  recoveryServices?: Readonly<{api:CheckpointKey;custodian:CheckpointKey}>;
}
const verified = new WeakMap<object,{canonical:string;root:Uint8Array}>();
export type ManagedEndpointPolicy = Readonly<ReleaseTrustManifest>;
export function canonicalManifest(input: unknown): string {
  if(!input||typeof input!=='object')throw new Error('invalid_release_manifest');
  exactFields(input, ['version','releaseId','apiOrigin','webOrigin','protocolMin','protocolMax','checkpointKeys',...('witnessKeys' in input?['witnessKeys']:[]),...('recoveryAuthorities' in input?['recoveryAuthorities']:[]),...('recoveryServices' in input?['recoveryServices']:[])]);
  identifier(input.releaseId);
  validateReleaseOrigins(input.apiOrigin,input.webOrigin);
  if (input.version !== 1 ||
      !Number.isSafeInteger(input.protocolMin) || !Number.isSafeInteger(input.protocolMax) ||
      (input.protocolMin as number) < 1 || (input.protocolMin as number) > 2 || (input.protocolMax as number) < 2) throw new Error('incompatible_release_manifest');
  if (!Array.isArray(input.checkpointKeys) || !input.checkpointKeys.length || input.checkpointKeys.length > 16) throw new Error('invalid_release_pins');
  const ids = new Set<string>();
  const pins = input.checkpointKeys.map((p: unknown) => {
    exactFields(p, ['keyId','publicKey']); identifier(p.keyId); base64(p.publicKey,32,32);
    if (ids.has(p.keyId)) throw new Error('duplicate_release_pin'); ids.add(p.keyId);
    return {keyId:p.keyId,publicKey:p.publicKey};
  }).sort((a,b)=>a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0);
  let recoveryAuthorities:CheckpointKey[]|undefined;
  if('recoveryAuthorities' in input){if(!Array.isArray(input.recoveryAuthorities)||input.recoveryAuthorities.length>16)throw new Error('invalid_recovery_pins');const seen=new Set<string>(),keys=new Set<string>();recoveryAuthorities=input.recoveryAuthorities.map((p:unknown)=>{exactFields(p,['keyId','publicKey']);identifier(p.keyId);base64(p.publicKey,32,32);if(seen.has(p.keyId)||keys.has(p.publicKey))throw new Error('duplicate_recovery_pin');seen.add(p.keyId);keys.add(p.publicKey);return {keyId:p.keyId,publicKey:p.publicKey};}).sort((a,b)=>a.keyId<b.keyId?-1:1);}
  let recoveryServices:ReleaseTrustManifest['recoveryServices'];
  if('recoveryServices' in input){
    exactFields(input.recoveryServices,['api','custodian']);
    const services=input.recoveryServices as {api:CheckpointKey;custodian:CheckpointKey};
    for(const p of [services.api,services.custodian]){exactFields(p,['keyId','publicKey']);identifier(p.keyId);base64(p.publicKey,32,32);}
    if(services.api.keyId===services.custodian.keyId||services.api.publicKey===services.custodian.publicKey)throw new Error('duplicate_recovery_service_pin');
    recoveryServices={api:{keyId:services.api.keyId,publicKey:services.api.publicKey},custodian:{keyId:services.custodian.keyId,publicKey:services.custodian.publicKey}};
  }
  let witnessKeys:CheckpointKey[]|undefined;
  if('witnessKeys' in input){if(!Array.isArray(input.witnessKeys)||!input.witnessKeys.length||input.witnessKeys.length>16)throw new Error('invalid_witness_pins');witnessKeys=input.witnessKeys.map((p:unknown)=>{exactFields(p,['keyId','publicKey']);identifier(p.keyId);base64(p.publicKey,32,32);return {keyId:p.keyId,publicKey:p.publicKey};});if(new Set(witnessKeys.map(p=>p.keyId)).size!==witnessKeys.length||new Set(witnessKeys.map(p=>p.publicKey)).size!==witnessKeys.length||witnessKeys.some(p=>pins.some(k=>k.publicKey===p.publicKey)||recoveryAuthorities?.some(k=>k.publicKey===p.publicKey)))throw new Error('invalid_witness_pins');witnessKeys.sort((a,b)=>a.keyId<b.keyId?-1:1);}
  return JSON.stringify({...('witnessKeys' in input?{witnessKeys}:{}),...('recoveryServices' in input?{recoveryServices}:{}),...('recoveryAuthorities' in input?{recoveryAuthorities}:{}),version:1,releaseId:input.releaseId,apiOrigin:input.apiOrigin,webOrigin:input.webOrigin,protocolMin:input.protocolMin,protocolMax:input.protocolMax,checkpointKeys:pins});
}
/** The root is supplied by the signed build, never by the network or user configuration. */
export function verifyReleaseManifest(signed: SignedManagedOperation, root: Uint8Array): ManagedEndpointPolicy {
  exactFields(signed,['canonical','signature']);
  if (typeof signed.canonical !== 'string' || signed.canonical.length > 16384 || root.length !== 32) throw new Error('invalid_release_manifest');
  base64(signed.signature,64,64);
  const value = JSON.parse(signed.canonical) as ReleaseTrustManifest;
  if (canonicalManifest(value) !== signed.canonical || !sodium.crypto_sign_verify_detached(Buffer.from(signed.signature,'base64'),signed.canonical,root)) throw new Error('invalid_release_signature');
  const result = Object.freeze({...value,...(value.witnessKeys?{witnessKeys:Object.freeze(value.witnessKeys.map(p=>Object.freeze({...p})))}:{}),...(value.recoveryServices?{recoveryServices:Object.freeze({api:Object.freeze({...value.recoveryServices.api}),custodian:Object.freeze({...value.recoveryServices.custodian})})}:{}),...(value.recoveryAuthorities?{recoveryAuthorities:Object.freeze(value.recoveryAuthorities.map(p=>Object.freeze({...p})))}:{}),checkpointKeys:Object.freeze(value.checkpointKeys.map(p=>Object.freeze({...p})))});
  verified.set(result,{canonical:signed.canonical,root:new Uint8Array(root)}); return result;
}
export function assertVerifiedPolicy(policy: ManagedEndpointPolicy): void {
  if (!verified.has(policy)) throw new Error('unverified_release_manifest');
}
// Separate v1 appendix: existing signed release artifacts and their format are
// unchanged. The caller cannot opt into a different root or inject a default pin.
async function verifyContinuationPin(policy:ManagedEndpointPolicy,appendix:SignedManagedOperation,domain:string):Promise<Readonly<CheckpointKey>>{
  assertVerifiedPolicy(policy);
  const provenance=verified.get(policy)!;
  exactFields(appendix,['canonical','signature']);
  if(typeof appendix.canonical!=='string'||appendix.canonical.length>1024||!policy.witnessKeys?.length)throw new Error('cloud_continuation_not_provisioned');
  base64(appendix.signature,64,64);
  const value:unknown=JSON.parse(appendix.canonical);
  exactFields(value,['version','domain','manifestDigest','keyId','publicKey']);
  identifier(value.keyId);base64(value.publicKey,32,32);
  const expected={version:1,domain,manifestDigest:await digest(provenance.canonical),keyId:value.keyId,publicKey:value.publicKey};
  const existing=[...policy.checkpointKeys,...policy.witnessKeys,...(policy.recoveryAuthorities??[]),...(policy.recoveryServices?[policy.recoveryServices.api,policy.recoveryServices.custodian]:[])];
  const rootKey=Buffer.from(provenance.root).toString('base64');
  if(appendix.canonical!==JSON.stringify(expected)||rootKey===value.publicKey||existing.some(p=>p.keyId===value.keyId||p.publicKey===value.publicKey)||
     !sodium.crypto_sign_verify_detached(Buffer.from(appendix.signature,'base64'),appendix.canonical,provenance.root))
    throw new Error('invalid_continuation_authority_pin');
  return Object.freeze({keyId:value.keyId,publicKey:value.publicKey});
}
export const verifyContinuationAuthority=(policy:ManagedEndpointPolicy,appendix:SignedManagedOperation)=>
  verifyContinuationPin(policy,appendix,'AgentKeychain-continuation-release-pin-v1');
export const verifyContinuationCommitAuthority=(policy:ManagedEndpointPolicy,appendix:SignedManagedOperation)=>
  verifyContinuationPin(policy,appendix,'AgentKeychain-continuation-main-commit-release-pin-v1');
export function productionPolicy(): ManagedEndpointPolicy {
  const artifact = releaseArtifact();
  if (!artifact) throw new Error('cloud_unavailable_not_provisioned');
  const policy=verifyReleaseManifest(artifact.manifest,Buffer.from(artifact.rootPublicKey,'base64'));
  if(!policy.witnessKeys?.length)throw new Error('cloud_witness_not_provisioned');return policy;
}
