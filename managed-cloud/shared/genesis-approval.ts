import {base64,exactFields,identifier,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {CheckpointKey} from './checkpoints.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from './device-protocol.ts';
import {rosterDigest,verifyRoster} from './roster.ts';

export const GENESIS_APPROVAL_DOMAIN='AgentKeychain-managed-genesis-approval-v1\0';
export const GENESIS_APPROVAL_TTL=600;
const audience='custodian:roster-genesis';
const reject=()=>new Error('invalid_genesis_approval');

export interface GenesisApproval {
 readonly version:1;
 readonly audience:typeof audience;
 readonly decisionId:string;
 readonly authorityKeyId:string;
 readonly grantDigest:string;
 readonly rosterDigest:string;
 readonly issuedAt:number;
 readonly expiresAt:number;
}

/** Supplied by Custody configuration only, never a caller or an enrollment record. */
export interface GenesisApprovalPolicy {
 readonly authority:Readonly<CheckpointKey>;
 readonly checkpointKeys:readonly Readonly<CheckpointKey>[];
 readonly recoveryAuthorities:readonly Readonly<CheckpointKey>[];
}

export function canonicalGenesisApproval(input:unknown):string{
 try{exactFields(input,['version','audience','decisionId','authorityKeyId','grantDigest','rosterDigest','issuedAt','expiresAt']);}catch{throw reject();}
 const {decisionId,authorityKeyId,grantDigest,rosterDigest,issuedAt,expiresAt}=input;
 if(input.version!==1||input.audience!==audience)throw reject();
 try{identifier(decisionId);}catch{throw reject();}
 const validDigest=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
 if(!validDigest(authorityKeyId)||!validDigest(grantDigest)||!validDigest(rosterDigest))throw reject();
 if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||issuedAt<1||expiresAt<=issuedAt||expiresAt-issuedAt>GENESIS_APPROVAL_TTL)throw reject();
 return JSON.stringify({version:1,audience,decisionId,authorityKeyId,grantDigest,rosterDigest,issuedAt,expiresAt});
}

/** Verifies an unconsumed approval for an initial witness. Does not mint an
 * approval, register a credential or consume a decision. The caller must bind
 * the returned decision to its first witness atomically in Custody storage.
 * An idempotent retry after commit reads the persisted witness instead. */
export async function verifyGenesisApproval(
 proof:unknown, grantBytes:unknown, roster:SignedManagedOperation, policy:GenesisApprovalPolicy, now=Math.floor(Date.now()/1000),
):Promise<Readonly<GenesisApproval>>{
 try{
  if(!Number.isSafeInteger(now)||now<1)throw reject();
  exactFields(proof,['canonical','signature']);
  const {canonical,signature}=proof;
  if(typeof canonical!=='string'||canonical.length>2048)throw reject();
  base64(signature,64,64);
  const data=JSON.parse(canonical) as GenesisApproval;
  if(canonicalGenesisApproval(data)!==canonical||data.issuedAt>now||data.expiresAt<=now)throw reject();

  const pin=policy.authority;
  base64(pin.publicKey,32,32);
  if(data.authorityKeyId!==pin.keyId||pin.keyId!==await digest(pin.publicKey)||!await verify(pin.publicKey,signature,GENESIS_APPROVAL_DOMAIN+canonical))throw reject();

  if(typeof grantBytes!=='string'||grantBytes.length>4096||await digest(grantBytes)!==data.grantDigest)throw reject();
  const grant=JSON.parse(grantBytes) as EnrollmentGrant;
  if(canonicalGrant(grant)!==grantBytes||grant.issuerDeviceId!==null||grant.expiresAt<data.expiresAt)throw reject();
  const current=await verifyRoster(roster,null,now),device=current.active[0];
  if(!device||current.issuer.kind!=='device'||current.issuer.id!==grant.deviceId||current.accountId!==grant.accountId||current.tenantId!==grant.tenantId||current.vaultId!==grant.vaultId||current.keyEpoch!==grant.keyEpoch||device.deviceId!==grant.deviceId||device.signingKey!==grant.signingKey||device.wrappingKey!==grant.wrappingKey)throw reject();
  if(JSON.stringify(current.checkpointKeys)!==JSON.stringify(policy.checkpointKeys)||JSON.stringify(current.recoveryAuthorities)!==JSON.stringify(policy.recoveryAuthorities))throw reject();
  if([device.signingKey,device.wrappingKey,...policy.checkpointKeys.map(k=>k.publicKey),...policy.recoveryAuthorities.map(k=>k.publicKey)].includes(pin.publicKey)||await rosterDigest(roster)!==data.rosterDigest)throw reject();
  return Object.freeze(data);
 }catch{
  // Do not propagate identities, input bytes or low-level parser text.
  throw reject();
 }
}
