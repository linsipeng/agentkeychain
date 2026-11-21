import {base64,exactFields,identifier,type SignedManagedOperation} from './protocol.ts';
import {digest,verify} from '../../managed-cloud/shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../../managed-cloud/shared/device-protocol.ts';
import {genesisRoot,type CheckpointKey} from '../../managed-cloud/shared/checkpoints.ts';
import {rosterDigest,verifyRoster} from '../../managed-cloud/shared/roster.ts';
import {verifyWitness} from '../../managed-cloud/shared/roster-witness.ts';

export const MAIN_PACKAGE_ABSENCE_DOMAIN='AgentKeychain-enrollment-continuation-package-absence-v1';
export const CUSTODY_PACKAGE_ABSENCE_HEAD_DOMAIN='AgentKeychain-enrollment-continuation-package-absence-current-head-v1';
const WINDOW=30;
const reject=()=>new Error('cloud_invalid_missing_package_evidence');

interface TrustedRound {
 readonly nonce:string;
 readonly requestedAt:number;
 readonly now:number;
 /** Canonical original grant from already verified Auth provenance, not a provider response. */
 readonly oldGrantCanonical:string;
 /** Exact retained original device-signed roster. */
 readonly roster:SignedManagedOperation;
 readonly originalDevice:{readonly signingKey:string;readonly wrappingKey:string};
 /** Explicit inputs for isolated verification. A future runtime must obtain all pins from verified release policy. */
 readonly pins:{
  readonly mainAbsence:CheckpointKey;readonly custodyCurrentHead:CheckpointKey;
  readonly historicalWitness:readonly CheckpointKey[];readonly checkpoint:readonly CheckpointKey[];
  readonly recovery:readonly CheckpointKey[];readonly otherAuthorities:readonly CheckpointKey[];
 };
}

function signed(input:unknown,max:number):SignedManagedOperation {
 exactFields(input,['canonical','signature']);
 if(typeof input.canonical!=='string'||input.canonical.length<1||input.canonical.length>max||typeof input.signature!=='string')throw reject();
 base64(input.signature,64,64);
 return {canonical:input.canonical,signature:input.signature};
}
function pinShape(pin:CheckpointKey){
 identifier(pin.keyId);base64(pin.publicKey,32,32);
}

/** Verify a single in-flight read-only observation. No private key, storage,
 * network, signer, or activation authority. Caller owns fresh per-round nonce
 * generation and original protected-state/provenance checks under lease. */
export async function verifyMissingPackageEvidence(input:unknown,round:TrustedRound):Promise<Readonly<{expiresAt:number}>>{
 try{
  exactFields(input,['mainAbsence','custodyCurrentHead','witness']);
  const main=signed(input.mainAbsence,3072),custody=signed(input.custodyCurrentHead,3072),witness=signed(input.witness,4096);
  const {now,requestedAt,nonce,pins,originalDevice,oldGrantCanonical}=round;
  if(!Number.isSafeInteger(now)||!Number.isSafeInteger(requestedAt)||requestedAt<1||requestedAt>now||now-requestedAt>=WINDOW||
     !/^[A-Za-z0-9_-]{43}$/.test(nonce)||typeof oldGrantCanonical!=='string'||oldGrantCanonical.length>4096)throw reject();
  const g=JSON.parse(oldGrantCanonical) as EnrollmentGrant;
  if(canonicalGrant(g)!==oldGrantCanonical||g.issuerDeviceId!==null||g.expiresAt>requestedAt||
     g.signingKey!==originalDevice.signingKey||g.wrappingKey!==originalDevice.wrappingKey)throw reject();
  const roles=[pins.mainAbsence,pins.custodyCurrentHead],existing=[...pins.historicalWitness,...pins.checkpoint,...pins.recovery,...pins.otherAuthorities];
  for(const p of [...roles,...existing])pinShape(p);
  for(const [i,p] of roles.entries()){
   if([g.signingKey,g.wrappingKey].includes(p.publicKey)||
      [...existing,roles[1-i]!].some(other=>p.keyId===other.keyId||p.publicKey===other.publicKey))throw reject();
  }
  if(new Set(pins.historicalWitness.map(p=>p.keyId)).size!==pins.historicalWitness.length)throw reject();
  const roster=signed(round.roster,64*1024),r=await verifyRoster(roster,null,now,true);
  const {requestId,accountId,tenantId,vaultId,deviceId,keyEpoch}=g,d=r.active[0];
  const samePins=(left:readonly CheckpointKey[],right:readonly CheckpointKey[])=>left.length===right.length&&
   left.every((p,i)=>p.keyId===right[i]!.keyId&&p.publicKey===right[i]!.publicKey);
  if(r.accountId!==accountId||r.tenantId!==tenantId||r.vaultId!==vaultId||r.keyEpoch!==keyEpoch||
     r.revision!==1||r.issuer.kind!=='device'||r.issuer.id!==deviceId||r.active.length!==1||r.revoked.length!==0||
     !d||d.deviceId!==deviceId||d.signingKey!==g.signingKey||d.wrappingKey!==g.wrappingKey||
     !samePins(r.checkpointKeys,pins.checkpoint)||!samePins(r.recoveryAuthorities,pins.recovery))throw reject();
  const [grantHash,rosterHash,witnessDigest]=await Promise.all([digest(oldGrantCanonical),rosterDigest(roster),digest(JSON.stringify([witness.canonical,witness.signature]))]);
  const w=await verifyWitness(witness,pins.historicalWitness,{accountId,tenantId,vaultId,revision:1,digest:rosterHash});
  const witnessKey=pins.historicalWitness.find(p=>p.keyId===w.keyId)!;
  if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(tenantId,vaultId)||!/^[a-f0-9]{64}$/.test(w.checkpointDigest)||
     [g.signingKey,g.wrappingKey,...pins.checkpoint.map(p=>p.publicKey),...pins.recovery.map(p=>p.publicKey)].includes(witnessKey.publicKey))throw reject();

  const check=async(proof:SignedManagedOperation,pin:CheckpointKey,domain:string,status:string)=>{
   const parsed:unknown=JSON.parse(proof.canonical);
   exactFields(parsed,['version','domain','keyId','nonce','requestId','grantDigest','rosterDigest','accountId','tenantId','vaultId','deviceId','keyEpoch','rosterRevision','witnessDigest','status','issuedAt','expiresAt']);
   const {issuedAt,expiresAt}=parsed;
   if(typeof issuedAt!=='number'||typeof expiresAt!=='number'||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
      issuedAt<requestedAt||issuedAt>now||now>=expiresAt||expiresAt-issuedAt>WINDOW||expiresAt>r.expiresAt)throw reject();
   const expected={version:1,domain,keyId:pin.keyId,nonce,requestId,grantDigest:grantHash,rosterDigest:rosterHash,
    accountId,tenantId,vaultId,deviceId,keyEpoch,rosterRevision:1,witnessDigest,status,issuedAt,expiresAt};
   if(proof.canonical!==JSON.stringify(expected)||!await verify(pin.publicKey,proof.signature,proof.canonical))throw reject();
   return expiresAt;
  };
  const expiries=await Promise.all([check(main,pins.mainAbsence,MAIN_PACKAGE_ABSENCE_DOMAIN,'absent'),
   check(custody,pins.custodyCurrentHead,CUSTODY_PACKAGE_ABSENCE_HEAD_DOMAIN,'current')]);
  return Object.freeze({expiresAt:Math.min(...expiries)});
 }catch{throw reject();}
}
