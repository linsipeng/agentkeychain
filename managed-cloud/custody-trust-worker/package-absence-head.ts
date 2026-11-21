import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisRoot,verifyCheckpoint,type CheckpointKey,type CheckpointSigner} from '../shared/checkpoints.ts';
import {digest,verify} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from '../shared/genesis-approval.ts';
import {rosterDigest,verifyRoster} from '../shared/roster.ts';
import {verifyWitness} from '../shared/roster-witness.ts';

const DOMAIN='AgentKeychain-enrollment-continuation-package-absence-current-head-v1';
const REQUEST_DOMAIN='AgentKeychain-enrollment-continuation-package-absence-current-head-request-v1';
const TTL=30;
const reject=()=>new Error('continuation_absence_head_unavailable');
const nowSeconds=()=>Math.floor(Date.now()/1000);
const signedDigest=(operation:SignedManagedOperation)=>digest(JSON.stringify([operation.canonical,operation.signature]));

export interface CustodyAbsenceHeadRequest {
 readonly nonce:string;
 readonly requestedAt:number;
 readonly deviceSignature:string;
 readonly originalGrant:string;
 readonly initialApproval:SignedManagedOperation;
 readonly roster:SignedManagedOperation;
}

export interface CustodyAbsenceHeadPolicy extends GenesisApprovalPolicy {
 readonly witness:CheckpointKey;
 readonly currentHead:CheckpointKey;
 readonly otherReleaseKeys:readonly CheckpointKey[];
}

interface StoredHead {
 event:number;revision:number;sequence:number;root:string;digest:string;
 roster:string;receipt:string;checkpoint:string;decisionId:string;
 authorityKeyId:string;attemptDigest:string;admissionExpiresAt:number;
 vetoUntil:number|null;accountVetoUntil:number|null;
}

export function custodyAbsenceHeadRequestProof(nonce:string,requestedAt:number,requestId:string,grantDigest:string,rosterDigest:string){
 return JSON.stringify({version:1,domain:REQUEST_DOMAIN,nonce,requestedAt,requestId,grantDigest,rosterDigest});
}
function shape(value:unknown,max:number):SignedManagedOperation{
 exactFields(value,['canonical','signature']);
 if(typeof value.canonical!=='string'||!value.canonical.length||value.canonical.length>max)throw reject();
 base64(value.signature,64,64);
 return {canonical:value.canonical,signature:value.signature};
}

/** Unbound Custody-only observation. Historical Auth admission is provenance,
 * not live approval; this signer never asserts that Main lacks a package.
 * Policy and the signer are operator-owned. No route, write or default state. */
export async function proveCustodyAbsenceHead(db:D1Database,input:CustodyAbsenceHeadRequest,
 policy:CustodyAbsenceHeadPolicy,signer:CheckpointSigner):Promise<{witness:SignedManagedOperation;head:SignedManagedOperation}>{
 try{
  exactFields(input,['nonce','requestedAt','deviceSignature','originalGrant','initialApproval','roster']);
  const {nonce,requestedAt,deviceSignature,originalGrant}=input,observed=nowSeconds();
  if(typeof nonce!=='string'||!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(nonce)||
     !Number.isSafeInteger(requestedAt)||requestedAt<1||requestedAt>observed||observed-requestedAt>=TTL||
     typeof originalGrant!=='string'||!originalGrant.length||originalGrant.length>4096)throw reject();
  base64(deviceSignature,64,64);
  const g=JSON.parse(originalGrant) as EnrollmentGrant;
  if(canonicalGrant(g)!==originalGrant||g.issuerDeviceId!==null||g.expiresAt>observed)throw reject();
  const {requestId,accountId,tenantId,vaultId,deviceId,keyEpoch}=g;
  const initialApproval=shape(input.initialApproval,2048),roster=shape(input.roster,16384);
  const [grantDigest,rosterHash]=await Promise.all([digest(originalGrant),rosterDigest(roster)]);
  if(!await verify(g.signingKey,deviceSignature,custodyAbsenceHeadRequestProof(nonce,requestedAt,requestId,grantDigest,rosterHash)))throw reject();
  const r=await verifyRoster(roster,null,observed);
  const first=r.active[0];
  if(!first||first.deviceId!==deviceId||first.signingKey!==g.signingKey||first.wrappingKey!==g.wrappingKey||
     r.issuedAt>observed||r.issuer.kind!=='device'||r.issuer.id!==deviceId||r.recovery!==null||
     r.accountId!==accountId||r.tenantId!==tenantId||r.vaultId!==vaultId||r.keyEpoch!==keyEpoch)throw reject();
  const current=policy.currentHead,witnessPin=policy.witness,local=await signer.key();
  for(const pin of [current,witnessPin,policy.authority,...policy.checkpointKeys,...policy.recoveryAuthorities,...policy.otherReleaseKeys]){
   base64(pin.publicKey,32,32);
   if(pin.keyId!==await digest(pin.publicKey))throw reject();
  }
  const custodyRoleConflicts=[g.signingKey,g.wrappingKey,policy.authority.publicKey,...policy.checkpointKeys.map(k=>k.publicKey),
   ...policy.recoveryAuthorities.map(k=>k.publicKey),...policy.otherReleaseKeys.map(k=>k.publicKey)];
  if(local.keyId!==current.keyId||local.publicKey!==current.publicKey||current.publicKey===witnessPin.publicKey||
     custodyRoleConflicts.includes(current.publicKey)||custodyRoleConflicts.includes(witnessPin.publicKey))throw reject();

  // Each first statement goes to the primary, including both fence reads.
  const read=()=>db.withSession('first-primary').prepare(`
   SELECT w.event,w.revision,w.sequence,w.root,w.digest,w.roster,w.receipt,w.checkpoint,
          a.decision_id AS decisionId,a.authority_key_id AS authorityKeyId,
          a.attempt_digest AS attemptDigest,a.expires_at AS admissionExpiresAt,
          d.expires_at AS vetoUntil,b.expires_at AS accountVetoUntil
   FROM roster_witness w
   JOIN genesis_admissions a ON a.tenant_id=w.tenant_id AND a.vault_id=w.vault_id AND a.witness_event=w.event
     AND a.witness_digest=w.digest AND a.attempt_digest=w.request_digest
   LEFT JOIN trust_devices d ON d.tenant_id=w.tenant_id AND d.vault_id=w.vault_id AND d.account_id=? AND d.device_id=?
   LEFT JOIN trust_accounts b ON b.account_id=?
   WHERE w.tenant_id=? AND w.vault_id=? AND w.event=1 AND w.revision=1 AND w.sequence=0
     AND NOT EXISTS(SELECT 1 FROM roster_witness newest WHERE newest.tenant_id=w.tenant_id AND newest.vault_id=w.vault_id AND newest.event>w.event)
     AND NOT EXISTS(SELECT 1 FROM recovery_revocation_witness v WHERE v.tenant_id=w.tenant_id AND v.vault_id=w.vault_id AND v.device_id=?)
     AND (d.device_id IS NULL OR (d.revoked=0 AND d.signing_key=? AND d.expires_at>unixepoch()))
     AND (b.account_id IS NULL OR (b.revoked=0 AND b.expires_at>unixepoch()))
  `).bind(accountId,deviceId,accountId,tenantId,vaultId,deviceId,g.signingKey).first<StoredHead>();
  const row=await read();
  if(!row||row.digest!==rosterHash||row.roster!==JSON.stringify(roster)||row.root!==await genesisRoot(tenantId,vaultId))throw reject();
  const witness=shape(JSON.parse(row.receipt),4096),checkpoint=shape(JSON.parse(row.checkpoint),4096);
  const w=await verifyWitness(witness,[witnessPin],{accountId,tenantId,vaultId,revision:1,digest:rosterHash},checkpoint);
  if(w.event!==row.event||w.sequence!==row.sequence||w.root!==row.root)throw reject();
  const checkpointKey=policy.checkpointKeys.find(pin=>pin.keyId===JSON.parse(checkpoint.canonical).keyId);
  if(!checkpointKey||(await verifyCheckpoint(checkpointKey,tenantId,vaultId,checkpoint)).sequence!==0)throw reject();
  // Exact digest of what the initial Custody transaction already authenticated
  // and consumed. This deliberately cannot authorize legacy, unproven heads.
  if(row.attemptDigest!==await digest(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',initialApproval,originalGrant,roster,checkpoint])))throw reject();
  const historicAt:unknown=JSON.parse(initialApproval.canonical).issuedAt;
  if(typeof historicAt!=='number'||historicAt>observed)throw reject();
  const approval=await verifyGenesisApproval(initialApproval,originalGrant,roster,policy,historicAt);
  if(approval.decisionId!==row.decisionId||approval.authorityKeyId!==row.authorityKeyId||
     row.admissionExpiresAt!==Math.min(approval.expiresAt,r.expiresAt))throw reject();
  const witnessDigest=await signedDigest(witness),issuedAt=nowSeconds();
  const expiresAt=Math.min(issuedAt+TTL,requestedAt+TTL,r.expiresAt,row.vetoUntil??Infinity,row.accountVetoUntil??Infinity);
  if(expiresAt<=issuedAt)throw reject();
  const canonical=JSON.stringify({version:1,domain:DOMAIN,keyId:current.keyId,nonce,requestId,grantDigest,rosterDigest:rosterHash,
   accountId,tenantId,vaultId,deviceId,keyEpoch,rosterRevision:1,witnessDigest,status:'current',issuedAt,expiresAt});
  const stillCurrent=async()=>JSON.stringify(await read())===JSON.stringify(row)&&nowSeconds()<expiresAt;
  if(!await stillCurrent())throw reject();
  const signature=await signer.sign(canonical);
  if(!await verify(current.publicKey,signature,canonical)||!await stillCurrent())throw reject();
  return {witness,head:{canonical,signature}};
 }catch{throw reject();}
}
