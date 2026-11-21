/** Read-only building blocks for first-device Main binding. No route, database
 * write, session issue or replay consumption. Do not accept a JSON observation
 * from a client as Custody provenance. */
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisRoot,verifyCheckpoint,type CheckpointKey} from './checkpoints.ts';
import {digest,verify} from './contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from './device-protocol.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from './genesis-approval.ts';
import {parseRoster} from './roster.ts';
import {verifyWitness} from './roster-witness.ts';

export const MAIN_BIND_GENESIS='AgentKeychain-first-device-main-binding-v1';
const TTL=30;
const denied=()=>new Error('genesis_main_binding_unavailable');
const now=()=>Math.floor(Date.now()/1000);
type Policy=GenesisApprovalPolicy&Readonly<{witness:Readonly<CheckpointKey>}>;
type VerifiedBinding=Readonly<{
 nonce:string;requestedAt:number;grant:Readonly<EnrollmentGrant>;attemptDigest:string;decisionId:string;
 authorityKeyId:string;rosterDigest:string;admissionExpiresAt:number;validUntil:number;
 roster:Readonly<SignedManagedOperation>;checkpoint:Readonly<SignedManagedOperation>;
}>;

function signed(value:unknown,max:number):Readonly<SignedManagedOperation>{
 exactFields(value,['canonical','signature']);const {canonical,signature}=value;
 if(typeof canonical!=='string'||!canonical||new TextEncoder().encode(canonical).length>max)throw denied();
 base64(signature,64,64);return Object.freeze({canonical,signature});
}
/** First admitted bytes remain immutable; this fresh proof only correlates a
 * device request with those bytes. It does not renew old grant or approval. */
export function mainGenesisBindingDeviceProof(nonce:string,requestedAt:number,attemptDigest:string){
 return JSON.stringify([MAIN_BIND_GENESIS,nonce,requestedAt,attemptDigest]);
}
export async function verifyMainGenesisBinding(raw:unknown,policy:GenesisApprovalPolicy):Promise<VerifiedBinding>{
 try{
  if(typeof raw!=='string'||raw.length>128*1024||new TextEncoder().encode(raw).length>128*1024)throw denied();
  const input:unknown=JSON.parse(raw);
  exactFields(input,['version','domain','nonce','requestedAt','proof','grant','roster','checkpoint','deviceSignature']);
  const {nonce,requestedAt,grant:grantBytes,deviceSignature}=input;
  if(typeof nonce!=='string'||nonce.length!==43||!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(nonce)||
     typeof requestedAt!=='number'||!Number.isSafeInteger(requestedAt)||requestedAt<1||requestedAt>now()||now()>=requestedAt+TTL||
     typeof grantBytes!=='string'||!grantBytes||new TextEncoder().encode(grantBytes).length>4096)throw denied();
  const grant=JSON.parse(grantBytes) as EnrollmentGrant;
  if(canonicalGrant(grant)!==grantBytes||grant.issuerDeviceId!==null)throw denied();
  base64(deviceSignature,64,64);
  const proof=signed(input.proof,2048),roster=signed(input.roster,64*1024),checkpoint=signed(input.checkpoint,4096);
  if(raw!==JSON.stringify({version:1,domain:MAIN_BIND_GENESIS,nonce,requestedAt,proof,grant:grantBytes,roster,checkpoint,deviceSignature}))throw denied();
  const attemptDigest=await digest(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',proof,grantBytes,roster,checkpoint]));
  if(!await verify(grant.signingKey,deviceSignature,mainGenesisBindingDeviceProof(nonce,requestedAt,attemptDigest)))throw denied();
  const approval=await verifyGenesisApproval(proof,grantBytes,roster,policy);
  const r=parseRoster(roster),pin=policy.checkpointKeys.find(p=>p.keyId===JSON.parse(checkpoint.canonical).keyId);
  if(r.revision!==1||r.active.length!==1||r.revoked.length||r.recovery!==null||!pin||
     (await verifyCheckpoint(pin,grant.tenantId,grant.vaultId,checkpoint)).sequence!==0)throw denied();
  const admissionExpiresAt=Math.min(approval.expiresAt,r.expiresAt),validUntil=Math.min(admissionExpiresAt,grant.expiresAt,requestedAt+TTL);
  if(now()>=validUntil)throw denied();
  const result=Object.freeze({nonce,requestedAt,grant:Object.freeze(grant),attemptDigest,decisionId:approval.decisionId,
   authorityKeyId:approval.authorityKeyId,rosterDigest:approval.rosterDigest,admissionExpiresAt,validUntil,roster,checkpoint});
  return result;
 }catch{throw denied();}
}

/** Custody-local only; requires an independently owned primary D1 binding.
 * Reads a positive exact admission, never promotes a generic signed witness.
 * A future private RPC must keep its call and reply bound to this exact fresh
 * request; subsequent Main one-use CAS must independently fence expiry. */
export async function readExactMainGenesisAdmission(db:Pick<D1Database,'withSession'>,raw:unknown,policy:Policy){
 try{
  const bound=await verifyMainGenesisBinding(raw,policy);
  const {grant:g,attemptDigest,decisionId,authorityKeyId,rosterDigest,roster,checkpoint,validUntil,admissionExpiresAt}=bound;
  const {witness}=policy;
  base64(witness.publicKey,32,32);
  if(witness.keyId!==await digest(witness.publicKey)||
    [g.signingKey,g.wrappingKey,policy.authority.publicKey,...policy.checkpointKeys.map(p=>p.publicKey),
     ...policy.recoveryAuthorities.map(p=>p.publicKey)].includes(witness.publicKey))throw denied();
  const read=()=>db.withSession('first-primary').prepare(`
    SELECT w.receipt,w.root,w.roster,w.checkpoint,a.expires_at AS expiresAt FROM roster_witness w
    JOIN genesis_admissions a ON a.tenant_id=w.tenant_id AND a.vault_id=w.vault_id
      AND a.witness_event=w.event AND a.witness_digest=w.digest AND a.attempt_digest=w.request_digest
    WHERE w.tenant_id=? AND w.vault_id=? AND w.event=1 AND w.revision=1 AND w.sequence=0 AND w.digest=?
      AND a.attempt_digest=? AND a.decision_id=? AND a.authority_key_id=? AND a.expires_at>unixepoch()
      AND NOT EXISTS(SELECT 1 FROM roster_witness n WHERE n.tenant_id=w.tenant_id AND n.vault_id=w.vault_id AND n.event>w.event)
      AND NOT EXISTS(SELECT 1 FROM recovery_revocation_witness v WHERE v.tenant_id=w.tenant_id AND v.vault_id=w.vault_id AND v.device_id=?)
      AND NOT EXISTS(SELECT 1 FROM trust_devices d WHERE d.tenant_id=w.tenant_id AND d.vault_id=w.vault_id
        AND d.device_id=? AND (d.account_id<>? OR d.signing_key<>? OR d.revoked<>0 OR d.expires_at<=unixepoch()))
      AND NOT EXISTS(SELECT 1 FROM trust_accounts t WHERE t.account_id=? AND (t.revoked<>0 OR t.expires_at<=unixepoch()))
  `).bind(g.tenantId,g.vaultId,rosterDigest,attemptDigest,decisionId,authorityKeyId,g.deviceId,g.deviceId,g.accountId,g.signingKey,g.accountId)
   .first<{receipt:string;root:string;roster:string;checkpoint:string;expiresAt:number}>();
  const row=await read();
  if(!row||row.expiresAt!==admissionExpiresAt||row.roster!==JSON.stringify(roster)||row.checkpoint!==JSON.stringify(checkpoint)||
     row.root!==await genesisRoot(g.tenantId,g.vaultId))throw denied();
  const receipt=signed(JSON.parse(row.receipt),4096);
  if(row.receipt!==JSON.stringify(receipt))throw denied();
  const w=await verifyWitness(receipt,[witness],{accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:rosterDigest},checkpoint);
  if(w.event!==1||w.sequence!==0||w.root!==row.root||JSON.stringify(await read())!==JSON.stringify(row)||now()>=validUntil)throw denied();
  return Object.freeze({nonce:bound.nonce,attemptDigest,receipt,validUntil});
 }catch{throw denied();}
}
