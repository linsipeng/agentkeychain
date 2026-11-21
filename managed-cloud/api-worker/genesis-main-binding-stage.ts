/** Unwired pilot stage adapter; creates no devices, active grants or sessions. */
import {Buffer} from 'node:buffer';
import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {genesisRoot,type CheckpointKey} from '../shared/checkpoints.ts';
import {digest} from '../shared/contracts.ts';
import {canonicalGrant} from '../shared/device-protocol.ts';
import {verifyMainGenesisBinding} from '../shared/genesis-main-binding.ts';
import type {GenesisApprovalPolicy} from '../shared/genesis-approval.ts';
import {verifyWitness} from '../shared/roster-witness.ts';

type Ports=Readonly<{
 MAIN:Pick<D1Database,'withSession'>;
 // This must be the exact private PilotCustodyGenesisBindingReadback binding.
 // Never instantiate from public request data or point at a Fetch proxy.
 PILOT_CUSTODY_GENESIS_BIND:{read(raw:string):Promise<unknown>};
}>;
type Policy=GenesisApprovalPolicy&Readonly<{witness:Readonly<CheckpointKey>}>;
const denied=()=>new Error('pilot_genesis_binding_stage_unavailable');
const now=()=>Math.floor(Date.now()/1000);
const scoped=`
 q.id=? AND q.account_id=? AND q.tenant_id=? AND q.vault_id=? AND q.device_id=?
 AND q.signing_key=? AND q.wrapping_key=? AND q.key_epoch=? AND q.expires_at=?
 AND unixepoch()>=? AND unixepoch()<?`;

/** Trusted composition only. This stages an exact existing Main account
 * relation after a short-lived Custody read; it is not cross-store atomic,
 * credential issuance, account creation, or permission to use a standard
 * device/session route. An installed-only issuer is a separate dependency. */
export async function stagePilotGenesisMainBinding(ports:Ports,policy:Policy,raw:string){
 try{
  const verified=await verifyMainGenesisBinding(raw,policy),g=verified.grant;
  const {witness}=policy;
  base64(witness.publicKey,32,32);
  if(witness.keyId!==await digest(witness.publicKey)||
     [g.signingKey,g.wrappingKey,policy.authority.publicKey,...policy.checkpointKeys.map(k=>k.publicKey),
      ...policy.recoveryAuthorities.map(k=>k.publicKey)].includes(witness.publicKey))throw denied();
  const result=await ports.PILOT_CUSTODY_GENESIS_BIND.read(raw);
  exactFields(result,['nonce','attemptDigest','receipt','validUntil']);
  const {validUntil}=result;
  if(typeof validUntil!=='number'||!Number.isSafeInteger(validUntil)||validUntil<=now()||
     validUntil>verified.validUntil||result.nonce!==verified.nonce||result.attemptDigest!==verified.attemptDigest)throw denied();
  exactFields(result.receipt,['canonical','signature']);
  if(typeof result.receipt.canonical!=='string'||Buffer.byteLength(result.receipt.canonical)>4096)throw denied();
  base64(result.receipt.signature,64,64);
  const receipt:SignedManagedOperation={canonical:result.receipt.canonical,signature:result.receipt.signature};
  const w=await verifyWitness(receipt,[witness],{accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,revision:1,digest:verified.rosterDigest},verified.checkpoint);
  if(w.event!==1||w.sequence!==0||w.root!==await genesisRoot(g.tenantId,g.vaultId)||now()>=validUntil)throw denied();
  const grant=canonicalGrant(g),custody=JSON.stringify(receipt),attempt=verified.attemptDigest;
  const tuple=[g.requestId,g.accountId,g.tenantId,g.vaultId,g.deviceId,g.signingKey,g.wrappingKey,g.keyEpoch,g.expiresAt,
   verified.requestedAt,validUntil];
  const db=ports.MAIN.withSession('first-primary');
  // D1 batch makes the CAS and readback one transaction. A same-tenant or
  // same-attempt conflict creates no new row; only exact readback can succeed.
  const [write,read]=await db.batch<{attemptDigest:string}>([
   db.prepare(`INSERT INTO pilot_genesis_main_binding_stage(tenant_id,vault_id,account_id,request_id,device_id,attempt_digest,grant,custody_receipt)
    SELECT q.tenant_id,q.vault_id,q.account_id,q.id,q.device_id,?,?,?
    FROM pilot_genesis_main_binding_eligible q WHERE ${scoped}
    AND NOT EXISTS(SELECT 1 FROM pilot_genesis_main_binding_stage p WHERE p.tenant_id=q.tenant_id OR p.request_id=q.id
      OR p.device_id=q.device_id OR p.attempt_digest=?)`).bind(attempt,grant,custody,...tuple,attempt),
   db.prepare(`SELECT p.attempt_digest AS attemptDigest FROM pilot_genesis_main_binding_stage p
    JOIN pilot_genesis_main_binding_eligible q ON q.id=p.request_id AND q.tenant_id=p.tenant_id AND q.account_id=p.account_id
      AND q.vault_id=p.vault_id AND q.device_id=p.device_id WHERE p.attempt_digest=? AND p.grant=? AND p.custody_receipt=? AND ${scoped}`)
    .bind(attempt,grant,custody,...tuple),
  ]);
  if(!write?.success||!read?.success||read.results.length!==1||read.results[0]?.attemptDigest!==attempt||now()>=validUntil)throw denied();
  return Object.freeze({state:'binding-staged-not-session' as const,attemptDigest:attempt});
 }catch{throw denied();}
}
