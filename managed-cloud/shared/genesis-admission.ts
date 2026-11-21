import {base64,exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {verifyCheckpoint,type CheckpointSigner} from './checkpoints.ts';
import {digest} from './contracts.ts';
import {verifyGenesisApproval,type GenesisApprovalPolicy} from './genesis-approval.ts';
import {parseRoster} from './roster.ts';
import {WITNESS_DOMAIN,verifyWitness,type WitnessData} from './roster-witness.ts';

export interface GenesisAdmissionRequest {
 readonly proof:SignedManagedOperation;
 readonly grant:string;
 readonly roster:SignedManagedOperation;
 readonly checkpoint:SignedManagedOperation;
}

function signed(input:unknown,max:number):SignedManagedOperation{
 exactFields(input,['canonical','signature']);
 const {canonical,signature}=input;
 if(typeof canonical!=='string'||canonical.length<1||canonical.length>max)throw new Error('invalid_genesis_admission');
 base64(signature,64,64);
 return {canonical,signature};
}

/** Non-RPC, Custody-only transaction. The caller must authenticate the
 * transport and provision the two independent pins from Custody configuration.
 * Later roster updates use their existing witness-chain path. */
export async function admitGenesis(
 db:D1Database, raw:GenesisAdmissionRequest, policy:GenesisApprovalPolicy,
 witness:{readonly keyId:string;readonly publicKey:string;readonly signer:CheckpointSigner},
):Promise<SignedManagedOperation>{
 const proof=signed(raw.proof,2048),roster=signed(raw.roster,512*1024),checkpoint=signed(raw.checkpoint,4096),grant=raw.grant;
 if(typeof grant!=='string'||grant.length<1||grant.length>4096)throw new Error('invalid_genesis_admission');
 const initial=parseRoster(roster);
 const {accountId,tenantId,vaultId}=initial;
 const requestDigest=await digest(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',proof,grant,roster,checkpoint]));
 const replay=()=>db.prepare('SELECT w.receipt FROM genesis_admissions a JOIN roster_witness w ON w.tenant_id=a.tenant_id AND w.vault_id=a.vault_id AND w.event=a.witness_event AND w.digest=a.witness_digest WHERE a.tenant_id=? AND a.vault_id=? AND a.attempt_digest=?').bind(tenantId,vaultId,requestDigest).first<string>('receipt');
 const prior=await replay();
 if(prior)return JSON.parse(prior) as SignedManagedOperation;
 const approval=await verifyGenesisApproval(proof,grant,roster,policy);
 const checkpointKey=(JSON.parse(checkpoint.canonical) as {keyId?:string}).keyId;
 const checkpointPin=policy.checkpointKeys.find(k=>k.keyId===checkpointKey);
 if(!checkpointPin)throw new Error('invalid_genesis_checkpoint');
 const end=await verifyCheckpoint(checkpointPin,tenantId,vaultId,checkpoint);
 if(end.sequence!==0)throw new Error('invalid_genesis_checkpoint');

 const key=await witness.signer.key();
 if(key.keyId!==witness.keyId||key.publicKey!==witness.publicKey||key.keyId!==await digest(key.publicKey)||
    [policy.authority,...policy.checkpointKeys,...policy.recoveryAuthorities].some(k=>k.publicKey===key.publicKey)||
    initial.active.some(d=>d.signingKey===key.publicKey||d.wrappingKey===key.publicKey))throw new Error('invalid_genesis_witness');
 const {rosterDigest}=approval;
 const data:WitnessData={version:1,keyId:key.keyId,accountId,tenantId,vaultId,event:1,revision:1,digest:rosterDigest,sequence:0,root:end.root,checkpointDigest:await digest(JSON.stringify(checkpoint))};
 const canonical=JSON.stringify(data),receipt={canonical,signature:await witness.signer.sign(WITNESS_DOMAIN+canonical)};
 await verifyWitness(receipt,[key],{accountId,tenantId,vaultId,revision:1,digest:rosterDigest},checkpoint);

 try{
  const result=await db.batch([
   db.prepare('INSERT INTO roster_witness(tenant_id,vault_id,event,revision,digest,sequence,root,request_digest,roster,checkpoint,receipt,checkpoint_suffix) VALUES(?,?,1,1,?,0,?,?,?,?,?,?)').bind(tenantId,vaultId,rosterDigest,end.root,requestDigest,JSON.stringify(roster),JSON.stringify(checkpoint),JSON.stringify(receipt),JSON.stringify([checkpoint])),
   db.prepare('INSERT INTO genesis_admissions(decision_id,authority_key_id,tenant_id,vault_id,witness_event,witness_digest,attempt_digest,expires_at) VALUES(?,?,?,?,1,?,?,?)').bind(approval.decisionId,approval.authorityKeyId,tenantId,vaultId,rosterDigest,requestDigest,Math.min(approval.expiresAt,initial.expiresAt)),
  ]);
  if(!result.every(row=>row.success))throw new Error('genesis_admission_conflict');
 }catch{
  const committed=await replay();
  if(committed)return JSON.parse(committed) as SignedManagedOperation;
  throw new Error('genesis_admission_conflict');
 }
 return receipt;
}
