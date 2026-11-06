import {digest,verify} from './contracts.ts';
import {parseRoster,rosterDigest,verifyRoster} from './roster.ts';
import {verifyCheckpoint,type Checkpoint,type CheckpointKey,type CheckpointSigner} from './checkpoints.ts';
import {exactFields,type SignedManagedOperation} from '../../src/cloud/protocol.ts';
export const WITNESS_DOMAIN='AgentKeychain-independent-roster-witness-v1\0';
export interface WitnessData {version:1;keyId:string;accountId:string;tenantId:string;vaultId:string;event:number;revision:number;digest:string;sequence:number;root:string;checkpointDigest:string}
export const WITNESS_PAGE_SIZE=128;
export interface WitnessRequest {prior?:SignedManagedOperation;rosters:SignedManagedOperation[];checkpoints:Checkpoint[]}
interface WitnessRow {event:number;revision:number;digest:string;sequence:number;root:string;request_digest:string;roster:string;checkpoint:string;receipt:string}
export async function verifyWitness(receipt:SignedManagedOperation,pins:readonly CheckpointKey[],expected:{accountId:string;tenantId:string;vaultId:string;revision:number;digest:string},checkpoint?:Checkpoint){
 exactFields(receipt,['canonical','signature']);const d=JSON.parse(receipt.canonical) as WitnessData;
 exactFields(d,['version','keyId','accountId','tenantId','vaultId','event','revision','digest','sequence','root','checkpointDigest']);
 const pin=pins.find(p=>p.keyId===d.keyId);
 if(!pin||d.version!==1||!Number.isSafeInteger(d.event)||d.event<1||!Number.isSafeInteger(d.sequence)||d.sequence<0||Object.entries(expected).some(([k,v])=>d[k as keyof WitnessData]!==v)||!await verify(pin.publicKey,receipt.signature,WITNESS_DOMAIN+receipt.canonical))throw new Error('invalid_witness');
 if(checkpoint&&d.checkpointDigest!==await digest(JSON.stringify(checkpoint)))throw new Error('invalid_witness_checkpoint');return d;
}
/** Only Custodian owns db and signer. authorizeGenesis uses independently provisioned device trust. */
export function rosterWitness(db:{prepare(sql:string):{bind(...values:unknown[]):{first<T>():Promise<T|null>;run():Promise<unknown>}}},signer:CheckpointSigner,pins:readonly CheckpointKey[],authorizeGenesis:(roster:SignedManagedOperation)=>Promise<boolean>,recoveryPins?:readonly CheckpointKey[]){
 const head=(tenant:string,vault:string)=>db.prepare('SELECT * FROM roster_witness WHERE tenant_id=? AND vault_id=? ORDER BY event DESC LIMIT 1').bind(tenant,vault).first<WitnessRow>();
 return {
 head,
 async accept(input:WitnessRequest):Promise<SignedManagedOperation>{
  if(!input.rosters.length||input.rosters.length>WITNESS_PAGE_SIZE||!input.checkpoints.length||input.checkpoints.length>WITNESS_PAGE_SIZE)throw new Error('invalid_witness_chain');
  const last=input.rosters.at(-1)!,r=parseRoster(last),hash=await rosterDigest(last),cp=input.checkpoints.at(-1)!;
  if(JSON.stringify(r.checkpointKeys)!==JSON.stringify(pins)||(recoveryPins&&JSON.stringify(r.recoveryAuthorities)!==JSON.stringify(recoveryPins)))throw new Error('invalid_witness_pins');
  const old=await head(r.tenantId,r.vaultId),requestDigest=await digest(JSON.stringify(input));
  if(old?.request_digest===requestDigest)return JSON.parse(old.receipt);
  if(old){
   if(r.revision<old.revision)throw new Error('witness_rollback');
   if(JSON.parse(cp.canonical).sequence<old.sequence)throw new Error('witness_stale_checkpoint');
   if(!input.prior||JSON.stringify(input.prior)!==old.receipt)throw new Error('witness_prior');
   if(JSON.stringify(input.rosters[0])!==old.roster||JSON.stringify(input.checkpoints[0])!==old.checkpoint)throw new Error('witness_anchor');
  }else if(input.prior)throw new Error('witness_prior');
  for(let i=0;i<input.rosters.length;i++)await verifyRoster(input.rosters[i]!,i?input.rosters[i-1]!:null,parseRoster(input.rosters[i]!).issuedAt,i===0);
  if(old){
   const anchor=input.rosters.find(s=>parseRoster(s).revision===old.revision);
   if(r.revision<old.revision||!anchor||await rosterDigest(anchor)!==old.digest)throw new Error('witness_rollback');
  }else if(!await authorizeGenesis(input.rosters[0]!))throw new Error('witness_untrusted_genesis');
  let previous:Awaited<ReturnType<typeof verifyCheckpoint>>|undefined;
  for(const c of input.checkpoints){
   const pin=pins.find(p=>p.keyId===JSON.parse(c.canonical).keyId);if(!pin)throw new Error('invalid_witness_checkpoint');
   const next=await verifyCheckpoint(pin,r.tenantId,r.vaultId,c);
   if(previous&&(next.sequence!==previous.sequence+1||next.previousRoot!==previous.root||next.root!==await digest(JSON.stringify(['AgentKeychain-sync-chain-v1',previous.root,next.sequence,next.operationDigest]))))throw new Error('invalid_witness_checkpoint_chain');previous=next;
  }
  const end=previous!;
  if(old){const anchor=input.checkpoints.find(c=>JSON.parse(c.canonical).sequence===old.sequence);if(end.sequence<old.sequence||!anchor||JSON.parse(anchor.canonical).root!==old.root)throw new Error('witness_stale_checkpoint');}
  else if(JSON.parse(input.checkpoints[0]!.canonical).sequence!==0)throw new Error('invalid_witness_checkpoint_chain');
  for(const d of r.revoked){
   if(JSON.parse(d.acceptedThrough.canonical).sequence>end.sequence)throw new Error('invalid_witness_checkpoint');
   if(old&&!parseRoster(JSON.parse(old.roster)).revoked.some(prior=>prior.deviceId===d.deviceId)){
    const exact=JSON.stringify(d.acceptedThrough);
    if(!input.checkpoints.some(c=>JSON.stringify(c)===exact)&&old.checkpoint!==exact&&!await db.prepare('SELECT 1 FROM roster_witness w,json_each(w.checkpoint_suffix) c WHERE w.tenant_id=? AND w.vault_id=? AND c.value=? LIMIT 1').bind(r.tenantId,r.vaultId,exact).first())throw new Error('witness_revocation_boundary');
   }
  }
  if(old&&r.revision===old.revision&&hash===old.digest&&end.sequence===old.sequence){if(JSON.stringify(cp)!==old.checkpoint)throw new Error('witness_checkpoint_conflict');return JSON.parse(old.receipt);}
  const key=await signer.key(),data:WitnessData={version:1,keyId:key.keyId,accountId:r.accountId,tenantId:r.tenantId,vaultId:r.vaultId,event:(old?.event??0)+1,revision:r.revision,digest:hash,sequence:end.sequence,root:end.root,checkpointDigest:await digest(JSON.stringify(cp))};
  const canonical=JSON.stringify(data),receipt={canonical,signature:await signer.sign(WITNESS_DOMAIN+canonical)};
  await verifyWitness(receipt,[key],{accountId:r.accountId,tenantId:r.tenantId,vaultId:r.vaultId,revision:r.revision,digest:hash},cp);

  try{await db.prepare('INSERT INTO roster_witness(tenant_id,vault_id,event,revision,digest,sequence,root,request_digest,roster,checkpoint,receipt,checkpoint_suffix) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(r.tenantId,r.vaultId,data.event,r.revision,hash,end.sequence,end.root,requestDigest,JSON.stringify(last),JSON.stringify(cp),JSON.stringify(receipt),JSON.stringify(input.checkpoints)).run();}
  catch(error){const raced=await head(r.tenantId,r.vaultId);if(raced?.request_digest===requestDigest)return JSON.parse(raced.receipt);throw error;}
  return receipt;
 },
 async requireLatest(rosters:SignedManagedOperation[],checkpoint:Checkpoint){
  const last=rosters.at(-1);if(!last)throw new Error('witness_missing');const r=parseRoster(last),h=await head(r.tenantId,r.vaultId);
  if(!h||h.revision!==r.revision||h.digest!==await rosterDigest(last)||h.checkpoint!==JSON.stringify(checkpoint))throw new Error('witness_not_latest');return JSON.parse(h.receipt) as SignedManagedOperation;
 }
 };
}
/** Pair a read with the independently acknowledged head across concurrent D1 writes.
 * A bounded retry/conflict is preferable to delivering mismatched signed evidence. */
export async function consistentWitnessSnapshot<T extends {head:{revision:number;digest:string}|null}>(fetchSnapshot:()=>Promise<T>,acknowledge:()=>Promise<SignedManagedOperation>){
 await fetchSnapshot(); // Authenticate possession before asking the independent service to work.
 for(let attempt=0;attempt<8;attempt++){
  const witness=await acknowledge(),snapshot=await fetchSnapshot(),head=JSON.parse(witness.canonical) as {revision:number;digest:string};
  if(snapshot.head?.revision===head.revision&&snapshot.head.digest===head.digest)return {...snapshot,witness};
 }
 throw new Error('witness_concurrent_change');
}
