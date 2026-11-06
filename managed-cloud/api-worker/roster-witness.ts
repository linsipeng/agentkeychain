import {checkpoint,genesisRoot,type Checkpoint,type CheckpointSigner} from '../shared/checkpoints.ts';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import {WITNESS_PAGE_SIZE,type WitnessRequest} from '../shared/roster-witness.ts';
import {rpcData} from '../shared/rpc-data.ts';
export interface WitnessRPC {head?(tenant:string,vault:string):Promise<SignedManagedOperation|null>;witness(input:WitnessRequest):Promise<SignedManagedOperation>}
export interface WitnessDatabase {prepare(sql:string):{bind(...values:unknown[]):{first<T>(field?:string):Promise<T|null>;all<T>():Promise<{results:T[]}>;run():Promise<unknown>}}}
export async function acknowledgeRoster(db:WitnessDatabase,tenant:string,vault:string,rpc:WitnessRPC,signer:CheckpointSigner){
 let priorRaw=await db.prepare("SELECT receipt FROM roster_witness_sagas WHERE tenant_id=? AND vault_id=? AND receipt IS NOT NULL ORDER BY revision DESC LIMIT 1").bind(tenant,vault).first<string>('receipt');
 let receipt:SignedManagedOperation,conflicts=0;
 for(;;){
  if(rpc.head){const current=await rpcData(rpc.head(tenant,vault));priorRaw=current?JSON.stringify(current):null;}
  const prior=priorRaw?JSON.parse(priorRaw) as SignedManagedOperation:undefined,h=prior?JSON.parse(prior.canonical) as {revision:number;sequence:number}:undefined;
  const cps=await db.prepare('SELECT canonical,signature FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? AND sequence>=? ORDER BY sequence LIMIT ?').bind(tenant,vault,h?.sequence??0,WITNESS_PAGE_SIZE).all<Checkpoint>();
  if((h?.sequence??0)===0&&(!cps.results.length||JSON.parse(cps.results[0]!.canonical).sequence!==0))cps.results.unshift(await checkpoint(signer,tenant,vault,0,await genesisRoot(tenant,vault),null,null));
  cps.results=cps.results.slice(0,WITNESS_PAGE_SIZE);
  const cpHead=await db.prepare('SELECT max(sequence) n FROM sync_checkpoints WHERE tenant_id=? AND vault_id=?').bind(tenant,vault).first<number>('n')??0;
  const caughtCheckpoint=JSON.parse(cps.results.at(-1)!.canonical).sequence===cpHead;
  const rows=await db.prepare('SELECT canonical,signature FROM signed_rosters WHERE tenant_id=? AND vault_id=? AND revision>=? ORDER BY revision LIMIT ?').bind(tenant,vault,h?.revision??1,caughtCheckpoint?WITNESS_PAGE_SIZE:1).all<SignedManagedOperation>();
  if(!rows.results.length)throw new Error('witness_missing_roster');
  try{receipt=await rpcData(rpc.witness({...(prior?{prior}:{}),rosters:rows.results,checkpoints:cps.results}));}catch(error){if(rpc.head&&error instanceof Error&&/witness_prior|witness_conflict|witness_rollback/.test(error.message)&&++conflicts<8)continue;throw error;}
  const acknowledged=JSON.parse(receipt.canonical) as {revision:number;digest:string;sequence:number};
  await db.prepare("UPDATE roster_witness_sagas SET state='acknowledged',receipt=? WHERE tenant_id=? AND vault_id=? AND revision=? AND digest=?").bind(JSON.stringify(receipt),tenant,vault,acknowledged.revision,acknowledged.digest).run();
  const latest=await db.prepare('SELECT max(revision) n FROM signed_rosters WHERE tenant_id=? AND vault_id=?').bind(tenant,vault).first<number>('n');
  if(caughtCheckpoint&&acknowledged.revision===latest)break;
  priorRaw=JSON.stringify(receipt);
 }
 // RPC returns only after Custodian commits its own monotonic record. A lost ACK
 // leaves this saga pending; retry resends exact signed history, never a head setter.
 const h=JSON.parse(receipt.canonical) as {revision:number;digest:string};
 await db.prepare("UPDATE roster_witness_sagas SET state='acknowledged',receipt=? WHERE tenant_id=? AND vault_id=? AND revision=? AND digest=?").bind(JSON.stringify(receipt),tenant,vault,h.revision,h.digest).run();return receipt;
}
