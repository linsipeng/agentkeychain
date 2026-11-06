import type {RecoveryRPC} from '../shared/recovery.ts';
import {checkpoint,genesisRoot,type Checkpoint,type CheckpointSigner} from '../shared/checkpoints.ts';
import type {RecoveryRevocation} from '../shared/revocation-witness.ts';
export async function acknowledgeLastDeviceRevocation(db:D1Database,tenant:string,device:string,rpc:RecoveryRPC,signer:CheckpointSigner){
 const rows=(await db.prepare('SELECT a.id,a.account_id,a.canonical,l.vault_id,l.package_id,b.sequence FROM last_device_revocations l JOIN device_actions a ON a.id=l.action_id JOIN device_revocation_boundaries b ON b.tenant_id=a.tenant_id AND b.device_id=a.target AND b.vault_id=l.vault_id WHERE a.tenant_id=? AND a.target=?').bind(tenant,device).all<{id:string;account_id:string;canonical:string;vault_id:string;package_id:string;sequence:number}>()).results;
 for(const row of rows){
  if(!rpc.witnessRevocation)throw new Error('witness_unavailable');
  const cp=row.sequence===0?await checkpoint(signer,tenant,row.vault_id,0,await genesisRoot(tenant,row.vault_id),null,null):await db.prepare('SELECT canonical,signature FROM sync_checkpoints WHERE tenant_id=? AND vault_id=? AND sequence=?').bind(tenant,row.vault_id,row.sequence).first<Checkpoint>();
  if(!cp)throw new Error('witness_missing_checkpoint');
  const canonical=JSON.stringify({version:1,accountId:row.account_id,tenantId:tenant,vaultId:row.vault_id,deviceId:device,packageId:row.package_id,actionId:row.id,actionCanonical:row.canonical,acceptedThrough:cp} satisfies RecoveryRevocation);
  await rpc.witnessRevocation(canonical);
 }
}
