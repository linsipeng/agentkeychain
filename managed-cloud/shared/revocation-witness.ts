import {exactFields} from '../../src/cloud/protocol.ts';
import type {Checkpoint} from './checkpoints.ts';
export interface RecoveryRevocation {version:1;accountId:string;tenantId:string;vaultId:string;deviceId:string;packageId:string;actionId:string;actionCanonical:string;acceptedThrough:Checkpoint}
export function parseRecoveryRevocation(canonical:string):RecoveryRevocation{
 const r=JSON.parse(canonical) as RecoveryRevocation;
 exactFields(r,['version','accountId','tenantId','vaultId','deviceId','packageId','actionId','actionCanonical','acceptedThrough']);
 const a=JSON.parse(r.actionCanonical);
 if(r.version!==1||JSON.stringify(r)!==canonical||a[0]!==r.tenantId||a[1]!==r.accountId||a[2]!==r.deviceId||a[5]!=='Access will require recovery')throw new Error('invalid_revocation');
 return r;
}
