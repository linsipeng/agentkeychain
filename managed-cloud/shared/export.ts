import {exactFields,identifier} from '../../src/cloud/protocol.ts';
export interface ExportIntent {version:1;action:'export';requestId:string;accountId:string;tenantId:string;vaultId:string;deviceId:string;contentDigest:string;outputDigest:string;expiresAt:number}
export function canonicalExport(i:ExportIntent){
 exactFields(i,['version','action','requestId','accountId','tenantId','vaultId','deviceId','contentDigest','outputDigest','expiresAt']);
 if(i.version!==1||i.action!=='export'||!Number.isSafeInteger(i.expiresAt)||i.expiresAt<1)throw new Error('invalid_request');
 for(const k of ['requestId','accountId','tenantId','vaultId','deviceId'] as const)identifier(i[k]);
 if(!/^[a-f0-9]{64}$/.test(i.contentDigest)||!/^[a-f0-9]{64}$/.test(i.outputDigest))throw new Error('invalid_request');
 return JSON.stringify({version:1,action:'export',requestId:i.requestId,accountId:i.accountId,tenantId:i.tenantId,vaultId:i.vaultId,deviceId:i.deviceId,contentDigest:i.contentDigest,outputDigest:i.outputDigest,expiresAt:i.expiresAt});
}
