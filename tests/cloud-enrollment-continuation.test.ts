import {expect,test} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalContinuationIntent,canonicalContinuationReceipt,continuationIssuerProof,verifyContinuationApproval} from '../managed-cloud/shared/enrollment-continuation.ts';
import {canonicalGrant} from '../managed-cloud/shared/device-protocol.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';

async function fixture(second=false){
 await sodium.ready;
 const now=2000000000;
 const b64=(x:Uint8Array)=>Buffer.from(x).toString('base64');
 const pair=()=>sodium.crypto_sign_keypair();
 const requester=pair(), authority=pair(), issuer=pair(), extra=pair();
 const sign=(message:string,key:ReturnType<typeof pair>)=>b64(sodium.crypto_sign_detached(message,key.privateKey));
 const grant={version:1,requestId:'old-request',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'original-device',signingKey:b64(requester.publicKey),wrappingKey:b64(extra.publicKey),issuerDeviceId:second?'trusted-issuer':null,keyEpoch:7,expiresAt:now-15};
 const oldGrantCanonical=canonicalGrant(grant), stage=second?'put-key-package':'publish-roster', payloadDigest=await digest('synthetic encrypted payload'), rosterDigest=await digest('synthetic roster');
 const witnessHead=second?{revision:2,digest:rosterDigest}:null;
 const intent={version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id:'a'.repeat(43),originalGrantDigest:await digest(oldGrantCanonical),requestId:grant.requestId,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey,issuerDeviceId:grant.issuerDeviceId,keyEpoch:grant.keyEpoch,stage,payloadDigest,rosterDigest,witnessHead,expiresAt:now+60};
 const proof=async (intentPatch={},receiptPatch={})=>{
  const canonical=canonicalContinuationIntent({...intent,...intentPatch});
  const receipt=canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',intentDigest:await digest(canonical),authorityKeyId:'approval-pin',approvedAt:now-5,expiresAt:now+50,...receiptPatch});
  return {target:{canonical,signature:sign(canonical,requester)},approval:{canonical:receipt,signature:sign(receipt,authority)},issuer:{deviceId:'trusted-issuer',publicKey:b64(issuer.publicKey),signature:sign(continuationIssuerProof(receipt),issuer)}};
 };
 const context={oldGrantCanonical,stage,payloadDigest,rosterDigest,witnessHead,authority:{keyId:'approval-pin',publicKey:b64(authority.publicKey)},issuer:null,now} as const;
 return {proof,context,grant,intent,sign,requester,authority};
}
test('first device requires the original device and separate pinned authority for the exact next stage',async()=>{
 const f=await fixture(), p=await f.proof();
 await expect(verifyContinuationApproval(p.target,p.approval,f.context)).resolves.toBeUndefined();
 await expect(verifyContinuationApproval({...p.target,signature:p.approval.signature},p.approval,f.context)).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,{...p.approval,signature:f.sign(p.approval.canonical,f.requester)},{...f.context,authority:{...f.context.authority,publicKey:f.grant.signingKey}})).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,stage:'put-key-package'})).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,payloadDigest:'a'.repeat(64)})).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,rosterDigest:'a'.repeat(64)})).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,now:f.context.now+50})).rejects.toThrow();
 for(const altered of [{deviceId:'other'},{requestId:'other'},{vaultId:'other'},{tenantId:'other'},{accountId:'other'},{keyEpoch:8},{originalGrantDigest:'a'.repeat(64)},{wrappingKey:Buffer.alloc(32,1).toString('base64')}]){
  const q=await f.proof(altered);
  await expect(verifyContinuationApproval(q.target,q.approval,f.context)).rejects.toThrow();
 }
 const premature=await f.proof({},{approvedAt:f.grant.expiresAt-1});
 await expect(verifyContinuationApproval(premature.target,premature.approval,f.context)).rejects.toThrow();
 const mismatched=await f.proof({},{intentDigest:'a'.repeat(64)});
 await expect(verifyContinuationApproval(mismatched.target,mismatched.approval,f.context)).rejects.toThrow();
 expect(()=>canonicalContinuationIntent({...f.intent,revoke:true})).toThrow();
});
test('subsequent device additionally requires its unchanged trusted issuer and current witnessed roster',async()=>{
 const f=await fixture(true),p=await f.proof();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,issuer:p.issuer})).resolves.toBeUndefined();
 await expect(verifyContinuationApproval(p.target,p.approval,f.context)).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,issuer:{...p.issuer,deviceId:'other'}})).rejects.toThrow();
 await expect(verifyContinuationApproval(p.target,p.approval,{...f.context,issuer:p.issuer,witnessHead:{revision:3,digest:f.context.rosterDigest}})).rejects.toThrow();
 expect(()=>canonicalContinuationIntent({...f.intent,witnessHead:null})).toThrow();
});
