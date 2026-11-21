import {expect,test} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalGrant} from '../managed-cloud/shared/device-protocol.ts';
import {canonicalContinuationIntent} from '../managed-cloud/shared/enrollment-continuation.ts';
import {canonicalContinuationAuthReadiness,CONTINUATION_AUTH_READY_DOMAIN,verifyContinuationAuthReadiness} from '../managed-cloud/shared/continuation-auth-readiness.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest} from '../managed-cloud/shared/roster.ts';
import {WITNESS_DOMAIN} from '../managed-cloud/shared/roster-witness.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';
import {genesisRoot} from '../managed-cloud/shared/checkpoints.ts';

async function signingFixture(){
 await sodium.ready;
 const k=sodium.crypto_sign_keypair(),publicKey=Buffer.from(k.publicKey).toString('base64');
 return {keyId:await digest(publicKey),publicKey,sign:async (value:string)=>Buffer.from(sodium.crypto_sign_detached(value,k.privateKey)).toString('base64')};
}
async function enrollmentFixture(now:number){
 const [device,checkpoint]=await Promise.all([signingFixture(),signingFixture()]);
 const grant={version:1,requestId:'request',accountId:'account',tenantId:'tenant',vaultId:'vault',deviceId:'device',signingKey:device.publicKey,
  wrappingKey:Buffer.from(sodium.crypto_box_keypair().publicKey).toString('base64'),issuerDeviceId:null,keyEpoch:1,expiresAt:now+480};
 const canonical=canonicalRoster({version:1,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,revision:1,previousDigest:null,keyEpoch:1,
  active:[{deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey}],revoked:[],issuer:{kind:'device',id:grant.deviceId},
  issuedAt:now,expiresAt:now+720,checkpointKeys:[{keyId:checkpoint.keyId,publicKey:checkpoint.publicKey}],recoveryAuthorities:[],recovery:null});
 return {grant,device,roster:{canonical,signature:await device.sign(ROSTER_DOMAIN+canonical)}};
}
test('independent Auth readiness binds exact grant bytes, current witnessed genesis and short ceremony nonce',async()=>{
 const now=2_000_000_000, nonce='a'.repeat(43),f=await enrollmentFixture(now-500),custody=await signingFixture();
 const g=f.grant,oldGrantCanonical=canonicalGrant(g),grantDigest=await digest(oldGrantCanonical),head=await rosterDigest(f.roster);
 const payloadDigest=await digest('exact synthetic package');
 const w=JSON.stringify({version:1,keyId:custody.keyId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,event:1,revision:1,digest:head,sequence:0,
 root:await genesisRoot(g.tenantId,g.vaultId),checkpointDigest:await digest('checkpoint')});
 const witness={canonical:w,signature:await custody.sign(WITNESS_DOMAIN+w)};
 const t=canonicalContinuationIntent({version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id:'z'.repeat(43),originalGrantDigest:grantDigest,
 requestId:g.requestId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,keyEpoch:g.keyEpoch,deviceId:g.deviceId,signingKey:g.signingKey,wrappingKey:g.wrappingKey,
 issuerDeviceId:null,stage:'put-key-package',payloadDigest,rosterDigest:head,witnessHead:{revision:1,digest:head},expiresAt:now+50});
 const target={canonical:t,signature:await f.device.sign(t)};
 const data={version:1,domain:CONTINUATION_AUTH_READY_DOMAIN,keyId:custody.keyId,nonce,grantDigest,intentDigest:await digest(t),
 witnessDigest:await digest(JSON.stringify([w,witness.signature])),payloadDigest,rosterDigest:head,requestId:g.requestId,accountId:g.accountId,
 tenantId:g.tenantId,vaultId:g.vaultId,deviceId:g.deviceId,keyEpoch:g.keyEpoch,issuedAt:now-1,expiresAt:now+25};
 const sign=async(patch={})=>{const canonical=canonicalContinuationAuthReadiness({...data,...patch});return {canonical,signature:await custody.sign(canonical)};};
 const signed=await sign(),expected={oldGrantCanonical,target,nonce,roster:f.roster,witness,payloadDigest,witnessPins:[custody],now,requestedAt:now-2};
 await expect(verifyContinuationAuthReadiness(signed,expected)).resolves.toBeUndefined();
 for(const change of [{nonce:'b'.repeat(43)},{oldGrantCanonical:canonicalGrant({...g,expiresAt:g.expiresAt-1})},{payloadDigest:'b'.repeat(64)},{requestedAt:now},{now:now+25},{witnessPins:[f.device]}])
  await expect(verifyContinuationAuthReadiness(signed,{...expected,...change})).rejects.toThrow('invalid_continuation_auth_readiness');
 for(const change of [{accountId:'other'},{tenantId:'other'},{vaultId:'other'},{keyEpoch:2},{intentDigest:'a'.repeat(64)}])
  await expect(verifyContinuationAuthReadiness(await sign(change),expected)).rejects.toThrow('invalid_continuation_auth_readiness');
 expect(()=>canonicalContinuationAuthReadiness({...data,expiresAt:now+100})).toThrow();
});
