import {beforeEach,expect,test,vi} from 'vitest';
import {applyD1Migrations} from 'cloudflare:test';
import {env} from 'cloudflare:workers';
import {advanceRoot,checkpoint,genesisRoot} from '../shared/checkpoints.ts';
import {CONTINUATION_HEAD_DOMAIN,proveFreshContinuationHead} from '../shared/continuation-fresh-head.ts';
import {digest,verify} from '../shared/contracts.ts';
import {canonicalGrant,canonicalPackage} from '../shared/device-protocol.ts';
import {canonicalContinuationIntent,canonicalContinuationReceipt} from '../shared/enrollment-continuation.ts';
import {rosterDigest} from '../shared/roster.ts';
import {rosterWitness} from '../shared/roster-witness.ts';
import {enrollmentFixture,signingFixture} from './synthetic-genesis-approval.ts';

const db=env.CUSTODIAN;
const nowSeconds=()=>Math.floor(Date.now()/1000);
beforeEach(async()=>await applyD1Migrations(db,env.MIGRATIONS));

async function pending(vaultId:string){
 const now=nowSeconds(),f=await enrollmentFixture(now,vaultId),a=await signingFixture(),w=await signingFixture();
 const {accountId,tenantId,deviceId,signingKey,wrappingKey,keyEpoch,requestId}=f.grant;
 const policy={authority:{keyId:a.keyId,publicKey:a.publicKey},witnessKeys:[{keyId:w.keyId,publicKey:w.publicKey}],checkpointKeys:f.policy.checkpointKeys,recoveryAuthorities:f.policy.recoveryAuthorities};
 const wSign={key:async()=>policy.witnessKeys[0]!,sign:w.sign},apiSign={key:async()=>policy.checkpointKeys[0]!,sign:f.checkpoint.sign};
 const ledger=rosterWitness(db,wSign,policy.checkpointKeys,async()=>true,policy.recoveryAuthorities);
 const zero=await genesisRoot(tenantId,vaultId),cp=await checkpoint(apiSign,tenantId,vaultId,0,zero,null,null);
 const witness=await ledger.accept({rosters:[f.roster],checkpoints:[cp]});
 const scoped={version:1,vaultId,targetDeviceId:deviceId,issuerDeviceId:deviceId,grantId:requestId,keyEpoch,wrappedVDK:btoa('x'.repeat(64))};
 const grant=canonicalGrant({...f.grant,expiresAt:now-10});
 const build=async (packageFields= scoped,expiresAt=now+120)=>{
  const packageCanonical=canonicalPackage(packageFields),keyPackage={canonical:packageCanonical,signature:await f.device.sign(packageCanonical)};
  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',keyPackage.canonical,keyPackage.signature]));
  const head=await rosterDigest(f.roster),exact=canonicalContinuationIntent({version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id:'A'.repeat(43),
    originalGrantDigest:await digest(grant),requestId,accountId,tenantId,vaultId,deviceId,signingKey,wrappingKey,issuerDeviceId:null,keyEpoch,
    stage:'put-key-package',payloadDigest,rosterDigest:head,witnessHead:{revision:1,digest:head},expiresAt});
  const receipt=canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',intentDigest:await digest(exact),authorityKeyId:a.keyId,approvedAt:now-3,expiresAt});
  return {nonce:'A'.repeat(43),grant,roster:f.roster,keyPackage,target:{canonical:exact,signature:await f.device.sign(exact)},approval:{canonical:receipt,signature:await a.sign(receipt)}};
 };
 return {f,now,wSign,apiSign,policy,ledger,witness,cp,zero,request:await build(),build,scoped};
}
test('signs only the client-compatible short-lived envelope over the actual current Custody witness',async()=>{
 const fixture=await pending('fresh-success');
 const {witness,freshHead}=await proveFreshContinuationHead(db,fixture.request,fixture.policy,fixture.wSign);
 expect(witness).toEqual(fixture.witness);
 const {request,policy}=fixture,{issuedAt,expiresAt}=JSON.parse(freshHead.canonical);
 expect(expiresAt-issuedAt).toBe(60);
 expect(issuedAt).toBeGreaterThanOrEqual(fixture.now);
 const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',request.keyPackage.canonical,request.keyPackage.signature]));
 expect(freshHead.canonical).toEqual(JSON.stringify({domain:CONTINUATION_HEAD_DOMAIN,keyId:policy.witnessKeys[0]!.keyId,nonce:request.nonce,requestId:fixture.f.grant.requestId,
  witnessDigest:await digest(JSON.stringify([witness.canonical,witness.signature])),approvalDigest:await digest(JSON.stringify([request.approval.canonical,request.approval.signature])),payloadDigest,issuedAt,expiresAt}));
 expect(await verify(policy.witnessKeys[0]!.publicKey,freshHead.signature,freshHead.canonical)).toBe(true);
 expect(await db.prepare("SELECT count(*) n FROM roster_witness WHERE vault_id='fresh-success'").first('n')).toBe(1);
});
test('does not sign after expiry, wrong context or unavailable authority',async()=>{
 const {now,request,policy,wSign,build,scoped}=await pending('fresh-scope');
 const sign=vi.fn(wSign.sign),local={...wSign,sign};
 const expired=await build(scoped,now-1),wrongGrant=await build({...scoped,grantId:'other-grant'});
 for(const input of [expired,wrongGrant,{...request,nonce:'invalid'}]){
  await expect(proveFreshContinuationHead(db,input,policy,local)).rejects.toThrow('continuation_head_rejected');
 }
 await expect(proveFreshContinuationHead(db,request,{...policy,authority:policy.witnessKeys[0]!},local)).rejects.toThrow('continuation_head_rejected');
 expect(sign).not.toHaveBeenCalled();
});
test('does not attest a device already vetoed by Custody',async()=>{
 const {f,now,request,policy,wSign}=await pending('fresh-veto');
 const {accountId,tenantId,vaultId,deviceId,signingKey}=f.grant;
 await db.prepare('INSERT INTO trust_devices VALUES(?,?,?,?,?,1,?)').bind(accountId,tenantId,vaultId,deviceId,signingKey,now+180).run();
 await expect(proveFreshContinuationHead(db,request,policy,wSign)).rejects.toThrow('continuation_head_rejected');
});
test('withholds a signature if the Custody head advances during signing',async()=>{
 const {f,request,policy,wSign,apiSign,ledger,witness,cp,zero}=await pending('fresh-advancing');
 const sign=async (message:string)=>{
  const next=await advanceRoot(zero,1,{canonical:'synthetic-activity',signature:'synthetic'});
  const cp1=await checkpoint(apiSign,f.grant.tenantId,f.grant.vaultId,1,next.root,zero,next.operationDigest);
  await ledger.accept({prior:witness,rosters:[f.roster],checkpoints:[cp,cp1]});
  return wSign.sign(message);
 };
 await expect(proveFreshContinuationHead(db,request,policy,{...wSign,sign})).rejects.toThrow('continuation_head_rejected');
 expect(await db.prepare("SELECT count(*) n FROM roster_witness WHERE vault_id='fresh-advancing'").first('n')).toBe(2);
});
