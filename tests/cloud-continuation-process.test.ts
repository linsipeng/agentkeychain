import {expect,test} from 'bun:test';
import {Database} from 'bun:sqlite';
import {mkdtempSync,readdirSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {URL} from "node:url";
import sodium from 'libsodium-wrappers-sumo';
import {createCloudKeys,destroyCloudKeys,sealKeyPackage} from '../src/cloud/crypto.ts';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import {selfAnchor} from '../src/cloud/enrollment.ts';
import {MemorySecureStore,type SecureAccount} from '../src/platform/secure-store.ts';
import {CloudStore} from '../src/cloud/persistence.ts';
import {canonicalGrant,requestProof} from '../managed-cloud/shared/device-protocol.ts';
import {canonicalContinuationIntent,canonicalContinuationReceipt} from '../managed-cloud/shared/enrollment-continuation.ts';
import {checkpoint,genesisRoot} from '../managed-cloud/shared/checkpoints.ts';
import {rosterDigest} from '../managed-cloud/shared/roster.ts';
import {rosterWitness} from '../managed-cloud/shared/roster-witness.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';
import {proveFreshContinuationHead,provePostCommitContinuationHead} from '../managed-cloud/shared/continuation-fresh-head.ts';
import {consumeGenesisPackageContinuation} from '../managed-cloud/api-worker/genesis-package-continuation.ts';
import {canonicalGenesisCommitProofExpectation,proveGenesisPackageCommit} from '../managed-cloud/api-worker/genesis-package-continuation-readback.ts';
import {authenticate} from '../managed-cloud/api-worker/auth.ts';

type SQL=string|number|null|Uint8Array;
/** The fixture runs actual SQL/transactions with Bun SQLite, not the Cloud D1 service. */
function adapter(db:Database){
 const prepare=(query:string)=>{
  const stmt=db.query(query);
  const bound=(args:SQL[])=>({
   first:async (column?:string)=>{const row=stmt.get(...args) as Record<string,unknown>|null;return column?row?.[column]??null:row;},
   run:async()=>stmt.run(...args),execute:()=>({results:stmt.all(...args)}),
  });
  return {...bound([]),bind:(...args:SQL[])=>bound(args)};
 };
 return {prepare,batch:async (rows:Array<{execute():unknown}>)=>db.transaction(()=>rows.map(row=>row.execute())).immediate()} as unknown as Parameters<typeof proveFreshContinuationHead>[0] & Parameters<typeof consumeGenesisPackageContinuation>[0];
}
function applySql(db:Database,dir:string){for(const f of readdirSync(dir).filter(x=>x.endsWith('.sql')).sort())db.exec(readFileSync(join(dir,f),'utf8'));}
const b64=(b:Uint8Array)=>Buffer.from(b).toString('base64');
const signedDigest=(x:{canonical:string;signature:string})=>digest(JSON.stringify([x.canonical,x.signature]));
const makeSigner=(keyId:string)=>{
 const pair=sodium.crypto_sign_keypair(),publicKey=b64(pair.publicKey),pin={keyId,publicKey};
 return {pin,key:async()=>pin,sign:async (m:string)=>b64(sodium.crypto_sign_detached(m,pair.privateKey)),clear:()=>pair.privateKey.fill(0)};
};
const random=()=>Buffer.from(sodium.randombytes_buf(32)).toString('base64url');

test('compiled synthetic continuation survives real process death before commit and before secure cleanup',async()=>{
 await sodium.ready;
 const home=mkdtempSync(join(tmpdir(),'akc-continuation-process-')),bin=join(home,'fixture-client');
 const main=new Database(':memory:'),custody=new Database(':memory:'),keys=await createCloudKeys(),secure=new MemorySecureStore();
 const root=makeSigner('release-root'),auth=makeSigner('auth'),owner=makeSigner('main-owner'),w=makeSigner('witness'),cp=makeSigner('checkpoint'),rollout=makeSigner('rollout');
 let service:ReturnType<typeof Bun.serve>|undefined;
 try{
  const compiled=await Bun.build({entrypoints:['scripts/phase45/continuation-client.ts'],compile:{outfile:bin}});
  expect(compiled.success).toBe(true);
  applySql(main,'managed-cloud/api-worker/migrations');applySql(main,'managed-cloud/api-worker/experimental');applySql(custody,'managed-cloud/recovery-worker/migrations');
  const m=adapter(main),c=adapter(custody),now=Math.floor(Date.now()/1000),apiOrigin='https://api.local.invalid';
  const canonical=canonicalManifest({version:1,releaseId:'compiled-fixture',apiOrigin,webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[cp.pin],witnessKeys:[w.pin]});
  const manifest={canonical,signature:await root.sign(canonical)},policy=verifyReleaseManifest(manifest,Buffer.from(root.pin.publicKey,'base64'));
  const pinAppendix=async(domain:string,pin:typeof owner.pin)=>{const body=JSON.stringify({version:1,domain,manifestDigest:await digest(canonical),...pin});return {canonical:body,signature:await root.sign(body)};};
  const authorityAppendix=await pinAppendix('AgentKeychain-continuation-release-pin-v1',auth.pin),commitAppendix=await pinAppendix('AgentKeychain-continuation-main-commit-release-pin-v1',owner.pin);
  const grant={version:1 as const,requestId:'orig',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,issuerDeviceId:null,signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:now-5};
  const {requestId,deviceId}=grant,oldGrantCanonical=canonicalGrant(grant);
  const roster=selfAnchor({...grant,expiresAt:now+360},keys,policy,true).signedRoster,head=await rosterDigest(roster);
  const checkpointZero=await checkpoint(cp,'t','v',0,await genesisRoot('t','v'),null,null);
  const witness=await rosterWitness(c,w,[cp.pin],async()=>true,[]).accept({rosters:[roster],checkpoints:[checkpointZero]});
  main.exec("INSERT INTO accounts VALUES('a'); INSERT INTO tenants VALUES('t'); INSERT INTO memberships VALUES('t','a',1); INSERT INTO vaults VALUES('t','v',0);");
  main.run("INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at,state,account_id,tenant_id,vault_id) VALUES(?, 'fixture-code','fixture-verify','fixture',?,?,?,'linux',?,'approved','a','t','v')",[requestId,deviceId,grant.signingKey,grant.wrappingKey,grant.expiresAt]);
  main.run("INSERT INTO devices VALUES('t',?,'a',?,1)",[deviceId,grant.signingKey]);
  main.run("INSERT INTO device_keys VALUES('t',?,?)",[deviceId,grant.wrappingKey]);
  main.run("INSERT INTO vault_devices VALUES('t','v',?,1)",[deviceId]);
  main.run("INSERT INTO enrollment_grants VALUES(?,'t','v',?,NULL,1,?,NULL)",[requestId,deviceId,oldGrantCanonical]);
  main.run("INSERT INTO signed_rosters VALUES('t','v','a',1,?,NULL,?,?,?)",[head,deviceId,roster.canonical,roster.signature]);
  main.run("UPDATE roster_witness_sagas SET state='acknowledged',receipt=? WHERE tenant_id='t' AND vault_id='v' AND revision=1",[JSON.stringify(witness)]);
  const keyPackage=sealKeyPackage(keys.vdk,{vaultId:'v',targetDeviceId:deviceId,keyEpoch:1,issuerDeviceId:deviceId,grantId:requestId},keys.wrappingPublic,keys.signingPrivate);
  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',keyPackage.canonical,keyPackage.signature]));
  const continuationId=random(),nonce=random(),targetBytes=canonicalContinuationIntent({version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id:continuationId,
   originalGrantDigest:await digest(oldGrantCanonical),requestId,accountId:'a',tenantId:'t',vaultId:'v',deviceId,keyEpoch:1,issuerDeviceId:null,
   signingKey:grant.signingKey,wrappingKey:grant.wrappingKey,stage:'put-key-package',payloadDigest,rosterDigest:head,witnessHead:{revision:1,digest:head},expiresAt:now+60});
  const deviceSign=(x:string)=>b64(sodium.crypto_sign_detached(x,keys.signingPrivate));
  const target={canonical:targetBytes,signature:deviceSign(targetBytes)},approvalBytes=canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',
   intentDigest:await digest(targetBytes),authorityKeyId:auth.pin.keyId,approvedAt:now,expiresAt:now+60});
  const approval={canonical:approvalBytes,signature:await auth.sign(approvalBytes)};
  const request={nonce,grant:oldGrantCanonical,target,approval,roster,keyPackage};
  const custodyPolicy={authority:auth.pin,witnessKeys:[w.pin],checkpointKeys:[cp.pin],recoveryAuthorities:[]};
  const prepared=await proveFreshContinuationHead(c,request,custodyPolicy,w);
  const expectation={commit:{continuationId,requestId,intentDigest:await digest(targetBytes),approvalDigest:await signedDigest(approval),payloadDigest},
   nonce,custodyFreshHeadDigest:await signedDigest(prepared.freshHead)};
  const raw=canonicalGenesisCommitProofExpectation(expectation),session=random(),sessionDigest=await digest(session),proofNonce=random(),timestamp=Math.floor(Date.now()/1000);
  main.run("INSERT INTO device_sessions VALUES(?,'t','v',?,'a',unixepoch()+600,1)",[sessionDigest,deviceId]);
  const authUrl=new URL(apiOrigin+'/isolated-fixture/main-proof');
  const httpProof=deviceSign(requestProof('POST',authUrl,await digest(raw),timestamp,proofNonce,sessionDigest));
  const scope=await authenticate(m,new Request(authUrl.href,{method:'POST',headers:{authorization:'Bearer '+session,'x-device-nonce':proofNonce,'x-device-proof':httpProof,'x-device-timestamp':String(timestamp)}}),'v',raw);
  const pins={mainCommitAuthority:owner.pin,approvalAuthority:auth.pin,witnesses:[w.pin],otherReleaseKeys:[cp.pin]};
  await expect(proveGenesisPackageCommit(m,scope,expectation,prepared,pins,owner)).rejects.toThrow('not_found');
  const consume={oldGrantCanonical,target,approval,keyPackage,witness,roster};
  await consumeGenesisPackageContinuation(m,consume,{authority:auth.pin,witnesses:[w.pin]});
  const commit=await proveGenesisPackageCommit(m,scope,expectation,prepared,pins,owner);
  const evidence={grant,target,approval,authorityAppendix,witness,roster,keyPackage,freshHead:prepared.freshHead,commitAppendix,commit};
  const rolloutAppendix=await pinAppendix('AgentKeychain-continuation-rollout-release-pin-v1',rollout.pin);
  const permit=async (scope:string,signer=rollout)=>{
   const value=JSON.stringify({version:1,domain:'AgentKeychain-continuation-rollout-capability-v1',mode:'synthetic-only',manifestDigest:await digest(canonical),
    keyId:rollout.pin.keyId,intentDigest:scope,authAppendixDigest:await signedDigest(authorityAppendix),commitAppendixDigest:await signedDigest(commitAppendix),
    witnessKeyId:w.pin.keyId,issuedAt:now,expiresAt:now+60});
   return {canonical:value,signature:await signer.sign(value)};
  };
  const signed={capability:await permit(await digest(targetBytes)),rolloutAppendix,authAppendix:authorityAppendix,commitAppendix};
  const token=random(),seen=new Set<string>();let unavailable=false,secureRequests=0;

  const accounts=new Set(['enrollment-intent','csk','signing-private','wrapping-private','roster-anchor','checkpoint-anchor','recovery-intent','recovery-anchor','refresh-credential']);
  service=Bun.serve({hostname:'127.0.0.1',port:0,async fetch(req){
   if(req.method!=='POST'||req.headers.get('authorization')!=='Bearer '+token)return new Response(null,{status:404});
   const path=new URL(req.url).pathname;
   try{
    const body=await req.json() as {nonce?:string;account?:SecureAccount;value?:string}|SecureAccount;
    if(path==='/custody/post'){
     if(unavailable||typeof body==='string'||typeof body.nonce!=='string'||seen.has(body.nonce))throw new Error();
     seen.add(body.nonce);
     return Response.json(await provePostCommitContinuationHead(c,{...request,nonce:body.nonce},prepared.freshHead,commit,
      {...custodyPolicy,mainCommitAuthority:owner.pin,otherReleaseKeys:[]},w));
    }
    secureRequests++;
    const account=typeof body==='string'?body:body.account;
    if(!account||!accounts.has(account))throw new Error();
    if(path==='/secure/get'){const value=await secure.get(account);try{return Response.json({value:value?b64(value):null});}finally{value?.fill(0);}}
    if(path==='/secure/put'&&typeof body==='object'&&typeof body.value==='string'){const value=Buffer.from(body.value,'base64');try{await secure.put(account,value);}finally{value.fill(0);}return Response.json({ok:true});}
    if(path==='/secure/remove'){await secure.remove(account);return Response.json({ok:true});}
    throw new Error();
   }catch{return new Response(null,{status:401});}
  }});
  const run=async(mode:string,extra={})=>{
   const child=Bun.spawn([bin],{cwd:home,env:{PATH:'/usr/bin:/bin',HOME:home,AGENTKEYCHAIN_HOME:home,AKC_KEYCHAIN_TEST_MODE:'1'},
    stdin:new globalThis.Blob([JSON.stringify({home,endpoint:service!.url.href,token,mode,manifest,root:root.pin.publicKey,signed,...extra})]),stdout:'pipe',stderr:'pipe'});
   const [status,output,error]=await Promise.all([child.exited,new Response(child.stdout).text(),new Response(child.stderr).text()]);
   return {status,output:output.trim(),error:error.trim()};
  };
  // Observe abandoned leases from real process death, then emulate 30 seconds
  // of lease expiry without consuming the short cryptographic proof window.
  const expireAbandonedLease=()=>{
   const db=new Database(join(home,'fixture.sqlite'));
   try{
    expect(db.query('SELECT count(*) AS n FROM cloud_enrollment_lock').get()).toEqual({n:1});
    db.run('UPDATE cloud_enrollment_lock SET expires=0');
   }finally{db.close();}
  };
  expect(await run('stage',{initialization:{keys:Object.fromEntries(Object.entries(keys).map(([k,v])=>[k,b64(v)])),nonce,evidence}})).toEqual({status:0,output:'ok',error:''});
  const beforeGate=secureRequests;
  expect(await run('unconfigured')).toMatchObject({status:1,error:'cloud_continuation_not_provisioned'});
  expect(await run('finalize',{signed:{...signed,capability:await permit(await digest(targetBytes),auth)}})).toMatchObject({status:1,error:'cloud_continuation_not_provisioned'});
  expect(secureRequests).toBe(beforeGate);
  expect(await run('finalize',{signed:{...signed,capability:await permit(await digest('foreign continuation'))}})).toMatchObject({status:1,error:'cloud_continuation_not_provisioned'});
  expect(seen.size).toBe(0);
  expect(await run('finalize',{fault:'after-checkpoint'})).toMatchObject({status:77});
  expect(await run('ready')).toMatchObject({status:1,error:'cloud_not_enrolled'});
  expect(await run('finalize')).toMatchObject({status:1,error:'cloud_enrollment_busy'});
  expireAbandonedLease();
  expect(await run('finalize',{fault:'before-cleanup'})).toMatchObject({status:78});
  expect(await run('ready')).toMatchObject({status:1,error:'cloud_enrollment_pending'});
  expireAbandonedLease();
  unavailable=true;
  expect(await run('finalize')).toMatchObject({status:1,error:'synthetic_transport_rejected'});
  expect(await run('ready')).toMatchObject({status:1,error:'cloud_enrollment_pending'});
  unavailable=false;
  expect(await run('finalize')).toEqual({status:0,output:'ok',error:''});
  expect(await run('ready')).toEqual({status:0,output:'ok',error:''});
  expect(seen.size).toBe(3);
  expect(main.query('SELECT count(*) n FROM genesis_package_continuations').get()).toEqual({n:1});
  expect(main.query('SELECT count(*) n FROM device_key_packages').get()).toEqual({n:1});
  expect(custody.query('SELECT count(*) n FROM roster_witness').get()).toEqual({n:1});
  const sqlite=new Database(join(home,'fixture.sqlite')),store=new CloudStore(sqlite,keys.csk);
  try{
   expect(store.get('state','enrollment')).toMatchObject({deviceId,signingPublic:grant.signingKey,wrappingPublic:grant.wrappingKey,vdk:b64(keys.vdk)});
   expect(store.all('pins')).toHaveLength(1);
   expect(await secure.get('enrollment-intent')).toBeNull();
  }finally{store.destroy();sqlite.close();}
 }finally{
  service?.stop(true);main.close();custody.close();destroyCloudKeys(keys);
  for(const s of [root,auth,owner,w,cp,rollout])s.clear();
  rmSync(home,{recursive:true,force:true});
 }
},30_000);
