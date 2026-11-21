import {URL} from 'node:url';
import {webcrypto as crypto} from 'node:crypto';
import {expect,test} from 'bun:test';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {canonicalManifest} from '../src/cloud/config.ts';
import {INSTALLED_PILOT_BINARY,INSTALLED_PILOT_CONTRACT,verifyInstalledContinuationPilot} from '../src/cloud/continuation-pilot-build.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';

async function authority(){
 const key=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 if(!('publicKey' in key))throw new Error('not a signing key pair');
 const publicKey=Buffer.from(await crypto.subtle.exportKey('raw',key.publicKey)).toString('base64');
 return {publicKey,pin:{keyId:await digest(publicKey),publicKey},sign:async(canonical:string)=>({canonical,
  signature:Buffer.from(await crypto.subtle.sign('Ed25519',key.privateKey,new TextEncoder().encode(canonical))).toString('base64')})};
}

async function makeArtifact(){
 const [root,checkpoint,witness,auth,main,rollout,genesis]=await Promise.all(Array.from({length:7},authority));
 const manifest=await root!.sign(canonicalManifest({version:1,releaseId:'continuation-pilot-local-fixture',
  apiOrigin:'https://api.web-pilot-local.example.com',webOrigin:'https://web-pilot-local.example.com',protocolMin:2,protocolMax:2,
  checkpointKeys:[checkpoint!.pin],witnessKeys:[witness!.pin]}));
 const manifestDigest=await digest(manifest.canonical);
 const sign=(domain:string,value:object)=>root!.sign(JSON.stringify({version:1,domain,manifestDigest,...value}));
 const [authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix]=await Promise.all([
  sign('AgentKeychain-continuation-auth-origin-pilot-v1',{authOrigin:'https://auth-pilot-local.example.com'}),
  sign('AgentKeychain-continuation-release-pin-v1',auth!.pin),sign('AgentKeychain-continuation-main-commit-release-pin-v1',main!.pin),
  sign('AgentKeychain-continuation-rollout-release-pin-v1',rollout!.pin),
 ]);
 const signedDigest=(s:{canonical:string;signature:string})=>digest(JSON.stringify([s.canonical,s.signature]));
 const issuedAt=Math.floor(Date.now()/1000),expiresAt=issuedAt+60,target=`${process.platform}-${process.arch}`;
 const installation=await root!.sign(JSON.stringify({version:1,domain:'AgentKeychain-continuation-installed-pilot-build-v1',
  mode:'disposable-only',contract:INSTALLED_PILOT_CONTRACT,target,manifestDigest:await signedDigest(manifest),authOriginDigest:await signedDigest(authOriginAppendix),
  authPinDigest:await signedDigest(authAppendix),mainPinDigest:await signedDigest(commitAppendix),rolloutPinDigest:await signedDigest(rolloutAppendix),genesisPin:genesis!.pin,issuedAt,expiresAt}));
 const artifact={manifest,authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix,installation};
 return {artifact,root:root!,target,expiresAt,auth:auth!,main:main!,witness:witness!};
}

test('only the isolated, signed pilot artifact can compile an inert pilot installation',async()=>{
 if(!/^(linux|darwin)-(arm64|x64)$/.test(`${process.platform}-${process.arch}`))return;
 const {artifact,root,target,expiresAt}=await makeArtifact();
 const dir=await mkdtemp(join(tmpdir(),'akc-pilot-build-test-'));
 try{
  const publicPath=join(dir,'pilot-public-key'),artifactPath=join(dir,'signed.json'),bin=join(dir,INSTALLED_PILOT_BINARY);
  const env={...process.env,HOME:dir,AGENTKEYCHAIN_HOME:join(dir,'untouchable'),AKC_KEYCHAIN_TEST_MODE:'1'};
  const compile=(outfile:string)=>Bun.spawnSync([process.execPath,'scripts/build-continuation-pilot.ts','--artifact',artifactPath,
   '--root-public-key',publicPath,'--outfile',outfile],{env});
  await writeFile(publicPath,root.publicKey);
  await writeFile(artifactPath,JSON.stringify({...artifact,installation:artifact.authAppendix}));
  expect(compile(bin).exitCode).not.toBe(0);
  expect(await Bun.file(bin).exists()).toBe(false);
  await writeFile(artifactPath,JSON.stringify(artifact));
  expect(compile(join(dir,'agentkeychain')).exitCode).not.toBe(0);
  const result=compile(bin);
  expect(result.stderr.toString()).toBe('');
  expect(result.exitCode).toBe(0);
  // Proves runtime pinning does not reread build files or accept env substitution.
  await writeFile(artifactPath,JSON.stringify(null));
  await writeFile(publicPath,'runtime override forbidden');
  const check=Bun.spawnSync([bin,'check-installation'],{env});
  expect(check.exitCode).toBe(0);
  expect(JSON.parse(check.stdout.toString())).toEqual({state:'transport_unavailable',releaseId:'continuation-pilot-local-fixture',
   contract:INSTALLED_PILOT_CONTRACT,expiresAt});
  expect(Bun.spawnSync([bin,'continue-enrollment'],{env}).stderr.toString()).toBe('cloud_continuation_pilot_transport_unavailable\n');
  expect(Bun.spawnSync([bin,'check-installation','--force'],{env}).exitCode).not.toBe(0);
  expect(await Bun.file(join(dir,'untouchable','vault.db')).exists()).toBe(false);
  // Refuse to overwrite a preexisting executable, even with a valid build claim.
  await writeFile(publicPath,root.publicKey);
  await writeFile(artifactPath,JSON.stringify(artifact));
  const marker=await mkdtemp(join(dir,'occupied-')),occupied=join(marker,INSTALLED_PILOT_BINARY);
  await writeFile(occupied,'keep original');
  expect(compile(occupied).exitCode).not.toBe(0);
  expect(await readFile(occupied,'utf8')).toBe('keep original');
  await expect(verifyInstalledContinuationPilot(artifact,root.publicKey,target==='linux-x64'?'darwin-arm64':'linux-x64')).rejects.toThrow('cloud_continuation_pilot_not_provisioned');
 }finally{await rm(dir,{recursive:true,force:true});}
},45000);

test('installed transport uses independent exact origins, and only post-queries with approved staged evidence',async()=>{
 const {Database}=await import('bun:sqlite'),{MemorySecureStore}=await import('../src/platform/secure-store.ts');
 const {CloudStore}=await import('../src/cloud/persistence.ts'),{createCloudKeys,destroyCloudKeys,sealKeyPackage}=await import('../src/cloud/crypto.ts');
 const {selfAnchor}=await import('../src/cloud/enrollment.ts'),{canonicalGrant,requestProof}=await import('../managed-cloud/shared/device-protocol.ts');
 const {genesisRoot}=await import('../managed-cloud/shared/checkpoints.ts'),{rosterDigest}=await import('../managed-cloud/shared/roster.ts');
 const {WITNESS_DOMAIN}=await import('../managed-cloud/shared/roster-witness.ts'),{verify}=await import('../managed-cloud/shared/contracts.ts');
 const {verifyReleaseManifest}=await import('../src/cloud/config.ts'),{installedContinuationPilotTransport}=await import('../src/cloud/continuation-pilot-transport.ts');
 const {protectEnrollmentKeys,withContinuationEnrollmentLease,stageGenesisContinuation}=await import('../src/cloud/enrollment-intent.ts');
 const {canonicalContinuationReceipt}=await import('../managed-cloud/shared/enrollment-continuation.ts');
 const {PILOT_POST_PROOF_PATH,canonicalPilotPostProof}=await import('../managed-cloud/shared/pilot-continuation-post-wire.ts');
 const {randomBytes}=await import('node:crypto'),{default:sodium}=await import('libsodium-wrappers-sumo');
 const {artifact,root,target,auth,main,witness:signer}=await makeArtifact();
 const gate=await verifyInstalledContinuationPilot(artifact,root.publicKey,target);
 expect(()=>installedContinuationPilotTransport({...gate})).toThrow('cloud_continuation_pilot_not_provisioned');
 const policy=verifyReleaseManifest(artifact.manifest,Buffer.from(root.publicKey,'base64'));
 const db=new Database(':memory:'),secure=new MemorySecureStore(),keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);
 const b64=(v:Uint8Array)=>Buffer.from(v).toString('base64'),deviceSign=async(m:string)=>b64(sodium.crypto_sign_detached(m,keys.signingPrivate));
 const now=Math.floor(Date.now()/1000),grant={version:1 as const,requestId:'request',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'device',
  keyEpoch:1,issuerDeviceId:null,signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:now-5};
 const identity={accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,deviceId:grant.deviceId};
 const {requestId,deviceId,tenantId,vaultId}=grant,oldGrantCanonical=canonicalGrant(grant);
 const roster=selfAnchor({...grant,expiresAt:now+180},keys,policy,true).signedRoster,head=await rosterDigest(roster);
 const keyPackage=sealKeyPackage(keys.vdk,{vaultId,targetDeviceId:deviceId,keyEpoch:1,issuerDeviceId:deviceId,grantId:requestId},keys.wrappingPublic,keys.signingPrivate);
 const nonce=()=>randomBytes(32).toString('base64url'),session={...identity,token:nonce(),expiresAt:now+60,signDeviceProof:deviceSign};
 const authOrigin=JSON.parse(artifact.authOriginAppendix.canonical).authOrigin;
 const calls:string[]=[],signedDigest=(x:{canonical:string;signature:string})=>digest(JSON.stringify([x.canonical,x.signature]));
 let returnWrongOrigin=false,returnWrongProof=false;
 const network:import('../src/cloud/http.ts').CloudFetch=async(url,init)=>{
  calls.push(url);expect(init).toMatchObject({method:'POST',credentials:'omit',redirect:'error',cache:'no-store'});
  const response=(value:object,status=200)=>{const r=Response.json(value,{status});
   Object.defineProperty(r,'url',{value:returnWrongOrigin?'https://other.invalid':url});return r;};
  const body=JSON.parse(String(init.body));
  if(url.startsWith(authOrigin+'/')){
   expect(init.headers).toEqual({'content-type':'application/json'});
   if(url.endsWith('/prepare'))return response({locator:body.locator});
   expect(url.endsWith('/poll')).toBe(true);
   return response({status:'pending'},202);
  }
  expect(url).toBe(policy.apiOrigin+PILOT_POST_PROOF_PATH);
  expect(canonicalPilotPostProof(body)).toBe(String(init.body));
  expect(body.request.grant).toBe(oldGrantCanonical);
  const headers=new globalThis.Headers(init.headers);
  expect(headers.get('origin')).toBeNull();expect(headers.get('cookie')).toBeNull();
  expect(headers.get('authorization')).toBe('Bearer '+session.token);
  expect(await verify(grant.signingKey,headers.get('x-device-proof')!,requestProof('POST',new URL(url),
   await digest(String(init.body)),Number(headers.get('x-device-timestamp')),headers.get('x-device-nonce')!,await digest(session.token)))).toBe(true);
  const prior=JSON.parse(body.main.canonical);
  const proof=JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-custody-post-commit-v1',
   keyId:signer.pin.keyId,nonce:returnWrongProof?nonce():body.request.nonce,mainCommitDigest:await signedDigest(body.main),requestId,
   continuationId:prior.continuationId,...identity,keyEpoch:1,witnessDigest:prior.witnessDigest,payloadDigest:prior.payloadDigest,issuedAt:now,expiresAt:now+30});
  return response(await signer.sign(proof));
 };
 const port=installedContinuationPilotTransport(gate,network);
 try{
  await protectEnrollmentKeys(secure,keys);
  store.put('state','pending',{requestId,deviceId});store.put('state','pending-approved',{requestId,deviceId,vaultId});
  store.put('state','pending-self-roster',roster);store.put('state','pending-package',keyPackage);
  await withContinuationEnrollmentLease(store,async lease=>{
   const bound={store,secure,lease};
   await expect(port.postFromProtectedStage({...bound,nonce:nonce(),session})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(calls).toHaveLength(0);
   const local:string[]=[];
   const options={...bound,oldGrantCanonical,roster,keyPackage,displayPairCode:(code:string)=>{local.push(code);}};
   await expect(port.prepare({...options,authorizeBeforePublish:async()=>{throw new Error('closed');}})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(calls).toHaveLength(0);expect(local).toHaveLength(0);
   returnWrongOrigin=true;
   await expect(port.prepare({...options,authorizeBeforePublish:async()=>{}})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(local).toHaveLength(0);
   returnWrongOrigin=false;
   const {stage,browserUrl}=await port.prepare({...options,authorizeBeforePublish:async()=>{}});
   expect(local).toHaveLength(1);
   const locator=browserUrl.split('#handoff=')[1]!;
   expect(await port.poll({...bound,locator,stage})).toEqual({status:'pending'});
   const target=stage.target,intentDigest=await digest(target.canonical),alignment=JSON.parse(target.canonical);
   const approval=await auth.sign(canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',
    intentDigest,authorityKeyId:auth.pin.keyId,approvedAt:now,expiresAt:now+45}));
   const witnessBytes=JSON.stringify({version:1,keyId:signer.pin.keyId,accountId:identity.accountId,tenantId,vaultId,event:1,revision:1,digest:head,
    sequence:0,root:await genesisRoot(tenantId,vaultId),checkpointDigest:await digest('fixture-checkpoint')});
   const witness={canonical:witnessBytes,signature:(await signer.sign(WITNESS_DOMAIN+witnessBytes)).signature};
   const preNonce=nonce(),witnessDigest=await signedDigest(witness),approvalDigest=await signedDigest(approval),payloadDigest=alignment.payloadDigest;
   const freshHead=await signer.sign(JSON.stringify({domain:'AgentKeychain-enrollment-continuation-current-head-v1',keyId:signer.pin.keyId,
    nonce:preNonce,requestId,witnessDigest,approvalDigest,payloadDigest,issuedAt:now,expiresAt:now+40}));
   const commit=await main.sign(JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-main-commit-v1',keyId:main.pin.keyId,
    nonce:preNonce,continuationId:alignment.id,requestId,...identity,keyEpoch:1,stage:'put-key-package',intentDigest,approvalDigest,payloadDigest,
    witnessDigest,custodyFreshHeadDigest:await signedDigest(freshHead),issuedAt:now,expiresAt:now+35}));
   await stageGenesisContinuation(secure,store,policy,preNonce,{grant,target,approval,authorityAppendix:artifact.authAppendix,witness,freshHead,roster,keyPackage,
    commit,commitAppendix:artifact.commitAppendix},lease);
   await expect(port.postFromProtectedStage({...bound,nonce:nonce(),session:{...session,deviceId:'other'}})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(calls).toHaveLength(3);
   const postNonce=nonce(),proof=await port.postFromProtectedStage({...bound,nonce:postNonce,session});
   expect(JSON.parse(proof.canonical).nonce).toBe(postNonce);
   returnWrongProof=true;
   await expect(port.postFromProtectedStage({...bound,nonce:nonce(),session})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(store.get('state','enrollment')).toBeNull();
  });
 }finally{store.destroy();db.close();destroyCloudKeys(keys);}
});
