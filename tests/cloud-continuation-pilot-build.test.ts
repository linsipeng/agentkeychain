import {URL} from 'node:url';
import {TextEncoder} from 'node:util';
import {webcrypto as crypto} from 'node:crypto';
import {expect,test} from 'bun:test';
import {mkdtemp,readFile,rm,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {canonicalManifest} from '../src/cloud/config.ts';
import {INSTALLED_PILOT_BINARY,INSTALLED_PILOT_CONTRACT,INSTALLED_PILOT_NATIVE_READER_ABI,
 installedContinuationPilotNativeReaderScope,verifyInstalledContinuationPilot} from '../src/cloud/continuation-pilot-build.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';
import {beginNativeInspectVerification,NATIVE_INSPECT_REPLY,verifyNativeInspectObservation} from '../src/cloud/continuation-pilot-native-inspect.ts';
import {parsePilotBrokerRequest} from '../src/cloud/pilot-broker-wire.ts';

async function authority(){
 const key=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 if(!('publicKey' in key))throw new Error('not a signing key pair');
 const publicKey=Buffer.from(await crypto.subtle.exportKey('raw',key.publicKey)).toString('base64');
 return {publicKey,pin:{keyId:await digest(publicKey),publicKey},sign:async(canonical:string)=>({canonical,
  signature:Buffer.from(await crypto.subtle.sign('Ed25519',key.privateKey,new TextEncoder().encode(canonical))).toString('base64')})};
}

async function makeArtifact(target=`${process.platform}-${process.arch}`){
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
 const issuedAt=Math.floor(Date.now()/1000),expiresAt=issuedAt+60;
 const installation=await root!.sign(JSON.stringify({version:1,domain:'AgentKeychain-continuation-installed-pilot-build-v1',
  mode:'disposable-only',contract:INSTALLED_PILOT_CONTRACT,target,manifestDigest:await signedDigest(manifest),authOriginDigest:await signedDigest(authOriginAppendix),
  authPinDigest:await signedDigest(authAppendix),mainPinDigest:await signedDigest(commitAppendix),rolloutPinDigest:await signedDigest(rolloutAppendix),genesisPin:genesis!.pin,issuedAt,expiresAt}));
 const artifact={manifest,authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix,installation};
 return {artifact,root:root!,target,expiresAt,auth:auth!,main:main!,witness:witness!,rollout:rollout!};
}

async function makeNativeClaim(artifact:Awaited<ReturnType<typeof makeArtifact>>['artifact'],target:string,
 readerPin:{keyId:string;publicKey:string},expiresAt:number){
 const {issuedAt}=JSON.parse(artifact.installation.canonical) as {issuedAt:number};
 return {version:1,domain:'AgentKeychain-installed-continuation-pilot-native-reader-v1',
  installationDigest:await digest(JSON.stringify([artifact.installation.canonical,artifact.installation.signature])),target,
  nativeImageSha256:'a'.repeat(64),abi:INSTALLED_PILOT_NATIVE_READER_ABI,readerPin,issuedAt,expiresAt} as const;
}

test('native read pin is root-only, exact installation, role, target, ABI and time bound',async()=>{
 const {artifact,root,target,expiresAt,rollout,auth}=await makeArtifact('linux-x64'),reader=await authority();
 const claim=await makeNativeClaim(artifact,target,reader.pin,expiresAt);
 const open=(nativeReaderAppendix:unknown)=>verifyInstalledContinuationPilot(
  {...artifact,nativeReaderAppendix} as typeof artifact,root.publicKey,target);
 const positive=await open(await root.sign(JSON.stringify(claim)));
 expect(installedContinuationPilotNativeReaderScope(positive)).toEqual({installationDigest:claim.installationDigest,target,
  nativeImageSha256:claim.nativeImageSha256,abi:claim.abi,readerPin:reader.pin,expiresAt});
 expect(()=>installedContinuationPilotNativeReaderScope({...positive})).toThrow('cloud_continuation_pilot_not_provisioned');
 const legacy=await verifyInstalledContinuationPilot(artifact,root.publicKey,target);
 expect(()=>installedContinuationPilotNativeReaderScope(legacy)).toThrow('cloud_continuation_pilot_not_provisioned');
 for(const fields of [{installationDigest:'b'.repeat(64)},{target:'linux-arm64'},{nativeImageSha256:'A'.repeat(64)},
  {abi:'other'},{readerPin:auth.pin},{readerPin:root.pin},{expiresAt:expiresAt+1},{expiresAt:claim.issuedAt},{extra:true}]){
  await expect(open(await root.sign(JSON.stringify({...claim,...fields})))).rejects.toThrow('cloud_continuation_pilot_not_provisioned');
 }
 await expect(open(await rollout.sign(JSON.stringify(claim)))).rejects.toThrow('cloud_continuation_pilot_not_provisioned');
 await expect(open(null)).rejects.toThrow('cloud_continuation_pilot_not_provisioned');
});

test('native inspect authenticates only a one-use correlated metadata response',async()=>{
 const {artifact,root,target,expiresAt,rollout}=await makeArtifact('linux-x64'),reader=await authority();
 const claim=await makeNativeClaim(artifact,target,reader.pin,expiresAt);
 const gate=await verifyInstalledContinuationPilot({...artifact,nativeReaderAppendix:await root.sign(JSON.stringify(claim))},root.publicKey,target);
 const profile='c'.repeat(64),begin=()=>beginNativeInspectVerification(gate,profile),encode=(s:string)=>new TextEncoder().encode(s);
 const replyValue=async(ticket:ReturnType<typeof begin>,override:object={})=>{
  const request=JSON.parse(ticket.request) as {nonce:string;wire:object;issuedAt:number};
  expect(parsePilotBrokerRequest(JSON.stringify(request.wire))).toEqual({version:1,op:'inspect',profileDigest:profile});
  return {version:1,domain:NATIVE_INSPECT_REPLY,keyId:reader.pin.keyId,abi:claim.abi,
   installationDigest:claim.installationDigest,profileDigest:profile,nonce:request.nonce,requestDigest:await digest(ticket.request),
   observedAt:request.issuedAt,status:'snapshot-present',...override};
 };
 const response=async(ticket:ReturnType<typeof begin>,override:object={},signer=reader)=>
  encode(JSON.stringify(await signer.sign(JSON.stringify(await replyValue(ticket,override)))));
 const fail='cloud_continuation_pilot_native_inspect_denied',first=begin(),frame=await response(first);
 await expect(verifyNativeInspectObservation({...first},frame)).rejects.toThrow(fail);
 expect(await verifyNativeInspectObservation(first,frame)).toEqual({status:'snapshot-present'});
 await expect(verifyNativeInspectObservation(first,frame)).rejects.toThrow(fail);
 await expect(verifyNativeInspectObservation(begin(),frame)).rejects.toThrow(fail);
 for(const override of [{installationDigest:'d'.repeat(64)},{profileDigest:'d'.repeat(64)},{abi:'other'},
  {requestDigest:'d'.repeat(64)},{status:'active'},{receipt:{}},{observedAt:expiresAt+1}]){
  const ticket=begin();await expect(verifyNativeInspectObservation(ticket,await response(ticket,override))).rejects.toThrow(fail);
 }
 const wrongRole=begin();
 await expect(verifyNativeInspectObservation(wrongRole,await response(wrongRole,{},rollout))).rejects.toThrow(fail);
 const noncanonical=begin();
 const pretty=await reader.sign(JSON.stringify(await replyValue(noncanonical),null,1));
 await expect(verifyNativeInspectObservation(noncanonical,encode(JSON.stringify(pretty)))).rejects.toThrow(fail);
 const duplicate=begin();
 const repeated=await reader.sign('{"version":1,'+JSON.stringify(await replyValue(duplicate)).slice(1));
 await expect(verifyNativeInspectObservation(duplicate,encode(JSON.stringify(repeated)))).rejects.toThrow(fail);
 const invalid=begin(),valid=await response(invalid);
 await expect(verifyNativeInspectObservation(invalid,new Uint8Array([0xff]))).rejects.toThrow(fail);
 await expect(verifyNativeInspectObservation(invalid,valid)).rejects.toThrow(fail);
 const empty=begin();
 expect(await verifyNativeInspectObservation(empty,await response(empty,{status:'empty'}))).toEqual({status:'empty'});
 const journal=begin();
 expect(await verifyNativeInspectObservation(journal,await response(journal,{status:'rollback-journal-present'})))
  .toEqual({status:'rollback-journal-present'});
});

test('only the isolated, signed pilot artifact can compile an inert pilot installation',async()=>{
 if(!/^(linux|darwin)-(arm64|x64)$/.test(`${process.platform}-${process.arch}`))return;
 const {artifact,root,target,expiresAt}=await makeArtifact();
 const dir=await mkdtemp(join(tmpdir(),'akc-pilot-build-test-'));
 try{
  const publicPath=join(dir,'pilot-public-key'),artifactPath=join(dir,'signed.json'),bin=join(dir,INSTALLED_PILOT_BINARY);
  const env={...process.env,HOME:dir,XDG_CONFIG_HOME:join(dir,'config'),XDG_DATA_HOME:join(dir,'data'),
   XDG_CACHE_HOME:join(dir,'cache'),DBUS_SESSION_BUS_ADDRESS:'unix:path='+join(dir,'no-bus'),
   AGENTKEYCHAIN_HOME:join(dir,'untouchable'),AKC_KEYCHAIN_TEST_MODE:'1'};
  const compile=(outfile:string)=>Bun.spawnSync([process.execPath,'scripts/build-continuation-pilot.ts','--artifact',artifactPath,
   '--root-public-key',publicPath,'--outfile',outfile],{env});
  await writeFile(publicPath,root.publicKey);
  await writeFile(artifactPath,JSON.stringify({...artifact,installation:artifact.authAppendix}));
  expect(compile(bin).exitCode).not.toBe(0);
  expect(await Bun.file(bin).exists()).toBe(false);
  const realArtifact=join(dir,'real-signed.json');
  await writeFile(realArtifact,JSON.stringify(artifact));
  await rm(artifactPath);
  await symlink(realArtifact,artifactPath);
  expect(compile(bin).exitCode).not.toBe(0);
  expect(await Bun.file(bin).exists()).toBe(false);
  await rm(artifactPath);
  const fifo=Bun.spawnSync(['mkfifo',artifactPath],{env,timeout:5000});
  expect(fifo.exitCode).toBe(0);
  const rejected=await Bun.spawn([process.execPath,'scripts/build-continuation-pilot.ts','--artifact',artifactPath,
   '--root-public-key',publicPath,'--outfile',bin],{env,stdout:'ignore',stderr:'ignore',timeout:5000}).exited;
  // Timeout termination (143) must not be mistaken for semantic rejection.
  expect(rejected).toBe(1);
  expect(await Bun.file(bin).exists()).toBe(false);
  await rm(artifactPath);
  const nativeClaim=await makeNativeClaim(artifact,target,(await authority()).pin,expiresAt);
  await writeFile(artifactPath,JSON.stringify({...artifact,nativeReaderAppendix:await root.sign(JSON.stringify({...nativeClaim,abi:'wrong'}))}));
  expect(compile(bin).exitCode).not.toBe(0);
  expect(await Bun.file(bin).exists()).toBe(false);
  await writeFile(artifactPath,JSON.stringify({...artifact,nativeReaderAppendix:await root.sign(JSON.stringify(nativeClaim))}));
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
 const {protectEnrollmentKeys,withContinuationEnrollmentLease}=await import('../src/cloud/enrollment-intent.ts');
 const {canonicalContinuationReceipt}=await import('../managed-cloud/shared/enrollment-continuation.ts');
 const {PILOT_POST_PROOF_PATH,canonicalPilotPostProof,PILOT_PREFLIGHT_PATH,PILOT_COMMIT_PATH,pilotPreflightInput,pilotCommitInput}=await import('../managed-cloud/shared/pilot-continuation-post-wire.ts');
 const {randomBytes}=await import('node:crypto'),{default:sodium}=await import('libsodium-wrappers-sumo');
 const {artifact,root,target,auth,main,witness:signer,rollout}=await makeArtifact();
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
 const commitBodies:string[]=[],requestNonces=new Set<string>();

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
  const path=new URL(url).pathname;
  expect(url).toBe(policy.apiOrigin+path);
  expect(path===PILOT_POST_PROOF_PATH?canonicalPilotPostProof(body):
   JSON.stringify(path===PILOT_PREFLIGHT_PATH?pilotPreflightInput(body):pilotCommitInput(body))).toBe(String(init.body));
  expect(body.request.grant).toBe(oldGrantCanonical);
  const headers=new globalThis.Headers(init.headers);
  expect(headers.get('origin')).toBeNull();expect(headers.get('cookie')).toBeNull();
  expect(headers.get('authorization')).toBe('Bearer '+session.token);
  expect(await verify(grant.signingKey,headers.get('x-device-proof')!,requestProof('POST',new URL(url),
   await digest(String(init.body)),Number(headers.get('x-device-timestamp')),headers.get('x-device-nonce')!,await digest(session.token)))).toBe(true);
  const httpNonce=headers.get('x-device-nonce')!;
  expect(requestNonces.has(httpNonce)).toBe(false);requestNonces.add(httpNonce);
  if(path===PILOT_PREFLIGHT_PATH){
   const witnessBytes=JSON.stringify({version:1,keyId:signer.pin.keyId,accountId:identity.accountId,tenantId,vaultId,event:1,revision:1,digest:head,
    sequence:0,root:await genesisRoot(tenantId,vaultId),checkpointDigest:await digest('fixture-checkpoint')});
   const witness={canonical:witnessBytes,signature:(await signer.sign(WITNESS_DOMAIN+witnessBytes)).signature};
   const freshHead=await signer.sign(JSON.stringify({domain:'AgentKeychain-enrollment-continuation-current-head-v1',keyId:signer.pin.keyId,
    nonce:body.request.nonce,requestId,witnessDigest:await signedDigest(witness),approvalDigest:await signedDigest(body.request.approval),
    payloadDigest:JSON.parse(body.request.target.canonical).payloadDigest,issuedAt:now,expiresAt:now+40}));
   return response({witness,freshHead});
  }
  if(path===PILOT_COMMIT_PATH){
   commitBodies.push(String(init.body));
   if(commitBodies.length===1)throw new Error('test_lost_commit_response');
   const target=JSON.parse(body.request.target.canonical);
   const commit=await main.sign(JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-main-commit-v1',keyId:main.pin.keyId,
    nonce:body.request.nonce,continuationId:target.id,requestId,...identity,keyEpoch:1,stage:'put-key-package',
    intentDigest:await digest(body.request.target.canonical),approvalDigest:await signedDigest(body.request.approval),payloadDigest:target.payloadDigest,
    witnessDigest:await signedDigest(body.witness),custodyFreshHeadDigest:await signedDigest(body.freshHead),issuedAt:now,expiresAt:now+35}));
   return response(commit);
  }
  expect(path).toBe(PILOT_POST_PROOF_PATH);
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
  const stage=await withContinuationEnrollmentLease(store,async lease=>{
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
   return stage;
  });
  const intentDigest=await digest(stage.target.canonical);
  const approval=await auth.sign(canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',
   intentDigest,authorityKeyId:auth.pin.keyId,approvedAt:now,expiresAt:now+45}));
  const permit=await rollout.sign(JSON.stringify({version:1,domain:'AgentKeychain-installed-continuation-pilot-commit-v1',keyId:rollout.pin.keyId,
   installationDigest:await signedDigest(artifact.installation),intentDigest,approvalDigest:await signedDigest(approval),issuedAt:now,expiresAt:now+35}));
  const input={stage,approval,permit,secure,store,session};
  await expect(port.commitApprovedStage({...input,permit:{...permit,signature:approval.signature}})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
  expect(calls).toHaveLength(3);
  await expect(port.commitApprovedStage(input)).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
  expect(calls.slice(3)).toEqual([policy.apiOrigin+PILOT_PREFLIGHT_PATH,policy.apiOrigin+PILOT_COMMIT_PATH]);
  const reopened=new CloudStore(db,keys.csk);
  try{
   const resume=installedContinuationPilotTransport(gate,network);
   expect(await resume.commitApprovedStage({...input,store:reopened})).toBe('commit-verified-not-active');
  }finally{reopened.destroy();}
  expect(commitBodies).toHaveLength(2);
  expect(commitBodies[0]).toBe(commitBodies[1]);
  expect(calls.slice(5)).toEqual([policy.apiOrigin+PILOT_COMMIT_PATH,policy.apiOrigin+PILOT_POST_PROOF_PATH]);
  await withContinuationEnrollmentLease(store,async lease=>{
   const bound={store,secure,lease};
   await expect(port.postFromProtectedStage({...bound,nonce:nonce(),session:{...session,deviceId:'other'}})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(calls).toHaveLength(7);
   const postNonce=nonce(),proof=await port.postFromProtectedStage({...bound,nonce:postNonce,session});
   expect(JSON.parse(proof.canonical).nonce).toBe(postNonce);
   returnWrongProof=true;
   await expect(port.postFromProtectedStage({...bound,nonce:nonce(),session})).rejects.toThrow('cloud_continuation_pilot_transport_unavailable');
   expect(store.get('state','enrollment')).toBeNull();
  });
 }finally{store.destroy();db.close();destroyCloudKeys(keys);}
});

test('isolated pilot location requires the signed directory identity and refuses existing profile data',async()=>{
 if(process.platform!=='linux'||!process.getuid?.())return;
 const {chmodSync,lstatSync,mkdirSync,realpathSync,renameSync,symlinkSync}=await import('node:fs');
 const {inspectInstalledPilotLocation}=await import('../src/cloud/continuation-pilot-location.ts');
 const {artifact,root,target,rollout,expiresAt}=await makeArtifact();
 const gate=await verifyInstalledContinuationPilot(artifact,root.publicKey,target);
 const base=realpathSync.native(await mkdtemp(join(tmpdir(),'akc-pilot-location-')));
 try{
  const path=join(base,'agentkeychain-pilot-case'),uid=process.getuid(),issuedAt=Math.floor(Date.now()/1000);
  mkdirSync(path,{mode:0o700});
  const stat=lstatSync(path,{bigint:true}),installationDigest=await digest(JSON.stringify([artifact.installation.canonical,artifact.installation.signature]));
  const input={version:1,domain:'AgentKeychain-installed-continuation-pilot-location-v1',keyId:rollout.pin.keyId,
   installationDigest,path,uid,device:stat.dev.toString(),inode:stat.ino.toString(),issuedAt,expiresAt};
  const signed=await rollout.sign(JSON.stringify(input)),check=()=>inspectInstalledPilotLocation(gate,signed);
  const result=await check();
  expect(result).toMatchObject({state:'empty-disposable-directory',expiresAt});
  expect(result.namespace).toMatch(/^agentkeychain\.pilot\.[a-f0-9]{64}$/);
  expect(await check()).toEqual(result);
  const reject='cloud_continuation_pilot_location_unavailable';
  await expect(inspectInstalledPilotLocation({...gate},signed)).rejects.toThrow(reject);
  for(const change of [{path:join(base,'.agentkeychain')},{installationDigest:'f'.repeat(64)},{uid:uid+1},
   {expiresAt:issuedAt-1},{inode:'123'}]){
   await expect(inspectInstalledPilotLocation(gate,await rollout.sign(JSON.stringify({...input,...change})))).rejects.toThrow(reject);
  }
  const other=await root.sign(signed.canonical);
  await expect(inspectInstalledPilotLocation(gate,other)).rejects.toThrow(reject);
  chmodSync(base,0o777);
  await expect(check()).rejects.toThrow(reject);
  chmodSync(base,0o700);chmodSync(path,0o750);
  await expect(check()).rejects.toThrow(reject);
  chmodSync(path,0o700);
  const marker=join(path,'vault.db');
  await writeFile(marker,'do not touch');
  await expect(check()).rejects.toThrow(reject);
  expect(await readFile(marker,'utf8')).toBe('do not touch');
  await rm(marker);
  const original=join(base,'relocated');
  renameSync(path,original);symlinkSync(original,path);
  await expect(check()).rejects.toThrow(reject);
  await rm(path);
  mkdirSync(path,{mode:0o700});
  await expect(check()).rejects.toThrow(reject);
 }finally{await rm(base,{force:true,recursive:true});}
});

test('Darwin scoped native candidate accepts only a same-install signed helper hash and exact immutable fixture grant',async()=>{
 const {DARWIN_NATIVE_LOCATION_DOMAIN,DARWIN_NATIVE_HELPER_DOMAIN,verifyDarwinPilotNativeInputs,darwinPilotNativeTrustSwift}=await import('../src/cloud/continuation-pilot-darwin-check.ts');
 const {artifact,root,rollout,target,expiresAt}=await makeArtifact('darwin-arm64');
 const gate=await verifyInstalledContinuationPilot(artifact,root.publicKey,target);
 const sorted=(v:Record<string,unknown>)=>JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0)));
 const installationDigest=await digest(JSON.stringify([artifact.installation.canonical,artifact.installation.signature]));
 const common={version:1,installationDigest,keyId:rollout.pin.keyId,issuedAt:expiresAt-60,expiresAt},directory='/private/tmp/akc-pilot-native-'+'f'.repeat(32);
 const uid=1001,directoryDevice='1',directoryInode='2',fileDevice='1',fileInode='3',sha='a'.repeat(64);
 const namespace='agentkeychain.pilot.'+await digest(JSON.stringify([DARWIN_NATIVE_LOCATION_DOMAIN,installationDigest,directory,String(uid),directoryDevice,directoryInode]));
 const locationBody={...common,domain:DARWIN_NATIVE_LOCATION_DOMAIN,directory,directoryDevice,directoryInode,fileDevice,fileInode,uid,namespace};
 const helperBody={...common,domain:DARWIN_NATIVE_HELPER_DOMAIN,target,helperSha256:sha};
 const location=await rollout.sign(sorted(locationBody)),helperAppendix=await rollout.sign(sorted(helperBody));
 const input={location,helperAppendix,examinedHelperSha256:sha,target,uid};
 const checked=await verifyDarwinPilotNativeInputs(gate,input);
 expect(JSON.parse(checked.nativeInput)).toEqual(location);
 expect(checked.expectedStatus).toBe('scoped-native-location-verified-not-active');
 expect(darwinPilotNativeTrustSwift(gate)).toContain(JSON.stringify(rollout.pin.publicKey));
 for(const change of [{target:'darwin-x64'},{target:'linux-x64'},{examinedHelperSha256:'b'.repeat(64)},{uid:0},{uid:1002},
  {now:expiresAt},{helperAppendix:await root.sign(helperAppendix.canonical)},{location:await root.sign(location.canonical)}]){
  await expect(verifyDarwinPilotNativeInputs(gate,{...input,...change})).rejects.toThrow('darwin_pilot_native_candidate_denied');
 }
 for(const change of [{directory:directory.replace('/private','')},{fileInode:'0'},{fileDevice:'9'},
  {namespace:'agentkeychain.vault'},{installationDigest:'b'.repeat(64)},{file:'login.keychain-db'}]){
  const wrong=await rollout.sign(sorted({...locationBody,...change}));
  await expect(verifyDarwinPilotNativeInputs(gate,{...input,location:wrong})).rejects.toThrow('darwin_pilot_native_candidate_denied');
 }
 await expect(verifyDarwinPilotNativeInputs({...gate},input)).rejects.toThrow('darwin_pilot_native_candidate_denied');
});

test('Darwin package index binds exact staged bytes to this pilot, not Apple publisher provenance',async()=>{
 const {createHash}=await import('node:crypto');
 const {DARWIN_PILOT_PACKAGE_DOMAIN,DARWIN_PILOT_NATIVE_BINARY,DARWIN_PILOT_CLI_IDENTIFIER,
  DARWIN_PILOT_NATIVE_IDENTIFIER,verifyDarwinPilotPackageStaging}=await import('../src/cloud/continuation-pilot-darwin-package.ts');
 const target='darwin-arm64' as const,publisherTeamId='SYNTHETIC1',policy={target,publisherTeamId};
 const {artifact,root,expiresAt}=await makeArtifact(target);
 const cli=Buffer.from('synthetic CLI image'),native=Buffer.from('synthetic native image');
 const payloads={[INSTALLED_PILOT_BINARY]:cli,[DARWIN_PILOT_NATIVE_BINARY]:native};
 const sha=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
 const issuedAt=Math.floor(Date.now()/1000);
 const claim={version:1,domain:DARWIN_PILOT_PACKAGE_DOMAIN,mode:'disposable-only',
  installationDigest:await digest(JSON.stringify([artifact.installation.canonical,artifact.installation.signature])),
  target,publisherTeamId,cliIdentifier:DARWIN_PILOT_CLI_IDENTIFIER,cliSha256:sha(cli),
  nativeIdentifier:DARWIN_PILOT_NATIVE_IDENTIFIER,nativeSha256:sha(native),issuedAt,expiresAt};
 const index=await root.sign(JSON.stringify(claim));
 const check=(next=index,files:unknown=payloads,expected=policy)=>
  verifyDarwinPilotPackageStaging(artifact,root.publicKey,next,expected,files);
 const verified=await check();
 expect(verified.state).toBe('staged-bytes-match-signed-index-not-authorized');
 expect(Object.isFrozen(verified)).toBe(true);
 const denied='darwin_pilot_package_denied';
 await expect(check(index,{...payloads,agentkeychain:cli})).rejects.toThrow(denied);
 await expect(check(index,{...payloads,[DARWIN_PILOT_NATIVE_BINARY]:Buffer.from('changed')})).rejects.toThrow(denied);
 await expect(check(index,payloads,{...policy,publisherTeamId:'DIFFERENT1'})).rejects.toThrow(denied);
 await expect(check(await root.sign(JSON.stringify({...claim,expiresAt:issuedAt-1})))).rejects.toThrow(denied);
 await expect(check(await root.sign(JSON.stringify({...claim,expiresAt:expiresAt+1})))).rejects.toThrow(denied);
 await expect(check(await root.sign(JSON.stringify({...claim,installationDigest:'0'.repeat(64)})))).rejects.toThrow(denied);
 await expect(check(await root.sign(JSON.stringify({...claim,nativeIdentifier:DARWIN_PILOT_CLI_IDENTIFIER})))).rejects.toThrow(denied);
 await expect(check(await (await authority()).sign(JSON.stringify(claim)))).rejects.toThrow(denied);
 await expect(check(await root.sign(JSON.stringify(claim,null,2)))).rejects.toThrow(denied);
});

test('offline pilot smoke installs the actual synthetic candidate only into the alternate directory',async()=>{
 if(process.platform!=='linux'||!process.getuid?.()||!['x64','arm64'].includes(process.arch))return;
 const {admitDisposablePilotPackage,offlineDomain}=await import('./native/pilot_offline_package.ts');
 const {mkdir,lstat,rename,open}=await import('node:fs/promises');
 const {createHash}=await import('node:crypto');
 const {installedContinuationPilotScope}=await import('../src/cloud/continuation-pilot-build.ts');
 const {artifact,root,target,rollout,expiresAt}=await makeArtifact();
 const gate=await verifyInstalledContinuationPilot(artifact,root.publicKey,target),scope=installedContinuationPilotScope(gate);
 const dir=await mkdtemp('/tmp/akc-offline-pilot-');
 try{
  const inbox=join(dir,'offline'),alternate=join(dir,'alternate'),home=join(dir,'home');
  for(const folder of [inbox,alternate,home])await mkdir(folder,{mode:0o700});
  const ordinary=join(home,'.agentkeychain'),defaultInstall=join(home,'.local','bin');
  await mkdir(ordinary,{mode:0o700});await mkdir(defaultInstall,{recursive:true,mode:0o700});
  const marker=join(ordinary,'vault.db'),ordinaryBin=join(defaultInstall,'agentkeychain');
  await writeFile(marker,'ordinary fixture untouched',{flag:'wx'});await writeFile(ordinaryBin,'ordinary binary untouched',{flag:'wx'});
  const binary=join(inbox,INSTALLED_PILOT_BINARY),material=join(dir,'artifact.json'),rootFile=join(dir,'root.pub');
  await writeFile(material,JSON.stringify(artifact));await writeFile(rootFile,root.publicKey);
  const env={PATH:'/usr/bin:/bin',HOME:home,XDG_CONFIG_HOME:join(dir,'config'),XDG_DATA_HOME:join(dir,'data'),XDG_CACHE_HOME:join(dir,'cache'),
   DBUS_SESSION_BUS_ADDRESS:'unix:path='+join(dir,'not-a-bus')};
  const build=Bun.spawnSync([process.execPath,'scripts/build-continuation-pilot.ts','--artifact',material,'--root-public-key',rootFile,'--outfile',binary],{env,timeout:30000});
  expect(build.exitCode).toBe(0);
  const clock=Math.floor(Date.now()/1000);
  const bytes=await readFile(binary);
  const claim={version:1,domain:offlineDomain,mode:'synthetic-only',installationDigest:scope.installationDigest,keyId:rollout.pin.keyId,
   target,name:INSTALLED_PILOT_BINARY,size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),issuedAt:clock,expiresAt};
  const seal=(change:Partial<typeof claim>={})=>rollout.sign(JSON.stringify({...claim,...change}));
  const denied='pilot_offline_fixture_denied',destination=join(alternate,INSTALLED_PILOT_BINARY);
  for(const invalid of [{issuedAt:clock-2,expiresAt:clock-1},{sha256:'0'.repeat(64)},{target:target==='linux-x64'?'linux-arm64':'linux-x64'}]){
   await expect(admitDisposablePilotPackage(gate,dir,await seal(invalid))).rejects.toThrow(denied);
   expect(await Bun.file(destination).exists()).toBe(false);
  }
  await expect(admitDisposablePilotPackage(gate,dir,await root.sign(JSON.stringify(claim)))).rejects.toThrow(denied);
  const original=join(inbox,'held');
  await rename(binary,original);await symlink(original,binary);
  await expect(admitDisposablePilotPackage(gate,dir,await seal())).rejects.toThrow(denied);
  await rm(binary);await rename(original,binary);
  const handle=await open(binary,'r+');
  try{
   const last=bytes.length-1,originalByte=bytes[last]!;
   await handle.write(Buffer.from([originalByte^1]),0,1,last);
   await expect(admitDisposablePilotPackage(gate,dir,await seal())).rejects.toThrow(denied);
   await handle.write(Buffer.from([originalByte]),0,1,last);
  }finally{await handle.close();}
  expect(await Bun.file(destination).exists()).toBe(false);
  const installed=await admitDisposablePilotPackage(gate,dir,await seal());
  expect(installed).toBe(destination);
  expect((await lstat(installed)).mode&0o7777).toBe(0o700);
  expect((await lstat(installed)).ino).not.toBe((await lstat(binary)).ino);
  await expect(admitDisposablePilotPackage(gate,dir,await seal())).rejects.toThrow(denied);
  await rm(binary);await rm(material);await rm(rootFile); // Verify from installed path alone.
  const execute=(args:string[],extra:Record<string,string>={})=>Bun.spawnSync([installed,...args],{cwd:home,env:{...env,...extra},timeout:8000});
  for(const extra of [{},{AKC_KEYCHAIN_TEST_MODE:'1',AGENTKEYCHAIN_HOME:ordinary,AKC_PILOT_ROOT_PUBLIC_KEY:'not a trust pin'}]){
   const status=execute(['check-installation'],extra);
   expect(status.exitCode).toBe(0);
   expect(JSON.parse(status.stdout.toString())).toEqual({state:'transport_unavailable',releaseId:'continuation-pilot-local-fixture',
    contract:INSTALLED_PILOT_CONTRACT,expiresAt});
   for(const command of ['continue-enrollment','login','check-native']){
    const rejected=execute([command],extra);
    expect(rejected.exitCode).toBe(1);expect(rejected.stdout.length).toBe(0);
    expect(rejected.stderr.toString()).toBe('cloud_continuation_pilot_transport_unavailable\n');
   }
  }
  expect(await readFile(marker,'utf8')).toBe('ordinary fixture untouched');
  expect(await readFile(ordinaryBin,'utf8')).toBe('ordinary binary untouched');
  expect(await Bun.file(join(defaultInstall,INSTALLED_PILOT_BINARY)).exists()).toBe(false);
 }finally{await rm(dir,{recursive:true,force:true});}
},45000);
