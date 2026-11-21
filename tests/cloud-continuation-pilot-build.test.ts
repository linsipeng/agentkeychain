import {URL} from 'node:url';
import {webcrypto as crypto} from 'node:crypto';
import {expect,test} from 'bun:test';
import {mkdtemp,readFile,rm,symlink,writeFile} from 'node:fs/promises';
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
