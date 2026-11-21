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
 return {artifact,root:root!,target,expiresAt};
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
