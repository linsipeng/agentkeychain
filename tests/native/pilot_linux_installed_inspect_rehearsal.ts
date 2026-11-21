/** Hosted test only; compiles and installs a separate synthetic read-only client. */
import {createHash,generateKeyPairSync,webcrypto as crypto} from 'node:crypto';
import {chmod,mkdtemp,readFile,rename,rm,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {TextEncoder} from 'node:util';
import {expect,test} from 'bun:test';
import {canonicalManifest} from '../../src/cloud/config.ts';
import {INSTALLED_PILOT_CONTRACT,INSTALLED_PILOT_NATIVE_READER_ABI} from '../../src/cloud/continuation-pilot-build.ts';
import {canonicalPilotBrokerRequest,emptyPilotBrokerReference,pilotBrokerOperationDigest,transitionPilotBrokerReference} from '../../src/cloud/pilot-broker-wire.ts';
import {digest} from '../../managed-cloud/shared/contracts.ts';

async function authority(){
 const key=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 if(!('publicKey' in key))throw new Error('not a signing key pair');
 const publicKey=Buffer.from(await crypto.subtle.exportKey('raw',key.publicKey)).toString('base64');
 return {publicKey,pin:{keyId:await digest(publicKey),publicKey},sign:async(canonical:string)=>({canonical,
  signature:Buffer.from(await crypto.subtle.sign('Ed25519',key.privateKey,new TextEncoder().encode(canonical))).toString('base64')})};
}
const signedDigest=(s:{canonical:string;signature:string})=>digest(JSON.stringify([s.canonical,s.signature]));
async function installMaterial(){
 const [root,checkpoint,witness,auth,main,rollout,genesis]=await Promise.all([
  authority(),authority(),authority(),authority(),authority(),authority(),authority()]);
 const manifest=await root.sign(canonicalManifest({version:1,releaseId:'continuation-pilot-installed-fixture',
  apiOrigin:'https://api.web-pilot-installed.example.com',webOrigin:'https://web-pilot-installed.example.com',protocolMin:2,protocolMax:2,
  checkpointKeys:[checkpoint.pin],witnessKeys:[witness.pin]}));
 const manifestDigest=await digest(manifest.canonical);
 const append=(domain:string,v:object)=>root.sign(JSON.stringify({version:1,domain,manifestDigest,...v}));
 const [authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix]=await Promise.all([
  append('AgentKeychain-continuation-auth-origin-pilot-v1',{authOrigin:'https://auth-pilot-installed.example.com'}),
  append('AgentKeychain-continuation-release-pin-v1',auth.pin),append('AgentKeychain-continuation-main-commit-release-pin-v1',main.pin),
  append('AgentKeychain-continuation-rollout-release-pin-v1',rollout.pin)]);
 const issuedAt=Math.floor(Date.now()/1000),expiresAt=issuedAt+180,target='linux-'+process.arch;
 const installation=await root.sign(JSON.stringify({version:1,domain:'AgentKeychain-continuation-installed-pilot-build-v1',
  mode:'disposable-only',contract:INSTALLED_PILOT_CONTRACT,target,manifestDigest:await signedDigest(manifest),
  authOriginDigest:await signedDigest(authOriginAppendix),authPinDigest:await signedDigest(authAppendix),
  mainPinDigest:await signedDigest(commitAppendix),rolloutPinDigest:await signedDigest(rolloutAppendix),genesisPin:genesis.pin,issuedAt,expiresAt}));
 return {root,target,issuedAt,expiresAt,installationDigest:await signedDigest(installation),
  artifact:{manifest,authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix,installation}};
}
const identityFields=['uid','device','parent','directory','lock','main'] as const;
type Identity=Record<(typeof identityFields)[number],string>;
function parseIdentity(x:Uint8Array):Identity{
 const z=JSON.parse(Buffer.from(x).toString('utf8')) as Record<string,unknown>;
 if(!z||Object.keys(z).join(',')!==identityFields.join(',')||identityFields.some(k=>
  typeof z[k]!=='string'||! /^(0|[1-9][0-9]{0,19})$/.test(z[k] as string)))throw Error('invalid fixture identity');
 return z as Identity;
}
const sha256=(data:Uint8Array)=>createHash('sha256').update(data).digest('hex');

test('separately installed read-only pilot verifies real SQLite through its sealed native child',async()=>{
 const pinned=process.env.AKC_SQLITE_FIXTURE_DIR;
 if(!pinned||process.env.RUNNER_ENVIRONMENT!=='github-hosted'||process.platform!=='linux'||process.arch!=='x64')
  throw Error('this fixture requires the pinned hosted Linux x64 lane');
 const dir=await mkdtemp('/tmp/akc-native-installed-');
 try{
  const driver=join(dir,'driver'),reader=join(dir,'reader'),header=join(dir,'pilot_linux_installed_inspect_fixture.h');
  const common=['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-I',pinned,'-I',dir];
  const sqlite=join(pinned,'sqlite3.o'),libs=['-lcrypto','-lm','-lpthread','-ldl'];
  const p=Bun.spawnSync([...common,'native/pilot-linux-descriptor-launch.c','native/pilot-linux-peer-frame.c',
   'tests/native/pilot_linux_installed_inspect_driver.c',sqlite,...libs,'-o',driver],{timeout:18000});
  expect(p.exitCode,p.stderr.toString()).toBe(0);
  const runDriver=(...argv:string[])=>Bun.spawnSync([driver,...argv],{env:{},timeout:6000});
  const prepared=runDriver('prepare',dir);expect(prepared.exitCode,prepared.stderr.toString()).toBe(0);
  const initial=parseIdentity(prepared.stdout);expect(initial.main).toBe('0');
  const m=await installMaterial();
  const profileDigest=await digest(JSON.stringify(['akc-installed-native-fixture-profile-v1',m.installationDigest,
   initial.uid,initial.device,initial.parent,initial.directory,initial.lock]));
  const record={nonce:Buffer.alloc(24,4).toString('base64url'),ciphertext:Buffer.alloc(24,5).toString('base64url')};
  const op=canonicalPilotBrokerRequest({version:1,op:'seed-pending',profileDigest,record});
  const operation=pilotBrokerOperationDigest(op),frame=JSON.stringify(record);
  const receipt=transitionPilotBrokerReference(profileDigest,emptyPilotBrokerReference(profileDigest),op).response;
  const seeded=runDriver('seed',dir,operation,frame,receipt);expect(seeded.exitCode,seeded.stderr.toString()).toBe(0);
  const ids=parseIdentity(seeded.stdout);expect(ids.main).not.toBe('0');
  expect({...ids,main:'0'}).toEqual(initial);
  const keys=generateKeyPairSync('ed25519');
  const privateDER=keys.privateKey.export({format:'der',type:'pkcs8'});
  const pub=keys.publicKey.export({format:'der',type:'spki'});
  expect(pub.length).toBe(44);
  const raw=pub.subarray(-32),publicKey=raw.toString('base64');
  try{
   expect(privateDER.length).toBe(48);
   expect(privateDER.subarray(0,16).toString('hex')).toBe('302e020100300506032b657004220420');
   await writeFile(header,[
    'static struct akc_inspect_scope binding={.installation_digest='+JSON.stringify(m.installationDigest)+
     ',.profile_digest='+JSON.stringify(profileDigest)+',.reader_public={'+[...raw].join(',')+'},.not_after='+m.expiresAt+'};',
    'static unsigned char fixture_seed[32]={'+[...privateDER.subarray(16)].join(',')+'};',
    'static const uid_t expected_uid='+ids.uid+';',
    'static const dev_t expected_device='+ids.device+';',
    'static const ino_t expected_parent='+ids.parent+',expected_directory='+ids.directory+
     ',expected_lock='+ids.lock+',expected_main='+ids.main+';',
    'static const char expected_operation[]='+JSON.stringify(operation)+',expected_frame[]='+JSON.stringify(frame)+
     ',expected_receipt[]='+JSON.stringify(receipt)+';',
   ].join('\n'),{flag:'wx',mode:0o600});
   // The generated header contains test-only private bytes; never print diagnostics from this compile.
   const native=Bun.spawnSync([...common,'-static','native/pilot-linux-peer-frame.c','native/pilot-linux-inspect-wire.c',
    'tests/native/pilot_linux_installed_inspect_target.c',sqlite,...libs,'-o',reader],{timeout:18000,stderr:'ignore'});
   expect(native.exitCode,'build isolated static reader').toBe(0);
  }finally{privateDER.fill(0);await rm(header,{force:true});}
  await chmod(reader,0o500);
  const image=sha256(await readFile(reader));
  const nativeClaim=await m.root.sign(JSON.stringify({version:1,domain:'AgentKeychain-installed-continuation-pilot-native-reader-v1',
   installationDigest:m.installationDigest,target:m.target,nativeImageSha256:image,abi:INSTALLED_PILOT_NATIVE_READER_ABI,
   readerPin:{keyId:await digest(publicKey),publicKey},issuedAt:m.issuedAt,expiresAt:m.expiresAt}));
  const program=join(dir,'compiled-fixture.ts'),built=join(dir,'built-fixture'),installed=join(dir,'installed-fixture');
  await writeFile(program,`import {verifyInstalledContinuationPilot,installedContinuationPilotNativeReaderScope} from ${JSON.stringify(resolve('src/cloud/continuation-pilot-build.ts'))};
import {beginNativeInspectVerification,verifyNativeInspectObservation} from ${JSON.stringify(resolve('src/cloud/continuation-pilot-native-inspect.ts'))};
try{
 const gate=await verifyInstalledContinuationPilot(${JSON.stringify({...m.artifact,nativeReaderAppendix:nativeClaim})},${JSON.stringify(m.root.publicKey)},'linux-'+process.arch);
 const scope=installedContinuationPilotNativeReaderScope(gate);
 const ticket=beginNativeInspectVerification(gate,${JSON.stringify(profileDigest)});
 const result=Bun.spawnSync([${JSON.stringify(driver)},'read',${JSON.stringify(dir)},scope.nativeImageSha256],{stdin:ticket.request,env:{},timeout:4800});
 if(result.exitCode!==0){process.exitCode=result.exitCode===79?79:77;}
 else{
  const observation=await verifyNativeInspectObservation(ticket,new Uint8Array(result.stdout));
  console.log(JSON.stringify(observation));
 }
}catch{process.exitCode=77;}\n`,{flag:'wx',mode:0o600});
  const build=Bun.spawnSync([process.execPath,'build','--compile',program,'--outfile',built],{timeout:24000});
  expect(build.exitCode,build.stderr.toString()).toBe(0);
  await writeFile(installed,await readFile(built),{flag:'wx',mode:0o700});
  await rm(built);await rm(program);
  const db=join(dir,'pilot','pilot.sqlite'),before=sha256(await readFile(db));
  const run=()=>Bun.spawnSync([installed],{env:{},timeout:7000});
  const pass=run();
  expect(pass.exitCode,'genuine native status').toBe(0);
  expect(pass.stdout.toString()).toBe('{"status":"snapshot-present"}\n');
  expect(sha256(await readFile(db))).toBe(before);
  const mutated=runDriver('tamper',dir,operation,frame);
  expect(mutated.exitCode,mutated.stderr.toString()).toBe(0);
  const deny=run();expect(deny.exitCode).toBe(79);expect(deny.stdout.length).toBe(0);
  await rename(db,db+'.fixture-held');
  try{const missing=run();expect(missing.exitCode).toBe(79);expect(missing.stdout.length).toBe(0);}
  finally{await rename(db+'.fixture-held',db);}
 }finally{await rm(dir,{recursive:true,force:true});}
},85000);
