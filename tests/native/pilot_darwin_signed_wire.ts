/** Run only after review on a disposable GitHub-hosted macOS VM.
 * Uses no external credentials or user Keychain, never runs ordinary CLI,
 * never prints fixture metadata/keys, never uploads results. */
import {constants,closeSync,fstatSync,lstatSync,mkdirSync,mkdtempSync,openSync,readFileSync,realpathSync,rmSync,writeFileSync} from 'node:fs';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {join} from 'node:path';
import {canonicalManifest} from '../../src/cloud/config.ts';
import {INSTALLED_PILOT_CONTRACT,verifyInstalledContinuationPilot} from '../../src/cloud/continuation-pilot-build.ts';
import {DARWIN_NATIVE_CHECK,DARWIN_NATIVE_HELPER_DOMAIN,DARWIN_NATIVE_LOCATION_DOMAIN,verifyDarwinPilotNativeInputs} from '../../src/cloud/continuation-pilot-darwin-check.ts';
import {exactFields} from '../../src/cloud/protocol.ts';

function must(value:unknown):asserts value {if(!value)throw new Error('fixture_denied');}
const sha=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex');
const json=(obj:Record<string,unknown>)=>JSON.stringify(Object.fromEntries(Object.entries(obj).sort(([a],[b])=>a<b?-1:a>b?1:0)));
const now=()=>Math.floor(Date.now()/1000);
function authority(){
 const k=generateKeyPairSync('ed25519'),publicKey=k.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64');
 return {pin:{keyId:sha(publicKey),publicKey},sign:(canonical:string)=>({canonical,signature:sign(null,Buffer.from(canonical),k.privateKey).toString('base64')})};
}
type ArchitecturePhase = 'matrix-architecture'|'bun-process-arch'|'uname-os'|'uname-arch'|'bun-native-query'|'bun-native-translated'|
 'bun-workflow-image'|'bun-os-image'|'bun-canonical-image'|'bun-image-identity'|'bun-lipo-tool'|'bun-lipo-arch'|'fixture-lipo-tool'|'fixture-lipo-arch'|'helper-lipo-tool'|'helper-lipo-arch';
let phase: 'runner'|ArchitecturePhase|'fixture'|'build'|'digest'|'positive'|'invalid-wire'|'missing-wrong-inode'|'unchanged-original'|'configuration'='runner';
const wireHash=(value:{canonical:string;signature:string})=>sha(JSON.stringify([value.canonical,value.signature]));
async function main(){
 must(process.platform==='darwin'&&!!process.getuid?.()&&process.getuid()===process.geteuid?.()&&
  process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&
  process.env.AKC_SIGNED_WIRE_REHEARSAL==='private-fixture-only-v1'&&process.argv.length===2);
 const trustedScratch=realpathSync.native('/private/tmp');
 must(trustedScratch==='/private/tmp'&&lstatSync(trustedScratch).uid===0&&(lstatSync(trustedScratch).mode&0o1000)!==0);
 const dir=mkdtempSync(trustedScratch+'/akc-wire-driver-');
 // A fixed argv and clean environment for all native subprocesses.
 const env={HOME:dir,TMPDIR:dir+'/',PATH:'/usr/bin:/bin',LC_ALL:'C',GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',
  DEVELOPER_DIR:'/Applications/Xcode_16.4.app/Contents/Developer'};
 function launch(argv:string[],extra:Record<string,string>={},stdin?:string){
  return Bun.spawnSync(argv,{env:{...env,...extra},cwd:process.cwd(),stdin:stdin===undefined?undefined:Buffer.from(stdin),
   stdout:'pipe',stderr:'pipe',timeout:20_000,maxBuffer:24*1024});
 }
 function capture(argv:string[],extra:Record<string,string>={},stdin?:string){
  const r=launch(argv,extra,stdin);must(r.exitCode===0&&r.stderr.length===0);return r.stdout.toString();
 }
 try{
  phase='matrix-architecture';
  const expectedArch=process.env.AKC_EXPECTED_DARWIN_ARCH;
  must(expectedArch==='arm64'||expectedArch==='x86_64');
  phase='bun-process-arch';
  must(process.arch===(expectedArch==='arm64'?'arm64':'x64'));
  // Bound argv; discard stderr even from successful probes. Never print a
  // tool's output or binary path; parse only fixed, expected stdout tokens.
  const uname=(flag:'-s'|'-m',expected:string)=>{
   const r=launch(['/usr/bin/uname',flag]);
   must(r.exitCode===0&&r.stdout.toString().trim()===expected);
  };
  phase='uname-os';
  uname('-s','Darwin');
  phase='uname-arch';
  uname('-m',expectedArch);
  phase='bun-native-query';
  // Apple's documented sysctl must run in the actual Bun process; probing a
  // child binary would only say whether that child was translated.
  const {dlopen,FFIType,ptr,read}=await import('bun:ffi');
  const sys=dlopen('/usr/lib/libSystem.B.dylib',{
   sysctlbyname:{args:[FFIType.ptr,FFIType.ptr,FFIType.ptr,FFIType.ptr,FFIType.u64],returns:FFIType.i32},
   __error:{args:[],returns:FFIType.ptr},
  });
  try{
   const name=Buffer.from('sysctl.proc_translated\0','utf8'),translated=new Int32Array(1),size=new BigUint64Array([4n]);
   const result=sys.symbols.sysctlbyname(ptr(name),ptr(translated),ptr(size),null,0n);
   if(result===0){
    must(size[0]===4n);
    phase='bun-native-translated';
    must(translated[0]===0);
   }else{
    const address=sys.symbols.__error();
    // POSIX ENOENT matches Apple's documented nontranslated case; only
    // allow absence on the known Intel matrix, not on Apple Silicon.
    must(result===-1&&address!==null&&read.i32(address)===2&&expectedArch==='x86_64');
   }
  }finally{sys.close();}
  const nativeArch=(path:string,role:'bun'|'fixture'|'helper')=>{
   const previous=phase;
   phase=`${role}-lipo-tool`;
   const output=launch(['/usr/bin/xcrun','lipo','-archs',path]);
   must(output.exitCode===0);
   phase=`${role}-lipo-arch`;
   // The official version uses distinct per-architecture assets. Do not
   // infer a universal distribution from an opaque acceptance failure.
   must(output.stdout.toString().trim()===expectedArch);
   phase=previous;
  };
  phase='bun-workflow-image';
  const workflowBun=process.env.AKC_SIGNED_WIRE_BUN;
  must(typeof workflowBun==='string'&&workflowBun.startsWith('/')&&workflowBun.length<=4095&&!/[\x00-\x1f\x7f]/.test(workflowBun));
  phase='bun-os-image';
  // Read the actual process text vnode path from Darwin, not Bun's
  // process.execPath shim or shell PATH. No falling back to either.
  const proc=dlopen('/usr/lib/libproc.dylib',{
   proc_pidpath:{args:[FFIType.i32,FFIType.ptr,FFIType.u32],returns:FFIType.i32},
  });
  const image=Buffer.alloc(4096);
  try{
   const length=proc.symbols.proc_pidpath(process.pid,ptr(image),image.length),end=image.indexOf(0);
   must(length>0&&length<=image.length&&end>0&&end<=length&&image[0]===47);
  }finally{proc.close();}
  const imagePath=new TextDecoder('utf-8',{fatal:true}).decode(image.subarray(0,image.indexOf(0)));
  phase='bun-canonical-image';
  // Use POSIX realpath, not a runtime-specific .native shim.
  const libc=dlopen('/usr/lib/libSystem.B.dylib',{
   realpath:{args:[FFIType.ptr,FFIType.ptr],returns:FFIType.ptr},
  });
  function canonical(path:string){
   const arg=Buffer.from(path+'\0','utf8'),out=Buffer.alloc(4096);
   const result=libc.symbols.realpath(ptr(arg),ptr(out)),end=out.indexOf(0);
   must(result!==null&&result!==0&&end>0&&out[0]===47);
   return new TextDecoder('utf-8',{fatal:true}).decode(out.subarray(0,end));
  }
  let actualBun:string,expectedBun:string;
  try{actualBun=canonical(imagePath);expectedBun=canonical(workflowBun);}
  finally{libc.close();}
  phase='bun-image-identity';
  must(actualBun===expectedBun);
  const bunFD=openSync(actualBun,constants.O_RDONLY|constants.O_NOFOLLOW);
  let bunImage;
  try{
   bunImage=fstatSync(bunFD,{bigint:true});
   const named=lstatSync(expectedBun,{bigint:true});
   must(bunImage.isFile()&&named.isFile()&&(bunImage.mode&0o111n)!==0n&&
    named.dev===bunImage.dev&&named.ino===bunImage.ino&&named.mode===bunImage.mode);
  }finally{closeSync(bunFD);}
  const verifyBunName=()=>{
   const current=lstatSync(actualBun,{bigint:true});
   must(current.isFile()&&current.dev===bunImage.dev&&current.ino===bunImage.ino&&current.mode===bunImage.mode);
  };
  nativeArch(actualBun,'bun');
  const baseline=capture(['/bin/bash','tests/native/pilot_darwin_keychain_config_digest.sh']);
  must(/^[a-f0-9]{64}\n$/.test(baseline));
  try{
   phase='fixture';
   const fixture=join(dir,'fixture');
   const version=launch([env.DEVELOPER_DIR+'/usr/bin/xcodebuild','-version']);
   must(version.exitCode===0&&version.stdout.toString().split('\n')[0]==='Xcode 16.4');
   // Deprecation warnings from fixture Swift compilation are not published.
   const compiled=Bun.spawnSync(['/usr/bin/xcrun','--sdk','macosx','swiftc','tests/native/pilot_darwin_keychain.swift','-o',fixture],
    {env,cwd:process.cwd(),stdout:'ignore',stderr:'ignore',timeout:100_000});
   must(compiled.exitCode===0);
   nativeArch(fixture,'fixture');
   const raw:unknown=JSON.parse(capture([fixture,'--provision-readonly-wire-fixture'],{AKC_DISPOSABLE_DARWIN_FIXTURE:'private-readonly-wire-fixture-v1'}));
   exactFields(raw,['directory','directoryDevice','directoryInode','fileDevice','fileInode','siblingInode']);
   const {directory,directoryDevice,directoryInode,fileDevice,fileInode,siblingInode}=raw;
   must(typeof directory==='string'&&/^\/private\/tmp\/akc-pilot-native-[a-f0-9]{32}$/.test(directory)&&
    fileDevice===directoryDevice&&fileInode!==siblingInode&&[directoryDevice,directoryInode,fileDevice,fileInode,siblingInode].every(v=>typeof v==='string'&&/^\d+$/.test(v)));
   const uid=process.getuid?.()!,target=`darwin-${process.arch}`;
   const root=authority(),checkpoint=authority(),witness=authority(),auth=authority(),main=authority(),rollout=authority(),genesis=authority();
   const manifest=root.sign(canonicalManifest({version:1,releaseId:'continuation-pilot-wire-fixture',
    webOrigin:'https://web-pilot-wire.example.invalid',apiOrigin:'https://api.web-pilot-wire.example.invalid',
    protocolMin:2,protocolMax:2,checkpointKeys:[checkpoint.pin],witnessKeys:[witness.pin]}));
   const manifestDigest=sha(manifest.canonical), appendix=(domain:string,obj:object)=>root.sign(JSON.stringify({version:1,domain,manifestDigest,...obj}));
   const authOriginAppendix=appendix('AgentKeychain-continuation-auth-origin-pilot-v1',{authOrigin:'https://auth-pilot-wire.example.invalid'});
   const authAppendix=appendix('AgentKeychain-continuation-release-pin-v1',auth.pin);
   const commitAppendix=appendix('AgentKeychain-continuation-main-commit-release-pin-v1',main.pin);
   const rolloutAppendix=appendix('AgentKeychain-continuation-rollout-release-pin-v1',rollout.pin);
   const issuedAt=now(),expiresAt=issuedAt+700;
   const installation=root.sign(JSON.stringify({version:1,domain:'AgentKeychain-continuation-installed-pilot-build-v1',mode:'disposable-only',
    contract:INSTALLED_PILOT_CONTRACT,target,manifestDigest:wireHash(manifest),authOriginDigest:wireHash(authOriginAppendix),
    authPinDigest:wireHash(authAppendix),mainPinDigest:wireHash(commitAppendix),rolloutPinDigest:wireHash(rolloutAppendix),genesisPin:genesis.pin,issuedAt,expiresAt}));
   const artifact={manifest,authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix,installation};
   const gate=await verifyInstalledContinuationPilot(artifact,root.pin.publicKey,target);
   phase='build';
   const install=join(dir,'candidate'),material=join(dir,'public.json'),pin=join(dir,'root.pub');
   mkdirSync(install,{mode:0o700});
   writeFileSync(material,JSON.stringify(artifact),{mode:0o600,flag:'wx'});
   writeFileSync(pin,root.pin.publicKey,{mode:0o600,flag:'wx'});
   const helper=join(install,'agentkeychain-continuation-pilot-darwin-check');
   const nativeEnv={AKC_DARWIN_NATIVE_CANDIDATE:'check-signed-disposable-v1'};
   verifyBunName();
   const build=Bun.spawnSync([actualBun,'scripts/build-continuation-pilot-darwin-check.ts','--artifact',material,
    '--root-public-key',pin,'--outfile',helper],{env:{...env,...nativeEnv},cwd:process.cwd(),stdout:'pipe',stderr:'pipe',timeout:155_000});
   must(build.exitCode===0&&build.stdout.length===0&&build.stderr.length===0);
   nativeArch(helper,'helper');
   must(launch(['/usr/bin/codesign','--force','--sign','-','--timestamp=none',helper]).exitCode===0);
   // Ad-hoc signing proves local code integrity, not publisher identity.
   // Use complete fd-based hash with no final symlink; retain and recheck file
   // identity around same exact path invocation on this sole-writer VM.
   const helperFD=openSync(helper,constants.O_RDONLY|constants.O_NOFOLLOW);
   const stat=fstatSync(helperFD,{bigint:true});
   must(stat.isFile()&&stat.nlink===1n&&stat.uid===BigInt(uid)&&stat.size<30_000_000n);
   const inspected=sha(readFileSync(helperFD));
   closeSync(helperFD);
   const installationDigest=wireHash(installation);
   const common={version:1,installationDigest,keyId:rollout.pin.keyId,issuedAt,expiresAt};
   const namespace='agentkeychain.pilot.'+sha(JSON.stringify([DARWIN_NATIVE_LOCATION_DOMAIN,installationDigest,directory,String(uid),directoryDevice,directoryInode]));
   const body={...common,domain:DARWIN_NATIVE_LOCATION_DOMAIN,directory,directoryDevice,directoryInode,fileDevice,fileInode,uid,namespace};
   const location=rollout.sign(json(body));
   const helperAppendix=rollout.sign(json({...common,domain:DARWIN_NATIVE_HELPER_DOMAIN,helperSha256:inspected,target}));
   async function approve(examinedHelperSha256:string){
    return verifyDarwinPilotNativeInputs(gate,{location,helperAppendix,examinedHelperSha256,target,uid});
   }
   phase='digest';
   // Actual fixed wrong bytes read through a no-follow fd; never attempt to
   // execute them. The TS contract only verifies the resulting supplied hash.
   const disagrees=join(install,'unlaunchable-wrong-digest-fixture');
   writeFileSync(disagrees,'not executable, synthetic digest mismatch',{flag:'wx',mode:0o600});
   const differentFD=openSync(disagrees,constants.O_RDONLY|constants.O_NOFOLLOW);
   let digestDenied=false;
   try{
    const different=sha(readFileSync(differentFD));
    must(different!==inspected);
    try{await approve(different);}catch{digestDenied=true;}
   }finally{closeSync(differentFD);}
   must(digestDenied);
   const expected=await approve(inspected);
   const checkBinary=()=>{
    const fd=openSync(helper,constants.O_RDONLY|constants.O_NOFOLLOW);
    try {
     const current=fstatSync(fd,{bigint:true}),named=lstatSync(helper,{bigint:true});
     must(current.dev===stat.dev&&current.ino===stat.ino&&current.uid===stat.uid&&current.mode===stat.mode&&
      current.size===stat.size&&current.nlink===1n&&named.dev===current.dev&&named.ino===current.ino&&sha(readFileSync(fd))===inspected);
     must(launch(['/usr/bin/codesign','--verify','--strict',helper]).exitCode===0);
     nativeArch(helper,'helper');
     const after=lstatSync(helper,{bigint:true});must(after.dev===current.dev&&after.ino===current.ino&&after.mode===current.mode&&after.nlink===1n);
    }finally{closeSync(fd);}
   };
   const invoke=async(input:string,success:boolean)=>{
    must(input.length>0&&Buffer.byteLength(input,'utf8')<=8192);
    checkBinary();
    // Always verify the still-current helper appendix via the separate valid
    // location, including when deliberately passing denial vectors to Swift.
    await approve(inspected);
    const actual=launch([helper,'check-scoped-store'],nativeEnv,input);
    if(success){
     must(actual.exitCode===0&&actual.stderr.length===0&&
       actual.stdout.toString()===JSON.stringify({version:1,state:DARWIN_NATIVE_CHECK})+'\n');
     checkBinary();
     await approve(inspected);
    }else must(actual.exitCode===1&&actual.stdout.length===0&&actual.stderr.toString()==='darwin_pilot_native_candidate_denied\n');
   };
   phase='positive';
   await invoke(expected.nativeInput,true);
   phase='invalid-wire';
   // Send intentionally stale/wrong signed wire directly to the checked
   // companion: these validate the native trust gate, not just the TS gate.
   await invoke(json({...rollout.sign(json({...body,issuedAt:now()-3,expiresAt:now()-1}))}),false);
   await invoke(json({...root.sign(location.canonical)}),false);
   await invoke(json({...rollout.sign(json({...body,namespace:'agentkeychain.vault'}))}),false);
   // Native absence in a distinct new owner-only directory; no deletion
   // or rename of any real/synthetic keychain, and no restoration path.
   phase='missing-wrong-inode';
   const absent=trustedScratch+'/akc-pilot-native-'+randomBytes(16).toString('hex');
   mkdirSync(absent,{mode:0o700});
   const empty=lstatSync(absent,{bigint:true});
   must(empty.isDirectory()&&empty.uid===BigInt(uid)&&(empty.mode&0o7777n)===0o700n&&realpathSync.native(absent)===absent);
   const emptyDev=String(empty.dev),emptyIno=String(empty.ino);
   const emptyScope='agentkeychain.pilot.'+sha(JSON.stringify([DARWIN_NATIVE_LOCATION_DOMAIN,installationDigest,absent,String(uid),emptyDev,emptyIno]));
   await invoke(json({...rollout.sign(json({...body,directory:absent,directoryDevice:emptyDev,directoryInode:emptyIno,
    fileDevice:emptyDev,namespace:emptyScope}))}),false);
   // The exact requested primary exists, but its signed inode is that of a
   // different genuine immutable synthetic sibling. Detects identity mismatch
   // without ever replacing, unlinking, or restoring either keychain file.
   await invoke(json({...rollout.sign(json({...body,fileInode:siblingInode}))}),false);
   phase='unchanged-original';
   await invoke(expected.nativeInput,true);
  }finally{
   const previous=phase;
   phase='configuration';
   must(capture(['/bin/bash','tests/native/pilot_darwin_keychain_config_digest.sh'])===baseline);
   phase=previous;
  }
  process.stdout.write('PASS signed Darwin companion wire, exact hash/signature and scoped fixture identity\n');
 }finally{rmSync(dir,{recursive:true,force:true});}
}
main().catch(()=>{process.stderr.write('darwin_pilot_signed_wire_rehearsal_denied phase='+phase+'\n');process.exitCode=1;});
