/** Explicit binary build for pre-reviewed disposable Darwin fixture only.
 * Not called by normal builds, release, installer or CLI dispatch. */
import {constants} from 'node:fs';
import {lstat,open,link,mkdtemp,realpath,rm,writeFile} from 'node:fs/promises';
import {basename,dirname,isAbsolute,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyInstalledContinuationPilot,type ContinuationPilotBuildArtifact} from '../src/cloud/continuation-pilot-build.ts';
import {darwinPilotNativeTrustSwift} from '../src/cloud/continuation-pilot-darwin-check.ts';

const name='agentkeychain-continuation-pilot-darwin-check';
const xcode='/Applications/Xcode_16.4.app/Contents/Developer';
const swift=xcode+'/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc';
const denied=()=>new Error('darwin_pilot_native_candidate_build_denied');
async function readPublic(path:string,limit:number){
 if(!isAbsolute(path)||!constants.O_NOFOLLOW||!constants.O_NONBLOCK)throw denied();
 const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const info=await handle.stat();
  if(!info.isFile()||info.size<1||info.size>limit)throw denied();
  const b=Buffer.alloc(limit+1),read=await handle.read(b,0,b.length,0);
  if(read.bytesRead!==info.size)throw denied();
  return new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(0,read.bytesRead));
 }finally{await handle.close();}
}
async function main(){
 if(process.platform!=='darwin'||!process.getuid?.()||process.getuid()!==process.geteuid?.()||
    process.env.GITHUB_ACTIONS!=='true'||process.env.RUNNER_ENVIRONMENT!=='github-hosted'||
    process.env.AKC_DARWIN_NATIVE_CANDIDATE!=='check-signed-disposable-v1')throw denied();
 const args=process.argv.slice(2);
 if(args.length!==6||args[0]!=='--artifact'||args[2]!=='--root-public-key'||args[4]!=='--outfile')throw denied();
 const output=args[5]!;
 if(!isAbsolute(output)||basename(output)!==name)throw denied();
 const parent=dirname(output),info=await lstat(parent);
 if(await realpath(parent)!==parent||!info.isDirectory()||info.uid!==process.getuid()||(info.mode&0o7777)!==0o700)throw denied();
 const artifact=JSON.parse(await readPublic(args[1]!,64*1024)) as ContinuationPilotBuildArtifact;
 const root=(await readPublic(args[3]!,128)).trim();
 const target=`${process.platform}-${process.arch}`;
 const gate=await verifyInstalledContinuationPilot(artifact,root,target);
 const dir=await mkdtemp(join(parent,'.continuation-native-build-'));
 try{
  const trusted=join(dir,'PilotNativeTrust.swift'),entry=join(dir,'main.swift'),result=join(dir,name);
  await writeFile(trusted,darwinPilotNativeTrustSwift(gate),{flag:'wx',mode:0o600});
  const src=fileURLToPath(new URL('../native/continuation-pilot-keychain-check.swift',import.meta.url));
  await writeFile(entry,await readPublic(src,32*1024),{flag:'wx',mode:0o600});
  // Exact disposable-runner toolchain and replace, do not spread, process
  // environment. No inherited SDKROOT, TOOLCHAINS, DYLD_*, TMPDIR or HOME.
  const env={HOME:dir,TMPDIR:dir+'/',PATH:'/usr/bin:/bin',LC_ALL:'C',DEVELOPER_DIR:xcode};
  if(await realpath(xcode)!==xcode||!(await realpath(swift)).startsWith(xcode+'/Toolchains/XcodeDefault.xctoolchain/usr/bin/'))throw denied();
  const version=Bun.spawnSync([xcode+'/usr/bin/xcodebuild','-version'],{cwd:dir,env,stdout:'pipe',stderr:'ignore',timeout:15_000});
  if(version.exitCode!==0||version.stdout.toString().split('\n')[0]!=='Xcode 16.4')throw denied();
  const sdkLookup=Bun.spawnSync(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],
   {cwd:dir,env,stdout:'pipe',stderr:'ignore',timeout:15_000});
  if(sdkLookup.exitCode!==0)throw denied();
  const inputSDK=sdkLookup.stdout.toString().trim();
  if(!isAbsolute(inputSDK))throw denied();
  const sdk=await realpath(inputSDK);
  if(!sdk.startsWith(xcode+'/Platforms/MacOSX.platform/Developer/SDKs/')||!sdk.endsWith('.sdk'))throw denied();
  const compile=Bun.spawnSync([swift,'-sdk',sdk,'-O',entry,trusted,'-o',result],
   {cwd:dir,env,stdout:'ignore',stderr:'ignore',timeout:120_000});
  if(compile.exitCode!==0||Math.floor(Date.now()/1000)>=gate.expiresAt)throw denied();
  const now=await lstat(parent);
  if(now.dev!==info.dev||now.ino!==info.ino||now.uid!==info.uid||now.mode!==info.mode||await realpath(parent)!==parent)throw denied();
  await link(result,output);
 }finally{await rm(dir,{recursive:true,force:true});}
}
main().catch(()=>{process.stderr.write('darwin_pilot_native_candidate_build_denied\n');process.exitCode=1;});
