/** Separately compiled CI-only check-native. Never called by the installed
 * or released CLI. Assumes the known disposable fixture has a sole writer. */
import {closeSync,constants,fstatSync,lstatSync,openSync,readFileSync,readSync,realpathSync,type BigIntStats} from 'node:fs';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {verifyInstalledContinuationPilot} from '../../src/cloud/continuation-pilot-build.ts';
import {DARWIN_NATIVE_CHECK,verifyDarwinPilotNativeInputs} from '../../src/cloud/continuation-pilot-darwin-check.ts';
import {compiledFixtureTrust} from './pilot_darwin_compiled_fixture_trust.ts';

const denied=()=>new Error('darwin_compiled_fixture_denied');
function must(value:unknown):asserts value {if(!value)throw denied();}
const sha=(v:Uint8Array)=>createHash('sha256').update(v).digest('hex');
const matching=(a:BigIntStats,b:BigIntStats)=>a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode&&a.uid===b.uid&&a.size===b.size&&a.nlink===b.nlink;
function input(){
 const b=Buffer.alloc(8193);
 let count=0;
 while(count<b.length){
  const n=readSync(0,b,count,b.length-count,null);
  if(n===0)break;
  count+=n;
 }
 must(count>0&&count<=8192);
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(0,count))) as unknown;
}
async function main(){
 const uid=process.getuid?.(),target=`${process.platform}-${process.arch}`,trust=compiledFixtureTrust();
 must(process.platform==='darwin'&&uid&&uid===process.geteuid?.()&&process.argv.length===3&&process.argv[2]==='check-native'&&
   process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted'&&
   process.env.AKC_COMPILED_DARWIN_FIXTURE==='check-native-fixture-v1'&&trust&&trust.target===target);
 const gate=await verifyInstalledContinuationPilot(trust.artifact,trust.rootPublicKey,target);
 const location=input(),root=trust.fixtureRoot;
 must(/^\/private\/tmp\/akc-wire-driver-[A-Za-z0-9]+$/.test(root)&&realpathSync.native(root)===root);
 const home=lstatSync(root,{bigint:true});
 must(home.isDirectory()&&home.uid===BigInt(uid)&&(home.mode&0o7777n)===0o700n);
 const directory=join(root,'candidate'),helper=join(directory,'agentkeychain-continuation-pilot-darwin-check');
 const dev='/Applications/Xcode_16.4.app/Contents/Developer';
 const environment={HOME:root,TMPDIR:root+'/',PATH:'/usr/bin:/bin',LC_ALL:'C',DEVELOPER_DIR:dev,
  GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',AKC_DARWIN_NATIVE_CANDIDATE:'check-signed-disposable-v1'};
 const run=(args:string[],stdin?:string)=>Bun.spawnSync(args,{env:environment,cwd:root,
  ...(stdin===undefined?{}:{stdin:Buffer.from(stdin)}),stdout:'pipe',stderr:'pipe',timeout:15_000,maxBuffer:8192});
 const flags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
 const directoryFD=openSync(directory,flags|constants.O_DIRECTORY);
 try{
  const openedDir=fstatSync(directoryFD,{bigint:true});
  must(openedDir.isDirectory()&&openedDir.uid===BigInt(uid)&&(openedDir.mode&0o7777n)===0o700n&&
   String(openedDir.dev)===trust.directory.device&&String(openedDir.ino)===trust.directory.inode);
  const helperFD=openSync(helper,flags);
  try{
   const opened=fstatSync(helperFD,{bigint:true}),f=trust.file;
   must(opened.isFile()&&opened.uid===BigInt(uid)&&opened.nlink===1n&&opened.dev===openedDir.dev&&
    (opened.mode&0o111n)!==0n&&(opened.mode&0o022n)===0n&&opened.size>0n&&opened.size<=30_000_000n&&
    String(opened.dev)===f.device&&String(opened.ino)===f.inode&&String(opened.uid)===f.uid&&String(opened.mode)===f.mode&&String(opened.size)===f.size);
   const identity=()=>{
    const activeRoot=lstatSync(root,{bigint:true}),activeDir=lstatSync(directory,{bigint:true}),named=lstatSync(helper,{bigint:true});
    must(activeRoot.dev===home.dev&&activeRoot.ino===home.ino&&activeRoot.mode===home.mode&&
     activeDir.dev===openedDir.dev&&activeDir.ino===openedDir.ino&&activeDir.uid===openedDir.uid&&activeDir.mode===openedDir.mode&&
     matching(opened,fstatSync(helperFD,{bigint:true}))&&matching(opened,named));
   };
   const rehash=()=>{
    identity();
    const second=openSync(helper,flags);
    try{
     must(matching(opened,fstatSync(second,{bigint:true})));
     const hash=sha(readFileSync(second));
     must(matching(opened,fstatSync(second,{bigint:true})));
     identity();
     return hash;
    }finally{closeSync(second);}
   };
   identity();
   const observed=sha(readFileSync(helperFD));
   identity();
   const verify=(examinedHelperSha256:string)=>verifyDarwinPilotNativeInputs(gate,{location,
    helperAppendix:trust.helperAppendix,examinedHelperSha256,target,uid});
   await verify(observed);
   must(run(['/usr/bin/codesign','--verify','--strict',helper]).exitCode===0);
   const arch=run(['/usr/bin/xcrun','lipo','-archs',helper]);
   must(arch.exitCode===0&&arch.stdout.toString().trim()===(target==='darwin-arm64'?'arm64':'x86_64'));
   const approved=await verify(rehash());
   const result=run([helper,'check-scoped-store'],approved.nativeInput);
   const expected=JSON.stringify({version:1,state:DARWIN_NATIVE_CHECK})+'\n';
   must(result.exitCode===0&&result.stderr.length===0&&result.stdout.toString()===expected);
   await verify(rehash());
   process.stdout.write(expected);
  }finally{closeSync(helperFD);}
 }finally{closeSync(directoryFD);}
}
main().catch(()=>{process.stderr.write('darwin_compiled_fixture_denied\n');process.exitCode=1;});
