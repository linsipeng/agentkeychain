/** Explicit standalone pilot compiler. Not called by release or install. */
import {mkdtemp,open,link,rm} from 'node:fs/promises';
import {basename,dirname,join,resolve,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {INSTALLED_PILOT_BINARY,verifyInstalledContinuationPilot,type ContinuationPilotBuildArtifact} from '../src/cloud/continuation-pilot-build.ts';

async function readBounded(path:string,max:number){
 const input=await open(path,'r');
 try{
  const info=await input.stat();
  if(!info.isFile()||info.size>max)throw new Error('invalid_pilot_input');
  const data=Buffer.alloc(max+1),{bytesRead}=await input.read(data,0,data.length,0);
  if(bytesRead>max||bytesRead!==info.size)throw new Error('invalid_pilot_input');
  return data.subarray(0,bytesRead).toString('utf8');
 }finally{await input.close();}
}

async function main(){
 const args=process.argv.slice(2),options=new Map<string,string>();
 if(args.length!==6)throw new Error('invalid_pilot_input');
 for(let i=0;i<args.length;i+=2){
  const key=args[i]!,value=args[i+1]!;
  if(!['--artifact','--root-public-key','--outfile'].includes(key)||options.has(key)||!value||value.startsWith('--'))throw new Error('invalid_pilot_input');
  options.set(key,value);
 }
 const outfile=options.get('--outfile')!;
 if(!isAbsolute(outfile)||basename(outfile)!==INSTALLED_PILOT_BINARY)throw new Error('invalid_pilot_input');
 const artifact=JSON.parse(await readBounded(options.get('--artifact')!,64*1024)) as ContinuationPilotBuildArtifact;
 const rootPublicKey=(await readBounded(options.get('--root-public-key')!,256)).trim();
 await verifyInstalledContinuationPilot(artifact,rootPublicKey,`${process.platform}-${process.arch}`);
 const source=fileURLToPath(new URL('../src/cli/continuation-pilot.ts',import.meta.url));
 const stub=fileURLToPath(new URL('../src/cli/continuation-pilot.generated.ts',import.meta.url));
 const temp=await mkdtemp(join(dirname(resolve(outfile)),'.continuation-pilot-'));
 try{
  const built=join(temp,INSTALLED_PILOT_BINARY);
  const result=await Bun.build({entrypoints:[source],compile:{outfile:built},plugins:[{
   name:'verified-continuation-pilot-trust',setup(build){
    build.onLoad({filter:/continuation-pilot\.generated\.ts$/},({path})=>{
     if(path!==stub)throw new Error('unexpected_pilot_artifact_path');
     return {contents:`export function installedPilotArtifact(){return ${JSON.stringify({artifact,rootPublicKey})};}`,loader:'ts'};
    });
   },
  }]});
  if(!result.success)throw new Error('cloud_continuation_pilot_build_failed');
  // Publish only a fully built file; a preexisting install path is never overwritten.
  await link(built,resolve(outfile));
 }finally{await rm(temp,{recursive:true,force:true});}
}

main().catch(()=>{process.stderr.write('cloud_continuation_pilot_build_rejected\n');process.exitCode=1;});
