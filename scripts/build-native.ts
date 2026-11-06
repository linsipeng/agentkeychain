import {mkdtemp,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {dirname,join,resolve} from 'node:path';
export async function buildNative(outfile:string){
 if(process.platform!=='darwin')return;
 const cache=await mkdtemp(join(tmpdir(),'akc-native-build-'));
 try{
  await mkdir(dirname(resolve(outfile)),{recursive:true});
  const result=spawnSync('swiftc',['-O','-module-cache-path',cache,'native/secure-store.swift','-o',resolve(outfile)],{stdio:'ignore'});
  if(result.status!==0)throw new Error('native_secure_store_build_failed');
 }finally{await rm(cache,{recursive:true,force:true});}
}
if(import.meta.main){if(!process.argv[2])throw new Error('native_output_required');await buildNative(process.argv[2]);}
