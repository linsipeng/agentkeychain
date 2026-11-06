import {test,expect} from 'bun:test';
import {runCloud} from '../src/cli/cloud.ts';
import {runExport} from '../src/cli/export.ts';
test('Windows cloud/export entrypoints reject before any vault, secure-store or output access',async()=>{
 for(const args of [['status'],['login'],['recover','synthetic'],['service','run'],['request-export','missing/output']])await expect(runCloud(args,'win32')).rejects.toThrow('cloud_platform_unsupported');
 await expect(runExport(['--out','missing/output'],'win32')).rejects.toThrow('cloud_platform_unsupported');
});
test('compiled Windows-injected CLI fails with an empty isolated home and no output',async()=>{
 const {mkdtempSync,mkdirSync,readdirSync,rmSync}=await import('node:fs'),{tmpdir}=await import('node:os'),{join}=await import('node:path'),{spawnSync}=await import('node:child_process');
 const root=mkdtempSync(join(tmpdir(),'akc-windows-')),home=join(root,'home');mkdirSync(home,{mode:0o700});
 try{
  const executable=join(root,'client'),built=await Bun.build({entrypoints:['scripts/phase45/windows-smoke.ts'],compile:{outfile:executable}});expect(built.success).toBe(true);
  for(const args of [['status'],['login'],['recover','synthetic'],['service','run'],['request-export',join(home,'out')],['export','--out',join(home,'out')]]){
   const result=spawnSync(executable,args,{env:{HOME:home,AGENTKEYCHAIN_HOME:join(home,'vault'),PATH:'/usr/bin:/bin'},encoding:'utf8'});expect(result.status).toBe(0);expect(readdirSync(home)).toEqual([]);
  }
 }finally{rmSync(root,{recursive:true,force:true});}
},30000);
