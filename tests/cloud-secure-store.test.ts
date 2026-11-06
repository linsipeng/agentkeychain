import {expect,test} from 'bun:test';
import {MemorySecureStore,CommandSecureStore,secureNamespace} from '../src/platform/secure-store.ts';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
test('secure store isolates paths, copies bytes, redacts failure and keeps values out of argv',async()=>{
 const root=mkdtempSync(join(tmpdir(),'akc-store-'));
 try{
  const ns=secureNamespace(root),store=new MemorySecureStore();
  const value=Buffer.from(globalThis.crypto.randomUUID());await store.put('csk',value);value.fill(0);
  const read=await store.get('csk');expect(read?.some(v=>v!==0)).toBe(true);read?.fill(0);
  expect((await store.get('csk'))?.some(v=>v!==0)).toBe(true);
  let called=false;
  const command=new CommandSecureStore('linux',ns,async(cmd,args,input)=>{
   called=true;expect(cmd).toBe('secret-tool');expect(args.join(' ').includes('synthetic-private')).toBe(false);expect(input?.toString()).toBe('c3ludGhldGljLXByaXZhdGU=');return Buffer.alloc(0);
  });
  await command.put('signing-private',Buffer.from('synthetic-private'));expect(called).toBe(true);
  const failing=new CommandSecureStore('macos',ns,async()=>{throw new Error('private-error');});
  await expect(failing.put('csk',Buffer.alloc(32))).rejects.toThrow('secure_store_unavailable');
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('native helper transport roundtrip, missing item, malformed output and failures use stubs only',async()=>{
 const saved=new Map<string,Buffer>(),seen:string[]=[];
 const store=new CommandSecureStore('macos','agentkeychain.cloud.synthetic',async(command,args,input)=>{
  expect(command).toBe('/synthetic/helper');expect(args).toEqual([]);
  const request=JSON.parse(Buffer.from(input!).toString()) as {action:string;account:string;value:string|null};seen.push(request.action);
  if(request.action==='put'){saved.set(request.account,Buffer.from(request.value!));return Buffer.alloc(0);}
  if(request.action==='remove'){saved.delete(request.account);return Buffer.alloc(0);}
  return Buffer.from(saved.get(request.account)??Buffer.alloc(0));
 },'/synthetic/helper');
 expect(await store.get('csk')).toBeNull();await store.put('csk',Buffer.from('synthetic-only'));expect(Buffer.from((await store.get('csk'))!).toString()).toBe('synthetic-only');await store.remove('csk');expect(await store.get('csk')).toBeNull();expect(seen).toEqual(['get','put','get','remove','get']);
 const malformed=new CommandSecureStore('macos','agentkeychain.cloud.synthetic',async()=>Buffer.from('not base64!'),'/synthetic/helper');await expect(malformed.get('csk')).rejects.toThrow('secure_store_unavailable');
});
