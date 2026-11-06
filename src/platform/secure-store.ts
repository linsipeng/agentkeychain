/* eslint-disable no-unused-vars -- interface parameters */
import {createHash} from 'node:crypto';
import {lstatSync,realpathSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {dirname,join} from 'node:path';
export type SecureAccount='enrollment-intent'|'csk'|'signing-private'|'wrapping-private'|'refresh-credential'|'checkpoint-anchor'|'roster-anchor'|'recovery-intent'|'recovery-anchor';
export interface SecureStore {get(account:SecureAccount):Promise<Uint8Array|null>;put(account:SecureAccount,value:Uint8Array):Promise<void>;remove(account:SecureAccount):Promise<void>}
export function secureNamespace(home:string):string {
 const stat=lstatSync(home);
 if(stat.isSymbolicLink()||!stat.isDirectory()||(stat.mode&0o077)!==0)throw new Error('unsafe_cloud_home');
 return 'agentkeychain.cloud.'+createHash('sha256').update(realpathSync(home)).digest('hex');
}
/** Injection-only test adapter. Never selected by an environment variable. */
export class MemorySecureStore implements SecureStore {
 private values=new Map<SecureAccount,Uint8Array>();
 async get(account:SecureAccount){return this.values.has(account)?new Uint8Array(this.values.get(account)!):null;}
 async put(account:SecureAccount,value:Uint8Array){this.values.get(account)?.fill(0);this.values.set(account,new Uint8Array(value));}
 async remove(account:SecureAccount){this.values.get(account)?.fill(0);this.values.delete(account);}
}
export type SecretRunner=(command:string,args:string[],input?:Uint8Array)=>Promise<Uint8Array>;
const run:SecretRunner=(command,args,input)=>new Promise((resolve,reject)=>{
 const child=spawn(command,args,{stdio:['pipe','pipe','ignore'],env:{PATH:'/usr/bin:/bin',...(process.env.DBUS_SESSION_BUS_ADDRESS?{DBUS_SESSION_BUS_ADDRESS:process.env.DBUS_SESSION_BUS_ADDRESS}:{})}});
 const chunks:Buffer[]=[];let size=0;
 const fail=()=>{child.kill();reject(new Error('secure_store_unavailable'));};
 const timer=setTimeout(fail,5000);
 child.stdout.on('data',(chunk:Buffer)=>{size+=chunk.length;if(size>65536)fail();else chunks.push(chunk);});
 child.on('error',()=>{clearTimeout(timer);fail();});child.stdin.on('error',()=>{});
 child.on('close',code=>{clearTimeout(timer);if(code===0){resolve(Buffer.concat(chunks));}else if(command==='secret-tool'&&args[0]==='lookup'&&code===1&&size===0){resolve(new Uint8Array());}else reject(new Error('secure_store_unavailable'));for(const c of chunks)c.fill(0);});
 child.stdin.end(input);
});
export class CommandSecureStore implements SecureStore {
 constructor(private backend:'macos'|'linux',private namespace:string,private runner:SecretRunner=run,private helper=join(dirname(process.execPath),'agentkeychain-secure-store')){}
 private async call(action:'get'|'put'|'remove',account:SecureAccount,value?:Uint8Array):Promise<Uint8Array>{
  let input:Buffer|undefined;
  try{
   if(value)input=Buffer.from(Buffer.from(value).toString('base64'));
   if(this.backend==='macos'){
    const request=Buffer.from(JSON.stringify({action,service:this.namespace,account,value:input?.toString()??null}));
    try{return await this.runner(this.helper,[],request);}finally{request.fill(0);}
   }
   return await this.runner('secret-tool',action==='put'?['store','--label=AgentKeychain cloud','service',this.namespace,'account',account]:[action==='get'?'lookup':'clear','service',this.namespace,'account',account],input);
  }catch{throw new Error('secure_store_unavailable');}finally{input?.fill(0);}
 }
 async get(account:SecureAccount){const output=await this.call('get',account);try{const text=Buffer.from(output).toString().trim();if(!text)return null;const bytes=Buffer.from(text,'base64');if(bytes.toString('base64')!==text)throw new Error('secure_store_unavailable');return bytes;}finally{output.fill(0);}}
 async put(account:SecureAccount,value:Uint8Array){(await this.call('put',account,value)).fill(0);}
 async remove(account:SecureAccount){(await this.call('remove',account)).fill(0);}
}
export function platformSecureStore(home:string):SecureStore {
 if(process.env.AKC_KEYCHAIN_TEST_MODE==='1')throw new Error('test_secure_store_injection_required');
 if(process.platform!=='darwin'&&process.platform!=='linux')throw new Error('cloud_secure_store_unsupported');
 return new CommandSecureStore(process.platform==='darwin'?'macos':'linux',secureNamespace(home));
}
