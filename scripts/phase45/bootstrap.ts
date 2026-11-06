import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import {sep} from 'node:path';
import {readSync,realpathSync} from 'node:fs';
import type {SignedManagedOperation} from '../../src/cloud/protocol.ts';
import type {SecureAccount,SecureStore} from '../../src/platform/secure-store.ts';
import type {LoginUI} from '../../src/cloud/login.ts';
let line='';const byte=Buffer.alloc(1);while(readSync(0,byte,0,1,null)){if(byte[0]===10)break;line+=byte.toString();if(line.length>32768)throw new Error('test_bootstrap_too_large');}
export const bootstrap=JSON.parse(line) as {fault?:string;clockOffset?:number;home:string;password:string;api:string;secure:string;token:string;manifest:SignedManagedOperation;rootPublicKey:string};line='';
export const nativeNow=Date.now;let clockOffset=bootstrap.clockOffset??0;Date.now=()=>nativeNow()+clockOffset;
if(!realpathSync(bootstrap.home).startsWith(realpathSync(tmpdir())+sep))throw new Error('test_home_required');
export async function testControl(path:string,value:unknown){const response=await fetch(bootstrap.secure+path,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+bootstrap.token},body:JSON.stringify({home:bootstrap.home,value,fault:bootstrap.fault})});if(!response.ok)throw new Error('test_control_failed');return response.json();}
export function testSecureStore():SecureStore{return {async get(account:SecureAccount){const result=await testControl('/get',account) as {value:string|null};return result.value?Buffer.from(result.value,'base64'):null;},async put(account:SecureAccount,value:Uint8Array){const slot=account==='enrollment-intent'&&JSON.parse(Buffer.from(value).toString()).activation?'enrollment-activation':account;if(bootstrap.fault==='secure:before:'+slot)process.exit(96);await testControl('/put',{account,value:Buffer.from(value).toString('base64')});if(bootstrap.fault==='secure:after:'+slot)process.exit(96);},async remove(account:SecureAccount){if(bootstrap.fault==='secure:before-remove:'+account)process.exit(96);await testControl('/remove',account);if(bootstrap.fault==='secure:after-remove:'+account)process.exit(96);}};}
export const testNetwork=async(url:string,init:RequestInit)=>{
 const u=new URL(url);if(u.origin!=='https://local.invalid')throw new Error('test_outbound_forbidden');if(bootstrap.fault==='before:'+u.pathname)process.exit(94);const response=await fetch(bootstrap.api+u.pathname+u.search,{...init,headers:{...init.headers,'x-test-source':createHash('sha256').update(bootstrap.home).digest('hex')}});if(bootstrap.fault==='after:'+u.pathname&&response.ok)process.exit(94);if(bootstrap.fault==='issuer-interrupt'&&u.pathname==='/v1/devices/enroll'&&response.ok)process.exit(93);return response;
};
export const testUI:LoginUI={async open(url){const response=await testControl('/browser',{url}) as {clockOffset?:number};if(response.clockOffset!==undefined)clockOffset=response.clockOffset;if(bootstrap.fault==='enrollment-interrupt')process.exit(92);},async confirmPhrase(phrase){const r=await testControl('/phrase',{phrase}) as {confirmed:boolean};return r.confirmed;},async wait(ms){if(bootstrap.fault==='delayed'){const response=await testControl('/clock',{}) as {clockOffset:number};clockOffset=response.clockOffset;return;}return new Promise(resolve=>setTimeout(()=>{resolve();},ms));}};
