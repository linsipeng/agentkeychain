import {afterEach,expect,test,vi} from 'vitest';
import {waitFor} from '@testing-library/react';
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
import {continuationApprovalPage} from '../../auth-trust-worker/experimental/continuation-page';
import {startContinuationApprovalPage} from '../src/continuation-approval-browser';
const origin='https://local.invalid';
const fromId=<T extends HTMLElement>(id:string)=>document.getElementById(id) as T;

afterEach(()=>{vi.unstubAllGlobals();document.body.replaceChildren();document.cookie='__Host-akc_genesis_csrf=; Secure; Path=/; Max-Age=0';});

test('isolated Auth browser bundle stays same-origin and exact GET-only',async()=>{
 const esbuild=resolve(process.cwd(),'../node_modules/esbuild/bin/esbuild');
 const artifact=execFileSync(esbuild,['src/continuation-approval-browser.ts','--bundle','--format=esm','--platform=browser','--target=es2022'],{encoding:'utf8'});
 const handler=continuationApprovalPage(origin,artifact);
 const shell=handler(new Request(origin+'/continuation/approve'));
 expect(shell.status).toBe(200);
 expect(shell.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
 expect(shell.headers.get('referrer-policy')).toBe('no-referrer');
 expect(shell.headers.get('cache-control')).toBe('no-store');
 expect(await shell.text()).toContain('src="/continuation/approve/browser.js"');
 const js=handler(new Request(origin+'/continuation/approve/browser.js'));
 expect(js.headers.get('content-type')).toContain('application/javascript');
 expect(await js.text()).toContain('navigator.credentials.get');
 expect(handler(new Request(origin+'/continuation/approve?request=extraneous')).status).toBe(404);
 expect(handler(new Request('https://other.invalid/continuation/approve')).status).toBe(404);
});

test('explicit review opens native UV only on click, and uncertain submission only reads back',async()=>{
 const shell=continuationApprovalPage(origin,'/* synthetic bundle */')(new Request(origin+'/continuation/approve'));
 document.body.innerHTML=new DOMParser().parseFromString(await shell.text(),'text/html').body.innerHTML;
 const token='a'.repeat(43),id='b'.repeat(43), stage={oldGrantCanonical:'fixture',target:{canonical:'target',signature:'sig'},roster:{},keyPackage:{}};
 document.cookie='__Host-akc_genesis_csrf='+token+'; Secure; Path=/';
 const pick=fromId<HTMLInputElement>('stage');
 Object.defineProperty(pick,'files',{value:[{size:100,text:async()=>JSON.stringify(stage)}]});
 vi.stubGlobal('isSecureContext',true);
 vi.stubGlobal('PublicKeyCredential',class {});
 const bytes=new Uint8Array([1]).buffer;
 const get=vi.fn(async()=>({id:'credential',rawId:bytes,getClientExtensionResults:()=>({}),response:{clientDataJSON:bytes,authenticatorData:bytes,signature:bytes,userHandle:null}}));
 Object.defineProperty(navigator,'credentials',{configurable:true,value:{get}});
 const calls:{url:string;body:unknown;csrf?:string}[]=[];
 vi.stubGlobal('fetch',vi.fn(async(url:string,options:RequestInit)=>{
  calls.push({url,body:JSON.parse(String(options.body)),csrf:new Headers(options.headers).get('x-csrf-token')??undefined});
  if(url.endsWith('/begin'))return Response.json({id,options:{challenge:'AQ',rpId:'local.invalid',userVerification:'required',allowCredentials:[{id:'AQ',type:'public-key'}]},
   display:{purpose:'continue-original-device-key-package',accountId:'a',deviceId:'original-device',vaultId:'v'}});
  if(url.endsWith('/complete'))throw new Error('test response loss');
  return Response.json({canonical:'persisted-approval',signature:'synthetic'});
 }));
 startContinuationApprovalPage();
 fromId<HTMLButtonElement>('review').click();
 const approve=fromId<HTMLButtonElement>('approve'),recover=fromId<HTMLButtonElement>('recover');
 await waitFor(()=>expect(approve.disabled).toBe(false));
 expect(fromId('device').textContent).toBe('original-device');
 expect(fromId('purpose').textContent).toContain('仅提交加密密钥包');
 expect(get).not.toHaveBeenCalled();
 approve.click();
 await waitFor(()=>expect(recover.disabled).toBe(false));
 expect(get).toHaveBeenCalledWith(expect.objectContaining({publicKey:expect.objectContaining({userVerification:'required',rpId:'local.invalid'})}));
 expect(approve.disabled).toBe(true);
 approve.click();
 recover.click();
 await waitFor(()=>expect(fromId<HTMLButtonElement>('download').disabled).toBe(false));
 expect(calls.map(x=>x.url)).toEqual(['/v1/auth/continuation-approval/begin','/v1/auth/continuation-approval/complete','/v1/auth/continuation-receipt']);
 expect(calls[2]).toMatchObject({csrf:token,body:{decisionId:id,oldGrantCanonical:stage.oldGrantCanonical,target:stage.target}});
});
