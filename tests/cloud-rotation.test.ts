import {expect,test} from 'bun:test';
import {startSecureCapture} from '../src/capture/server.ts';
import {URLSearchParams} from 'node:url';
test('approval capture reports a prepared request rather than falsely reporting a saved value',async()=>{
 const capture=await startSecureCapture({name:'synthetic',purpose:'Request rotation',scope:'test',permission:'test',openBrowser:false,successMessage:'Request prepared; approval is still required.',onSubmit:async()=>{}});
 try{const response=await fetch(capture.url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({value:'synthetic'})});expect(await response.text()).toContain('Request prepared; approval is still required.');expect(await capture.done).toBe('stored');}finally{capture.close();}
});
