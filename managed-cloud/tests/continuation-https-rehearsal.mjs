/** Disposable transport rehearsal, never a deployable auth backend.
 * Run with Node 24: node --experimental-transform-types managed-cloud/tests/continuation-https-rehearsal.mjs [--browser]
 * --browser requires a sandbox-capable Chromium and certutil. An ephemeral virtual authenticator is used in browser mode. */
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync,writeFileSync,mkdirSync} from 'node:fs';
import {request,createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {createCompiledPilotBrowserFixture,pilotBrowserHost,pilotBrowserOrigin,verifyCompiledPilotBrowser} from './compiled-pilot-browser-fixture.mjs';
import {chromiumTestPipe} from './chromium-test-pipe.mjs';
import {webauthn,random} from '../api-worker/webauthn.ts';
import {digest} from '../shared/contracts.ts';
import {continuationApprovalPage} from '../auth-trust-worker/experimental/continuation-page.ts';

const browser=process.argv.includes('--browser');
assert.ok(process.argv.slice(2).every(option=>option==='--browser'));
const dir=mkdtempSync(join(tmpdir(),'akc-https-'));
const file=name=>join(dir,name);
const run=(program,args,environment=process.env)=>execFileSync(program,args,{env:environment,stdio:'pipe',timeout:20_000});
const names=['auth','api','web'].map(role=>role+'.akc-rehearsal.invalid');
let server,pilot;
try{
 run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',file('ca.key'),'-out',file('ca.pem'),'-days','1','-subj','/CN=AgentKeychain ephemeral test CA','-addext','basicConstraints=critical,CA:TRUE']);
 run('openssl',['req','-newkey','rsa:2048','-nodes','-keyout',file('server.key'),'-out',file('request.pem'),'-subj','/CN='+names[0]]);
 writeFileSync(file('ext'),['basicConstraints=critical,CA:FALSE','extendedKeyUsage=serverAuth','subjectAltName='+[...names,pilotBrowserHost].map(host=>'DNS:'+host).join(',')].join('\n'));
 run('openssl',['x509','-req','-in',file('request.pem'),'-CA',file('ca.pem'),'-CAkey',file('ca.key'),'-CAcreateserial','-out',file('server.pem'),'-days','1','-extfile',file('ext')]);
 if(browser)pilot=await createCompiledPilotBrowserFixture(file('pilot-test-invitation.json'));
 const bundle=(await build({entryPoints:[fileURLToPath(new URL('../web/src/continuation-approval-browser.ts',import.meta.url))],bundle:true,format:'esm',write:false})).outputFiles[0].text;
 let origins,handle;
 const received=[];
 const token='fixture-noncredential',probeId=randomUUID();
 const registrationNonce=random(),authenticationNonce=random(),userId=random();
 let completeProbe;
 let initialRegistration,verifiedAssertion=false;

 const probeComplete=new Promise(resolve=>{completeProbe=resolve;});

 server=createServer({key:readFileSync(file('server.key')),cert:readFileSync(file('server.pem'))},async(req,res)=>{
  try{
   if(pilot&&req.headers.host===pilotBrowserHost){
    if(!req.url?.startsWith('/')||req.url.startsWith('//')||!['GET','POST'].includes(req.method)){res.writeHead(404).end();return;}
    const url=new URL(req.url,pilotBrowserOrigin),headers=new Headers();
    const allowedHeaders=new Set(['origin','sec-fetch-site','content-type','cookie','x-csrf-token']);
    for(let i=0;i<req.rawHeaders.length;i+=2)if(allowedHeaders.has(req.rawHeaders[i].toLowerCase()))
     headers.append(req.rawHeaders[i],req.rawHeaders[i+1]);
    let body;
    if(req.method==='POST'){
     const chunks=[];let bytes=0;
     for await(const chunk of req){bytes+=chunk.length;if(bytes>64*1024){res.writeHead(413).end();return;}chunks.push(chunk);}
     body=Buffer.concat(chunks);
    }
    // Tunnel only the loopback socket; forward browser Origin/Fetch-Metadata and
    // cookies byte-for-byte, not synthesized headers from a Node client.
    const response=await pilot.dispatch(url.toString(),{method:req.method,headers,body});
    const output=Object.fromEntries(response.headers);
    for(const field of ['set-cookie','transfer-encoding','content-length','connection','content-encoding'])delete output[field];
    if(response.headers.getSetCookie().length)output['set-cookie']=response.headers.getSetCookie();
    received.push({origin:pilotBrowserOrigin,path:url.pathname,cookie:!!req.headers.cookie,status:response.status});
    res.writeHead(response.status,output).end(Buffer.from(await response.arrayBuffer()));
    return;
   }
   const origin=origins.find(o=>new URL(o).host===req.headers.host);
   if(!origin||!req.url?.startsWith('/')||req.url.startsWith('//')){res.writeHead(404).end();return;}
   const u=new URL(req.url,origin);
   if(u.origin!==origin){res.writeHead(404).end();return;}
   received.push({origin,path:u.pathname,cookie:!!req.headers.cookie});
   // The probe sets one synthetic cookie only. Cross-origin fetches are never allowed.
   if(req.method==='GET'&&u.pathname==='/probe'&&origin===origins[0]){
    res.writeHead(200,{'content-type':'text/html','content-security-policy':"default-src 'none'; script-src 'self'; connect-src 'self'",
     'permissions-policy':'publickey-credentials-create=(self), publickey-credentials-get=(self)',
     'set-cookie':'__Host-akc_rehearsal='+token+'; Secure; HttpOnly; SameSite=Strict; Path=/'});
    res.end('<!doctype html><p id="proof">pending</p><script src="/probe.js"></script>');return;
   }
   if(req.method==='GET'&&u.pathname==='/probe.js'&&origin===origins[0]){
    res.writeHead(200,{'content-type':'application/javascript'});
    res.end(`globalThis.runProbe=async()=>{
      const crossOrigin=${JSON.stringify(origins[1])};
      const evidence={cookie:false,csp:false,fetchBlocked:false,secure:isSecureContext,
       webauthn:typeof PublicKeyCredential==='function'&&typeof navigator.credentials?.get==='function',
       httpOnly:!document.cookie.includes('akc_rehearsal'),registration:false,assertion:false};
      const bytes=value=>Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
      const post=async(path,value)=>{
       const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)});
       if(!r.ok)throw new Error('webauthn_probe_'+r.status);
       return r;
      };
      try{
       evidence.cookie=(await fetch('/cookie',{cache:'no-store'})).ok;
       const violation=new Promise(resolve=>{
        document.addEventListener('securitypolicyviolation',event=>{
         if(event.effectiveDirective==='connect-src'&&event.disposition==='enforce') {
          try{if(new URL(event.blockedURI).origin===crossOrigin)resolve(true);}catch{}
         }
        });
        setTimeout(()=>resolve(false),3000);
       });
       try{await fetch(crossOrigin+'/cookie');}catch{evidence.fetchBlocked=true;}
       evidence.csp=await violation;
      }catch{}
      try{
       const reg=await (await fetch('/probe-webauthn/options')).json();
       reg.challenge=bytes(reg.challenge);reg.user.id=bytes(reg.user.id);reg.timeout=5000;
       const credential=await navigator.credentials.create({publicKey:reg});
       const options=await (await post('/probe-webauthn/registration',credential.toJSON())).json();
       evidence.registration=true;
       options.challenge=bytes(options.challenge);options.timeout=5000;
       const assertion=await navigator.credentials.get({publicKey:options});
       await post('/probe-webauthn/assertion',assertion.toJSON());
       evidence.assertion=true;
      }catch(error){evidence.webauthnError=error.name||'Error';}
      document.querySelector('#proof').textContent=JSON.stringify(evidence);
      await fetch('/probe-complete/${probeId}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(evidence)});
    };`);return;
   }
   if(browser&&origin===origins[0]&&u.pathname.startsWith('/probe-webauthn/')&&
      req.headers.cookie==='__Host-akc_rehearsal='+token){
    const policy={origin,rpId:names[0]};
    if(req.method==='GET'&&u.pathname==='/probe-webauthn/options'&&!initialRegistration){
     res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'})
      .end(JSON.stringify(await webauthn.registrationOptions(policy,userId,registrationNonce)));return;
    }
    if(req.method==='POST'&&req.headers.origin===origin&&req.headers['content-type']==='application/json'){
     let body='';
     for await(const chunk of req){body+=chunk;if(body.length>8192){res.writeHead(413).end();return;}}
     if(u.pathname==='/probe-webauthn/registration'&&!initialRegistration){
      const response=JSON.parse(body);
      await assert.rejects(webauthn.registration(policy,await digest(authenticationNonce),response));
      initialRegistration=await webauthn.registration(policy,await digest(registrationNonce),response);
      res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'})
       .end(JSON.stringify(await webauthn.authenticationOptions(policy,authenticationNonce)));return;
     }
     if(u.pathname==='/probe-webauthn/assertion'&&initialRegistration&&!verifiedAssertion){
      const response=JSON.parse(body),challenge=await digest(authenticationNonce);
      await assert.rejects(webauthn.authentication({...policy,origin:origins[1]},challenge,response,initialRegistration));
      const counter=await webauthn.authentication(policy,challenge,response,initialRegistration);
      verifiedAssertion=counter>initialRegistration.counter;
      res.writeHead(verifiedAssertion?204:403).end();return;
     }
    }
    res.writeHead(404).end();return;
   }
   if(req.method==='POST'&&u.pathname==='/probe-complete/'+probeId&&origin===origins[0]&&
      req.headers.cookie==='__Host-akc_rehearsal='+token){
    let body='';
    for await(const chunk of req){body+=chunk;if(body.length>512){res.writeHead(413).end();return;}}
    const evidence=JSON.parse(body);
    res.writeHead(204).end();
    completeProbe(evidence);
    return;
   }
   if(req.method==='GET'&&u.pathname==='/cookie'){
    res.writeHead(origin===origins[0]&&req.headers.cookie==='__Host-akc_rehearsal='+token?200:403).end();return;
   }
   if(origin!==origins[0]){res.writeHead(404).end();return;}
   const result=handle(new Request(u,{method:req.method}));
   res.writeHead(result.status,Object.fromEntries(result.headers)).end(await result.text());
  }catch{res.writeHead(500).end();}
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const {port}=server.address();origins=names.map(host=>'https://'+host+':'+port);
 handle=continuationApprovalPage(origins[0],bundle);
 const ca=readFileSync(file('ca.pem'));
 const get=(host,path,trust=true,hostHeader)=>new Promise((resolve,reject)=>{
  const req=request({hostname:host,port,path,agent:false,ca:trust?ca:undefined,headers:hostHeader?{host:hostHeader}:undefined,
   lookup:(_host,options,cb)=>options.all?cb(null,[{address:'127.0.0.1',family:4}]):cb(null,'127.0.0.1',4)},res=>{
   let body='';res.setEncoding('utf8').on('data',chunk=>body+=chunk).on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));
  });
  req.on('error',reject).setTimeout(3_000,()=>req.destroy(new Error('fixture_timeout'))).end();
 });
 await assert.rejects(get(names[0],'/continuation/approve',false),{code:'UNABLE_TO_VERIFY_LEAF_SIGNATURE'});
 await assert.rejects(get('wrong.akc-rehearsal.invalid','/continuation/approve'),{code:'ERR_TLS_CERT_ALTNAME_INVALID'});
 const page=await get(names[0],'/continuation/approve');
 assert.equal(page.status,200);assert.match(page.body,/id="approve" type="button" disabled/);
 assert.match(page.headers['content-security-policy'],/script-src 'self'; connect-src 'self'.*frame-ancestors 'none'/);
 assert.equal(page.headers['permissions-policy'],'publickey-credentials-get=(self), publickey-credentials-create=()');
 assert.equal((await get(names[0],'/continuation/approve/browser.js')).body,bundle);
 for(const name of names.slice(1))assert.equal((await get(name,'/continuation/approve')).status,404);
 const probe=await get(names[0],'/probe');
 assert.deepEqual(probe.headers['set-cookie'],['__Host-akc_rehearsal='+token+'; Secure; HttpOnly; SameSite=Strict; Path=/']);
 console.log('PASS real HTTPS: scoped CA, hostname verification, exact Auth assets and origin isolation');

 if(browser){
  const compiled=await get(pilotBrowserHost,'/pilot/genesis',true,pilotBrowserHost);
  assert.equal(compiled.status,200);
  assert.match(compiled.body,/id="register" disabled/);
  assert.match(compiled.headers['content-security-policy'],/frame-ancestors 'none'/);
  assert.equal(compiled.headers['permissions-policy'],'publickey-credentials-get=(self), publickey-credentials-create=(self)');
  const wrongPort=await get(pilotBrowserHost,'/pilot/genesis');
  assert.equal(wrongPort.status,404);
  const home=file('home'),db=join(home,'.pki','nssdb');
  mkdirSync(db,{recursive:true});
  const env={...process.env,HOME:home,XDG_CONFIG_HOME:file('config'),XDG_DATA_HOME:file('data'),XDG_CACHE_HOME:file('cache')};
  run('certutil',['-N','-d','sql:'+db,'--empty-password'],env);
  run('certutil',['-A','-d','sql:'+db,'-n','akc-disposable-root','-t','C,,','-i',file('ca.pem')],env);
  const flags=['--headless','--no-first-run','--disable-background-networking','--no-proxy-server',
   '--host-resolver-rules='+[...names.map(host=>'MAP '+host+' 127.0.0.1'),'MAP '+pilotBrowserHost+':443 127.0.0.1:'+port].join(', ')];
  // Retain a sandboxed browser for the actual DOM and asynchronous HTTPS
  // checks. One-shot --dump-dom can exit successfully with empty output.
  const child=spawn(process.env.CHROMIUM??'chromium',[...flags,'--remote-debugging-pipe','--user-data-dir='+file('probe-profile'),'about:blank'],
   {env,stdio:['ignore','ignore','pipe','pipe','pipe']});
  const cdp=chromiumTestPipe(child);
  const verifyHandoffDOM=async()=>{
   const expected=origins[0]+'/continuation/approve#handoff='+'a'.repeat(43);
   const {browserContextId}=await cdp('Target.createBrowserContext',{disposeOnDetach:true});
   try{
    const {targetId}=await cdp('Target.createTarget',{url:'about:blank',browserContextId});
    const {sessionId}=await cdp('Target.attachToTarget',{targetId,flatten:true});
    const navigation=await cdp('Page.navigate',{url:expected},sessionId);
    assert.ok(!navigation.errorText,'handoff page HTTPS navigation failed');
    let state;
    for(let i=0;i<60;i++){
     const {result,exceptionDetails}=await cdp('Runtime.evaluate',{expression:`({
      expectedURL:location.href===${JSON.stringify(expected)},
      secure:isSecureContext,
      loaded:document.readyState==='complete',
      manualHidden:document.getElementById('manual')?.hidden===true,
      handoffVisible:document.getElementById('handoff')?.hidden===false,
     })`,returnByValue:true},sessionId);
     assert.ok(!exceptionDetails,'handoff page state evaluation failed');
     state=result.value;
     if(state?.expectedURL&&state.secure&&state.loaded&&state.manualHidden&&state.handoffVisible)return;
     if(i<59)await delay(100,undefined,{signal:timer.signal});
    }
    assert.deepEqual(state,{expectedURL:true,secure:true,loaded:true,manualHidden:true,handoffVisible:true},
      'handoff fragment must hide manual input and show handoff on the expected secure page');
   }finally{
    if(child.exitCode===null&&child.signalCode===null)await cdp('Target.disposeBrowserContext',{browserContextId});
   }
  };
  const start=async()=>{
   await verifyHandoffDOM();
   let page;
   for(let i=0;i<30&&!page;i++){
    const {targetInfos}=await cdp('Target.getTargets');
    page=targetInfos.find(t=>t.type==='page'&&t.url==='about:blank');
    if(!page)await delay(100,undefined,{signal:timer.signal});
   }
   assert.ok(page,'disposable browser must provide its own blank page');
   const {sessionId}=await cdp('Target.attachToTarget',{targetId:page.targetId,flatten:true});
   await cdp('WebAuthn.enable',{enableUI:false},sessionId);
   await cdp('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,
    hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}},sessionId);
   const navigation=await cdp('Page.navigate',{url:origins[0]+'/probe'},sessionId);
   assert.ok(!navigation.errorText,navigation.errorText);
   for(let i=0;i<60;i++){
    const {result}=await cdp('Runtime.evaluate',{expression:"typeof globalThis.runProbe==='function'",returnByValue:true},sessionId);
    if(result.value===true){
     const called=await cdp('Runtime.evaluate',{expression:'globalThis.runProbe()',userGesture:true,awaitPromise:true},sessionId);
     assert.ok(!called.exceptionDetails,'synthetic HTTPS probe threw');
     const evidence=await probeComplete;
     await verifyCompiledPilotBrowser(cdp,pilot,file('pilot-test-invitation.json'),ms=>delay(ms,undefined,{signal:timer.signal}));
     return evidence;
    }
    await delay(100,undefined,{signal:timer.signal});
   }
   throw new Error('disposable browser probe script was not loaded');
  };
  let stderr='';
  child.stderr.on('data',chunk=>{stderr=(stderr+chunk).slice(-4096);});
  const exited=new Promise((resolve,reject)=>{
   child.once('error',reject);
   child.once('close',(code,signal)=>resolve({code,signal}));
  });
  const timer=new AbortController();
  try{
   const evidence=await Promise.race([
    start(),
    exited.then(({code,signal})=>{throw new Error(`browser exited before HTTPS probe completed: ${code??signal}\n${stderr}`);}),
    delay(50_000,undefined,{signal:timer.signal}).then(()=>{throw new Error(`browser HTTPS probe timed out; requests: ${JSON.stringify(received.slice(-12))}\n${stderr}`);}),
   ]);
   assert.deepEqual(evidence,{cookie:true,csp:true,fetchBlocked:true,secure:true,webauthn:true,httpOnly:true,registration:true,assertion:true});
   assert.equal(verifiedAssertion,true);
  }finally{
   timer.abort();
   const running=()=>child.exitCode===null&&child.signalCode===null;
   if(running())child.kill('SIGTERM');
   const kill=setTimeout(()=>{if(running())child.kill('SIGKILL');},2000);
   try{await exited.catch(()=>{});}finally{clearTimeout(kill);}
  }
  assert.ok(received.some(r=>r.origin===origins[0]&&r.path==='/cookie'&&r.cookie));
  assert.ok(!received.some(r=>r.origin===origins[1]&&r.path==='/cookie'));
  for(const [path,status] of [['registration/begin',200],['registration/complete',204],['consent/begin',200],['consent/complete',200]]){
   const hit=received.find(r=>r.origin===pilotBrowserOrigin&&r.path==='/v1/auth/pilot-genesis/'+path);
   assert.ok(hit,path);assert.equal(hit.status,status);
   if(path!=='registration/begin')assert.equal(hit.cookie,true);
  }
  console.log('PASS sandboxed browser: exact compiled pilot page registered, reviewed and approved one synthetic device; no vault activation');

  console.log('PASS sandboxed browser: signed TLS transport, bundle, CSP, host-only cookie and WebAuthn registration and a verified assertion with a disposable virtual authenticator');
 }
}finally{
 if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 await pilot?.dispose();
 rmSync(dir,{recursive:true,force:true});
}
