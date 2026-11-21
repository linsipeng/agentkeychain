/** Disposable transport rehearsal, never a deployable auth backend.
 * Run with Node 24: node --experimental-transform-types managed-cloud/tests/continuation-https-rehearsal.mjs [--browser]
 * --browser requires a sandbox-capable Chromium and certutil. An ephemeral virtual authenticator is used in browser mode. */
import assert from 'node:assert/strict';
import {execFileSync,execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtempSync,readFileSync,rmSync,writeFileSync,mkdirSync} from 'node:fs';
import {request,createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
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
let server;
try{
 run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',file('ca.key'),'-out',file('ca.pem'),'-days','1','-subj','/CN=AgentKeychain ephemeral test CA','-addext','basicConstraints=critical,CA:TRUE']);
 run('openssl',['req','-newkey','rsa:2048','-nodes','-keyout',file('server.key'),'-out',file('request.pem'),'-subj','/CN='+names[0]]);
 writeFileSync(file('ext'),['basicConstraints=critical,CA:FALSE','extendedKeyUsage=serverAuth','subjectAltName='+names.map(host=>'DNS:'+host).join(',')].join('\n'));
 run('openssl',['x509','-req','-in',file('request.pem'),'-CA',file('ca.pem'),'-CAkey',file('ca.key'),'-CAcreateserial','-out',file('server.pem'),'-days','1','-extfile',file('ext')]);
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
 const get=(host,path,trust=true)=>new Promise((resolve,reject)=>{
  const req=request({hostname:host,port,path,agent:false,ca:trust?ca:undefined,
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
  const home=file('home'),db=join(home,'.pki','nssdb');
  mkdirSync(db,{recursive:true});
  const env={...process.env,HOME:home,XDG_CONFIG_HOME:file('config'),XDG_DATA_HOME:file('data'),XDG_CACHE_HOME:file('cache')};
  run('certutil',['-N','-d','sql:'+db,'--empty-password'],env);
  run('certutil',['-A','-d','sql:'+db,'-n','akc-disposable-root','-t','C,,','-i',file('ca.pem')],env);
  const flags=['--headless','--no-first-run','--disable-background-networking','--no-proxy-server',
   '--host-resolver-rules='+names.map(host=>'MAP '+host+' 127.0.0.1').join(', ')];
  const render=async (path, profile)=>promisify(execFile)(process.env.CHROMIUM??'chromium',[...flags,'--dump-dom','--timeout=10000','--user-data-dir='+file(profile),origins[0]+path],{env,timeout:20_000,maxBuffer:1024*1024});
  const doc=await render('/continuation/approve#handoff='+'a'.repeat(43),'continuation-profile');
  assert.match(doc.stdout,/<div id="manual" hidden="">/);
  assert.doesNotMatch(doc.stdout,/<div id="handoff" hidden/);
  // Unlike --dump-dom, retain the real browser until its async network/CSP
  // assertions report back to this isolated HTTPS server, or time out.
  const child=spawn(process.env.CHROMIUM??'chromium',[...flags,'--remote-debugging-pipe','--user-data-dir='+file('probe-profile'),'about:blank'],
   {env,stdio:['ignore','ignore','pipe','pipe','pipe']});
  const cdp=chromiumTestPipe(child);
  const start=async()=>{
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
     return probeComplete;
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
    delay(22_000,undefined,{signal:timer.signal}).then(()=>{throw new Error(`browser HTTPS probe timed out; requests: ${JSON.stringify(received.slice(-12))}\n${stderr}`);}),
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
  console.log('PASS sandboxed browser: signed TLS transport, bundle, CSP, host-only cookie and WebAuthn registration and a verified assertion with a disposable virtual authenticator');
 }
}finally{
 if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 rmSync(dir,{recursive:true,force:true});
}
