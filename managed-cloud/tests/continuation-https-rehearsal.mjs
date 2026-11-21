/** Disposable transport rehearsal, never a deployable auth backend.
 * Run with Node 24: node --experimental-strip-types managed-cloud/tests/continuation-https-rehearsal.mjs [--browser]
 * --browser requires a sandbox-capable Chromium and certutil. No authenticator is invoked. */
import assert from 'node:assert/strict';
import {execFileSync,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtempSync,readFileSync,rmSync,writeFileSync,mkdirSync} from 'node:fs';
import {request,createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
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
 const token='fixture-noncredential';
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
     'set-cookie':'__Host-akc_rehearsal='+token+'; Secure; HttpOnly; SameSite=Strict; Path=/'});
    res.end('<!doctype html><p id="proof">pending</p><script src="/probe.js"></script>');return;
   }
   if(req.method==='GET'&&u.pathname==='/probe.js'&&origin===origins[0]){
    res.writeHead(200,{'content-type':'application/javascript'});
    res.end(`(async()=>{const r=await fetch('/cookie');let blocked=false;try{await fetch(${JSON.stringify(origins[1]+'/cookie')});}catch{blocked=true;}if(r.ok&&blocked&&isSecureContext&&typeof PublicKeyCredential==='function'&&typeof navigator.credentials?.get==='function'&&!document.cookie.includes('akc_rehearsal'))document.querySelector('#proof').textContent='secure-context-csp-cookie-webauthn-available';})();`);return;
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
   '--host-resolver-rules='+names.map(host=>'MAP '+host+' 127.0.0.1').join(', '),'--dump-dom','--timeout=10000'];
  const render=async (path, profile)=>promisify(execFile)(process.env.CHROMIUM??'chromium',[...flags,'--user-data-dir='+file(profile),origins[0]+path],{env,timeout:20_000,maxBuffer:1024*1024});
  const doc=await render('/continuation/approve#handoff='+'a'.repeat(43),'continuation-profile');
  assert.match(doc.stdout,/<div id="manual" hidden="">/);
  assert.doesNotMatch(doc.stdout,/<div id="handoff" hidden/);
  const browserProbe=await render('/probe','probe-profile');
  assert.match(browserProbe.stdout,/>secure-context-csp-cookie-webauthn-available</);
  assert.ok(received.some(r=>r.origin===origins[0]&&r.path==='/cookie'&&r.cookie));
  assert.ok(!received.some(r=>r.origin===origins[1]&&r.path==='/cookie'));
  console.log('PASS sandboxed browser: signed TLS transport, bundle, CSP, host-only cookie and WebAuthn API reachability; no authenticator invoked');
 }
}finally{
 if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 rmSync(dir,{recursive:true,force:true});
}
