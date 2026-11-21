/** Run after the explicit build: node --test tests/continuation-pilot-bundle.test.mjs */
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import pilot from '../dist/auth-trust-worker/pilot-continuation.js';
import mainPilot from '../dist/api-worker/pilot-continuation-post.js';

const pin=()=>{
 const publicKey=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64');
 return {keyId:createHash('sha256').update(publicKey).digest('hex'),publicKey};
};
const origin='https://auth-pilot-v07.sandbox.example';
const request=(path,method='GET')=>new Request(origin+path,{method});
const fixture=()=>{
 const approval=pin(),config={genesis:pin(),approval,checkpointKeys:[pin()],recoveryAuthorities:[],witnesses:[pin()]},calls=[];
 const env={AUTH:{prepare(){calls.push('db');throw new Error('unexpected database');}},PILOT_AUTH_MODE:'continuation-v1',
  PILOT_AUTH_ORIGIN:origin,PILOT_AUTH_EXPIRES_AT:String(Math.floor(Date.now()/1000)+120),PILOT_AUTH_PINS:JSON.stringify(config),
  PILOT_APPROVAL_SIGNER:{async key(){calls.push('pin');return approval;},async sign(){calls.push('sign');throw new Error('unexpected signature');}},
  PILOT_CUSTODY_READINESS:{async readiness(){calls.push('custody');throw new Error('unavailable');}},
  PILOT_HANDOFF_HMAC:Buffer.alloc(32,1).toString('base64')};
 return {env,calls,config};
};

test('compiled pilot serves only the exact origin assets, with embedded browser and security headers',async()=>{
 const {env,calls}=fixture();
 const page=await pilot.fetch(request('/continuation/approve'),env);
 const js=await pilot.fetch(request('/continuation/approve/browser.js'),env);
 assert.equal(page.status,200);assert.equal(js.status,200);
 assert.match(await page.text(),/使用通行密钥确认/);
 assert.match(await js.text(),/navigator.credentials.get/);
 assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
 assert.equal(page.headers.get('cache-control'),'no-store');
 for(const req of [new Request('https://normal.example/continuation/approve'),new Request('http://auth-pilot-v07.sandbox.example/continuation/approve'),
  request('/continuation/approve?bypass=1'),request('/continuation/approve','POST'),request('/v1/auth/session'),request('/v1/auth/continuation-handoff/other','POST')]){
  assert.equal((await pilot.fetch(req,env)).status,404);
 }
 assert.deepEqual(calls,['pin','pin']);
});

test('compiled pilot is closed for missing mode, deadlines, bindings, signer substitution or reused role',async()=>{
 const {env,config}=fixture(),req=request('/continuation/approve');
 for(const patch of [{PILOT_AUTH_MODE:undefined},{PILOT_AUTH_MODE:'enabled'},{PILOT_AUTH_ORIGIN:'https://normal.example'},
  {PILOT_AUTH_EXPIRES_AT:String(Math.floor(Date.now()/1000)-1)},{PILOT_AUTH_EXPIRES_AT:String(Math.floor(Date.now()/1000)+8*86400)},
  {AUTH:undefined},{PILOT_CUSTODY_READINESS:undefined},{PILOT_HANDOFF_HMAC:'x'},
  {PILOT_APPROVAL_SIGNER:{...env.PILOT_APPROVAL_SIGNER,key:async()=>pin()}},
  {PILOT_AUTH_PINS:JSON.stringify({...config,witnesses:[config.approval]})}]){
  const result=await pilot.fetch(req,{...env,...patch});
  assert.equal(result.status,404);assert.equal(await result.text(),'');assert.equal(result.headers.get('cache-control'),'no-store');
 }
});

test('missing exact proof in a known route cannot invoke database, readiness, or signing',async()=>{
 const {env,calls}=fixture();
 const denied=await pilot.fetch(new Request(origin+'/v1/auth/continuation-approval/begin',{
  method:'POST',headers:{origin,'content-type':'application/json'},body:'{}',
 }),env);
 assert.equal(denied.status,401);
 assert.deepEqual(calls,['pin']);
});

test('compiled Main pilot closes unconfigured and long-lived origins without touching storage',async()=>{
 const mainOrigin='https://api.web-pilot-v07.sandbox.example';
 const make=(origin=mainOrigin)=>new Request(origin+'/v1/pilot/continuation/post-commit-proof',{
  method:'POST',headers:{'content-type':'application/json'},body:'{}',
 });
 let reads=0,rpcs=0;
 const env={MAIN:{withSession(){reads++;throw new Error('unexpected database');}},PILOT_MAIN_MODE:'continuation-v1',
  PILOT_MAIN_ORIGIN:mainOrigin,PILOT_MAIN_EXPIRES_AT:String(Math.floor(Date.now()/1000)+120),PILOT_CUSTODY_WITNESS:JSON.stringify(pin()),
  PILOT_CUSTODY_POST:{async post(){rpcs++;throw new Error('unexpected RPC');}}};
 for(const [request,override] of [[make(),{PILOT_MAIN_MODE:undefined}],
  [make(),{PILOT_MAIN_EXPIRES_AT:String(Math.floor(Date.now()/1000)+8*86400)}],
  [make('https://api.example.com'),{PILOT_MAIN_ORIGIN:'https://api.example.com'}],[make(),{}]]){
  assert.equal((await mainPilot.fetch(request,{...env,...override})).status,404);
 }
 assert.deepEqual([reads,rpcs],[0,0]);
});

test('compiled pilot registration stays closed unless exact separate mode and distinct invite pin are configured',async()=>{
 const {env,config}=fixture(),path='/v1/auth/pilot-genesis/registration/begin';
 const req=()=>new Request(origin+path,{method:'POST',headers:{origin,'sec-fetch-site':'same-origin','content-type':'application/json'},body:'{}'});
 for(const patch of [{},{PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1'},
  {PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(config.genesis)},
  {PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(config.witnesses[0])}]){
  assert.equal((await pilot.fetch(req(),{...env,...patch})).status,404);
 }
 assert.equal((await pilot.fetch(req(),{...env,PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(pin())})).status,401);
});

test('compiled first-device consent only mounts with separate explicit mode and exact genesis signer role',async()=>{
 const {env,config}=fixture(),path='/v1/auth/pilot-genesis/consent/begin';
 const req=()=>new Request(origin+path,{method:'POST',headers:{origin,'sec-fetch-site':'same-origin','content-type':'application/json'},body:'{}'});
 const on={...env,PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(pin())};
 const role=(key)=>({async key(){return key;},async sign(){throw new Error('unexpected signature');}});
 for(const patch of [{},{PILOT_GENESIS_CONSENT_MODE:'consent-v1'},
  {PILOT_GENESIS_CONSENT_MODE:'consent-v1',PILOT_GENESIS_APPROVAL_SIGNER:role(config.approval)}]){
  assert.equal((await pilot.fetch(req(),{...on,...patch})).status,404);
 }
 assert.equal((await pilot.fetch(req(),{...on,PILOT_GENESIS_CONSENT_MODE:'consent-v1',PILOT_GENESIS_APPROVAL_SIGNER:role(config.genesis)})).status,401);
});

test('compiled genesis browser rehearses explicit create, fresh get and lost-response readback in memory',async()=>{
 const {env,config}=fixture();
 const on={...env,PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(pin()),
  PILOT_GENESIS_CONSENT_MODE:'consent-v1',PILOT_GENESIS_APPROVAL_SIGNER:{async key(){return config.genesis;},async sign(){throw new Error('unexpected');}}};
 const pageReq=()=>new Request(origin+'/pilot/genesis');
 assert.equal((await pilot.fetch(pageReq(),env)).status,404);
 assert.equal((await pilot.fetch(new Request(origin+'/pilot/genesis?invite=no'),on)).status,404);
 const page=await pilot.fetch(pageReq(),on);
 assert.equal(page.status,200);
 assert.match(page.headers.get('content-security-policy'),/connect-src 'self'; form-action 'none'/);
 assert.equal(page.headers.get('permissions-policy'),'publickey-credentials-get=(self), publickey-credentials-create=(self)');
 assert.match(await page.text(),/id="approve" disabled/);
 const asset=await pilot.fetch(new Request(origin+'/pilot/genesis/browser.js'),on);
 const script=await asset.text();
 assert.equal(asset.status,200);
 assert.doesNotMatch(script,/localStorage|sessionStorage|indexedDB|location.hash|credentials:\s*"include"/);

 const handlers={},elements={},calls=[],errors=[];
 for(const id of ['fixture','register','review-approval','approve','readback','status','details','account','vault','device','proof','receipt']){
  elements[id]={disabled:id!=='fixture',addEventListener(event,cb){handlers[id+'/'+event]=cb;}};
 }
 const op={canonical:'synthetic',signature:'synthetic'},accountId='account',vaultId='vault',deviceId='device',
  payload={invite:op,oldGrantCanonical:JSON.stringify({accountId,vaultId,deviceId}),roster:op},csrf='a'.repeat(43),id='b'.repeat(43),
  rpId=new URL(origin).hostname,buffer=new ArrayBuffer(2);
 elements.fixture.files=[{size:100,text:async()=>JSON.stringify(payload)}];
 const fakeCredential={id:'Ag',rawId:buffer,type:'public-key',getClientExtensionResults:()=>({}),
  response:{clientDataJSON:buffer,attestationObject:buffer,authenticatorData:buffer,signature:buffer,userHandle:null}};
 const replacements={document:{getElementById:id=>elements[id]},window:{PublicKeyCredential:function(){}},isSecureContext:true,location:{hostname:rpId},
  navigator:{credentials:{
   async create({publicKey}){calls.push('create');assert.equal(publicKey.authenticatorSelection.userVerification,'required');return fakeCredential;},
   async get({publicKey}){calls.push('get');assert.equal(publicKey.userVerification,'required');return fakeCredential;},
  }},
  fetch:async(url,request)=>{
   calls.push(url.split('/').slice(-2).join('/'));
   try {
    assert.match(url,/^\/v1\/auth\/pilot-genesis\/(registration|consent)\/[a-z]+$/);
    assert.equal(request.credentials,'same-origin');assert.equal(request.redirect,'error');assert.equal(request.cache,'no-store');
    const sent=JSON.parse(request.body);assert.deepEqual(sent.invite,payload.invite);
    if(url.endsWith('registration/begin'))return Response.json({csrf,options:{challenge:'Ag',rp:{id:rpId},user:{id:'Ag'},authenticatorSelection:{userVerification:'required'}}});
    assert.equal(request.headers['x-csrf-token'],csrf);
    if(url.endsWith('registration/complete'))return new Response(null,{status:204});
    if(url.endsWith('consent/begin'))return Response.json({id,options:{rpId,challenge:'Ag',userVerification:'required'},display:{purpose:'approve-first-device-genesis',accountId,vaultId,deviceId}});
    assert.equal(sent.id,id);
    if(url.endsWith('consent/complete'))throw new Error('simulated lost response after commit');
    return Response.json(op);
   }catch(error){if(error.code==='ERR_ASSERTION')errors.push(error);throw error;}
  }};
 const originals=Object.fromEntries(Object.keys(replacements).map(k=>[k,Object.getOwnPropertyDescriptor(globalThis,k)]));
 try{
  for(const [k,value] of Object.entries(replacements))Object.defineProperty(globalThis,k,{value,configurable:true,writable:true});
  await import('data:text/javascript;base64,'+Buffer.from(script).toString('base64'));
  const event=async(key)=>{handlers[key]();await new Promise(resolve=>setImmediate(resolve));};
  await event('fixture/change');assert.deepEqual(calls,[]);
  await event('register/click');assert.deepEqual(calls,['registration/begin','create','registration/complete']);
  await event('review-approval/click');assert.equal(calls.at(-1),'consent/begin');assert.ok(!calls.includes('get'));
  await event('approve/click');assert.deepEqual(calls.slice(-2),['get','consent/complete']);assert.equal(elements.readback.disabled,false);
  await event('readback/click');assert.equal(calls.at(-1),'consent/readback');assert.equal(elements.proof.value,JSON.stringify(op));
  assert.equal(calls.filter(x=>x==='get').length,1);assert.deepEqual(errors,[]);
 }finally{
  for(const [key,descriptor] of Object.entries(originals)){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}
 }
});
