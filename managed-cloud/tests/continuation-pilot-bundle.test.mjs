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
