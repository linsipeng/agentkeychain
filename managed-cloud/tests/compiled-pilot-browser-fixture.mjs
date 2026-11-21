/** One-run actual compiled pilot Auth; only invitation/signing keys are synthetic. */
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {unstable_splitSqlQuery} from 'wrangler';
import {verifyGenesisApproval} from '../shared/genesis-approval.ts';
import {canonicalGrant} from '../shared/device-protocol.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest} from '../shared/roster.ts';

export const pilotBrowserHost='auth-pilot-browser.fixture.invalid';
export const pilotBrowserOrigin='https://'+pilotBrowserHost;
const relative=name=>fileURLToPath(new URL('../'+name,import.meta.url));
const hash=s=>createHash('sha256').update(s).digest('hex');
const random=()=>randomBytes(32).toString('base64url');
function key(algorithm='ed25519'){
 const p=generateKeyPairSync(algorithm),publicKey=p.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 return {pin:{keyId:hash(publicKey),publicKey},sign:message=>sign(null,Buffer.from(message),p.privateKey).toString('base64'),
  pkcs8:p.privateKey.export({format:'der',type:'pkcs8'}).toString('base64')};
}
export async function createCompiledPilotBrowserFixture(fixtureFile){
 execFileSync(process.execPath,[relative('build-continuation-pilot.mjs')],{stdio:'pipe',timeout:15000});
 const [genesis,approval,invite,device,wrap,checkpoint,witness]=[key(),key(),key(),key(),key('x25519'),key(),key()];
 const now=Math.floor(Date.now()/1000),expiresAt=now+180,database='compiled-browser-auth',base={
  modules:true,compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
  outboundService:()=>new Response(null,{status:502})};
 const policy={genesis:genesis.pin,approval:approval.pin,checkpointKeys:[checkpoint.pin],recoveryAuthorities:[],witnesses:[witness.pin]};
 const mf=new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',port:0,workers:[
  {...base,name:database,routes:[pilotBrowserOrigin+'/*'],scriptPath:relative('dist/auth-trust-worker/pilot-continuation.js'),d1Databases:{AUTH:database},
   bindings:{PILOT_AUTH_MODE:'continuation-v1',PILOT_AUTH_ORIGIN:pilotBrowserOrigin,PILOT_AUTH_EXPIRES_AT:String(expiresAt),
    PILOT_AUTH_PINS:JSON.stringify(policy),PILOT_HANDOFF_HMAC:randomBytes(32).toString('base64'),PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',
    PILOT_GENESIS_CONSENT_MODE:'consent-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(invite.pin)},
   serviceBindings:{PILOT_APPROVAL_SIGNER:{name:'browser-signers',entrypoint:'Continuation'},PILOT_GENESIS_APPROVAL_SIGNER:{name:'browser-signers',entrypoint:'Genesis'},
    PILOT_CUSTODY_READINESS:{name:'browser-custody',entrypoint:'PilotCustodyReadiness'}}},
  {...base,name:'browser-custody',scriptPath:relative('dist/custody-trust-worker/pilot-continuation.js')},
  {...base,name:'browser-signers',bindings:{GENESIS:JSON.stringify({...genesis.pin,privateKey:genesis.pkcs8}),CONTINUATION:JSON.stringify({...approval.pin,privateKey:approval.pkcs8})},
   script:`import {WorkerEntrypoint} from 'cloudflare:workers';
    class Role extends WorkerEntrypoint {
     async key(){const {keyId,publicKey}=JSON.parse(this.env[this.role]);return {keyId,publicKey};}
    }
    export class Genesis extends Role {role='GENESIS';async sign(message){
     if(typeof message!=='string'||message.length>4096||!message.startsWith('AgentKeychain-managed-genesis-approval-v1\\0'))throw new Error('wrong_synthetic_role');
     const bytes=Uint8Array.from(atob(JSON.parse(this.env.GENESIS).privateKey),c=>c.charCodeAt(0));
     const k=await crypto.subtle.importKey('pkcs8',bytes,'Ed25519',false,['sign']);
     return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',k,new TextEncoder().encode(message)))));
    }}
    export class Continuation extends Role {role='CONTINUATION';async sign(){throw new Error('outside_browser_genesis_test');}}
    export default {fetch(){return new Response(null,{status:404});}};`},
 ]}));
 try{
  await mf.ready;
  const db=await mf.getD1Database('AUTH',database);
  for(const filename of ['auth-trust-worker/experimental/genesis-registration.sql','auth-trust-worker/pilot-migrations/0001-exact-genesis-registration.sql'])
   await db.batch(unstable_splitSqlQuery(await readFile(relative(filename),'utf8')).map(sql=>db.prepare(sql)));
  const bound={accountId:'browser-test-account',tenantId:'browser-test-tenant',vaultId:'browser-test-vault',deviceId:'browser-test-device',requestId:random(),keyEpoch:1};
  const {accountId,tenantId,vaultId,deviceId,keyEpoch}=bound,signingKey=device.pin.publicKey,wrappingKey=wrap.pin.publicKey;
  const oldGrantCanonical=canonicalGrant({version:1,...bound,signingKey,wrappingKey,issuerDeviceId:null,expiresAt});
  const rosterCanonical=canonicalRoster({version:1,accountId,tenantId,vaultId,revision:1,previousDigest:null,keyEpoch,active:[{deviceId,signingKey,wrappingKey}],
   revoked:[],issuer:{kind:'device',id:deviceId},issuedAt:now,expiresAt,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:[],recovery:null});
  const roster={canonical:rosterCanonical,signature:device.sign(ROSTER_DOMAIN+rosterCanonical)};
  const canonical=JSON.stringify({version:1,domain:'AgentKeychain-pilot-genesis-registration-invite-v1',keyId:invite.pin.keyId,
   origin:pilotBrowserOrigin,rpId:pilotBrowserHost,id:random(),...bound,grantDigest:hash(oldGrantCanonical),
   rosterDigest:await rosterDigest(roster),issuedAt:now,expiresAt:now+150});
  await writeFile(fixtureFile,JSON.stringify({invite:{canonical,signature:invite.sign(canonical)},oldGrantCanonical,roster}),{mode:0o600,flag:'wx'});
  return {db,dispatch:(url,init)=>{
   if(new URL(url).origin!==pilotBrowserOrigin)throw new Error('not_synthetic_pilot_origin');
   return mf.dispatchFetch(url,init);
  },dispose:()=>mf.dispose(),assertReceipt:async proof=>{
   const verified=await verifyGenesisApproval(proof,oldGrantCanonical,roster,
    {authority:genesis.pin,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities});
   assert.equal(verified.authorityKeyId,genesis.pin.keyId);
   assert.equal(verified.grantDigest,hash(oldGrantCanonical));
   assert.equal(verified.rosterDigest,await rosterDigest(roster));
   const scope=JSON.parse(oldGrantCanonical);
   assert.equal(scope.accountId,bound.accountId);
   assert.equal(scope.requestId,bound.requestId);
   assert.deepEqual(proof,await db.prepare('SELECT canonical,signature FROM auth_genesis_decisions').first());
   assert.equal(await db.prepare('SELECT count(*) n FROM auth_genesis_decisions').first('n'),1);
   assert.equal(await db.prepare('SELECT count(*) n FROM auth_genesis_pins').first('n'),1);
  }};
 }catch(error){await mf.dispose();throw error;}
}

/** Exercise the shipped pilot page and its actual Worker handlers, not a probe page. */
export async function verifyCompiledPilotBrowser(cdp,pilot,fixtureFile,delay){
 const {targetId}=await cdp('Target.createTarget',{url:'about:blank'});
 const {sessionId}=await cdp('Target.attachToTarget',{targetId,flatten:true});
 const call=(name,params={})=>cdp(name,params,sessionId);
 const evaluate=async(expression,userGesture=false)=>{
  const result=await call('Runtime.evaluate',{expression,userGesture,returnByValue:true});
  assert.ok(!result.exceptionDetails,'compiled pilot browser evaluation failed');
  return result.result.value;
 };
 const until=async(expression,description)=>{
  for(let i=0;i<100;i++){
   if(await evaluate(expression))return;
   await delay(75);
  }
  const status=await evaluate("document.getElementById('status')?.textContent||''");
  throw new Error('compiled pilot browser missed '+description+' ('+status+')');
 };
 const total=table=>pilot.db.prepare('SELECT count(*) n FROM '+table).first('n');
 await call('WebAuthn.enable',{enableUI:false});
 await call('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,
  hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const navigation=await call('Page.navigate',{url:pilotBrowserOrigin+'/pilot/genesis'});
 assert.ok(!navigation.errorText,navigation.errorText);
 await until("location.origin==="+JSON.stringify(pilotBrowserOrigin)+"&&isSecureContext&&document.readyState==='complete'&&!!document.getElementById('fixture')",'exact HTTPS page');
 const {root}=await call('DOM.getDocument');
 const {nodeId}=await call('DOM.querySelector',{nodeId:root.nodeId,selector:'#fixture'});
 assert.ok(nodeId);
 await call('DOM.setFileInputFiles',{nodeId,files:[fixtureFile]});
 const click=async id=>{
  await until("document.getElementById('"+id+"')?.disabled===false",id+' enabled');
  await evaluate("document.getElementById('"+id+"').click()",true);
 };
 await click('register');
 await until("!document.getElementById('review-approval').disabled",'verified registration');
 assert.equal(await total('auth_genesis_pins'),1);
 const {cookies}=await call('Network.getCookies',{urls:[pilotBrowserOrigin+'/pilot/genesis']});
 const session=cookies.find(c=>c.name==='__Host-akc_pilot_genesis_registration');
 assert.ok(session,'Chromium stores the actual pilot Auth session cookie');
 assert.equal(session.secure,true);
 assert.equal(session.httpOnly,true);
 assert.equal(session.sameSite,'Strict');
 assert.equal(session.domain,pilotBrowserHost);
 assert.equal(session.path,'/');

 assert.equal(await total('auth_genesis_decisions'),0);
 await click('review-approval');
 await until("!document.getElementById('approve').disabled",'review accepted');
 assert.equal(await total('auth_genesis_decisions'),0);
 await click('approve');
 await until("!document.getElementById('receipt').hidden",'verified consent and signed receipt');
 const proof=JSON.parse(await evaluate("document.getElementById('proof').value"));
 await pilot.assertReceipt(proof);
 assert.equal(await evaluate("document.cookie.includes('akc_')"),false);
 await cdp('Target.closeTarget',{targetId});
}
