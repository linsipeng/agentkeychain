/** One-run actual compiled pilot Auth; only invitation/signing keys are synthetic. */
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readdir,readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {unstable_splitSqlQuery} from 'wrangler';
import {verifyGenesisApproval} from '../shared/genesis-approval.ts';
import {checkpoint as signCheckpoint,genesisRoot} from '../shared/checkpoints.ts';
import {verifyWitness,WITNESS_DOMAIN} from '../shared/roster-witness.ts';
import {canonicalGrant,requestProof} from '../shared/device-protocol.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest} from '../shared/roster.ts';

export const pilotBrowserHost='auth-pilot-browser.fixture.invalid';
export const pilotBrowserOrigin='https://'+pilotBrowserHost;
const mainOrigin='https://api.web-pilot-browser.fixture.invalid';
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
 await build({absWorkingDir:relative('.'),entryPoints:['api-worker/index.ts','recovery-worker/index.ts'],
  outbase:'.',outdir:'dist/compiled-browser',bundle:true,format:'esm',platform:'neutral',mainFields:['module','main'],
  external:['cloudflare:workers','cloudflare:email','node:buffer','node:net'],target:'es2022'});
 const [genesis,approval,invite,device,wrap,checkpoint,witness,recoveryApi,recoveryCustody]=
  [key(),key(),key(),key(),key('x25519'),key(),key(),key(),key()];
 const now=Math.floor(Date.now()/1000),expiresAt=now+180,database='compiled-browser-auth',
  mainDatabase='compiled-browser-main',custodyDatabase='compiled-browser-custody',base={
  modules:true,compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
  outboundService:()=>new Response(null,{status:502})};
 const policy={genesis:genesis.pin,approval:approval.pin,checkpointKeys:[checkpoint.pin],recoveryAuthorities:[],witnesses:[witness.pin]};
 const signer=(name,role,kind)=>({...base,name,bindings:{ROLE:JSON.stringify({...role.pin,privateKey:role.pkcs8}),KIND:kind},
  script:`import {WorkerEntrypoint} from 'cloudflare:workers';
   export class Signer extends WorkerEntrypoint {
    async key(){const {keyId,publicKey}=JSON.parse(this.env.ROLE);return {keyId,publicKey};}
    async sign(message){
     if(typeof message!=='string'||message.length>4096)throw new Error('wrong_synthetic_role');
     const kind=this.env.KIND;
     if(kind==='genesis'&&!message.startsWith('AgentKeychain-managed-genesis-approval-v1'+String.fromCharCode(0)))throw new Error('wrong_synthetic_role');
     if(kind==='witness'&&!message.startsWith(${JSON.stringify(WITNESS_DOMAIN)}))throw new Error('wrong_synthetic_role');
     if(kind==='checkpoint'){
      const c=JSON.parse(message);
      if(Object.keys(c).join(',')!=='version,tenantId,vaultId,keyId,sequence,root,previousRoot,operationDigest'||
         c.version!==1||c.tenantId!=='browser-test-tenant'||c.vaultId!=='browser-test-vault'||
         c.keyId!==(await this.key()).keyId||c.sequence!==0||c.previousRoot!==null||c.operationDigest!==null)throw new Error('wrong_synthetic_checkpoint');
     }
     if(!['genesis','witness','checkpoint'].includes(kind))throw new Error('outside_browser_genesis_test');
     const bytes=Uint8Array.from(atob(JSON.parse(this.env.ROLE).privateKey),c=>c.charCodeAt(0));
     const k=await crypto.subtle.importKey('pkcs8',bytes,'Ed25519',false,['sign']);
     return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',k,new TextEncoder().encode(message)))));
    }
   }
   export default {fetch(){return new Response(null,{status:404});}};`});
 const checkpointService={name:'browser-checkpoint-signer',entrypoint:'Signer'};
 const mf=new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',port:0,workers:[
  {...base,name:database,routes:[pilotBrowserOrigin+'/*'],scriptPath:relative('dist/auth-trust-worker/pilot-continuation.js'),d1Databases:{AUTH:database},
   bindings:{PILOT_AUTH_MODE:'continuation-v1',PILOT_AUTH_ORIGIN:pilotBrowserOrigin,PILOT_AUTH_EXPIRES_AT:String(expiresAt),
    PILOT_AUTH_PINS:JSON.stringify(policy),PILOT_HANDOFF_HMAC:randomBytes(32).toString('base64'),PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',
    PILOT_GENESIS_CONSENT_MODE:'consent-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(invite.pin)},
   serviceBindings:{PILOT_APPROVAL_SIGNER:{name:'browser-continuation-disabled',entrypoint:'Signer'},
    PILOT_GENESIS_APPROVAL_SIGNER:{name:'browser-genesis-signer',entrypoint:'Signer'},
    PILOT_CUSTODY_READINESS:{name:'browser-package-readiness-disabled',entrypoint:'PilotCustodyReadiness'}}},
  {...base,name:'browser-package-readiness-disabled',scriptPath:relative('dist/custody-trust-worker/pilot-continuation.js')},
  {...base,name:custodyDatabase,scriptPath:relative('dist/compiled-browser/recovery-worker/index.js'),d1Databases:{CUSTODIAN:custodyDatabase},
   bindings:{GENESIS_ADMISSION_MODE:'independent-v1',GENESIS_APPROVAL_PIN:JSON.stringify(genesis.pin)},
   serviceBindings:{ROSTER_WITNESS_SIGNER:{name:'browser-witness-signer',entrypoint:'Signer'},
    RECOVERY_TRUST_POLICY:{name:'browser-release-policy',entrypoint:'Policy'}}},
  {...base,name:'browser-release-policy',bindings:{MANIFEST:JSON.stringify({checkpointKeys:policy.checkpointKeys,
   recoveryAuthorities:policy.recoveryAuthorities,witnessKeys:policy.witnesses,recoveryServices:{api:recoveryApi.pin,custodian:recoveryCustody.pin}})},
   script:`import {WorkerEntrypoint} from 'cloudflare:workers';
    export class Policy extends WorkerEntrypoint {async manifest(){return this.env.MANIFEST;}}
    export default {fetch(){return new Response(null,{status:404});}};`},
  {...base,name:mainDatabase,routes:[mainOrigin+'/*'],scriptPath:relative('dist/compiled-browser/api-worker/index.js'),d1Databases:{MAIN:mainDatabase},
   bindings:{AUTH_ORIGIN:pilotBrowserOrigin,DEVICE_API_ORIGIN:mainOrigin},
   serviceBindings:{RECOVERY:{name:custodyDatabase,entrypoint:'Custodian'},CHECKPOINT_SIGNER:checkpointService,
    TRUSTED_AUTH_SOURCE:{name:'browser-test-ingress',entrypoint:'Source'}}},
  {...base,name:'browser-test-ingress',script:`import {WorkerEntrypoint} from 'cloudflare:workers';
   export class Source extends WorkerEntrypoint {async resolve(req){const url=new URL(req.url);
    if(url.origin!==${JSON.stringify(mainOrigin)}||url.pathname!=='/v1/devices/roster-put')throw new Error('outside_browser_test_ingress');
    return 'browser-device-fixture';}}
   export default {fetch(){return new Response(null,{status:404});}};`},
  {...base,name:'browser-private-probe',serviceBindings:{ADMISSION:{name:custodyDatabase,entrypoint:'GenesisAdmission'},
    HEAD:{name:custodyDatabase,entrypoint:'Custodian'},CHECKPOINT:checkpointService},
   script:`import {WorkerEntrypoint} from 'cloudflare:workers';
    export default class extends WorkerEntrypoint {
     async admit(v){return JSON.stringify(structuredClone(await this.env.ADMISSION.admit(v)));}
     async head(t,v){return JSON.stringify(structuredClone(await this.env.HEAD.witnessHead(t,v)));}
     async ingress(){return (await this.env.ADMISSION.fetch('https://custody.fixture.invalid/')).status;}
     async checkpoint(s){return this.env.CHECKPOINT.sign(s);}
    }`},
  signer('browser-genesis-signer',genesis,'genesis'),signer('browser-continuation-disabled',approval,'disabled'),
  signer('browser-witness-signer',witness,'witness'),signer('browser-checkpoint-signer',checkpoint,'checkpoint'),
 ]}));
 try{
  await mf.ready;
  const db=await mf.getD1Database('AUTH',database),main=await mf.getD1Database('MAIN',mainDatabase),custody=await mf.getD1Database('CUSTODIAN',custodyDatabase);
  for(const [folder,store] of [['api-worker',main],['recovery-worker',custody]]){
   const directory=relative(folder+'/migrations');
   for(const name of (await readdir(directory)).filter(n=>n.endsWith('.sql')).sort())
    await store.batch(unstable_splitSqlQuery(await readFile(directory+'/'+name,'utf8')).map(sql=>store.prepare(sql)));
  }
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
  },admitAndPublish:async proof=>{
   // Consume the exact browser-returned envelope. The graph has no legacy genesis binding.
   const probe=await mf.getWorker('browser-private-probe'),root=await genesisRoot(tenantId,vaultId);
   assert.equal(await probe.ingress(),404);
   const cp=await signCheckpoint({key:async()=>checkpoint.pin,sign:s=>probe.checkpoint(s)},tenantId,vaultId,0,root,null,null);
   const input={proof,grant:oldGrantCanonical,roster,checkpoint:cp};
   const count=(store,table)=>store.prepare('SELECT count(*) n FROM '+table).first('n');
   assert.equal(await count(custody,'genesis_admissions'),0);
   assert.equal(await count(main,'signed_rosters'),0);
   const wrongRole={...proof,signature:invite.sign('AgentKeychain-managed-genesis-approval-v1\0'+proof.canonical)};
   await assert.rejects(async()=>await probe.admit({...input,proof:wrongRole}),/genesis_admission_rejected/);
   assert.equal(await count(custody,'genesis_admissions'),0);
   const admission=JSON.parse(await probe.admit(input));
   assert.deepEqual(JSON.parse(await probe.admit(input)),admission);
   assert.deepEqual(JSON.parse(await probe.head(tenantId,vaultId)),admission);
   const rosterHash=await rosterDigest(roster),verified=await verifyWitness(admission,[witness.pin],
    {accountId,tenantId,vaultId,revision:1,digest:rosterHash},cp);
   assert.equal(verified.root,root);assert.equal(verified.sequence,0);assert.equal(verified.event,1);
   assert.equal(await count(custody,'genesis_admissions'),1);
   assert.equal(await count(custody,'roster_witness'),1);
   assert.equal(await custody.prepare('SELECT attempt_digest FROM genesis_admissions').first('attempt_digest'),
    hash(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',proof,oldGrantCanonical,roster,cp])));
   // Only the already-enrolled synthetic device/session are setup data. Main itself commits and acknowledges the roster.
   const session=random(),sessionDigest=hash(session);
   await main.batch([
    main.prepare('INSERT INTO accounts VALUES(?)').bind(accountId),main.prepare('INSERT INTO tenants VALUES(?)').bind(tenantId),
    main.prepare('INSERT INTO memberships VALUES(?,?,1)').bind(tenantId,accountId),
    main.prepare('INSERT INTO vaults VALUES(?,?,0)').bind(tenantId,vaultId),
    main.prepare('INSERT INTO devices VALUES(?,?,?,?,1)').bind(tenantId,deviceId,accountId,signingKey),
    main.prepare('INSERT INTO device_keys VALUES(?,?,?)').bind(tenantId,deviceId,wrappingKey),
    main.prepare('INSERT INTO vault_devices VALUES(?,?,?,1)').bind(tenantId,vaultId,deviceId),
    main.prepare('INSERT INTO device_sessions(digest,tenant_id,vault_id,device_id,account_id,expires_at,active) VALUES(?,?,?,?,?,unixepoch()+180,1)').bind(sessionDigest,tenantId,vaultId,deviceId,accountId),
   ]);
   const url=new URL(mainOrigin+'/v1/devices/roster-put'),body=JSON.stringify(roster),timestamp=Math.floor(Date.now()/1000),nonce=random();
   const response=await mf.dispatchFetch(url,{method:'POST',body,headers:{'content-type':'application/json',authorization:'Bearer '+session,
    'x-device-timestamp':String(timestamp),'x-device-nonce':nonce,'x-device-proof':device.sign(requestProof('POST',url,hash(body),timestamp,nonce,sessionDigest))}});
   assert.equal(response.status,200);
   assert.deepEqual(await response.json(),{accepted:true,witness:admission});
   assert.deepEqual(await main.prepare('SELECT canonical,signature FROM signed_rosters').first(),roster);
   assert.deepEqual(await main.prepare('SELECT state,digest,receipt FROM roster_witness_sagas').first(),
    {state:'acknowledged',digest:rosterHash,receipt:JSON.stringify(admission)});
   assert.equal(await count(custody,'genesis_admissions'),1);
   assert.equal(await count(custody,'roster_witness'),1);
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
 await pilot.admitAndPublish(proof);
 assert.equal(await evaluate("document.cookie.includes('akc_')"),false);
 await cdp('Target.closeTarget',{targetId});
}
