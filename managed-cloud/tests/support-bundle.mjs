/** Actual five production bundles + manifest-derived services and D1. Only the
 * external EMAIL provider is replaced; its synthetic mailbox never exposes codes. */
import assert from 'node:assert/strict';
import {readFile,readdir,mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes,generateKeyPairSync,createPrivateKey,sign as nodeSign} from 'node:crypto';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions,Log,LogLevel} from 'miniflare';
import {unstable_readConfig,unstable_getMiniflareWorkerOptions,unstable_splitSqlQuery} from 'wrangler';
import {manifests,plan,releaseManifest} from '../provisioning/render.mjs';
await build({entryPoints:['shared/recovery-crypto.ts','shared/recovery.ts','shared/roster.ts','shared/checkpoints.ts','shared/device-protocol.ts'],outdir:'dist/support-shared',bundle:true,format:'esm',platform:'node',target:'es2022'});
const {seal,open,encode64}=await import('../dist/support-shared/recovery-crypto.js');
const {packageContext,releaseContext}=await import('../dist/support-shared/recovery.js');
const {canonicalRoster,ROSTER_DOMAIN,rosterDigest}=await import('../dist/support-shared/roster.js');
const {checkpoint,genesisRoot}=await import('../dist/support-shared/checkpoints.js');
const {canonicalGrant}=await import('../dist/support-shared/device-protocol.js');
await build({entryPoints:['tests/genesis-transport-fixture.ts'],outfile:'dist/test-genesis-transport.mjs',bundle:true,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','node:buffer','node:net'],target:'es2022'});
execFileSync(process.execPath,['build-continuation-pilot.mjs']);
await build({entryPoints:['tests/virtual-authenticator.ts'],outfile:'dist/support-shared/pilot-passkey.js',bundle:true,format:'esm',platform:'node',target:'es2022'});
const {virtualAuthenticator}=await import('../dist/support-shared/pilot-passkey.js');
const sha=s=>createHash('sha256').update(s).digest('hex'),raw=()=>randomBytes(32).toString('base64url');
function ring(algorithm){const pair=generateKeyPairSync(algorithm),publicKey=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),keyId=sha(publicKey);return {activeId:keyId,keys:[{keyId,publicKey,privateKey:pair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64')}]};}
const apiRings={CHECKPOINT_KEYRING:ring('ed25519'),ACCOUNT_KEYRING:ring('ed25519'),WRAP_KEYRING:ring('x25519'),RELEASE_KEYRING:ring('ed25519')},custodyRings={WITNESS_KEYRING:ring('ed25519'),TRUST_KEYRING:ring('ed25519'),WRAP_KEYRING:ring('x25519'),RELEASE_KEYRING:ring('ed25519')};
const pub=r=>({keyId:r.activeId,publicKey:r.keys[0].publicKey});
const genesisAuthority=ring('ed25519');
const ringSign=(r,message)=>nodeSign(null,Buffer.from(message),createPrivateKey({format:'der',type:'pkcs8',key:Buffer.from(r.keys[0].privateKey,'base64')})).toString('base64');
const independentName='synthetic-independent-custodian',invalidName='synthetic-admission-unconfigured',issuerName='synthetic-independent-auth';

const pilotAuth='compiled-pilot-genesis-auth',pilotSigner='synthetic-private-pilot-signers',pilotCustody='compiled-pilot-custody-readiness';
const pilotOrigin='https://auth-pilot-acceptance.fixture.invalid',pilotInvite=ring('ed25519'),pilotContinuation=ring('ed25519');
const apiPeer=Object.values(apiRings).flatMap(r=>r.keys.map(k=>k.publicKey)),custodyPeer=Object.values(custodyRings).flatMap(r=>r.keys.map(k=>k.publicKey));
const policy=releaseManifest({releaseId:'synthetic-support',checkpointKeys:[pub(apiRings.CHECKPOINT_KEYRING)],witnessKeys:[pub(custodyRings.WITNESS_KEYRING)],recoveryAuthorities:[pub(custodyRings.TRUST_KEYRING)],recoveryServices:{api:pub(apiRings.RELEASE_KEYRING),custodian:pub(custodyRings.RELEASE_KEYRING)}},plan.apiDomain,plan.webDomain,{api:apiPeer,custodian:custodyPeer});
const configs=manifests({main:'11111111-1111-4111-8111-111111111111',custodian:'22222222-2222-4222-8222-222222222222',auth:'33333333-3333-4333-8333-333333333333',emailFrom:'verify@agentkeychain.soupsam.com'});
const encoded=r=>Object.fromEntries(Object.entries(r).map(([k,v])=>[k,JSON.stringify(v)]));
const authKeys={EMAIL_HASH_KEY:randomBytes(32).toString('base64'),CODE_HASH_KEY:randomBytes(32).toString('base64'),SOURCE_HASH_KEY:randomBytes(32).toString('base64')};
const apiKeys={AUTH_BOOTSTRAP_KEY:raw(),AUTH_EMAIL_KEY:raw(),AUTH_LOOKUP_KEY:raw()};
await mkdir('dist/support-config',{recursive:true});const workers=[];
for(const [folder,c] of Object.entries(configs)){
 const path=resolve('dist/support-config/'+folder+'.json');await writeFile(path,JSON.stringify(c));
 const options=unstable_getMiniflareWorkerOptions(unstable_readConfig({config:path})).workerOptions;delete options.modulesRules;
 // The native mail sink persists message bodies; use an in-memory test provider.
 delete options.email;
 const bindings={...c.vars,...(folder==='api-worker'?apiKeys:folder==='auth-trust-worker'?authKeys:folder==='api-trust-worker'?{...encoded(apiRings),PEER_PUBLIC_KEYS:JSON.stringify(Object.values(custodyRings).map(r=>r.keys[0].publicKey))}:folder==='custody-trust-worker'?{...encoded(custodyRings),PEER_PUBLIC_KEYS:JSON.stringify(Object.values(apiRings).map(r=>r.keys[0].publicKey)),RELEASE_POLICY:JSON.stringify(policy)}:{})};
 workers.push({...options,name:c.name,modules:true,scriptPath:resolve('dist/'+folder+'/index.js'),modulesRoot:resolve('dist'),bindings,...(folder==='auth-trust-worker'?{serviceBindings:{EMAIL:{name:'synthetic-mailbox',entrypoint:'Mailbox'}}}:{}),outboundService:()=>new Response(null,{status:502})});
}
workers.push({name:issuerName,compatibilityDate:plan.compatibilityDate,compatibilityFlags:plan.compatibilityFlags,modules:true,
 scriptPath:resolve('dist/test-genesis-transport.mjs'),modulesRoot:resolve('dist'),d1Databases:{AUTH:'isolated-genesis-auth'},
 bindings:{AUTHORITY_PRIVATE:genesisAuthority.keys[0].privateKey,APPROVAL_POLICY:JSON.stringify({authority:pub(genesisAuthority),checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities})},
 outboundService:()=>new Response(null,{status:502})});
// Synthetic-only staging graphs. Production renderer grants no ingress binding.
for(const name of [independentName,invalidName]){
 const base=workers.find(w=>w.name===plan.workers['recovery-worker']);
 const {GENESIS_AUTH:_legacy,...independentBindings}=base.serviceBindings;
 workers.push({...base,name,d1Databases:{CUSTODIAN:name},serviceBindings:name===invalidName?base.serviceBindings:independentBindings,bindings:{
  ...base.bindings,GENESIS_ADMISSION_MODE:'independent-v1',
  ...(name===independentName?{GENESIS_APPROVAL_PIN:JSON.stringify(pub(genesisAuthority))}:{})}});
}
for(const name of [independentName,invalidName,plan.workers['recovery-worker']])workers.push({name:name+'-test-admission',modules:true,compatibilityDate:plan.compatibilityDate,serviceBindings:{ADMISSION:{name,entrypoint:'GenesisAdmission'},WITNESS:{name,entrypoint:'Custodian'}},script:`import {WorkerEntrypoint} from 'cloudflare:workers';export default class extends WorkerEntrypoint{async admit(v){return JSON.stringify(structuredClone(await this.env.ADMISSION.admit(v)));}async admitAndDrop(v){await this.env.ADMISSION.admit(v);}async witness(v){return JSON.stringify(structuredClone(await this.env.WITNESS.witness(v)));}async head(t,v){return JSON.stringify(structuredClone(await this.env.WITNESS.witnessHead(t,v)));}async ingressStatus(){return (await this.env.ADMISSION.fetch('https://fixture.invalid/')).status;}}`});
workers.push({name:'synthetic-mailbox',modules:true,compatibilityDate:plan.compatibilityDate,serviceBindings:{API:plan.workers['api-worker']},script:`import {WorkerEntrypoint} from 'cloudflare:workers';const messages=new Map();export class Mailbox extends WorkerEntrypoint{
 async send(message){if(typeof message.to!=='string'||!/Your verification code is [0-9]{6}\\./.test(message.text))throw new Error('invalid_test_email');messages.set(message.to,message.text.match(/[0-9]{6}/)[0]);return {messageId:'synthetic'};}
 async metadata(){return JSON.stringify({count:messages.size,recipients:[...messages.keys()].map(e=>e[0]+'***@'+e.split('@')[1])});}
 async submit(email,route,body,headers){const proof=messages.get(email);if(!proof)throw new Error('missing_test_email');return this.env.API.fetch(new Request('https://${plan.webDomain}/v1/auth/'+route,{method:'POST',headers,body:JSON.stringify({...body,email,proof}),cf:{colo:'SJC'}}));}
}export default Mailbox;`});
for(const [folder,entrypoints] of [['api-trust-worker',['CheckpointSigner','RecoveryReleaseSigner','RecoveryAuthority','RosterGenesisAuthority','RecoveryKeys','AccountAttester']],['custody-trust-worker',['RosterWitnessSigner','RecoveryTrustSigner','RecoveryReleaseSigner','RecoveryTrustPolicy','RecoveryAuthority','RecoveryKeys']]])for(const entrypoint of entrypoints)workers.push({name:folder+'-'+entrypoint,modules:true,compatibilityDate:plan.compatibilityDate,serviceBindings:{TARGET:{name:plan.workers[folder],entrypoint}},script:`import {WorkerEntrypoint} from 'cloudflare:workers';export default class extends WorkerEntrypoint{async key(){const k=await this.env.TARGET.key();return JSON.stringify({keyId:k.keyId,publicKey:k.publicKey});}async sign(m){return this.env.TARGET.sign(m);}async manifest(){return this.env.TARGET.manifest();}async rewrap(...a){const v=await this.env.TARGET.rewrap(...a);try{return JSON.stringify(structuredClone(v));}finally{v[Symbol.dispose]?.();}}async authorize(...a){return this.env.TARGET.authorize(...a);}async rosterGenesis(s){return this.env.TARGET.rosterGenesis(s);}async probe(method){return await this.env.TARGET[method]();}}`});
const invalidPolicies=[
 {...policy,webOrigin:undefined}, {...policy,apiOrigin:policy.webOrigin},
 {...policy,webOrigin:policy.apiOrigin}, {...policy,webOrigin:'https://attacker.test'},
 {...policy,webOrigin:policy.webOrigin+'/'}, {...policy,apiOrigin:policy.apiOrigin+'?x'},
 {...policy,recoveryServices:{api:policy.recoveryServices.custodian,custodian:policy.recoveryServices.api}},
 {...policy,witnessKeys:policy.checkpointKeys,checkpointKeys:policy.witnessKeys}
];
for(const [i,p] of invalidPolicies.entries()){
 const name='invalid-policy-'+i,base=workers.find(w=>w.name===plan.workers['custody-trust-worker']);
 workers.push({...base,name,bindings:{...base.bindings,RELEASE_POLICY:JSON.stringify(p)}});
 workers.push({name:name+'-probe',modules:true,compatibilityDate:plan.compatibilityDate,serviceBindings:{TARGET:{name,entrypoint:'RecoveryTrustPolicy'}},script:`import {WorkerEntrypoint} from 'cloudflare:workers';export default class extends WorkerEntrypoint{async manifest(){return this.env.TARGET.manifest();}}`});
}
// Auth has only its own D1, private distinct signer ports and read-only
// Custody RPC. The already compiled recovery worker remains the admission owner.
const pilotClock=String(Math.floor(Date.now()/1000)+600);
workers.push({name:pilotSigner,modules:true,compatibilityDate:plan.compatibilityDate,
 bindings:{GENESIS:JSON.stringify(genesisAuthority.keys[0]),CONTINUATION:JSON.stringify(pilotContinuation.keys[0])},script:`
 import {WorkerEntrypoint} from 'cloudflare:workers';
 class SyntheticRole extends WorkerEntrypoint { async key(){const {keyId,publicKey}=this.role();return {keyId,publicKey};}
  async sign(message){
   if(typeof message!=='string'||!message.startsWith(this.domain))throw new Error('unexpected_signing_role');
   const bytes=Uint8Array.from(atob(this.role().privateKey),c=>c.charCodeAt(0));
   const privateKey=await crypto.subtle.importKey('pkcs8',bytes,'Ed25519',false,['sign']);
   return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(message)))));
  }
 }
 export class Genesis extends SyntheticRole { domain='AgentKeychain-managed-genesis-approval-v1\\0';role(){return JSON.parse(this.env.GENESIS);} }
 export class Continuation extends SyntheticRole { domain='{"version":1,"domain":"AgentKeychain-enrollment-continuation-approval-v1"';role(){return JSON.parse(this.env.CONTINUATION);} }
 export default {fetch(){return new Response(null,{status:404});}};
 `});
workers.push({name:pilotCustody,modules:true,compatibilityDate:plan.compatibilityDate,compatibilityFlags:plan.compatibilityFlags,
 scriptPath:resolve('dist/custody-trust-worker/pilot-continuation.js'),modulesRoot:resolve('dist'),
 d1Databases:{CUSTODIAN:independentName},outboundService:()=>new Response(null,{status:502})});
workers.push({name:pilotAuth,routes:[pilotOrigin+'/*'],modules:true,compatibilityDate:plan.compatibilityDate,compatibilityFlags:plan.compatibilityFlags,
 scriptPath:resolve('dist/auth-trust-worker/pilot-continuation.js'),modulesRoot:resolve('dist'),d1Databases:{AUTH:'isolated-compiled-pilot-auth'},
 bindings:{PILOT_AUTH_MODE:'continuation-v1',PILOT_AUTH_ORIGIN:pilotOrigin,PILOT_AUTH_EXPIRES_AT:pilotClock,
  PILOT_AUTH_PINS:JSON.stringify({genesis:pub(genesisAuthority),approval:pub(pilotContinuation),checkpointKeys:policy.checkpointKeys,
   recoveryAuthorities:policy.recoveryAuthorities,witnesses:policy.witnessKeys}),PILOT_HANDOFF_HMAC:randomBytes(32).toString('base64'),
  PILOT_GENESIS_REGISTRATION_MODE:'invitation-v1',PILOT_GENESIS_INVITE_PIN:JSON.stringify(pub(pilotInvite)),PILOT_GENESIS_CONSENT_MODE:'consent-v1'},
 serviceBindings:{PILOT_APPROVAL_SIGNER:{name:pilotSigner,entrypoint:'Continuation'},PILOT_GENESIS_APPROVAL_SIGNER:{name:pilotSigner,entrypoint:'Genesis'},
  PILOT_CUSTODY_READINESS:{name:pilotCustody,entrypoint:'PilotCustodyReadiness'}},outboundService:()=>new Response(null,{status:502})});

const mf=new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',port:0,inspectorPort:0,log:new Log(LogLevel.NONE),workers}));
try{
 await mf.ready;
 const issuerDb=await mf.getD1Database('AUTH',issuerName);
 for(const file of ['genesis-registration.sql','genesis-readback.sql'])await issuerDb.batch(unstable_splitSqlQuery(await readFile('auth-trust-worker/experimental/'+file,'utf8')).map(sql=>issuerDb.prepare(sql)));
 for(const [folder,binding] of [['api-worker','MAIN'],['recovery-worker','CUSTODIAN'],['auth-trust-worker','AUTH']]){const db=await mf.getD1Database(binding,plan.workers[folder]);for(const file of (await readdir(folder+'/migrations')).filter(n=>n.endsWith('.sql')).sort())await db.batch(unstable_splitSqlQuery(await readFile(folder+'/migrations/'+file,'utf8')).map(sql=>db.prepare(sql)));}
 for(const name of [independentName,invalidName]){
  const db=await mf.getD1Database('CUSTODIAN',name);
  for(const file of (await readdir('recovery-worker/migrations')).filter(n=>n.endsWith('.sql')).sort())await db.batch(unstable_splitSqlQuery(await readFile('recovery-worker/migrations/'+file,'utf8')).map(sql=>db.prepare(sql)));
 }
 for(const folder of Object.keys(configs).filter(f=>f!=='api-worker'))assert.equal((await (await mf.getWorker(plan.workers[folder])).fetch('https://private.invalid/')).status,404);
 const db=await mf.getD1Database('MAIN',plan.workers['api-worker']),auth=await mf.getD1Database('AUTH',plan.workers['auth-trust-worker']);
 const origin='https://'+plan.webDomain,email='synthetic@example.invalid',invitation=raw();
 const {createHmac}=await import('node:crypto');const identity=createHmac('sha256',Buffer.from(apiKeys.AUTH_LOOKUP_KEY,'base64url')).update('email\0'+email).digest('base64url');
 await db.prepare('INSERT INTO invitations(digest,email_lookup,encrypted_email,expires_at) VALUES(?,?,?,unixepoch()+600)').bind(sha(invitation),identity,'synthetic-unused-display').run();
 const fetch=(path,init={})=>mf.dispatchFetch(origin+'/v1/auth/'+path,{...init,cf:{colo:'SJC'},headers:{'cf-connecting-ip':'192.0.2.1',...init.headers}});
 let headers;async function bootstrap(){const r=await fetch('bootstrap');assert.equal(r.status,200);const cookie=r.headers.getSetCookie().map(v=>v.split(';')[0]).join('; ');headers={origin,cookie,'x-csrf-token':/__Host-akc_(?:boot_|recovery_)?csrf=([^;]+)/.exec(cookie)[1],'content-type':'application/json','cf-connecting-ip':'192.0.2.1'};}
 const post=(route,body)=>fetch(route,{method:'POST',headers,body:JSON.stringify(body)});
 const mailbox=await mf.getWorker('synthetic-mailbox');
 await bootstrap();let requested=await post('email/request',{email,purpose:'invitation',context:invitation});assert.equal(requested.status,200);assert.deepEqual(await requested.json(),{accepted:true,retryAfter:60});
 assert.deepEqual(JSON.parse(await mailbox.metadata()),{count:1,recipients:['s***@example.invalid']});
 let result=await mailbox.submit(email,'invitation/verify',{invitation},headers);assert.equal(result.status,200);assert.ok((await result.json()).verificationId);
 result=await mailbox.submit(email,'invitation/verify',{invitation},headers);assert.equal(result.status,401);
 const rows=JSON.stringify(await auth.prepare('SELECT * FROM email_codes').all());assert.ok(!rows.includes(email));
 await auth.prepare('UPDATE email_rates SET last_sent=last_sent-60').run();await bootstrap();
 const requestRef=raw(),target={id:'synthetic-case',packageId:'synthetic-package',targetDeviceId:raw(),signingKey:randomBytes(32).toString('base64'),wrappingKey:randomBytes(32).toString('base64'),nonce:'synthetic-nonce'};
 await db.prepare('INSERT INTO recovery_targets(digest,target,expires_at) VALUES(?,?,unixepoch()+600)').bind(sha(requestRef),JSON.stringify(target)).run();
 requested=await post('email/request',{email,purpose:'recovery',context:requestRef});assert.equal(requested.status,200);
 result=await mailbox.submit(email,'recovery/verify',{requestRef},headers);assert.equal(result.status,200);assert.deepEqual(await result.json(),{accepted:true});
 assert.equal((await auth.prepare("SELECT consumed FROM email_codes WHERE purpose='recovery'").first()).consumed,1);
 const signer=await mf.getWorker('api-trust-worker-CheckpointSigner');assert.deepEqual(JSON.parse(await signer.key()),pub(apiRings.CHECKPOINT_KEYRING));
 await assert.rejects(async()=>await signer.sign('arbitrary'));
 for(const [folder,entrypoint] of [['api-trust-worker','RecoveryReleaseSigner'],['custody-trust-worker','RosterWitnessSigner'],['custody-trust-worker','RecoveryTrustSigner'],['custody-trust-worker','RecoveryReleaseSigner']]){const s=await mf.getWorker(folder+'-'+entrypoint);assert.ok(JSON.parse(await s.key()).keyId);await assert.rejects(async()=>await s.sign('arbitrary'));}
 assert.equal(await (await mf.getWorker('custody-trust-worker-RecoveryTrustPolicy')).manifest(),JSON.stringify(policy));
 for(const i of invalidPolicies.keys())await assert.rejects(async()=>await (await mf.getWorker('invalid-policy-'+i+'-probe')).manifest());
 const custodyDb=await mf.getD1Database('CUSTODIAN',plan.workers['recovery-worker']);
 const issuer=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']),issuerKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',issuer.publicKey))),targetPair=await crypto.subtle.generateKey('X25519',true,['deriveBits']);
 const wrappingKey=encode64(new Uint8Array(await crypto.subtle.exportKey('raw',targetPair.publicKey))),now=Math.floor(Date.now()/1000);
 const c={version:1,id:'production-support-case',packageId:'production-support-package',accountId:'a',tenantId:'t',vaultId:'v',keyEpoch:1,targetDeviceId:raw(),signingKey:randomBytes(32).toString('base64'),wrappingKey,createdAt:now,notBefore:now+86400,expiresAt:now+172800,nonce:'synthetic-nonce'};
 const m={version:1,packageId:c.packageId,accountId:'a',tenantId:'t',vaultId:'v',keyEpoch:1,policy:'two-party-24h',issuerDeviceId:'d',apiKeyId:apiRings.WRAP_KEYRING.activeId,custodianKeyId:custodyRings.WRAP_KEYRING.activeId,wrappedVDK:randomBytes(60).toString('base64')};
 const shares={api:randomBytes(32),custodian:randomBytes(32)};
 m.apiShare=await seal(apiRings.WRAP_KEYRING.keys[0].publicKey,shares.api,packageContext(m,'api'));m.custodianShare=await seal(custodyRings.WRAP_KEYRING.keys[0].publicKey,shares.custodian,packageContext(m,'custodian'));
 const sign=async value=>encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',issuer.privateKey,new TextEncoder().encode(value)))),canonical=JSON.stringify(c),packageCanonical=JSON.stringify(m),signature=await sign(packageCanonical);
 await db.batch([db.prepare("INSERT INTO accounts VALUES('a')"),db.prepare("INSERT INTO tenants VALUES('t')"),db.prepare("INSERT INTO memberships VALUES('t','a',1)"),db.prepare("INSERT INTO vaults VALUES('t','v',0)"),db.prepare("INSERT INTO devices VALUES('t','d','a',?,1)").bind(issuerKey),db.prepare("INSERT INTO vault_devices VALUES('t','v','d',1)"),db.prepare("INSERT INTO recovery_packages_v1 VALUES(?,'t','v','a',1,?,?,1)").bind(m.packageId,packageCanonical,signature),db.prepare("INSERT INTO recovery_sagas(id,tenant_id,vault_id,account_id,package_id,canonical,request_digest,session_digest,state,not_before,expires_at,proof_digest,challenge) VALUES(?,'t','v','a',?,?,?,'synthetic-session','prepared',?,?,'synthetic-proof','synthetic-challenge')").bind(c.id,m.packageId,canonical,sha(canonical),c.notBefore,c.expiresAt)]);
 await custodyDb.batch([custodyDb.prepare("INSERT INTO trust_devices VALUES('a','t','v','d',?,0,?)").bind(issuerKey,c.expiresAt),custodyDb.prepare("INSERT INTO recovery_packages VALUES(?,?,?,'a','t','v',1)").bind(m.packageId,packageCanonical,signature),custodyDb.prepare("INSERT INTO recovery_sagas VALUES(?,?,?,'prepared',?,?,NULL)").bind(c.id,m.packageId,canonical,c.notBefore,c.expiresAt)]);
 const genesis=await mf.getWorker('api-trust-worker-RosterGenesisAuthority');
 const rosterCanonical=canonicalRoster({version:1,accountId:'a',tenantId:'t',vaultId:'v',revision:1,previousDigest:null,keyEpoch:1,active:[{deviceId:'d',signingKey:issuerKey,wrappingKey}],revoked:[],issuer:{kind:'device',id:'d'},issuedAt:now,expiresAt:now+60,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities,recovery:null});
 assert.equal(await genesis.rosterGenesis({canonical:rosterCanonical,signature:await sign(ROSTER_DOMAIN+rosterCanonical)}),true);
 const roster={canonical:rosterCanonical,signature:await sign(ROSTER_DOMAIN+rosterCanonical)};
 const cp=await checkpoint({key:async()=>pub(apiRings.CHECKPOINT_KEYRING),sign:async m=>ringSign(apiRings.CHECKPOINT_KEYRING,m)},'t','v',0,await genesisRoot('t','v'),null,null);
 const grant=canonicalGrant({version:1,requestId:'synthetic-admission',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',signingKey:issuerKey,wrappingKey,issuerDeviceId:null,keyEpoch:1,expiresAt:now+60});
 const isolatedAuth=await mf.getWorker(issuerName),sessionToken=raw(),anti=raw();
 const decisionId=await isolatedAuth.issueAndDropResponse(grant,roster,sessionToken,anti);
 const issuerOrigin='https://independent-auth.fixture.invalid';
 const readback=async (decision=decisionId,headers={})=>JSON.parse(await isolatedAuth.syntheticReadback({
  origin:issuerOrigin,'content-type':'application/json','x-csrf-token':anti,cookie:'__Host-akc_genesis_session='+sessionToken+'; __Host-akc_genesis_csrf='+anti,...headers},
  JSON.stringify({decisionId:decision,grant,roster})));
 assert.equal((await readback(raw())).status,401);
 assert.equal((await readback(decisionId,{'x-csrf-token':raw()})).status,401);
 const firstRead=await readback();assert.equal(firstRead.status,200);
 const proof=firstRead.body,retried=await readback();assert.equal(retried.status,200);assert.deepEqual(retried.body,proof);
 assert.equal(await issuerDb.prepare('SELECT count(*) n FROM auth_genesis_decisions').first('n'),1);
 const admission={proof,grant,roster,checkpoint:cp};
 const independent=await mf.getWorker(independentName+'-test-admission'),unconfigured=await mf.getWorker(invalidName+'-test-admission'),legacy=await mf.getWorker(plan.workers['recovery-worker']+'-test-admission');
 assert.equal(await independent.ingressStatus(),404);
 await assert.rejects(async()=>await legacy.admit(admission),/genesis_admission_unavailable/);
 await assert.rejects(async()=>await unconfigured.admit(admission),/genesis_admission_unavailable/);
 // The exact same genesis was approved by the old API-backed validator above:
 // an incomplete independent config must nevertheless refuse that fallback.
 await assert.rejects(async()=>await unconfigured.witness({rosters:[roster],checkpoints:[cp]}),/witness_untrusted_genesis/);
 await assert.rejects(async()=>await independent.witness({rosters:[roster],checkpoints:[cp]}),/witness_untrusted_genesis/);
 await independent.admitAndDrop(admission);
 const receipt=await independent.admit(admission);
 assert.deepEqual(await independent.head('t','v'),receipt);
 assert.deepEqual(await independent.admit(admission),receipt);
 assert.deepEqual(await independent.witness({prior:JSON.parse(receipt),rosters:[roster],checkpoints:[cp]}),receipt);
 const independentDb=await mf.getD1Database('CUSTODIAN',independentName);
 assert.equal(await independentDb.prepare('SELECT count(*) n FROM genesis_admissions').first('n'),1);
 assert.equal(await independentDb.prepare('SELECT count(*) n FROM roster_witness').first('n'),1);
 // Reach the real compiled pilot Auth HTTP route, with no direct pin seed.
 const pilotDb=await mf.getD1Database('AUTH',pilotAuth);
 for(const file of ['auth-trust-worker/experimental/genesis-registration.sql','auth-trust-worker/pilot-migrations/0001-exact-genesis-registration.sql']){
  const sql=await readFile(file,'utf8');
  await pilotDb.batch(unstable_splitSqlQuery(sql).map(line=>pilotDb.prepare(line)));
 }
 const pAccount='pilot-account',pTenant='pilot-tenant',pVault='pilot-vault',pDevice='pilot-device',pRequest=raw();
 const pNow=Math.floor(Date.now()/1000),bound={accountId:pAccount,tenantId:pTenant,vaultId:pVault,deviceId:pDevice,requestId:pRequest,keyEpoch:1};
 const pDeviceKey=ring('ed25519'),pWrapping=pub(ring('x25519')).publicKey, pSigning=pub(pDeviceKey).publicKey;
 const pGrant=canonicalGrant({version:1,...bound,signingKey:pSigning,wrappingKey:pWrapping,issuerDeviceId:null,expiresAt:pNow+120});
 const pRosterCanonical=canonicalRoster({version:1,accountId:pAccount,tenantId:pTenant,vaultId:pVault,revision:1,previousDigest:null,keyEpoch:1,
  active:[{deviceId:pDevice,signingKey:pSigning,wrappingKey:pWrapping}],revoked:[],issuer:{kind:'device',id:pDevice},issuedAt:pNow,expiresAt:pNow+120,
  checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities,recovery:null});
 const pRoster={canonical:pRosterCanonical,signature:ringSign(pDeviceKey,ROSTER_DOMAIN+pRosterCanonical)};
 const pCheckpoint=await checkpoint({key:async()=>pub(apiRings.CHECKPOINT_KEYRING),sign:async m=>ringSign(apiRings.CHECKPOINT_KEYRING,m)},
  pTenant,pVault,0,await genesisRoot(pTenant,pVault),null,null);
 const rpId=new URL(pilotOrigin).hostname;
 const inviteCanonical=JSON.stringify({version:1,domain:'AgentKeychain-pilot-genesis-registration-invite-v1',keyId:pub(pilotInvite).keyId,
  origin:pilotOrigin,rpId,id:raw(),...bound,grantDigest:sha(pGrant),rosterDigest:await rosterDigest(pRoster),issuedAt:pNow,expiresAt:pNow+100});
 const invite={canonical:inviteCanonical,signature:ringSign(pilotInvite,inviteCanonical)},payload={invite,oldGrantCanonical:pGrant,roster:pRoster};
 const postPilot=(path,b,session={})=>mf.dispatchFetch(pilotOrigin+'/v1/auth/pilot-genesis/'+path,{method:'POST',
  headers:{origin:pilotOrigin,'sec-fetch-site':'same-origin','content-type':'application/json',...session},body:JSON.stringify(b)});
 const pBegin=await postPilot('registration/begin',payload);assert.equal(pBegin.status,200);
 const pCookie=pBegin.headers.get('set-cookie').split(';')[0];
 const opened=await pBegin.json(),browser={cookie:pCookie,'x-csrf-token':opened.csrf},passkey=await virtualAuthenticator();
 assert.equal(await pilotDb.prepare('SELECT count(*) n FROM auth_genesis_pins').first('n'),0);
 assert.equal((await postPilot('registration/complete',{...payload,response:await passkey.register(opened.options.challenge,{origin:pilotOrigin,rpId})},browser)).status,204);
 assert.equal(await pilotDb.prepare('SELECT count(*) n FROM auth_genesis_pins').first('n'),1);
 assert.equal(await pilotDb.prepare('SELECT count(*) n FROM auth_genesis_decisions').first('n'),0);
 const firstDevice={grant:pGrant,roster:pRoster,checkpoint:pCheckpoint};
 await assert.rejects(async()=>independent.admit({...firstDevice,proof:invite}),/genesis_admission_rejected/);
 const consent=await postPilot('consent/begin',payload,browser);assert.equal(consent.status,200);
 const reviewed=await consent.json();assert.deepEqual(reviewed.display,{purpose:'approve-first-device-genesis',accountId:pAccount,vaultId:pVault,deviceId:pDevice});
 assert.equal(reviewed.options.userVerification,'required');
 assert.equal((await postPilot('consent/readback',{...payload,id:reviewed.id},browser)).status,401);
 const noUv=await passkey.assert(reviewed.options.challenge,{origin:pilotOrigin,rpId,uv:false,counter:1});
 assert.equal((await postPilot('consent/complete',{...payload,id:reviewed.id,response:noUv},browser)).status,401);
 assert.equal(await pilotDb.prepare('SELECT count(*) n FROM auth_genesis_decisions').first('n'),0);
 const assertion=await passkey.assert(reviewed.options.challenge,{origin:pilotOrigin,rpId,counter:1});
 const done=await postPilot('consent/complete',{...payload,id:reviewed.id,response:assertion},browser);assert.equal(done.status,200);
 // Drop Auth result; the separate narrow readback must return its exact commit.
 await done.body.cancel();
 const restored=await postPilot('consent/readback',{...payload,id:reviewed.id},browser);assert.equal(restored.status,200);
 const signedProof=await restored.json(),storedProof=await pilotDb.prepare('SELECT canonical,signature FROM auth_genesis_decisions').first();
 assert.deepEqual(signedProof,storedProof);
 assert.equal((await postPilot('consent/readback',{...payload,id:reviewed.id},{...browser,cookie:'__Host-akc_pilot_genesis_registration='+raw()})).status,401);
 const differentlySigned={...signedProof,signature:ringSign(pilotContinuation,'AgentKeychain-managed-genesis-approval-v1\0'+signedProof.canonical)};
 await assert.rejects(async()=>independent.admit({...firstDevice,proof:differentlySigned}),/genesis_admission_rejected/);
 await assert.rejects(async()=>independent.admit({...firstDevice,grant:pGrant.replace(pRequest,'substituted-request'),proof:signedProof}),/genesis_admission_rejected/);
 assert.equal(await independentDb.prepare('SELECT count(*) n FROM genesis_admissions WHERE tenant_id=? AND vault_id=?').bind(pTenant,pVault).first('n'),0);
 await independent.admitAndDrop({...firstDevice,proof:signedProof});
 const pReceipt=await independent.admit({...firstDevice,proof:signedProof});
 assert.deepEqual(await independent.head(pTenant,pVault),pReceipt);
 assert.equal(await independentDb.prepare('SELECT count(*) n FROM genesis_admissions WHERE tenant_id=? AND vault_id=?').bind(pTenant,pVault).first('n'),1);
 assert.equal(await independentDb.prepare('SELECT count(*) n FROM roster_witness WHERE tenant_id=? AND vault_id=?').bind(pTenant,pVault).first('n'),1);
 console.log('PASS compiled pilot Auth registration, consent and exact readback → independent Custody admission and retry');
 // Seed drift-free legacy data using the actual prior-mode worker's own
 // persisted local fixture result; independent startup must still read it.
 const legacyReceipt=await legacy.witness({rosters:[roster],checkpoints:[cp]});
 const legacyRow=await custodyDb.prepare("SELECT tenant_id,vault_id,event,revision,digest,sequence,root,request_digest,roster,checkpoint,receipt,checkpoint_suffix FROM roster_witness WHERE tenant_id='t' AND vault_id='v'").first();
 const upgradedDb=await mf.getD1Database('CUSTODIAN',invalidName);
 await upgradedDb.prepare('INSERT INTO roster_witness(tenant_id,vault_id,event,revision,digest,sequence,root,request_digest,roster,checkpoint,receipt,checkpoint_suffix) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(...Object.values(legacyRow)).run();
 assert.equal(await unconfigured.head('t','v'),legacyReceipt);
 assert.equal(await unconfigured.witness({prior:JSON.parse(legacyReceipt),rosters:[roster],checkpoints:[cp]}),legacyReceipt);
 assert.equal(await upgradedDb.prepare('SELECT count(*) n FROM genesis_admissions').first('n'),0);


 // An eligible recovery gets the same browser result as the earlier decoy,
 // but has a real restricted account session and invokes the production attester.
 await db.prepare("INSERT INTO account_emails VALUES('a',?,?,1)").bind(randomBytes(64).toString('base64'),identity).run();
 for(const database of [db,custodyDb])await database.prepare("INSERT INTO trust_accounts VALUES('a',?,0,?)").bind(apiRings.ACCOUNT_KEYRING.keys[0].publicKey,c.expiresAt).run();
 const eligibleRef=raw(),eligibleTarget={id:'eligible-case',packageId:m.packageId,targetDeviceId:raw(),signingKey:c.signingKey,wrappingKey,nonce:'eligible-nonce'};
 await db.prepare('INSERT INTO recovery_targets(digest,target,expires_at) VALUES(?,?,unixepoch()+600)').bind(sha(eligibleRef),JSON.stringify(eligibleTarget)).run();
 await auth.prepare('UPDATE email_rates SET last_sent=last_sent-60').run();await bootstrap();
 assert.equal((await post('email/request',{email,purpose:'recovery',context:eligibleRef})).status,200);
 const eligible=await mailbox.submit(email,'recovery/verify',{requestRef:eligibleRef},headers);assert.equal(eligible.status,200);assert.deepEqual(await eligible.clone().json(),{accepted:true});
 assert.equal((await db.prepare('SELECT account_id FROM recovery_sessions WHERE case_id=?').bind(eligibleTarget.id).first()).account_id,'a');
 const cookie=eligible.headers.getSetCookie().map(v=>v.split(';')[0]).join('; ');headers={...headers,cookie,'x-csrf-token':/__Host-akc_(?:boot_|recovery_)?csrf=([^;]+)/.exec(cookie)[1]};
 const started=await post('recovery/start',{});assert.equal(started.status,200);assert.equal((await started.json()).state,'prepared');
 assert.equal((await db.prepare('SELECT count(*) n FROM recovery_authorizations WHERE case_id=?').bind(eligibleTarget.id).first()).n,1);
 const evidence={mode:'device',confirmerId:'d',signature:await sign(JSON.stringify(['AgentKeychain-recovery-confirm-v1',canonical])),proof:null};
 for(const [folder,party,box,keyId] of [['api-trust-worker','api',m.apiShare,m.apiKeyId],['custody-trust-worker','custodian',m.custodianShare,m.custodianKeyId]]){
  const authService=await mf.getWorker(folder+'-RecoveryAuthority'),keys=await mf.getWorker(folder+'-RecoveryKeys');
  for(const method of ['rings','ring','registry','signer','authority'])await assert.rejects(async()=>await keys.probe(method));
  const args=[keyId,box,packageContext(m,party),wrappingKey,releaseContext(canonical,party)];
  await assert.rejects(async()=>await keys.rewrap(...args));
  assert.equal(await authService.authorize(canonical,{...evidence,signature:randomBytes(64).toString('base64')}),false);
  assert.equal(await authService.authorize(canonical,evidence),true);
  await assert.rejects(async()=>await keys.rewrap(keyId,box,args[2],c.signingKey,args[4]));
  await assert.rejects(async()=>await keys.rewrap(keyId,{...box,ciphertext:randomBytes(48).toString('base64')},...args.slice(2)));
  const wrapped=JSON.parse(await keys.rewrap(...args));assert.deepEqual(Buffer.from(await open(targetPair.privateKey,wrapped,args[4])),shares[party]);
 }
 await custodyDb.prepare("UPDATE trust_devices SET revoked=1 WHERE device_id='d'").run();
 const custodyKeys=await mf.getWorker('custody-trust-worker-RecoveryKeys');await assert.rejects(async()=>await custodyKeys.rewrap(m.custodianKeyId,m.custodianShare,packageContext(m,'custodian'),wrappingKey,releaseContext(canonical,'custodian')));
 await db.prepare("UPDATE recovery_sagas SET state='cancelled' WHERE id=?").bind(c.id).run();const apiWrap=await mf.getWorker('api-trust-worker-RecoveryKeys');await assert.rejects(async()=>await apiWrap.rewrap(m.apiKeyId,m.apiShare,packageContext(m,'api'),wrappingKey,releaseContext(canonical,'api')));
 console.log('Support bundle: all five production Workers, three D1s, exact service graph, private HTTP, invitation/recovery code request+consume+replay, key metadata, signer oracle rejection, non-exported helpers, independent authorized rewrap/revocation/cancellation, and synthetic independent Auth registration/approval, lost Auth response/readback, and Custody first witness/replay passed.');
}finally{await mf.dispose();}
