import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
/** Executes the built API module in standalone workerd, with manifest-derived
 * dates, flags, D1 and service bindings. No Vitest loader or compatibility extras.
 * All keys/proofs are ephemeral synthetic data; no outbound network is allowed. */
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_getMiniflareWorkerOptions as manifest, unstable_splitSqlQuery as splitSql, unstable_readConfig as readConfig } from 'wrangler';

await build({entryPoints:['tests/synthetic-recovery.ts'],outfile:'dist/test-recovery.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({entryPoints:['shared/recovery-crypto.ts','shared/recovery.ts','shared/roster.ts','../src/cloud/crypto.ts','../src/cloud/protocol.ts'],outdir:'dist/test-shared',outbase:'..',bundle:true,external:['libsodium-wrappers-sumo'],format:'esm',platform:'node',target:'es2022'});
const {seal,open,encode64,splitRecoveryKey,joinRecoveryKey,wrapVaultKey,unwrapVaultKey}=await import('../dist/test-shared/managed-cloud/shared/recovery-crypto.js');
const {packageContext,releaseContext,vaultKeyContext}=await import('../dist/test-shared/managed-cloud/shared/recovery.js');
await build({entryPoints:['tests/synthetic-checkpoint.ts'],outfile:'dist/test-checkpoint.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({ entryPoints: ['tests/virtual-authenticator.ts'], outfile: 'dist/test-authenticator.mjs', bundle: true, format: 'esm', platform: 'node', target: 'es2022' });
const { virtualAuthenticator } = await import('../dist/test-authenticator.mjs');
const fromManifest = path => {
    const config = readConfig({ config: path });
    return { ...manifest(config).workerOptions, name: config.name };
};
const api = fromManifest('api-worker/wrangler.toml');
const recovery = fromManifest('recovery-worker/wrangler.toml');
// Wrangler supplies source-file scanning defaults. These are irrelevant to a
// single already-bundled ES module; Miniflare 5 deliberately refuses to convert
// scanning rules. Assert the exact defaults before dropping only that field.
for (const options of [api, recovery]) {
    assert.deepEqual(options.modulesRules, [
        { type: 'Text', fallthrough: undefined, include: ['**/*.txt', '**/*.html', '**/*.sql'] },
        { type: 'Data', fallthrough: undefined, include: ['**/*.bin'] },
        { type: 'CompiledWasm', fallthrough: undefined, include: ['**/*.wasm', '**/*.wasm?module'] },
    ]);
    delete options.modulesRules;
}
assert.deepEqual(api.compatibilityFlags, ['nodejs_compat']);
assert.equal(api.compatibilityDate, '2026-07-16');
assert.deepEqual(Object.keys(api.d1Databases), ['MAIN']);
assert.deepEqual(Object.keys(api.serviceBindings).sort(), ['CHECKPOINT_SIGNER', 'EMAIL_VERIFIER', 'RECOVERY', 'RECOVERY_ACCOUNT_ATTESTER', 'RECOVERY_AUTH', 'RECOVERY_KEYS', 'RECOVERY_RELEASE_SIGNER', 'TRUSTED_AUTH_SOURCE']);
// Existing process fault fixtures remain synthetic; production support composition
// is independently exercised by support-bundle.mjs under the staging manifests.
Object.assign(api.serviceBindings,{
 CHECKPOINT_SIGNER:{name:'agentkeychain-checkpoint-signer',entrypoint:'CheckpointSigner'},
 EMAIL_VERIFIER:{name:'agentkeychain-auth-trust',entrypoint:'EmailVerifier'},TRUSTED_AUTH_SOURCE:{name:'agentkeychain-auth-trust',entrypoint:'TrustedAuthSource'},
 RECOVERY_AUTH:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryAuthority'},RECOVERY_KEYS:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryKeys'},
 RECOVERY_RELEASE_SIGNER:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryReleaseSigner'},RECOVERY_ACCOUNT_ATTESTER:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryTestService'}
});
Object.assign(recovery.serviceBindings,{
 RECOVERY_AUTH:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryAuthority'},RECOVERY_KEYS:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryKeys'},RECOVERY_RELEASE_SIGNER:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryReleaseSigner'},
 ROSTER_WITNESS_SIGNER:{name:'agentkeychain-custody-recovery',entrypoint:'RosterWitnessSigner'},RECOVERY_TRUST_SIGNER:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryTrustSigner'},RECOVERY_TRUST_POLICY:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryTrustSigner'}
});
const raw = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
const proof = raw(), origin = 'https://local.invalid', email = 'bundle@example.invalid';
const bindings = { AUTH_ORIGIN: origin, DEVICE_API_ORIGIN: 'https://api.local.invalid', AUTH_RP_ID: 'local.invalid', AUTH_BOOTSTRAP_KEY: raw(), AUTH_EMAIL_KEY: raw(), AUTH_LOOKUP_KEY: raw() };
const noOutbound = () => new Response(null, { status: 502 });
await build({stdin:{contents:`import api from './api-worker/index.js'; const now=Date.now; export default {async fetch(request,env){if(new URL(request.url).pathname==='/__clock'){const offset=Number(new URL(request.url).searchParams.get('offset'));Date.now=()=>now()+offset;return Response.json({ok:true});}const db=env.MAIN;return api.fetch(request,{...env,MAIN:{prepare(sql){return db.prepare(sql.replaceAll('unixepoch()','(unixepoch()+(SELECT delta FROM synthetic_clock))'));},batch(statements){return db.batch(statements);}}});}};`,resolveDir:resolve('dist'),sourcefile:'recovery-process-api.ts'},outfile:'dist/recovery-process-api.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({entryPoints:['recovery-worker/index.ts'],outfile:'dist/recovery-process-custodian.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022',plugins:[{name:'synthetic-clock',setup(b){b.onLoad({filter:/recovery-worker\/index\.ts$/},async({path})=>({loader:'ts',contents:'const nativeNow=Date.now;function clockDB(db:any){return {prepare(sql:string){return db.prepare(sql.replaceAll(\'unixepoch()\',\'(unixepoch()+(SELECT delta FROM synthetic_clock))\'));},batch(statements:any[]){return db.batch(statements);}}}\n'+(await readFile(path,'utf8')).replaceAll('this.env.CUSTODIAN','clockDB(this.env.CUSTODIAN)').replace('    override async fetch()', '    async clock(offset:number){Date.now=()=>nativeNow()+offset;}\n    override async fetch()')}));}}]});
const mf = new Miniflare(convertV4MiniflareOptions({
    host: '127.0.0.1', port: 0, inspectorPort: 0,
    workers: [
        { ...api, modules: true, modulesRoot: resolve('dist'), scriptPath: resolve('dist/recovery-process-api.mjs'), bindings, serviceBindings:{...api.serviceBindings,RECOVERY_ACCOUNT_ATTESTER:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryTestService'},RECOVERY_RELEASE_SIGNER:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryReleaseSigner'}}, outboundService: noOutbound },
        // Test-only native-device transport: Node/Undici injects sec-fetch-mode
        // even on stub fetches. Construct device requests inside workerd instead.
        {name:'synthetic-device-transport',modules:true,compatibilityDate:api.compatibilityDate,serviceBindings:{WITNESS:{name:'agentkeychain-custody-recovery',entrypoint:'RosterWitnessSigner'},CUSTODIAN:{name:recovery.name,entrypoint:'Custodian'},API:api.name,AUTHORITY:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryTrustSigner'},API_RELEASE:{name:'agentkeychain-api-recovery',entrypoint:'RecoveryReleaseSigner'},CUSTODY_RELEASE:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryReleaseSigner'},CHECKPOINT:{name:'agentkeychain-checkpoint-signer',entrypoint:'CheckpointSigner'}},outboundService:noOutbound,
            script:`export default {async fetch(request,env){const {role,operation,args,route,body,path,method,headers}=await request.json();if(role)return Response.json((await env[role][operation](...args))??null);return env.API.fetch(new Request('https://api.local.invalid'+(path??('/v1/devices/'+route)),{method:method??'POST',headers:headers??{'content-type':'application/json'},...((method??'POST')==='GET'?{}:{body:path?body:JSON.stringify(body)})}));}};`},
        {name:'agentkeychain-checkpoint-signer',modules:true,modulesRoot:resolve('dist'),scriptPath:resolve('dist/test-checkpoint.mjs'),compatibilityDate:api.compatibilityDate,compatibilityFlags:api.compatibilityFlags,outboundService:noOutbound},
        ...['agentkeychain-api-recovery','agentkeychain-custody-recovery'].map(name=>({name,modules:true,modulesRoot:resolve('dist'),scriptPath:resolve('dist/test-recovery.mjs'),compatibilityDate:api.compatibilityDate,compatibilityFlags:api.compatibilityFlags,outboundService:noOutbound})),
        { ...recovery, modules: true, modulesRoot: resolve('dist'), scriptPath: resolve('dist/recovery-process-custodian.mjs'), serviceBindings:{...recovery.serviceBindings,RECOVERY_RELEASE_SIGNER:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryReleaseSigner'},RECOVERY_TRUST_SIGNER:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryTrustSigner'},RECOVERY_TRUST_POLICY:{name:'agentkeychain-custody-recovery',entrypoint:'RecoveryTrustSigner'},ROSTER_WITNESS_SIGNER:{name:'agentkeychain-custody-recovery',entrypoint:'RosterWitnessSigner'}}, outboundService: noOutbound },
        { name: 'agentkeychain-auth-trust', modules: true, compatibilityDate: api.compatibilityDate, bindings: { PROOF: proof }, outboundService: noOutbound,
            script: `import { WorkerEntrypoint } from 'cloudflare:workers';
                export class EmailVerifier extends WorkerEntrypoint { request(){return {accepted:true,retryAfter:60};} verify(email, proof) { return email === 'bundle@example.invalid' && JSON.parse(proof)[2].startsWith(this.env.PROOF); } }
                export class TrustedAuthSource extends WorkerEntrypoint { resolve() { return 'synthetic-bundle-source'; } }
                export default { fetch() { return new Response(null, {status:404}); } };` },
    ],
}));
try {
    await mf.ready;
    const db = await mf.getD1Database('MAIN', api.name);
    await db.exec('CREATE TABLE synthetic_clock(delta INTEGER NOT NULL);INSERT INTO synthetic_clock VALUES(0)');
    for (const name of (await readdir('api-worker/migrations')).filter(n => n.endsWith('.sql')).sort()) {
        const statements = splitSql(await readFile('api-worker/migrations/' + name, 'utf8'));
        await db.batch(statements.map(sql => db.prepare(sql.trimStart().startsWith('CREATE TRIGGER')?sql.replaceAll('unixepoch()','(unixepoch()+(SELECT delta FROM synthetic_clock))'):sql)));
    }
    const custodyDb=await mf.getD1Database('CUSTODIAN',recovery.name);
    await custodyDb.exec('CREATE TABLE synthetic_clock(delta INTEGER NOT NULL);INSERT INTO synthetic_clock VALUES(0)');
    for(const name of (await readdir('recovery-worker/migrations')).filter(n=>n.endsWith('.sql')).sort()){await custodyDb.batch(splitSql(await readFile('recovery-worker/migrations/'+name,'utf8')).map(sql=>custodyDb.prepare(sql.trimStart().startsWith('CREATE TRIGGER')?sql.replaceAll('unixepoch()','(unixepoch()+(SELECT delta FROM synthetic_clock))'):sql)));}
    // Public fetch dispatch avoids the internal /cdn-cgi proxy Origin policy.
    const worker = { fetch: (input, init) => mf.dispatchFetch(input, init) };
    for (const route of ['/sign-in','/app/requests/synthetic','/recovery/synthetic']) {
        const page=await worker.fetch(origin+route,{headers:{accept:'text/html'}});
        assert.equal(page.status,200);const html=await page.text();assert.match(html,/<div id="root"><\/div>/);assert.equal(page.headers.get('cache-control'),'no-store');assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
        const asset=html.match(/src="([^"]+\.js)"/)[1];const js=await worker.fetch(origin+asset);assert.equal(js.status,200);assert.ok((await js.text()).length>1000);
    }
    assert.equal((await worker.fetch(origin+'/assets/source.map')).status,404);
    assert.equal((await worker.fetch(origin+'/src/main.tsx')).status,404);
    let cookies, csrf;
    const remember = r => {
        cookies = r.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
        csrf = /__Host-akc_csrf=([^;]+)/.exec(cookies)[1];
    };
    const bootstrap = async () => { const r = await worker.fetch(origin + '/v1/auth/bootstrap'); assert.equal(r.status, 200); remember(r); };
    const post = (route, body) => worker.fetch(origin + '/v1/auth/' + route, { method: 'POST', headers: { origin, cookie: cookies, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const sha = async v => Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))).toString('hex');
    const lookupKey = await crypto.subtle.importKey('raw', Buffer.from(bindings.AUTH_LOOKUP_KEY, 'base64url'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const lookup = Buffer.from(await crypto.subtle.sign('HMAC', lookupKey, new TextEncoder().encode('email\0' + email))).toString('base64url');
    const invitation = raw();
    const emailKey=await crypto.subtle.importKey('raw',Buffer.from(bindings.AUTH_EMAIL_KEY,'base64url'),{name:'AES-GCM'},false,['encrypt']);
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const encrypted=Buffer.from(iv).toString('base64url')+'.'+Buffer.from(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(lookup)},emailKey,new TextEncoder().encode(email))).toString('base64url');
    await db.prepare('INSERT INTO invitations(digest,email_lookup,encrypted_email,expires_at) VALUES(?,?,?,unixepoch()+600)').bind(await sha(invitation),lookup,encrypted).run();
    await bootstrap();
    const display=await post('invitation/detail',{invitation});assert.equal(display.status,200);assert.equal((await display.json()).maskedEmail,'b***@e***.invalid');
    const verified = await post('invitation/verify', { invitation, email, proof });
    assert.equal(verified.status, 200);
    const registration = await post('registration/options', await verified.json());
    assert.equal(registration.status, 200);
    const options = await registration.json();
    assert.equal(options.options.authenticatorSelection.residentKey, 'required');
    assert.equal(options.options.authenticatorSelection.requireResidentKey, true);
    const authenticator = await virtualAuthenticator('ES256');
    const body = { challengeId: options.challengeId, userId: options.userId, response: await authenticator.register(options.options.challenge) };
    const registered = await post('registration/verify', body);
    assert.equal(registered.status, 200);
    remember(registered);
    assert.equal((await worker.fetch(origin + '/v1/auth/session', { headers: { cookie: cookies } })).status, 200);
    await bootstrap();
    const login = await (await post('authentication/options', { email })).json();
    assert.deepEqual(login.options.allowCredentials ?? [], []);
    assert.equal((await post('authentication/verify', { challengeId: login.challengeId, response: await authenticator.assert(login.options.challenge, { badSignature: true }) })).status, 401);
    const authenticated = await post('authentication/verify', { challengeId: login.challengeId, response: await authenticator.assert(login.options.challenge, { userHandle: options.userId }) });
    assert.equal(authenticated.status, 200);
    remember(authenticated);
    // Generated API device/bootstrap, actual passkey step-up and signed sync.
    const deviceWorker=await mf.getWorker('synthetic-device-transport');
    const devicePost=(route,body)=>deviceWorker.fetch(origin,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({route,body})});
    const keys=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
    const wrapping=await crypto.subtle.generateKey('X25519',true,['deriveBits']);
    const signingKey=Buffer.from(await crypto.subtle.exportKey('raw',keys.publicKey)).toString('base64');
    const wrappingKey=Buffer.from(await crypto.subtle.exportKey('raw',wrapping.publicKey)).toString('base64');
    const sign=async value=>Buffer.from(await crypto.subtle.sign('Ed25519',keys.privateKey,new TextEncoder().encode(value))).toString('base64');
    const authorization=await devicePost('authorize',{signingKey,wrappingKey,platform:'linux',proof:await sign(JSON.stringify(['AgentKeychain-device-authorize-v1',signingKey,wrappingKey,'linux']))});
    assert.equal(authorization.status,200);const pairing=await authorization.json();
    assert.equal((await worker.fetch(pairing.verificationUri,{headers:{cookie:cookies}})).status,200);
    const pending=await post('devices/pending',{verificationCode:pairing.verificationCode,issuerDeviceId:null});assert.equal(pending.status,200);const grant=await pending.json();assert.equal(grant.phrase,pairing.phrase);
    const grantStep=await(await post('step-up/options',{actionDigest:grant.actionDigest})).json();
    const grantStepped=await post('step-up/verify',{challengeId:grantStep.challengeId,actionDigest:grant.actionDigest,response:await authenticator.assert(grantStep.options.challenge)});assert.equal(grantStepped.status,200);remember(grantStepped);
    assert.equal((await post('devices/approve',{canonical:grant.canonical,signature:null,confirmed:true})).status,200);
    const challenge=await(await devicePost('challenge',{deviceId:pairing.deviceId})).json();
    const issued=await devicePost('token',{challengeId:challenge.challengeId,signature:await sign(JSON.stringify(['AgentKeychain-device-challenge-v1',challenge.challengeId,await sha(challenge.challenge),challenge.deviceId,challenge.vaultId,challenge.expiresAt]))});assert.equal(issued.status,200);const session=await issued.json();
    const deviceCall=async(path,body)=>{const method=body?'POST':'GET',nonce=raw(),timestamp=Math.floor(Date.now()/1000);return worker.fetch(bindings.DEVICE_API_ORIGIN+path,{method,headers:{'content-type':'application/json',authorization:'Bearer '+session.token,'x-device-nonce':nonce,'x-device-timestamp':String(timestamp),'x-device-proof':await sign(JSON.stringify(['AgentKeychain-device-request-v1',method,path,await sha(body??''),timestamp,nonce,await sha(session.token)]))},...(body?{body}:{})});};
    // Begin an independent recovery scenario with a fresh synthetic rate window.
    // Production per-account limits remain unchanged and have dedicated regression tests.
    await db.prepare('DELETE FROM auth_rate_windows').run();
    const browser=await(await worker.fetch(origin+'/v1/auth/session',{headers:{cookie:cookies}})).json();
    const apiAuthority=await mf.getWorker('agentkeychain-api-recovery');
    const custodyAuthority=await mf.getWorker('agentkeychain-custody-recovery');
    for(const authority of [apiAuthority,custodyAuthority])await authority.trust(browser.accountId,browser.tenantId,session.vaultId,session.deviceId,signingKey);
    const recoveryKeys=await(await deviceCall('/v1/devices/recovery-keys',JSON.stringify({}))).json();
    const recoveryKey=crypto.getRandomValues(new Uint8Array(32)),[shareA,shareB]=splitRecoveryKey(recoveryKey);
    const recoveryPackage={version:1,packageId:raw(),accountId:browser.accountId,tenantId:browser.tenantId,vaultId:session.vaultId,keyEpoch:1,policy:'two-party-24h',issuerDeviceId:session.deviceId,apiKeyId:recoveryKeys.api.keyId,custodianKeyId:recoveryKeys.custodian.keyId,wrappedVDK:encode64(crypto.getRandomValues(new Uint8Array(48)))};
    const syntheticVDK=crypto.getRandomValues(new Uint8Array(32));recoveryPackage.wrappedVDK=await wrapVaultKey(recoveryKey,syntheticVDK,vaultKeyContext(recoveryPackage));
    recoveryPackage.apiShare=await seal(recoveryKeys.api.publicKey,shareA,packageContext(recoveryPackage,'api'));
    recoveryPackage.custodianShare=await seal(recoveryKeys.custodian.publicKey,shareB,packageContext(recoveryPackage,'custodian'));
    const packageCanonical=JSON.stringify(recoveryPackage);
    assert.equal((await deviceCall('/v1/devices/recovery-package',JSON.stringify({canonical:packageCanonical,signature:await sign(packageCanonical)}))).status,200);
    const {sealPayload,objectId}=await import('../dist/test-shared/src/cloud/crypto.js');
    const {canonicalOperation}=await import('../dist/test-shared/src/cloud/protocol.js');
    const syntheticValue=raw()+raw(),header={protocolVersion:2,vaultId:session.vaultId,objectId:objectId(syntheticVDK,'recovery-synthetic'),deviceId:session.deviceId,operationId:raw(),kind:'put',generation:1,keyEpoch:1,approvalRef:null};
    const operation=canonicalOperation({...header,envelope:sealPayload(syntheticVDK,header,{name:'recovery-synthetic',value:syntheticValue,scopes:['test'],metadata:null,localVersion:1})});
    assert.equal((await deviceCall('/v1/vaults/'+session.vaultId+'/sync/push',JSON.stringify({canonical:operation,signature:await sign(operation)}))).status,200);
    const {canonicalRoster,ROSTER_DOMAIN,rosterDigest}=await import('../dist/test-shared/managed-cloud/shared/roster.js');
    const remote=role=>new Proxy({}, {get:(_,operation)=>(...args)=>deviceWorker.fetch(origin,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({role,operation,args})}).then(r=>r.json())});
    const authority=remote('AUTHORITY'),apiRelease=remote('API_RELEASE'),custodyRelease=remote('CUSTODY_RELEASE'),cpSigner=remote('CHECKPOINT');
    const cp=await cpSigner.key(),authorityPin=await authority.key();
    const manifestCanonical=JSON.stringify({witnessKeys:[await remote('WITNESS').key()],recoveryServices:{api:await apiRelease.key(),custodian:await custodyRelease.key()},recoveryAuthorities:[authorityPin],version:1,releaseId:'compiled-recovery',apiOrigin:'https://api.local.invalid',webOrigin:origin,protocolMin:2,protocolMax:2,checkpointKeys:[cp]});
    await authority.configure(manifestCanonical);
    const now=Math.floor(Date.now()/1000),rosterCanonical=canonicalRoster({version:1,accountId:browser.accountId,tenantId:browser.tenantId,vaultId:session.vaultId,revision:1,previousDigest:null,keyEpoch:1,active:[{deviceId:session.deviceId,signingKey,wrappingKey}],revoked:[],issuer:{kind:'device',id:session.deviceId},issuedAt:now,expiresAt:now+2592000,checkpointKeys:[cp],recoveryAuthorities:[authorityPin],recovery:null});
    const initialRoster={canonical:rosterCanonical,signature:await sign(ROSTER_DOMAIN+rosterCanonical)};
    await db.prepare('INSERT INTO signed_rosters VALUES(?,?,?,?,?,NULL,?,?,?)').bind(browser.tenantId,session.vaultId,browser.accountId,1,await rosterDigest(initialRoster),session.deviceId,initialRoster.canonical,initialRoster.signature).run();
    const accountPin=await apiAuthority.accountKey();for(const actor of [apiAuthority,custodyAuthority])await actor.verifier(browser.accountId,accountPin.publicKey);
    let clockOffset=0,activeFault=null,activeHome=null,activeCase=null;
    const setClock=async(offset)=>{clockOffset=offset;await db.prepare('UPDATE synthetic_clock SET delta=?').bind(offset/1000).run();await custodyDb.prepare('UPDATE synthetic_clock SET delta=?').bind(offset/1000).run();await worker.fetch(origin+'/__clock?offset='+offset);await apiAuthority.clock(offset);await custodyAuthority.clock(offset);await remote('CUSTODIAN').clock(offset);};
    const root=await mkdtemp(join(tmpdir(),'akc-recovery-process-')),binary=join(root,'client'),password=raw()+raw(),token=raw(),secrets=new Map(),secureFaults=new Set();
    const spawnClient=(command,args,input,cwd=resolve('..'))=>{
        const p=spawn(command,args,{cwd,env:{PATH:process.env.PATH,TMPDIR:tmpdir()},stdio:['pipe','pipe','pipe']});let out='',err='';
        p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.stdin.end(input);
        const done=new Promise(resolve=>{p.on('exit',code=>resolve(code));p.on('error',()=>resolve(-1));});return {p,done,out:()=>out,err:()=>err};
    };
    const control=createServer(async(req,res)=>{
        try{
            let rawBody='';for await(const chunk of req)rawBody+=chunk;
            let result;
            if(req.url.startsWith('/api/')){
                const headers={};for(const k of ['content-type','authorization','x-device-nonce','x-device-timestamp','x-device-proof'])if(req.headers[k])headers[k]=req.headers[k];
                const response=await deviceWorker.fetch(origin,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({path:req.url.slice(4),method:req.method,headers,body:rawBody})});
                res.writeHead(response.status,{'content-type':'application/json'});let text=await response.text();
                if(response.ok&&req.url.endsWith('/recovery-target-status')&&['reject:target','reject:epoch'].includes(activeFault)){
                    const value=JSON.parse(text),c=JSON.parse(value.canonical);if(activeFault==='reject:target')c.targetDeviceId=raw();else c.keyEpoch++;value.canonical=JSON.stringify(c);text=JSON.stringify(value);
                }
                if(response.ok&&req.url.endsWith('/recovery-target-trust')&&['reject:authority','reject:authority-id','reject:roster','reject:pin','reject:replay'].includes(activeFault)){
                    const value=JSON.parse(text),intent=JSON.parse(Buffer.from(secrets.get(activeHome+':recovery-intent'),'base64').toString()),c=intent.snapshot.data.caseCanonical;
                    const key=await crypto.subtle.importKey('pkcs8',Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),Buffer.from(intent.keys.wrappingPrivate,'base64')]),'X25519',false,['deriveBits']);
                    const bytes=await open(key,value.sealed,'AgentKeychain-recovery-trust-v1\0'+c,768*1024),signed=JSON.parse(new TextDecoder().decode(bytes));bytes.fill(0);const bundle=JSON.parse(signed.canonical);
                    if(activeFault==='reject:authority')signed.signature=Buffer.alloc(64).toString('base64');
                    else{if(activeFault==='reject:authority-id')bundle.authorityKeyId='untrusted-authority';if(activeFault==='reject:roster'){const head=bundle.rosters.at(-1),r=JSON.parse(head.canonical);r.active.find(d=>d.deviceId===intent.snapshot.target.targetDeviceId).signingKey=Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64');head.canonical=JSON.stringify(r);}if(activeFault==='reject:pin'){const release=JSON.parse(bundle.releaseCanonical);release.checkpointKeys[0].publicKey=Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64');bundle.releaseCanonical=JSON.stringify(release);}if(activeFault==='reject:replay')bundle.caseCanonical=JSON.stringify({...JSON.parse(c),id:raw()});signed.canonical=JSON.stringify(bundle);signed.signature=await authority.sign('AgentKeychain-recovery-trust-v1\0'+signed.canonical);}
                    const plain=new TextEncoder().encode(JSON.stringify(signed));try{value.sealed=await seal(intent.snapshot.target.wrappingKey,plain,'AgentKeychain-recovery-trust-v1\0'+c);}finally{plain.fill(0);}text=JSON.stringify(value);
                }
                if(response.ok&&req.url.endsWith('/recovery-target-trust')&&activeFault==='reject:trust-version'){
                    const old=JSON.parse(text),name='binding-refresh-'+raw(),h={...header,objectId:objectId(syntheticVDK,name),operationId:raw()};
                    const op=canonicalOperation({...h,envelope:sealPayload(syntheticVDK,h,{name,value:syntheticValue,scopes:['test'],metadata:null,localVersion:1})});
                    assert.equal((await deviceCall('/v1/vaults/'+session.vaultId+'/sync/push',JSON.stringify({canonical:op,signature:await sign(op)}))).status,200);
                    const refreshed=await deviceWorker.fetch(origin,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({path:req.url.slice(4),method:req.method,headers,body:rawBody})});
                    assert.equal(refreshed.status,200);const value=await refreshed.json();
                    assert.equal(value.receiptVersion,old.receiptVersion+1);assert.equal(value.binding.rosterDigest,old.binding.rosterDigest);
                    for(const field of ['checkpointDigest','refreshDigest','witnessDigest'])assert.notEqual(value.binding[field],old.binding[field]);
                    value.sealed=old.sealed;text=JSON.stringify(value);
                }
                res.end(text);return;
            }
            if(req.headers.authorization!=='Bearer '+token)throw new Error('unauthorized');
            const body=JSON.parse(rawBody),key=body.home+':';
            if(req.url==='/get')result={value:secrets.get(key+body.value)??null};
            else if(req.url==='/put'){
                const fault=body.fault,account=body.value.account,hit=!secureFaults.has(key)&&["secure-before:"+account,"secure-after:"+account].includes(fault);
                if(hit){secureFaults.add(key);if(fault.startsWith('secure-before:')){res.writeHead(503);res.end('{}');return;}}
                secrets.set(key+account,body.value.value);
                if(hit){res.writeHead(503);res.end('{}');return;}result={ok:true};
            }
            else if(req.url==='/remove'){secrets.delete(key+body.value);result={ok:true};}
            else if(req.url==='/clock'){
                assert.equal(await custodyDb.prepare('SELECT state FROM recovery_sagas WHERE id=?').bind(activeCase).first('state'),'prepared');
                await setClock(86401000);result={clockOffset};
            }
            else if(req.url==='/browser'){
                const reference=new URLSearchParams(new URL(body.value.url).hash.slice(1)).get('requestRef');
                await db.prepare('DELETE FROM auth_rate_windows').run();await bootstrap();
                const verified=await post('recovery/verify',{email,proof:proof+raw(),requestRef:reference});assert.equal(verified.status,200);remember(verified);
                const started=await post('recovery/start',{});assert.equal(started.status,200);
                const target=JSON.parse(await db.prepare('SELECT target FROM recovery_targets WHERE digest=?').bind(await sha(reference)).first('target'));
                const canonical=await db.prepare('SELECT canonical FROM recovery_sagas WHERE id=?').bind(target.id).first('canonical');
                activeCase=target.id;
                if(body.fault==='reject:cancelled'){
                    const authorization={action:'cancel',nonce:raw(),expiresAt:Math.floor(Date.now()/1000)+300,deviceId:session.deviceId,signature:''};authorization.signature=await sign(JSON.stringify(['AgentKeychain-recovery-cancel-v1',canonical,authorization.action,authorization.nonce,authorization.expiresAt,authorization.deviceId]));
                    const cancelled=await deviceCall('/v1/devices/recovery-cancel',JSON.stringify({id:target.id,authorization}));assert.equal(cancelled.status,200);
                }else if(body.fault==='reject:expired'){await setClock(172801000);}
                else if(body.fault!=='delayed'){const confirmed=await deviceCall('/v1/devices/recovery-confirm',JSON.stringify({id:target.id,signature:await sign(JSON.stringify(['AgentKeychain-recovery-confirm-v1',canonical]))}));assert.equal(confirmed.status,200);}
                if(body.fault==='reject:live-epoch'){
                    const next={...recoveryPackage,packageId:raw(),keyEpoch:2},key=crypto.getRandomValues(new Uint8Array(32)),parts=splitRecoveryKey(key),vdk=crypto.getRandomValues(new Uint8Array(32));
                    try{next.wrappedVDK=await wrapVaultKey(key,vdk,vaultKeyContext(next));next.apiShare=await seal(recoveryKeys.api.publicKey,parts[0],packageContext(next,'api'));next.custodianShare=await seal(recoveryKeys.custodian.publicKey,parts[1],packageContext(next,'custodian'));const canonical=JSON.stringify(next);assert.equal((await deviceCall('/v1/devices/recovery-package',JSON.stringify({canonical,signature:await sign(canonical)}))).status,200);}finally{key.fill(0);vdk.fill(0);parts.forEach(p=>p.fill(0));}
                }
                result={ok:true,clockOffset};
            }else throw new Error('unknown_control');
            res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(result));
        }catch(error){process.stderr.write('control: '+error.message+'\n');res.writeHead(500);res.end('{}');}
    });
    await new Promise(resolve=>control.listen(0,'127.0.0.1',resolve));
    const local='http://127.0.0.1:'+control.address().port;
    try{
        const build=spawnClient('bun',['scripts/phase45/build-client.ts',binary],'');assert.equal(await build.done,0,build.err());
        const manifestSignature=await sign(manifestCanonical);
        const faults=[null,'before:/v1/devices/recovery-target','after:/v1/devices/recovery-target','before:waiting_for_release','after:waiting_for_release','after:/v1/devices/recovery-target-delivery','after:released','after:api-share','after:custodian-share','after:reconstruction','after:reconstructed','before:activating','after:activating','after:/v1/devices/recovery-target-finish','before:/v1/devices/recovery-target-readback','after:/v1/devices/recovery-target-readback','after:server_completed','before:sqlite-commit','after:sqlite-commit','after:local_committed','after:final-readback','after:active',...['recovery-intent','signing-private','wrapping-private','csk','refresh-credential','roster-anchor','checkpoint-anchor','recovery-anchor'].flatMap(a=>['secure-before:'+a,'secure-after:'+a]),'reject:cancelled','reject:expired','reject:target','reject:epoch','reject:authority','reject:authority-id','reject:roster','reject:pin','reject:replay','reject:trust-version','delayed','expire-before-activation','expire-after-activation','reject:live-epoch'];
        let cases=0,activated=0,synced=0;
        const selected=process.argv[2]?faults.filter(f=>f===process.argv[2]):faults.filter(f=>!f?.startsWith('expire-')&&f!=='reject:live-epoch');
        for(const fault of selected){
            const home=join(root,'case-'+cases);activeHome=home;activeFault=fault;await mkdir(home,{mode:0o700});
            const init=spawnClient('bun',['scripts/recovery/init.ts'],JSON.stringify({home,password}));assert.equal(await init.done,0,init.err());
            const boot=fault=>JSON.stringify({fault:fault==='expire-before-activation'?'after:activating':fault==='expire-after-activation'?'after:/v1/devices/recovery-target-finish':fault,clockOffset,home,password,api:local+'/api',secure:local,token,manifest:{canonical:manifestCanonical,signature:manifestSignature},rootPublicKey:signingKey})+'\n';
            await db.prepare('DELETE FROM auth_rate_windows').run();
            const run=spawnClient(binary,['cloud','recover',recoveryPackage.packageId],boot(fault));
            const timeout=setTimeout(()=>run.p.kill('SIGKILL'),30000);
            const code=await run.done;clearTimeout(timeout);assert.equal(code,fault&&fault!=='delayed'?(fault.startsWith('secure-')||fault.startsWith('reject:')?1:94):0,String(fault)+' '+run.err());
            if(fault?.startsWith('reject:')){
                assert.ok(!run.out().includes('"state":"active"'));
                const intent=JSON.parse(Buffer.from(secrets.get(home+':recovery-intent'),'base64').toString());
                if(['reject:cancelled','reject:expired','reject:target','reject:epoch','reject:live-epoch'].includes(fault)){assert.ok(Object.values(intent.keys).every(v=>v===''),fault+' must erase intent keys; stage='+intent.snapshot.stage);assert.equal(Object.keys(intent.snapshot.data).length,0);}else activated++;
                assert.ok(!secrets.has(home+':csk'));if(fault==='reject:trust-version'){const id=JSON.parse(intent.snapshot.data.caseCanonical).id;assert.equal(await custodyDb.prepare('SELECT count(*) n FROM recovery_trust_commits WHERE case_id=?').bind(id).first('n'),0);assert.ok(!secrets.has(home+':refresh-credential'));}cases++;
                assert.equal(await db.prepare('SELECT count(*) n FROM devices').first('n'),activated+1);
                await setClock(0);process.stdout.write('Recovery process scenario '+cases+': '+fault+' PASS\n');continue;
            }
            if(fault?.startsWith('expire-'))await setClock(172801000);
            if(fault)await new Promise(resolve=>setTimeout(resolve,600));
            await db.prepare('DELETE FROM auth_rate_windows').run();
            const resumed=spawnClient(binary,['cloud','recover',recoveryPackage.packageId],boot(null));
            const rt=setTimeout(()=>resumed.p.kill('SIGKILL'),30000);const rc=await resumed.done;clearTimeout(rt);
            if(fault==='expire-before-activation'){
                assert.equal(rc,1);assert.ok(resumed.err().includes('cloud_recovery_expired'));const intent=JSON.parse(Buffer.from(secrets.get(home+':recovery-intent'),'base64').toString());assert.ok(Object.values(intent.keys).every(v=>v===''));assert.equal(await db.prepare('SELECT count(*) n FROM devices').first('n'),1);cases++;process.stdout.write('Recovery process scenario '+cases+': '+fault+' PASS\n');continue;
            }
            assert.equal(rc,0,String(fault)+' '+resumed.err());
            assert.match(resumed.out(),/"state":"active"/);
            cases++;activated++;
            assert.equal(await db.prepare('SELECT count(*) n FROM devices').first('n'),activated+1);
            assert.equal(await custodyDb.prepare('SELECT count(*) n FROM recovery_trust_receipts').first('n'),activated);
            assert.equal(await db.prepare('SELECT count(*) n FROM device_sessions').first('n'),synced+1);
            for(let retry=0;retry<2;retry++){const sync=spawnClient(binary,['cloud','sync-now'],boot(null));assert.equal(await sync.done,0,sync.err());}
            synced++;assert.equal(await db.prepare('SELECT count(*) n FROM device_sessions').first('n'),synced+1);
            const get=spawnClient(binary,['get','recovery-synthetic'],boot(null));assert.equal(await get.done,0,get.err());assert.ok(get.out().trim()===syntheticValue,'recovered payload must decrypt exactly');
            const logout=spawnClient(binary,['cloud','logout'],boot(null));assert.equal(await logout.done,0,logout.err());
            const blocked=spawnClient(binary,['cloud','sync-now'],boot(null));assert.equal(await blocked.done,1);
            const login=spawnClient(binary,['cloud','login'],boot(null));assert.equal(await login.done,0,login.err());
            assert.equal(await db.prepare('SELECT count(*) n FROM device_sessions').first('n'),synced+1);
            for(const value of [syntheticValue,Buffer.from(syntheticVDK).toString('base64'),Buffer.from(recoveryKey).toString('base64')]){for(const output of [run.out(),run.err(),resumed.out(),resumed.err()])assert.ok(!output.includes(value));for(const suffix of ['','-wal']){try{assert.ok(!(await readFile(join(home,'vault.db'+suffix))).includes(Buffer.from(value)));}catch(e){if(e.code!=='ENOENT')throw e;}}}
            const privateMaterials=[Buffer.from(syntheticVDK),Buffer.from(recoveryKey),Buffer.from(shareA),Buffer.from(shareB),...['csk','signing-private','wrapping-private','refresh-credential'].map(account=>Buffer.from(secrets.get(home+':'+account),'base64'))];
            for(const suffix of ['','-wal']){try{const bytes=await readFile(join(home,'vault.db'+suffix));for(const material of privateMaterials)assert.ok(!bytes.includes(material),'no plaintext key/share/refresh in SQLite artifacts');}catch(e){if(e.code!=='ENOENT')throw e;}}
            for(const output of [run.out(),run.err(),resumed.out(),resumed.err()])for(const material of privateMaterials)assert.ok(!output.includes(material.toString('base64')),'no key/share/refresh in process logs');
            privateMaterials.forEach(bytes=>bytes.fill(0));
            process.stdout.write('Recovery process scenario '+cases+': '+(fault??'fast')+' PASS\n');
        }
        process.stdout.write('Compiled recovery: '+cases+' scenarios, actual CLI + two Workers + fake secure store; exact device/session counts and plaintext checks PASS\n');
    }finally{await new Promise(resolve=>control.close(resolve));await rm(root,{recursive:true,force:true});}
}finally{await mf.dispose();}
