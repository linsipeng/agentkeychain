import { assertSafeView } from '../web/src/safe-view.ts';
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
await build({entryPoints:['shared/recovery-crypto.ts','shared/recovery.ts'],outdir:'dist/test-shared',bundle:true,format:'esm',platform:'node',target:'es2022'});
const {seal,open,encode64,splitRecoveryKey,joinRecoveryKey,wrapVaultKey,unwrapVaultKey}=await import('../dist/test-shared/recovery-crypto.js');
const {packageContext,releaseContext,vaultKeyContext}=await import('../dist/test-shared/recovery.js');
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
const bindings = { AUTH_ORIGIN: origin, AUTH_RP_ID: 'local.invalid', AUTH_BOOTSTRAP_KEY: raw(), AUTH_EMAIL_KEY: raw(), AUTH_LOOKUP_KEY: raw() };
const noOutbound = () => new Response(null, { status: 502 });
const mf = new Miniflare(convertV4MiniflareOptions({
    host: '127.0.0.1', port: 0, inspectorPort: 0,
    workers: [
        { ...api, modules: true, modulesRoot: resolve('dist'), scriptPath: resolve('dist/api-worker/index.js'), bindings, outboundService: noOutbound },
        // Test-only native-device transport: Node/Undici injects sec-fetch-mode
        // even on stub fetches. Construct device requests inside workerd instead.
        {name:'synthetic-device-transport',modules:true,compatibilityDate:api.compatibilityDate,serviceBindings:{API:api.name},outboundService:noOutbound,
            script:`export default {async fetch(request,env){const {route,body}=await request.json();return env.API.fetch(new Request('https://local.invalid/v1/devices/'+route,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}));}};`},
        {name:'agentkeychain-checkpoint-signer',modules:true,modulesRoot:resolve('dist'),scriptPath:resolve('dist/test-checkpoint.mjs'),compatibilityDate:api.compatibilityDate,compatibilityFlags:api.compatibilityFlags,outboundService:noOutbound},
        ...['agentkeychain-api-recovery','agentkeychain-custody-recovery'].map(name=>({name,modules:true,modulesRoot:resolve('dist'),scriptPath:resolve('dist/test-recovery.mjs'),compatibilityDate:api.compatibilityDate,compatibilityFlags:api.compatibilityFlags,outboundService:noOutbound})),
        { ...recovery, modules: true, modulesRoot: resolve('dist'), scriptPath: resolve('dist/recovery-worker/index.js'), outboundService: noOutbound },
        { name: 'agentkeychain-auth-trust', modules: true, compatibilityDate: api.compatibilityDate, bindings: { PROOF: proof }, outboundService: noOutbound,
            script: `import { WorkerEntrypoint } from 'cloudflare:workers';
                export class EmailVerifier extends WorkerEntrypoint { request(){return {accepted:true,retryAfter:60};} verify(email, proof) { return email === 'bundle@example.invalid' && JSON.parse(proof)[2] === this.env.PROOF; } }
                export class TrustedAuthSource extends WorkerEntrypoint { resolve() { return 'synthetic-bundle-source'; } }
                export default { fetch() { return new Response(null, {status:404}); } };` },
    ],
}));
try {
    await mf.ready;
    const db = await mf.getD1Database('MAIN', api.name);
    for (const name of (await readdir('api-worker/migrations')).filter(n => n.endsWith('.sql')).sort()) {
        const statements = splitSql(await readFile('api-worker/migrations/' + name, 'utf8'));
        await db.batch(statements.map(sql => db.prepare(sql)));
    }
    const custodyDb=await mf.getD1Database('CUSTODIAN',recovery.name);
    for(const name of (await readdir('recovery-worker/migrations')).filter(n=>n.endsWith('.sql')).sort()){await custodyDb.batch(splitSql(await readFile('recovery-worker/migrations/'+name,'utf8')).map(sql=>custodyDb.prepare(sql)));}
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
    const deviceCall=async(path,body)=>{const method=body?'POST':'GET',nonce=raw(),timestamp=Math.floor(Date.now()/1000);return worker.fetch(origin+path,{method,headers:{'content-type':'application/json',authorization:'Bearer '+session.token,'x-device-nonce':nonce,'x-device-timestamp':String(timestamp),'x-device-proof':await sign(JSON.stringify(['AgentKeychain-device-request-v1',method,path,await sha(body??''),timestamp,nonce,await sha(session.token)]))},...(body?{body}:{})});};
    const canonical=JSON.stringify({protocolVersion:2,vaultId:session.vaultId,objectId:'synthetic',deviceId:session.deviceId,operationId:raw(),kind:'put',generation:1,keyEpoch:1,envelope:{nonce:Buffer.alloc(24,1).toString('base64'),ciphertext:Buffer.alloc(48,2).toString('base64')},approvalRef:null});
    const pushed=await deviceCall('/v1/vaults/'+session.vaultId+'/sync/push',JSON.stringify({canonical,signature:await sign(canonical)}));assert.equal(pushed.status,200);const receipt=await pushed.json();assert.equal(JSON.parse(receipt.checkpoint.canonical).sequence,1);
    const pulled=await deviceCall('/v1/vaults/'+session.vaultId+'/sync/pull');assert.equal(pulled.status,200);const page=await pulled.json();assert.equal(page.versions.length,1);assert.deepEqual(page.checkpoint,receipt.checkpoint);
    const keyPackage=JSON.stringify({version:1,vaultId:session.vaultId,targetDeviceId:session.deviceId,keyEpoch:1,wrappedVDK:Buffer.alloc(80,3).toString('base64'),issuerDeviceId:session.deviceId,grantId:pairing.requestId});
    assert.equal((await deviceCall('/v1/devices/enroll',JSON.stringify({canonical:keyPackage,signature:await sign(keyPackage)}))).status,200);
    const fetched=await deviceCall('/v1/devices/key-packages');assert.equal(fetched.status,200);assert.equal((await fetched.json()).canonical,keyPackage);
    const stepFor=async actionDigest=>{const options=await(await post('step-up/options',{actionDigest})).json();const r=await post('step-up/verify',{challengeId:options.challengeId,actionDigest,response:await authenticator.assert(options.options.challenge)});assert.equal(r.status,200);remember(r);};
    const updateCanonical=JSON.stringify({...JSON.parse(canonical),operationId:raw(),approvalRef:raw()});
    const updateSigned={canonical:updateCanonical,signature:await sign(updateCanonical)};
    assert.equal((await deviceCall('/v1/vaults/'+session.vaultId+'/sync/push',JSON.stringify(updateSigned))).status,403);
    const requested=await deviceCall('/v1/devices/approvals',JSON.stringify({operation:updateSigned,expiresIn:300}));assert.equal(requested.status,200);
    assert.equal((await deviceCall('/v1/devices/approvals',JSON.stringify({operation:updateSigned,expiresIn:300}))).status,200);
    const approval=await(await post('approvals/detail',{id:JSON.parse(updateCanonical).approvalRef})).json();
    await stepFor(approval.approveDigest);
    assert.equal((await post('approvals/approve',{id:approval.id,confirmed:true})).status,200);
    assert.equal((await deviceCall('/v1/vaults/'+session.vaultId+'/sync/push',JSON.stringify(updateSigned))).status,200);
    const activity=await(await post('activity/list',{after:0,limit:100,minimum:0})).json();
    assert.equal(activity.verification,'verified');
    assert.ok(activity.events.every(e=>typeof e.id==='string' && /^[a-f0-9]{32}$/.test(e.id)));
    assert.equal(typeof activity.nextCursor,'string');
    assert.equal((await post('activity/detail',{id:activity.events[0].id,minimum:activity.through})).status,200);
    assert.equal((await post('activity/detail',{id:1,minimum:0})).status,400);
    await db.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES(?,?,'approval.pending')").bind(activity.events[0].tenant_id,'synthetic-other-account').run();
    const isolated=await(await post('activity/list',{after:activity.nextCursor,limit:100,minimum:activity.through})).json();
    assert.equal(isolated.events.length,0);assert.equal(isolated.through,activity.through);
    // Begin an independent recovery scenario with a fresh synthetic rate window.
    // Production per-account limits remain unchanged and have dedicated regression tests.
    await db.prepare('DELETE FROM auth_rate_windows').run();
    const browser=await(await worker.fetch(origin+'/v1/auth/session',{headers:{cookie:cookies}})).json();
    const apiAuthority=await mf.getWorker('agentkeychain-api-recovery');
    const custodyAuthority=await mf.getWorker('agentkeychain-custody-recovery');
    for(const authority of [apiAuthority,custodyAuthority])await authority.trust(browser.accountId,browser.tenantId,session.vaultId,session.deviceId,signingKey);
    const accountPin=await apiAuthority.accountKey();for(const actor of [apiAuthority,custodyAuthority])await actor.verifier(browser.accountId,accountPin.publicKey);
    const recoveryKeys=await(await deviceCall('/v1/devices/recovery-keys',JSON.stringify({}))).json();
    const recoveryKey=crypto.getRandomValues(new Uint8Array(32)),[shareA,shareB]=splitRecoveryKey(recoveryKey);
    const recoveryPackage={version:1,packageId:raw(),accountId:browser.accountId,tenantId:browser.tenantId,vaultId:session.vaultId,keyEpoch:1,policy:'two-party-24h',issuerDeviceId:session.deviceId,apiKeyId:recoveryKeys.api.keyId,custodianKeyId:recoveryKeys.custodian.keyId,wrappedVDK:encode64(crypto.getRandomValues(new Uint8Array(48)))};
    const syntheticVDK=crypto.getRandomValues(new Uint8Array(32));recoveryPackage.wrappedVDK=await wrapVaultKey(recoveryKey,syntheticVDK,vaultKeyContext(recoveryPackage));
    recoveryPackage.apiShare=await seal(recoveryKeys.api.publicKey,shareA,packageContext(recoveryPackage,'api'));
    recoveryPackage.custodianShare=await seal(recoveryKeys.custodian.publicKey,shareB,packageContext(recoveryPackage,'custodian'));
    const packageCanonical=JSON.stringify(recoveryPackage);
    assert.equal((await deviceCall('/v1/devices/recovery-package',JSON.stringify({canonical:packageCanonical,signature:await sign(packageCanonical)}))).status,200);
    const targetSigning=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']),targetWrapping=await crypto.subtle.generateKey('X25519',true,['deriveBits']);
    const recoveryRequest={id:raw(),packageId:recoveryPackage.packageId,targetDeviceId:raw(),signingKey:encode64(new Uint8Array(await crypto.subtle.exportKey('raw',targetSigning.publicKey))),wrappingKey:encode64(new Uint8Array(await crypto.subtle.exportKey('raw',targetWrapping.publicKey))),nonce:raw()};
    const targetSign=async value=>encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',targetSigning.privateKey,new TextEncoder().encode(value))));
    const targetSignature=await targetSign(JSON.stringify(['AgentKeychain-recovery-target-v1',recoveryRequest]));
    const possessionResponse=await devicePost('recovery-target-challenge',{target:recoveryRequest,signature:targetSignature});assert.equal(possessionResponse.status,200,await possessionResponse.clone().text());const possession=await possessionResponse.json();
    const possessionProof=encode64(await open(targetWrapping.privateKey,possession.box,'AgentKeychain-recovery-target-possession-v1\0'+possession.challengeRef+'\0'+JSON.stringify(recoveryRequest)));
    const prepared=await devicePost('recovery-target',{target:recoveryRequest,signature:targetSignature,challengeRef:possession.challengeRef,proof:possessionProof});assert.equal(prepared.status,200);
    const {requestRef}=await prepared.json();
    for(const route of ['start','detail','release','finish','status','notifications','review','cancel']) {
        const denied=await post('recovery/'+route,recoveryRequest);assert.equal(denied.status,['start','status','cancel'].includes(route)?401:404);assertSafeView(await denied.json());
    }
    const normalCookies=cookies;
    await bootstrap();
    const restricted=await post('recovery/verify',{email,proof,requestRef});assert.equal(restricted.status,200);assertSafeView(await restricted.clone().json());remember(restricted);
    const startedResponse=await post('recovery/start',{});assert.equal(startedResponse.status,200);assertSafeView(await startedResponse.json());
    const targetCall=async(route,extra={})=>{const body={requestRef,...extra};const r=await devicePost(route,{...body,signature:await targetSign(JSON.stringify(['AgentKeychain-recovery-target-call-v1',route,body]))});assert.equal(r.status,200);return r.json();};
    const started=await targetCall('recovery-target-status');
    const released=await targetCall('recovery-target-release',{evidence:{mode:'device',confirmerId:session.deviceId,signature:await sign(JSON.stringify(['AgentKeychain-recovery-confirm-v1',started.canonical])),proof:null}});
    assertSafeView(await(await post('recovery/status',{id:recoveryRequest.id})).json());
    // Only the synthetic target device decrypts and proves possession.
    assert.deepEqual(joinRecoveryKey(await open(targetWrapping.privateKey,released.api,releaseContext(started.canonical,'api')),await open(targetWrapping.privateKey,released.custodian,releaseContext(started.canonical,'custodian'))),recoveryKey);
    assert.deepEqual(await unwrapVaultKey(recoveryKey,released.wrappedVDK,vaultKeyContext(recoveryPackage)),syntheticVDK);
    assert.equal((await db.prepare('SELECT count(*) n FROM devices').first()).n,1);
    const recoveryProof=encode64(await open(targetWrapping.privateKey,started.challenge,releaseContext(started.canonical,'api')+'proof'));
    const recoverySignature=encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',targetSigning.privateKey,new TextEncoder().encode(JSON.stringify(['AgentKeychain-recovery-proof-v1',started.canonical,recoveryProof])))));
    await targetCall('recovery-target-finish',{proof:recoveryProof,completionSignature:recoverySignature});
    assert.equal((await db.prepare('SELECT count(*) n FROM devices').first()).n,2);
    assert.equal((await worker.fetch(origin+'/v1/auth/session',{headers:{cookie:normalCookies}})).status,401);
    await bootstrap();const relogin=await(await post('authentication/options',{email})).json();const logged=await post('authentication/verify',{challengeId:relogin.challengeId,response:await authenticator.assert(relogin.options.challenge,{userHandle:options.userId})});assert.equal(logged.status,200);remember(logged);
    const review=await(await post('web/query',{view:'recovery',id:recoveryRequest.id})).json();assertSafeView(review);assert.equal(review.reviewRequired,true);
    const reviewOptions=await(await post('web/options',{ref:review.reviewRef})).json();
    const reviewVerified=await post('web/verify',{ref:review.reviewRef,challengeId:reviewOptions.challengeId,response:await authenticator.assert(reviewOptions.options.challenge)});assert.equal(reviewVerified.status,200);remember(reviewVerified);
    const reviewed=await post('web/execute',{ref:review.reviewRef,confirmed:true});assert.equal(reviewed.status,200);assertSafeView(await reviewed.json());
    const afterReview=await(await post('web/query',{view:'recovery',id:recoveryRequest.id})).json();assertSafeView(afterReview);assert.equal(afterReview.reviewRequired,false);
    const recoveredChallengeResponse=await devicePost('challenge',{deviceId:recoveryRequest.targetDeviceId});assert.equal(recoveredChallengeResponse.status,200);const recoveredChallenge=await recoveredChallengeResponse.json();
    const recoveredSignature=encode64(new Uint8Array(await crypto.subtle.sign('Ed25519',targetSigning.privateKey,new TextEncoder().encode(JSON.stringify(['AgentKeychain-device-challenge-v1',recoveredChallenge.challengeId,await sha(recoveredChallenge.challenge),recoveredChallenge.deviceId,recoveredChallenge.vaultId,recoveredChallenge.expiresAt])))));
    assert.equal((await devicePost('token',{challengeId:recoveredChallenge.challengeId,signature:recoveredSignature})).status,200);
    const actionDigest = await sha('synthetic-bundle-action');
    const step = await (await post('step-up/options', { actionDigest })).json();
    const stepped = await post('step-up/verify', { challengeId: step.challengeId, actionDigest, response: await authenticator.assert(step.options.challenge) });
    assert.equal(stepped.status, 200);
    remember(stepped);
    assert.equal((await post('logout', {})).status, 200);
    assert.equal((await worker.fetch(origin + '/v1/auth/session', { headers: { cookie: cookies } })).status, 401);
    // Phase 2A routing remains distinct in the generated module.
    assert.equal((await worker.fetch(origin + '/v1/vaults/synthetic/sync/pull')).status, 401);
    assert.equal((await (await mf.getWorker(recovery.name)).fetch(origin)).status, 404);
    assert.equal((await db.prepare('SELECT count(*) n FROM accounts').first()).n, 1);
    process.stdout.write('Generated API bundle: manifest flags/bindings, D1 migrations, real ES256 registration/login/step-up/logout device enrollment, sessions, key packages, signed sync, exact approval, verified audit, two-Worker recovery proof/activation and route isolation PASS\n');
} finally { await mf.dispose(); }
