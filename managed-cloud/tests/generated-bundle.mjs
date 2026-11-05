/** Executes the built API module in standalone workerd, with manifest-derived
 * dates, flags, D1 and service bindings. No Vitest loader or compatibility extras.
 * All keys/proofs are ephemeral synthetic data; no outbound network is allowed. */
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_getMiniflareWorkerOptions as manifest, unstable_splitSqlQuery as splitSql, unstable_readConfig as readConfig } from 'wrangler';

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
assert.deepEqual(Object.keys(api.serviceBindings).sort(), ['CHECKPOINT_SIGNER', 'EMAIL_VERIFIER', 'RECOVERY', 'TRUSTED_AUTH_SOURCE']);
const raw = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
const proof = raw(), origin = 'https://local.invalid', email = 'bundle@example.invalid';
const bindings = { AUTH_ORIGIN: origin, AUTH_RP_ID: 'local.invalid', AUTH_BOOTSTRAP_KEY: raw(), AUTH_EMAIL_KEY: raw(), AUTH_LOOKUP_KEY: raw() };
const noOutbound = () => new Response(null, { status: 502 });
const mf = new Miniflare(convertV4MiniflareOptions({
    host: '127.0.0.1', port: 0, inspectorPort: 0,
    workers: [
        { ...api, modules: true, modulesRoot: resolve('dist'), scriptPath: resolve('dist/api-worker/index.js'), bindings, outboundService: noOutbound },
        {name:'agentkeychain-checkpoint-signer',modules:true,modulesRoot:resolve('dist'),scriptPath:resolve('dist/test-checkpoint.mjs'),compatibilityDate:api.compatibilityDate,compatibilityFlags:api.compatibilityFlags,outboundService:noOutbound},
        { ...recovery, modules: true, modulesRoot: resolve('dist'), scriptPath: resolve('dist/recovery-worker/index.js'), outboundService: noOutbound },
        { name: 'agentkeychain-auth-trust', modules: true, compatibilityDate: api.compatibilityDate, bindings: { PROOF: proof }, outboundService: noOutbound,
            script: `import { WorkerEntrypoint } from 'cloudflare:workers';
                export class EmailVerifier extends WorkerEntrypoint { verify(email, proof) { return email === 'bundle@example.invalid' && proof === this.env.PROOF; } }
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
    // Public fetch dispatch avoids the internal /cdn-cgi proxy Origin policy.
    const worker = { fetch: (input, init) => mf.dispatchFetch(input, init) };
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
    await db.prepare('INSERT INTO invitations VALUES(?,?,unixepoch()+600,NULL)').bind(await sha(invitation), lookup).run();
    await bootstrap();
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
    const devicePost=(route,body)=>worker.fetch(origin+'/v1/devices/'+route,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
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
    process.stdout.write('Generated API bundle: manifest flags/bindings, D1 migrations, real ES256 registration/login/step-up/logout device enrollment, sessions, key packages, signed sync and route isolation PASS\n');
} finally { await mf.dispose(); }
