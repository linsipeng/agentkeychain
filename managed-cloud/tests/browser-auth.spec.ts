import { beforeEach, expect, test } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, reset } from 'cloudflare:test';
import { createBrowserAuth, type BrowserConfig, emailLookup } from '../api-worker/browser-auth.ts';
import { virtualAuthenticator, type VectorOptions } from './virtual-authenticator.ts';
import { random } from '../api-worker/webauthn.ts';
import { browserRepository } from '../api-worker/browser-repository.ts';
import { digest } from '../shared/contracts.ts';
let config: BrowserConfig;
let handle: (request: Request) => Promise<Response>;
let cookies: string;
let csrf: string;
const origin = 'https://local.invalid';
async function count(table: string) {
    return (await env.MAIN.prepare(`SELECT count(*) n FROM ${table}`).first<{
        n: number;
    }>())!.n;
}
function remember(response: Response) {
    const values = response.headers.getSetCookie();
    if (values.length) {
        cookies = values.map(v => v.split(';')[0]).join('; ');
        csrf = /__Host-akc_csrf=([^;]+)/.exec(cookies)![1]!;
    }
}
async function call(path: string, body: unknown = {}, headers: Record<string, string> = {}) {
    return handle(new Request(origin + '/v1/auth/' + path, { method: 'POST', headers: { origin, 'content-type': 'application/json', cookie: cookies, 'x-csrf-token': csrf, ...headers }, body: JSON.stringify(body) }));
}
beforeEach(async () => {
    await reset();
    await applyD1Migrations(env.MAIN, env.MIGRATIONS);
    config = { origin, rpId: 'local.invalid', bootstrapKey: await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']), emailKey: await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']), lookupKey: await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']), trustedSource: async () => 'synthetic-source', verifyEmail: async () => false };
    handle = createBrowserAuth(env.MAIN, config);
    const response = await handle(new Request(origin + '/v1/auth/bootstrap'));
    expect(response.status).toBe(200);
    remember(response);
});
test('bootstrap and safe methods never write; cookies have exact policy', async () => {
    expect(await count('browser_sessions')).toBe(0);
    const response = await handle(new Request(origin + '/v1/auth/bootstrap'));
    const values = response.headers.getSetCookie();
    expect(values[0]).toMatch(/^__Host-akc_session=.+; Secure; HttpOnly; SameSite=Lax; Path=\/; Max-Age=300$/);
    expect(values[1]).toMatch(/^__Host-akc_csrf=.+; Secure; SameSite=Strict; Path=\/; Max-Age=300$/);
    expect(await count('auth_rate_windows')).toBe(0);
});
test('safe and invalid routes do not invoke trusted-source RPC', async () => {
    let calls = 0;
    config.trustedSource = async () => { calls++; return 'synthetic-source'; };
    handle = createBrowserAuth(env.MAIN, config);
    expect((await handle(new Request(origin + '/v1/auth/bootstrap'))).status).toBe(200);
    expect((await handle(new Request(origin + '/v1/auth/session', { headers: { cookie: cookies } }))).status).toBe(200);
    expect((await handle(new Request(origin + '/v1/auth/not-a-route'))).status).toBe(404);
    expect(calls).toBe(0);
});
test('unsafe requests require origin AND csrf cookie/header AND session', async () => {
    for (const headers of [{ origin: 'https://foreign.invalid' }, { 'x-csrf-token': '' }, { cookie: '' }, { cookie: cookies.split('; ')[0]! }, { 'content-type': 'text/plain' }] as Record<string, string>[]) {
        expect((await call('authentication/options', { email: 'synthetic@example.invalid' }, headers)).status).toBe(401);
    }
    expect(await count('webauthn_challenges')).toBe(0);
});
test('unknown login remains generic and does not enumerate credentials', async () => {
    const response = await call('authentication/options', { email: 'synthetic@example.invalid' });
    expect(response.status).toBe(200);
    const options = await response.json() as {
        options: {
            allowCredentials?: unknown[];
        };
        challengeId: string;
    };
    expect(options.options.allowCredentials ?? []).toEqual([]);
    const failure = await call('authentication/verify', { challengeId: options.challengeId, response: { id: crypto.randomUUID() } });
    expect(failure.status).toBe(401);
    expect(await failure.json()).toEqual({ error: { code: 'unauthorized' } });
    expect(await count('browser_sessions')).toBe(0);
    expect(await digest(cookies)).toHaveLength(64);
});
interface Options {
    challengeId: string;
    userId: string;
    options: {
        challenge: string;
        rp?: {
            id: string;
        };
        user?: {
            id: string;
        };
        authenticatorSelection?: {
            userVerification: string;
            residentKey: string;
        };
        attestation?: string;
    };
}
const email = 'synthetic@example.invalid';
async function bootstrap() { const r = await handle(new Request(origin + '/v1/auth/bootstrap')); remember(r); }
async function invite(address = email) {
    const invitation = random(), proof = random();
    config.verifyEmail = async (e, p) => e === address && p === proof;
    await env.MAIN.prepare('INSERT INTO invitations VALUES(?,?,unixepoch()+600,NULL)').bind(await digest(invitation), await emailLookup(config, address)).run();
    return { invitation, email: address, proof };
}
async function registrationOptions(address = email) {
    const invitation = await invite(address), verified = await call('invitation/verify', invitation);
    expect(verified.status).toBe(200);
    const verification = await verified.json() as {
        verificationId: string;
    };
    const r = await call('registration/options', verification);
    expect(r.status).toBe(200);
    return { options: await r.json() as Options, invitation, verification };
}
async function register(address = email) {
    const { options, invitation } = await registrationOptions(address), authenticator = await virtualAuthenticator();
    const body = { challengeId: options.challengeId, userId: options.userId, response: await authenticator.register(options.options.challenge) };
    const r = await call('registration/verify', body);
    expect(r.status).toBe(200);
    remember(r);
    return { authenticator, options, invitation, body };
}
async function loginOptions(address = email) {
    const r = await call('authentication/options', { email: address });
    expect(r.status).toBe(200);
    return await r.json() as Options;
}
async function current() { return handle(new Request(origin + '/v1/auth/session', { headers: { cookie: cookies } })); }
test('real none attestation registers one account/tenant/vault/key/session, encrypted email and digest-only cookies', async () => {
    const { options, invitation } = await register();
    expect(options.options.attestation).toBe('none');
    expect(options.options.authenticatorSelection).toMatchObject({ userVerification: 'required', residentKey: 'required', requireResidentKey: true });
    expect(options.options.challenge).toHaveLength(43);
    for (const table of ['accounts', 'tenants', 'vaults', 'passkeys', 'browser_sessions', 'memberships'])
        expect(await count(table)).toBe(1);
    const record = await env.MAIN.prepare('SELECT * FROM account_emails').first<{
        encrypted_email: string;
        verified: number;
    }>();
    expect(record!.encrypted_email).not.toContain(email);
    expect(record!.verified).toBe(1);
    const all = JSON.stringify((await env.MAIN.prepare('SELECT * FROM browser_sessions').all()).results);
    expect(all).not.toContain(csrf);
    expect(all).not.toContain(/__Host-akc_session=([^;]+)/.exec(cookies)![1]!);
    expect((await current()).status).toBe(200);
    await bootstrap();
    expect((await call('invitation/verify', invitation)).status).toBe(401);
});
test.each(['expired', 'wrong-email', 'wrong-proof'] as const)('invitation rejects %s without creating account', async (mode) => {
    const data = await invite();
    if (mode === 'expired')
        await env.MAIN.prepare('UPDATE invitations SET expires_at=unixepoch()-1').run();
    if (mode === 'wrong-email')
        data.email = 'other@example.invalid';
    if (mode === 'wrong-proof')
        data.proof = random();
    const r = await call('invitation/verify', data);
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: { code: 'unauthorized' } });
    for (const table of ['accounts', 'passkeys', 'browser_sessions', 'account_verifications'])
        expect(await count(table)).toBe(0);
});
test.each([
    ['wrong-rp', { rpId: 'other.invalid' }], ['wrong-origin', { origin: 'https://other.invalid' }], ['no-uv', { uv: false }], ['no-up', { up: false, uv: true }], ['top-origin', { topOrigin: origin, crossOrigin: false }], ['wrong-purpose', { type: 'webauthn.get' }], ['iframe', { crossOrigin: true }],
] as [
    string,
    VectorOptions
][])('invalid registration %s leaves no account/passkey/session', async (_name, vector) => {
    const { options } = await registrationOptions(), authenticator = await virtualAuthenticator();
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response: await authenticator.register(options.options.challenge, vector) })).status).toBe(401);
    for (const table of ['accounts', 'passkeys', 'browser_sessions', 'auth_acceptances'])
        expect(await count(table)).toBe(0);
});
test('cancelled/expired registration leaves invitation unconsumed and no business records', async () => {
    const { options } = await registrationOptions();
    for (const table of ['accounts', 'passkeys', 'browser_sessions'])
        expect(await count(table)).toBe(0);
    await env.MAIN.prepare('UPDATE webauthn_challenges SET expires_at=unixepoch()-1').run();
    const authenticator = await virtualAuthenticator();
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response: await authenticator.register(options.options.challenge) })).status).toBe(401);
    expect((await env.MAIN.prepare('SELECT consumed_at FROM invitations').first())!.consumed_at).toBeNull();
});
test('concurrent registration consumes invitation and challenge once and issues exactly one session', async () => {
    const { options } = await registrationOptions(), a = await virtualAuthenticator(), body = { challengeId: options.challengeId, userId: options.userId, response: await a.register(options.options.challenge) };
    const responses = await Promise.all([call('registration/verify', body), call('registration/verify', body)]);
    expect(responses.map(r => r.status).sort()).toEqual([200, 401]);
    for (const table of ['accounts', 'passkeys', 'browser_sessions', 'auth_acceptances'])
        expect(await count(table)).toBe(1);
});
test('audit failure rolls entire registration back including invitation and challenge consumption', async () => {
    const { options } = await registrationOptions(), a = await virtualAuthenticator(), body = { challengeId: options.challengeId, userId: options.userId, response: await a.register(options.options.challenge) };
    await env.MAIN.exec("CREATE TRIGGER auth_fault BEFORE INSERT ON auth_audit BEGIN SELECT RAISE(ABORT,'synthetic_fault'); END;");
    expect((await call('registration/verify', body)).status).toBe(401);
    for (const table of ['accounts', 'passkeys', 'browser_sessions', 'auth_acceptances', 'consumed_bootstraps'])
        expect(await count(table)).toBe(0);
    expect((await env.MAIN.prepare('SELECT consumed_at FROM invitations').first())!.consumed_at).toBeNull();
    expect((await env.MAIN.prepare('SELECT consumed_at FROM webauthn_challenges').first())!.consumed_at).toBeNull();
    await env.MAIN.exec('DROP TRIGGER auth_fault');
    expect((await call('registration/verify', body)).status).toBe(200);
});
test.each([
    ['bad-signature', { badSignature: true }], ['wrong-rp', { rpId: 'foreign.invalid' }], ['wrong-origin', { origin: 'https://foreign.invalid' }], ['no-uv', { uv: false }], ['no-up', { up: false, uv: true }], ['top-origin', { topOrigin: origin, crossOrigin: false }], ['wrong-purpose', { type: 'webauthn.create' }], ['foreign-user', { userHandle: random() }],
] as [
    string,
    VectorOptions
][])('real assertion rejects %s', async (_name, vector) => {
    const { authenticator } = await register();
    await bootstrap();
    const options = await loginOptions();
    const r = await call('authentication/verify', { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge, vector) });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: { code: 'unauthorized' } });
    expect(await count('browser_sessions')).toBe(1);
});
test('valid assertion concurrency and replay produce exactly one new session', async () => {
    const { authenticator } = await register();
    await bootstrap();
    const options = await loginOptions();
    const body = { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge, { counter: 2 }) };
    const results = await Promise.all([call('authentication/verify', body), call('authentication/verify', body)]);
    expect(results.map(r => r.status).sort()).toEqual([200, 401]);
    expect((await call('authentication/verify', body)).status).toBe(401);
    expect(await count('browser_sessions')).toBe(2);
});
test('counter regression is audited only after valid signature, retains high-water mark', async () => {
    const { authenticator } = await register();
    await env.MAIN.prepare('UPDATE passkeys SET counter=9').run();
    await bootstrap();
    const options = await loginOptions();
    const bad = await call('authentication/verify', { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge, { counter: 1, badSignature: true }) });
    expect(bad.status).toBe(401);
    expect((await env.MAIN.prepare("SELECT count(*) n FROM auth_audit WHERE event='counter_risk'").first())!.n).toBe(0);
    const good = await call('authentication/verify', { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge, { counter: 0 }) });
    expect(good.status).toBe(200);
    expect((await env.MAIN.prepare('SELECT counter FROM passkeys').first())!.counter).toBe(9);
    expect((await env.MAIN.prepare("SELECT count(*) n FROM auth_audit WHERE event='counter_risk'").first())!.n).toBe(1);
});
test('step-up binds action, rotates cookies, revokes old session, preserves absolute expiry', async () => {
    const { authenticator } = await register(), old = cookies, actionDigest = await digest('synthetic-action');
    const options = await (await call('step-up/options', { actionDigest })).json() as Options;
    const assertion = await authenticator.assert(options.options.challenge);
    expect((await call('step-up/verify', { challengeId: options.challengeId, actionDigest: await digest('different'), response: assertion })).status).toBe(401);
    const good = await call('step-up/verify', { challengeId: options.challengeId, actionDigest, response: assertion });
    expect(good.status).toBe(200);
    remember(good);
    expect(cookies).not.toBe(old);
    expect((await handle(new Request(origin + '/v1/auth/session', { headers: { cookie: old } }))).status).toBe(401);
    expect((await current()).status).toBe(200);
    const sessions = (await env.MAIN.prepare('SELECT * FROM browser_sessions').all()).results;
    expect(sessions[0]!.absolute_expires).toBe(sessions[1]!.absolute_expires);
    expect(sessions[1]!.step_up_digest).toBe(actionDigest);
    expect((await call('logout')).status).toBe(200);
    expect((await current()).status).toBe(401);
});
test.each(['idle', 'absolute', 'privilege', 'passkey'] as const)('session rejects %s expiry/revocation', async (mode) => {
    await register();
    if (mode === 'idle')
        await env.MAIN.prepare('UPDATE browser_sessions SET last_seen=unixepoch()-1800').run();
    if (mode === 'absolute') {
        await env.MAIN.exec('DROP TRIGGER browser_session_pin');
        await env.MAIN.prepare('UPDATE browser_sessions SET absolute_expires=unixepoch()').run();
    }
    if (mode === 'privilege')
        await env.MAIN.prepare('UPDATE memberships SET active=0').run();
    if (mode === 'passkey')
        await env.MAIN.prepare('UPDATE passkeys SET active=0').run();
    expect((await current()).status).toBe(401);
    expect((await call('session/refresh')).status).toBe(401);
});
test('GET/HEAD never refresh, consume, or create durable state', async () => {
    await register();
    await env.MAIN.prepare('UPDATE browser_sessions SET last_seen=unixepoch()-100').run();
    const before = JSON.stringify((await env.MAIN.prepare('SELECT * FROM browser_sessions').all()).results), n = await count('auth_rate_windows');
    for (const method of ['GET', 'HEAD'])
        for (const route of ['session', 'bootstrap', 'registration/options', 'authentication/verify', 'step-up/verify', 'logout', 'session/refresh'])
            await handle(new Request(origin + '/v1/auth/' + route, { method, headers: { cookie: cookies } }));
    expect(JSON.stringify((await env.MAIN.prepare('SELECT * FROM browser_sessions').all()).results)).toBe(before);
    expect(await count('auth_rate_windows')).toBe(n);
});
test('cross-account credential, user handle and session cannot authenticate another account', async () => {
    const a = await register();
    const first = cookies, firstCsrf = csrf;
    await bootstrap();
    await register('second@example.invalid');
    const second = cookies;
    await bootstrap();
    const options = await loginOptions('second@example.invalid');
    expect((await call('authentication/verify', { challengeId: options.challengeId, response: await a.authenticator.assert(options.options.challenge) })).status).toBe(401);
    cookies = first;
    csrf = firstCsrf;
    const actionDigest = await digest('action');
    const step = await (await call('step-up/options', { actionDigest })).json() as Options;
    cookies = second;
    csrf = /__Host-akc_csrf=([^;]+)/.exec(second)![1]!;
    expect((await call('step-up/verify', { challengeId: step.challengeId, actionDigest, response: await a.authenticator.assert(step.options.challenge) })).status).toBe(401);
});
test('five failed attempts permanently exhaust challenge', async () => {
    const { authenticator } = await register();
    await bootstrap();
    const options = await loginOptions();
    for (let i = 0; i < 5; i++)
        expect((await call('authentication/verify', { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge, { badSignature: true }) })).status).toBe(401);
    expect((await call('authentication/verify', { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge) })).status).toBe(401);
    expect((await env.MAIN.prepare('SELECT attempts FROM webauthn_challenges WHERE id=?').bind(options.challengeId).first())!.attempts).toBe(5);
});
test('identity limits survive spoofed source headers; different identities cannot rotate fallback source', async () => {
    const first = await call('authentication/options', { email });
    expect(first.status).toBe(200);
    await env.MAIN.prepare("UPDATE auth_rate_windows SET hits=30 WHERE kind='identity'").run();
    expect((await call('authentication/options', { email }, { 'x-forwarded-for': random(), 'cf-connecting-ip': random() })).status).toBe(429);
    expect((await call('authentication/options', { email: 'other@example.invalid' })).status).toBe(200);
    await env.MAIN.prepare("UPDATE auth_rate_windows SET hits=120 WHERE kind='source'").run();
    expect((await call('authentication/options', { email: 'third@example.invalid' }, { 'forwarded': random(), 'x-real-ip': random(), 'cf-connecting-ip': random() })).status).toBe(429);
    expect((await env.MAIN.prepare("SELECT count(*) n FROM auth_rate_windows WHERE kind='source'").first())!.n).toBe(1);
});
test('shared limits are atomic under contention, cleanup bounded, trusted binding explicit', async () => {
    const repo = browserRepository(env.MAIN), identity = await digest(random());
    const result = await Promise.all(Array.from({ length: 40 }, () => repo.rate('identity', identity, 30)));
    expect(result.filter(Boolean)).toHaveLength(30);
    await env.MAIN.batch(Array.from({ length: 65 }, (_, i) => env.MAIN.prepare("INSERT INTO auth_rate_windows VALUES('source',?,unixepoch()/60-4,1)").bind(String(i))));
    await repo.rate('source', await digest(random()), 120);
    expect((await env.MAIN.prepare('SELECT count(*) n FROM auth_rate_windows WHERE window<unixepoch()/60-2').first())!.n).toBe(33);
    config.trustedSource = async () => 'authenticated-proxy-source';
    handle = createBrowserAuth(env.MAIN, config);
    expect((await call('authentication/options', { email })).status).toBe(200);
});
test('audit is redacted and append-only including REPLACE; passkey ownership immutable', async () => {
    await register();
    const events = (await env.MAIN.prepare('SELECT * FROM auth_audit').all()).results;
    expect(Object.keys(events[0]!).sort()).toEqual(['account_id', 'created_at', 'event', 'id', 'tenant_id']);
    expect(JSON.stringify(events)).not.toContain(email);
    for (const sql of ["UPDATE auth_audit SET event='logout'", "DELETE FROM auth_audit", "INSERT OR REPLACE INTO auth_audit(id,event) VALUES(1,'logout')", "UPDATE passkeys SET account_id='other'", "INSERT OR REPLACE INTO passkeys SELECT * FROM passkeys"])
        await expect(env.MAIN.prepare(sql).run()).rejects.toThrow();
});
test.each(['expired', 'wrong-challenge', 'wrong-route'] as const)('authentication rejects %s challenge', async (mode) => {
    const { authenticator } = await register();
    await bootstrap();
    const options = await loginOptions();
    if (mode === 'expired')
        await env.MAIN.prepare('UPDATE webauthn_challenges SET expires_at=unixepoch()-1 WHERE id=?').bind(options.challengeId).run();
    const body = { challengeId: options.challengeId, response: await authenticator.assert(mode === 'wrong-challenge' ? random() : options.options.challenge) };
    expect((await call(mode === 'wrong-route' ? 'step-up/verify' : 'authentication/verify', mode === 'wrong-route' ? { ...body, actionDigest: await digest('a') } : body)).status).toBe(401);
    expect(await count('browser_sessions')).toBe(1);
});
test('authenticated CSRF rejects header-only, cookie-only, mismatch, forged pair, origin-only and duplicate cookies', async () => {
    await register();
    const sessionCookie = cookies.split(';')[0]!;
    for (const headers of [
        { cookie: sessionCookie }, { 'x-csrf-token': '' }, { 'x-csrf-token': random() },
        { cookie: sessionCookie + '; __Host-akc_csrf=forged', 'x-csrf-token': 'forged' },
        { cookie: sessionCookie, 'x-csrf-token': '' }, { origin: '' }, { cookie: cookies + '; ' + sessionCookie },
    ] as Record<string, string>[])
        expect((await call('logout', {}, headers)).status).toBe(401);
    expect((await current()).status).toBe(200);
});
test('refresh moves idle timestamp only through CSRF-protected POST; successful cookies exact', async () => {
    const { authenticator } = await register();
    await bootstrap();
    const options = await loginOptions();
    const login = await call('authentication/verify', { challengeId: options.challengeId, response: await authenticator.assert(options.options.challenge) });
    const values = login.headers.getSetCookie();
    expect(values[0]).toMatch(/^__Host-akc_session=[A-Za-z0-9_-]{43}; Secure; HttpOnly; SameSite=Lax; Path=\/; Max-Age=43200$/);
    expect(values[1]).toMatch(/^__Host-akc_csrf=[A-Za-z0-9_-]{43}; Secure; SameSite=Strict; Path=\/; Max-Age=43200$/);
    remember(login);
    await env.MAIN.prepare('UPDATE browser_sessions SET last_seen=unixepoch()-100').run();
    expect((await call('session/refresh')).status).toBe(200);
    const row = await env.MAIN.prepare('SELECT max(last_seen) seen, unixepoch() now FROM browser_sessions').first<{
        seen: number;
        now: number;
    }>();
    expect(row!.seen).toBe(row!.now);
});
test('registration cannot replace user binding or reuse same invitation through two challenges', async () => {
    const { options, verification } = await registrationOptions(), a = await virtualAuthenticator();
    const second = await (await call('registration/options', verification)).json() as Options;
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: random(), response: await a.register(options.options.challenge) })).status).toBe(401);
    const oldCookie = cookies, oldCsrf = csrf;
    const good = await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response: await a.register(options.options.challenge) });
    expect(good.status).toBe(200);
    cookies = oldCookie;
    csrf = oldCsrf;
    expect((await call('registration/verify', { challengeId: second.challengeId, userId: second.userId, response: await a.register(second.options.challenge) })).status).toBe(401);
    expect(await count('accounts')).toBe(1);
});
test('production entrypoint uses real adapter and explicit ephemeral bindings; no email binding fails closed', async () => {
    const { default: worker } = await import('../api-worker/index.ts');
    const { encode } = await import('../api-worker/webauthn.ts');
    const raw = () => encode(crypto.getRandomValues(new Uint8Array(32)));
    const bindings = { MAIN: env.MAIN, RECOVERY: env.RECOVERY, AUTH_ORIGIN: origin, AUTH_RP_ID: 'local.invalid', AUTH_BOOTSTRAP_KEY: raw(), AUTH_EMAIL_KEY: raw(), AUTH_LOOKUP_KEY: raw(), TRUSTED_AUTH_SOURCE: { resolve: async () => 'synthetic-source' }, EMAIL_VERIFIER: { verify: async (e: string, p: string) => config.verifyEmail(e, p) } };
    config.lookupKey = await crypto.subtle.importKey('raw', Uint8Array.from(atob(bindings.AUTH_LOOKUP_KEY.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    handle = request => worker.fetch(request, bindings);
    await bootstrap();
    const data = await invite();
    expect((await call('invitation/verify', data)).status).toBe(200);
    const a = await register('entrypoint@example.invalid');
    expect((await current()).status).toBe(200);
    await bootstrap();
    const opts = await loginOptions('entrypoint@example.invalid');
    expect((await call('authentication/verify', { challengeId: opts.challengeId, response: await a.authenticator.assert(opts.options.challenge) })).status).toBe(200);
    const noEmail = { ...bindings, EMAIL_VERIFIER: undefined };
    handle = request => worker.fetch(request, noEmail);
    expect((await handle(new Request(origin + '/v1/auth/bootstrap'))).status).toBe(503);
    const unavailable = await worker.fetch(new Request(origin + '/v1/auth/bootstrap'), { MAIN: env.MAIN, RECOVERY: env.RECOVERY });
    expect(unavailable.status).toBe(503);
});
test('strict rate counters are shared by separate handler instances and trusted source never changes identity budget', async () => {
    const one = await call('authentication/options', { email });
    expect(one.status).toBe(200);
    await env.MAIN.prepare("UPDATE auth_rate_windows SET hits=30 WHERE kind='identity'").run();
    config.trustedSource = async () => 'another-stable-source';
    handle = createBrowserAuth(env.MAIN, config);
    expect((await call('authentication/options', { email })).status).toBe(429);
    handle = createBrowserAuth(env.MAIN, { ...config });
    expect((await call('authentication/options', { email })).status).toBe(429);
});
test('ES256 none registration and signed assertion run through unmocked workerd adapter', async () => {
    const { options } = await registrationOptions(), a = await virtualAuthenticator('ES256');
    const registered = await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response: await a.register(options.options.challenge) });
    expect(registered.status).toBe(200);
    await bootstrap();
    const login = await loginOptions();
    expect((await call('authentication/verify', { challengeId: login.challengeId, response: await a.assert(login.options.challenge, { badSignature: true }) })).status).toBe(401);
    expect((await call('authentication/verify', { challengeId: login.challengeId, response: await a.assert(login.options.challenge) })).status).toBe(200);
});
test.each(['session-revoked', 'session-idle-expired', 'email-changed', 'membership-revoked', 'key-revoked', 'challenge-expired'] as const)('acceptance rechecks %s after successful cryptographic verification', async (mode) => {
    const { authenticator } = await register(), actionDigest = await digest('action');
    const options = await (await call('step-up/options', { actionDigest })).json() as Options;
    const sessionDigest = await digest(/__Host-akc_session=([^;]+)/.exec(cookies)![1]!);
    const repo = browserRepository(env.MAIN), c = (await repo.attempt(options.challengeId, sessionDigest, 'step-up'))!;
    const stored = (await repo.key(authenticator.id, c.identity_hash))!, session = (await repo.session(sessionDigest))!;
    const { webauthn, decode } = await import('../api-worker/webauthn.ts');
    const counter = await webauthn.authentication(config, c.challenge_digest, await authenticator.assert(options.options.challenge), { id: stored.id, publicKey: decode(stored.public_key), counter: stored.counter });
    if (mode === 'session-idle-expired')
        await env.MAIN.prepare('UPDATE browser_sessions SET last_seen=unixepoch()-1801').run();
    if (mode === 'email-changed')
        await env.MAIN.prepare('UPDATE account_emails SET lookup_hash=?').bind(await digest(random())).run();
    if (mode === 'session-revoked')
        await repo.logout(sessionDigest);
    if (mode === 'membership-revoked')
        await env.MAIN.prepare('UPDATE memberships SET active=0').run();
    if (mode === 'key-revoked')
        await env.MAIN.prepare('UPDATE passkeys SET active=0').run();
    if (mode === 'challenge-expired')
        await env.MAIN.prepare('UPDATE webauthn_challenges SET expires_at=unixepoch()-1 WHERE id=?').bind(c.id).run();
    await expect(repo.accept({ challenge: c, account: stored.account_id, tenant: session.tenant_id, key: { ...stored, counter }, sessionDigest: await digest(random()), csrfDigest: await digest(random()), absoluteExpiry: session.absolute_expires, actionDigest })).rejects.toThrow();
    expect(await count('browser_sessions')).toBe(1);
    expect((await env.MAIN.prepare('SELECT consumed_at FROM webauthn_challenges WHERE id=?').bind(c.id).first())!.consumed_at).toBeNull();
});
test('commit rechecks anonymous session expiry even when its challenge remains live', async () => {
    const { options } = await registrationOptions(), a = await virtualAuthenticator();
    await env.MAIN.prepare('UPDATE webauthn_challenges SET auth_expires=unixepoch()-1 WHERE id=?').bind(options.challengeId).run();
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response: await a.register(options.options.challenge) })).status).toBe(401);
    expect(await count('accounts')).toBe(0);
    expect(await count('browser_sessions')).toBe(0);
});
test('browser cookies and device bearer credentials never substitute for each other', async () => {
    await register();
    const { default: worker } = await import('../api-worker/index.ts');
    const vault = (await env.MAIN.prepare('SELECT id FROM vaults').first<{
        id: string;
    }>())!.id;
    const sync = await worker.fetch(new Request(origin + '/v1/vaults/' + vault + '/sync/pull', { headers: { cookie: cookies } }), { MAIN: env.MAIN, RECOVERY: env.RECOVERY });
    expect(sync.status).toBe(401);
    const browser = await handle(new Request(origin + '/v1/auth/session', { headers: { authorization: 'Bearer ' + random() } }));
    expect(browser.status).toBe(401);
});
test('standards-conforming nonresident-only authenticator cannot create an account with issued options', async () => {
    const { options } = await registrationOptions();
    // Model the WebAuthn create algorithm's resident-key capability decision,
    // not an invented resident bit in signed authenticatorData.
    const create = async (supportsResident: boolean) => {
        const selection = options.options.authenticatorSelection! as {
            residentKey: string;
            requireResidentKey?: boolean;
        };
        if (!supportsResident && (selection.residentKey === 'required' || selection.requireResidentKey === true))
            throw new Error('ConstraintError');
        return (await virtualAuthenticator()).register(options.options.challenge);
    };
    await expect(create(false)).rejects.toThrow('ConstraintError');
    expect(await count('accounts')).toBe(0);
    expect(await count('passkeys')).toBe(0);
    const response = await create(true);
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response })).status).toBe(200);
});
test('explicit nonresident credential property is rejected by production adapter', async () => {
    const { options } = await registrationOptions(), a = await virtualAuthenticator();
    const response = await a.register(options.options.challenge);
    response.clientExtensionResults = { credProps: { rk: false } };
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response })).status).toBe(401);
    expect(await count('accounts')).toBe(0);
});
test.each(['consumed', 'expired'] as const)('invitation %s during suspended email verification never returns phantom id', async (mode) => {
    const data = await invite();
    let entered!: () => void, resume!: () => void;
    const started = new Promise<void>(r => { entered = r; });
    const barrier = new Promise<void>(r => { resume = r; });
    config.verifyEmail = async () => { entered(); await barrier; return true; };
    const pending = call('invitation/verify', data);
    await started;
    await env.MAIN.prepare(mode === 'consumed' ? 'UPDATE invitations SET consumed_at=unixepoch()' : 'UPDATE invitations SET expires_at=unixepoch()-1').run();
    resume();
    const response = await pending;
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: { code: 'unauthorized' } });
    expect(await count('account_verifications')).toBe(0);
});
test.each(['invalid-invitation', 'wrong-email', 'wrong-proof', 'valid', 'throw'] as const)('verifier invocation equivalent for %s', async (mode) => {
    const data = await invite(), verifier = config.verifyEmail;
    let calls = 0;
    config.verifyEmail = async (e, p) => {
        calls++;
        if (mode === 'throw')
            throw new Error('private-provider-detail');
        return verifier(e, p);
    };
    if (mode === 'invalid-invitation')
        data.invitation = random();
    if (mode === 'wrong-email')
        data.email = 'wrong@example.invalid';
    if (mode === 'wrong-proof')
        data.proof = random();
    const response = await call('invitation/verify', data);
    expect(calls).toBe(1);
    expect(response.status).toBe(mode === 'valid' ? 200 : 401);
    if (mode !== 'valid')
        expect(await response.json()).toEqual({ error: { code: 'unauthorized' } });
});
test.each(['packed', 'malformed'] as const)('production adapter rejects actual %s attestation bytes', async (mode) => {
    const { options } = await registrationOptions(), a = await virtualAuthenticator();
    const response = await a.register(options.options.challenge, { attestationFormat: 'packed' });
    if (mode === 'malformed')
        response.response.attestationObject = 'AA';
    expect((await call('registration/verify', { challengeId: options.challengeId, userId: options.userId, response })).status).toBe(401);
    expect(await count('accounts')).toBe(0);
});
test.each(['origin', 'content-type', 'x-csrf-token'])('duplicate and combined %s are rejected after workerd normalization', async (header) => {
    await register();
    const headers = new Headers({ origin, 'content-type': 'application/json', cookie: cookies, 'x-csrf-token': csrf });
    const value = headers.get(header)!;
    headers.append(header, value);
    expect(headers.get(header)).toBe(value + ', ' + value);
    for (const combined of [headers.get(header)!, value + ',' + value]) {
        headers.set(header, combined);
        expect((await handle(new Request(origin + '/v1/auth/logout', { method: 'POST', headers, body: '{}' }))).status).toBe(401);
    }
    expect((await current()).status).toBe(200);
});
test('logout audit failure rolls back revocation and preserves session', async () => {
    await register();
    await env.MAIN.exec("CREATE TRIGGER logout_fault BEFORE INSERT ON auth_audit WHEN NEW.event='logout' BEGIN SELECT RAISE(ABORT,'private-storage-detail'); END");
    const response = await call('logout');
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: { code: 'unauthorized' } });
    expect((await current()).status).toBe(200);
});
test.each(['missing-source', 'non-string', 'empty', 'space', 'uppercase', 'oversized', 'unicode', 'throw', 'unstable', 'missing-verifier', 'malformed-key', 'short-key', 'equal-bootstrap-email', 'equal-bootstrap-lookup', 'equal-email-lookup'] as const)('production binding %s fails closed without leaking', async (mode) => {
    const { browserFetch } = await import('../api-worker/browser-bindings.ts');
    const bindings = {
        MAIN: env.MAIN, AUTH_ORIGIN: origin, AUTH_RP_ID: 'local.invalid',
        AUTH_BOOTSTRAP_KEY: random(), AUTH_EMAIL_KEY: random(), AUTH_LOOKUP_KEY: random(),
        EMAIL_VERIFIER: { verify: async () => true } as {
            verify: (e: string, p: string) => Promise<boolean>;
        } | undefined,
        TRUSTED_AUTH_SOURCE: { resolve: async () => 'synthetic-source' } as {
            resolve: (r: Request) => Promise<string>;
        } | undefined,
    };
    if (mode === 'missing-source')
        bindings.TRUSTED_AUTH_SOURCE = undefined;
    if (mode === 'non-string')
        bindings.TRUSTED_AUTH_SOURCE = { resolve: async () => null as unknown as string };
    if (mode === 'missing-verifier')
        bindings.EMAIL_VERIFIER = undefined;
    if (mode === 'malformed-key')
        bindings.AUTH_EMAIL_KEY = '!'.repeat(43);
    if (mode === 'short-key')
        bindings.AUTH_EMAIL_KEY = 'AA';
    if (mode === 'equal-bootstrap-email')
        bindings.AUTH_EMAIL_KEY = bindings.AUTH_BOOTSTRAP_KEY;
    if (mode === 'equal-bootstrap-lookup')
        bindings.AUTH_LOOKUP_KEY = bindings.AUTH_BOOTSTRAP_KEY;
    if (mode === 'equal-email-lookup')
        bindings.AUTH_LOOKUP_KEY = bindings.AUTH_EMAIL_KEY;
    const values: Record<string, string> = { empty: '', space: ' source ', uppercase: 'SOURCE', oversized: 'a'.repeat(129), unicode: '源' };
    if (mode in values)
        bindings.TRUSTED_AUTH_SOURCE = { resolve: async () => values[mode]! };
    if (mode === 'throw')
        bindings.TRUSTED_AUTH_SOURCE = { resolve: async () => { throw new Error('private-source-detail'); } };
    if (mode === 'unstable')
        bindings.TRUSTED_AUTH_SOURCE = { resolve: async () => random().toLowerCase() };
    const bootstrap = await browserFetch(new Request(origin + '/v1/auth/bootstrap'), bindings);
    const outputModes = ['non-string', 'empty', 'space', 'uppercase', 'oversized', 'unicode', 'throw', 'unstable'];
    const response = outputModes.includes(mode) ? await (async () => {
        expect(bootstrap.status).toBe(200);
        const cookieHeader = bootstrap.headers.getSetCookie().map(v => v.split(';')[0]).join('; ');
        const csrfValue = /__Host-akc_csrf=([^;]+)/.exec(cookieHeader)![1]!;
        return browserFetch(new Request(origin + '/v1/auth/invitation/verify', { method: 'POST', headers: { origin, 'content-type': 'application/json', cookie: cookieHeader, 'x-csrf-token': csrfValue }, body: JSON.stringify({ invitation: 'synthetic-invite', email: 'synthetic@example.invalid', proof: 'synthetic-proof' }) }), bindings);
    })() : bootstrap;
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: { code: 'unavailable' } });
    expect(await count('auth_rate_windows')).toBe(0);
});
test('wrong-purpose CryptoKeys cannot activate direct composition', async () => {
    const handler = createBrowserAuth(env.MAIN, { ...config, bootstrapKey: config.emailKey, emailKey: config.bootstrapKey });
    expect((await handler(new Request(origin + '/v1/auth/bootstrap'))).status).toBe(503);
});
test.each(['membership', 'email', 'passkey', 'bootstrap-used', 'bootstrap-expired'] as const)('authentication acceptance rechecks %s after actual crypto', async (mode) => {
    const { authenticator } = await register();
    await bootstrap();
    const options = await loginOptions(), repo = browserRepository(env.MAIN);
    const sessionDigest = await digest(/__Host-akc_session=([^;]+)/.exec(cookies)![1]!);
    const challenge = (await repo.attempt(options.challengeId, sessionDigest, 'authentication'))!;
    const stored = (await repo.key(authenticator.id, challenge.identity_hash))!;
    const tenant = (await repo.membership(stored.account_id))!.tenant_id;
    const { webauthn, decode } = await import('../api-worker/webauthn.ts');
    const counter = await webauthn.authentication(config, challenge.challenge_digest, await authenticator.assert(options.options.challenge), { id: stored.id, publicKey: decode(stored.public_key), counter: stored.counter });
    if (mode === 'membership')
        await env.MAIN.prepare('UPDATE memberships SET active=0').run();
    if (mode === 'email')
        await env.MAIN.prepare('UPDATE account_emails SET lookup_hash=?').bind(await digest(random())).run();
    if (mode === 'passkey')
        await env.MAIN.prepare('UPDATE passkeys SET active=0').run();
    if (mode === 'bootstrap-used')
        await env.MAIN.prepare('INSERT INTO consumed_bootstraps VALUES(?,unixepoch()+300)').bind(sessionDigest).run();
    if (mode === 'bootstrap-expired')
        await env.MAIN.prepare('UPDATE webauthn_challenges SET auth_expires=unixepoch()-1 WHERE id=?').bind(challenge.id).run();
    await expect(repo.accept({ challenge, account: stored.account_id, tenant, key: { ...stored, counter }, sessionDigest: await digest(random()), csrfDigest: await digest(random()), absoluteExpiry: Math.floor(Date.now() / 1000) + 43200, actionDigest: null })).rejects.toThrow();
    expect(await count('browser_sessions')).toBe(1);
    expect((await env.MAIN.prepare('SELECT consumed_at FROM webauthn_challenges WHERE id=?').bind(challenge.id).first())!.consumed_at).toBeNull();
    expect((await env.MAIN.prepare("SELECT count(*) n FROM auth_audit WHERE event='authenticated'").first())!.n).toBe(0);
});
test('cleanup bounds storage reclamation, retains live/recent state and forensic events', async () => {
    await register();
    const series = 'WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65)';
    await env.MAIN.prepare(`${series} INSERT INTO account_verifications SELECT 'expired-v-'||x,invitation_digest,session_digest,email_lookup,encrypted_email,unixepoch()-90000,NULL FROM n,account_verifications WHERE id=(SELECT id FROM account_verifications LIMIT 1)`).run();
    await env.MAIN.prepare(`${series} INSERT INTO webauthn_challenges SELECT 'expired-c-'||x,challenge_digest,purpose,session_digest,identity_hash,account_id,'expired-v-'||x,request_digest,auth_expires,unixepoch()-90000,1,unixepoch()-90001 FROM n,webauthn_challenges WHERE id=(SELECT id FROM webauthn_challenges LIMIT 1)`).run();
    await env.MAIN.prepare("INSERT INTO auth_acceptances SELECT id FROM webauthn_challenges WHERE id LIKE 'expired-c-%'").run();
    await env.MAIN.prepare(`${series} INSERT INTO browser_sessions SELECT 'expired-s-'||x,csrf_digest,account_id,tenant_id,created_at,unixepoch()-100000,unixepoch()-90000,revoked,step_up_digest,step_up_expires FROM n,browser_sessions WHERE digest=(SELECT digest FROM browser_sessions LIMIT 1)`).run();
    await env.MAIN.prepare(`${series} INSERT INTO consumed_bootstraps SELECT 'expired-b-'||x,unixepoch()-90000 FROM n`).run();
    await env.MAIN.prepare(`${series} INSERT INTO auth_audit(event,created_at) SELECT 'rejected',unixepoch()-2592060 FROM n`).run();
    await env.MAIN.prepare("INSERT INTO auth_audit(event,created_at) VALUES('rejected',unixepoch()-2591940),('authenticated',unixepoch()-3000000)").run();
    // Recently expired artifacts and recent rejects remain available for investigation.
    await env.MAIN.prepare("INSERT INTO consumed_bootstraps VALUES('recent-expiry',unixepoch()-1),('live-bootstrap',unixepoch()+600)").run();
    const tables = ['webauthn_challenges', 'account_verifications', 'browser_sessions', 'consumed_bootstraps', 'auth_acceptances', 'auth_audit'];
    const before = await Promise.all(tables.map(count));
    const repo = browserRepository(env.MAIN);
    await repo.cleanup();
    expect(await Promise.all(tables.map(count))).toEqual(before.map(n => n - 32));
    expect((await current()).status).toBe(200);
    await repo.cleanup();
    await repo.cleanup();
    expect((await env.MAIN.prepare("SELECT count(*) n FROM auth_audit WHERE event='rejected'").first())!.n).toBe(1);
    expect((await env.MAIN.prepare("SELECT count(*) n FROM auth_audit WHERE event='authenticated'").first())!.n).toBe(1);
    expect(await count('consumed_bootstraps')).toBe(3);
    expect(await count('webauthn_challenges')).toBe(1);
    expect(await count('account_verifications')).toBe(1);
    expect(await count('auth_acceptances')).toBe(1);
    expect((await current()).status).toBe(200);
    await expect(env.MAIN.prepare("DELETE FROM auth_audit WHERE event='rejected'").run()).rejects.toThrow();
});
test('cleanup does not delete expired verifications referenced by live challenges', async () => {
    const { options } = await registrationOptions();
    await env.MAIN.prepare('UPDATE account_verifications SET expires_at=unixepoch()-90000').run();
    await browserRepository(env.MAIN).cleanup();
    expect(await count('account_verifications')).toBe(1);
    expect((await env.MAIN.prepare('SELECT id FROM webauthn_challenges WHERE id=?').bind(options.challengeId).first())!.id).toBe(options.challengeId);
});
test('wrong-purpose lookup HMAC cannot sign an anonymous bootstrap', async () => {
    const { encode } = await import('../api-worker/webauthn.ts');
    const payload = encode(new TextEncoder().encode(JSON.stringify({ n: random(), e: Math.floor(Date.now() / 1000) + 300, c: await digest(csrf) })));
    const signature = encode(new Uint8Array(await crypto.subtle.sign('HMAC', config.lookupKey, new TextEncoder().encode('bootstrap\0' + payload))));
    cookies = `__Host-akc_session=p.${payload}.${signature}; __Host-akc_csrf=${csrf}`;
    expect((await call('authentication/options', { email })).status).toBe(401);
    expect(await count('webauthn_challenges')).toBe(0);
});
test('failed-request flood remains rate bounded without accumulating credential state', async () => {
    const data = await invite();
    data.proof = random();
    let invocations = 0;
    config.verifyEmail = async () => { invocations++; return false; };
    const results = [];
    for (let i = 0; i < 160; i++)
        results.push((await call('invitation/verify', data)).status);
    expect(results.filter(s => s === 401)).toHaveLength(30);
    expect(results.filter(s => s === 429)).toHaveLength(130);
    expect(invocations).toBe(30);
    expect(await count('auth_audit')).toBe(120);
    expect(await count('auth_rate_windows')).toBe(2);
    for (const table of ['accounts', 'passkeys', 'browser_sessions', 'account_verifications', 'webauthn_challenges'])
        expect(await count(table)).toBe(0);
});
test('competing successful registration consumes invitation while another verification awaits provider', async () => {
    const { options, invitation } = await registrationOptions(), authenticator = await virtualAuthenticator();
    const body = { challengeId: options.challengeId, userId: options.userId, response: await authenticator.register(options.options.challenge) };
    const originalCookies = cookies, originalCsrf = csrf;
    await bootstrap();
    let entered!: () => void, resume!: () => void;
    const started = new Promise<void>(r => { entered = r; });
    const barrier = new Promise<void>(r => { resume = r; });
    config.verifyEmail = async () => { entered(); await barrier; return true; };
    const pending = call('invitation/verify', invitation);
    await started;
    cookies = originalCookies;
    csrf = originalCsrf;
    expect((await call('registration/verify', body)).status).toBe(200);
    resume();
    const result = await pending;
    expect(result.status).toBe(401);
    expect(await result.json()).toEqual({ error: { code: 'unauthorized' } });
    expect(await count('account_verifications')).toBe(1);
    expect(await count('accounts')).toBe(1);
});
test('device approval uses actual Passkey step-up, exact action digest, confirmation and existing CSRF boundary', async () => {
    const { authenticator } = await register();
    const { syntheticSigner } = await import('./synthetic-signer.ts');
    const { deviceFetch } = await import('../api-worker/device-http.ts');
    const { enrollmentProof } = await import('../shared/device-protocol.ts');
    const signer = await syntheticSigner(), key = await signer.key(), wrappingKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const authorized = await deviceFetch(new Request(origin + '/v1/devices/authorize', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ signingKey: key.publicKey, wrappingKey, platform: 'linux', proof: await signer.sign(enrollmentProof(key.publicKey, wrappingKey, 'linux')) }) }), { MAIN: env.MAIN, AUTH_ORIGIN: origin, TRUSTED_AUTH_SOURCE: { resolve: async () => 'synthetic-device-source' } });
    expect(authorized.status).toBe(200);
    const pairing = await authorized.json() as {
        verificationCode: string;
    };
    const pending = { verificationCode: pairing.verificationCode, issuerDeviceId: null };
    expect((await call('devices/pending', pending, { 'x-csrf-token': '' })).status).toBe(401);
    expect((await call('devices/pending', pending, { origin: 'https://foreign.invalid' })).status).toBe(401);
    const p = await call('devices/pending', pending);
    expect(p.status).toBe(200);
    const grant = await p.json() as {
        canonical: string;
        actionDigest: string;
    };
    const approval = { canonical: grant.canonical, signature: null, confirmed: true };
    expect((await call('devices/approve', approval)).status).toBe(401);
    const step = async (actionDigest: string) => {
        const opts = await (await call('step-up/options', { actionDigest })).json() as Options;
        const verified = await call('step-up/verify', { challengeId: opts.challengeId, actionDigest, response: await authenticator.assert(opts.options.challenge) });
        expect(verified.status).toBe(200);
        remember(verified);
    };
    await step(await digest('wrong-device-action'));
    expect((await call('devices/approve', approval)).status).toBe(401);
    await step(grant.actionDigest);
    expect((await call('devices/approve', { ...approval, confirmed: false })).status).toBe(400);
    expect((await call('devices/approve', approval)).status).toBe(200);
    expect((await call('devices/approve', approval)).status).toBe(404);
    expect(await count('devices')).toBe(1);
    expect(await count('device_actions')).toBe(1);
});
test('device verification URI has an authenticated read-only JSON landing contract', async () => {
    await register();
    const before = await count('device_requests');
    const r = await handle(new Request(origin + '/v1/auth/devices/verification', { headers: { cookie: cookies } }));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ authentication: 'passkey', verificationCodeRequired: true, submitUri: origin + '/v1/auth/devices/pending' });
    expect(await count('device_requests')).toBe(before);
});
test.each(['approvals/approve','approvals/deny','approvals/cancel','recovery/start','recovery/release','activity/list'])('Phase 2D %s preserves session, CSRF and trusted origin boundary',async route=>{
 expect((await call(route,{id:'unknown',confirmed:true})).status).toBe(401);
 await register();
 for(const headers of [{origin:'https://foreign.invalid'},{'x-csrf-token':''},{cookie:''},{'content-type':'text/plain'}] as Record<string,string>[]) expect((await call(route,{id:'unknown',confirmed:true},headers)).status).toBe(401);
});
test('approval JSON rejects batch/permanent authority and foreign identifiers',async()=>{
 await register();
 expect((await call('approvals/approve',{id:'unknown',confirmed:true,permanent:true})).status).not.toBe(200);
 expect((await call('approvals/approve',{ids:['unknown'],confirmed:true})).status).not.toBe(200);
 expect((await call('approvals/detail',{id:'foreign'})).status).toBe(404);
});
