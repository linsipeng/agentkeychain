import { assertSafeView } from '../web/src/safe-view.ts';
import { beforeEach, expect, test } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, reset } from 'cloudflare:test';
import { canonicalGrant, canonicalPackage, requestProof } from '../shared/device-protocol.ts';
beforeEach(async () => { await reset(); await applyD1Migrations(env.MAIN, env.MIGRATIONS); });
test('grant and package canonicalization reject unknown fields and bind independent keys', () => {
    const grant = { version: 1, requestId: 'r', accountId: 'a', tenantId: 't', vaultId: 'v', deviceId: 'd', signingKey: btoa('s'.repeat(32)), wrappingKey: btoa('w'.repeat(32)), issuerDeviceId: 'i', keyEpoch: 1, expiresAt: 2000000000 };
    expect(JSON.parse(canonicalGrant(grant))).toEqual(grant);
    expect(() => canonicalGrant({ ...grant, admin: true })).toThrow();
    expect(() => canonicalGrant({ ...grant, wrappingKey: grant.signingKey })).toThrow();
    const pkg = { version: 1, vaultId: 'v', targetDeviceId: 'd', keyEpoch: 1, wrappedVDK: btoa('c'.repeat(80)), issuerDeviceId: 'i', grantId: 'r' };
    expect(JSON.parse(canonicalPackage(pkg))).toEqual(pkg);
    expect(() => canonicalPackage({ ...pkg, keyEpoch: 0 })).toThrow();
});
test('proof binds normalized query, timestamp and session identifier', () => {
    const proof = requestProof('GET', new URL('https://local.invalid/v1/devices?b=2&a=1'), '0'.repeat(64), 10, 'nonce', '1'.repeat(64));
    expect(proof).toBe(requestProof('GET', new URL('https://local.invalid/v1/devices?a=1&b=2'), '0'.repeat(64), 10, 'nonce', '1'.repeat(64)));
    expect(proof).not.toBe(requestProof('GET', new URL('https://local.invalid/v1/devices?b=2&a=1'), '0'.repeat(64), 11, 'nonce', '1'.repeat(64)));
});
import { deviceFetch } from '../api-worker/device-http.ts';
import { deviceRepository } from '../api-worker/device-repository.ts';
import { digest, verify } from '../shared/contracts.ts';
import { enrollmentProof, enrollmentReconcileProof, enrollmentRetireProof, actionDigest, challengeProof } from '../shared/device-protocol.ts';
import { authenticate } from '../api-worker/auth.ts';
import type { SessionRow } from '../api-worker/browser-repository.ts';
const origin = 'https://local.invalid';
const db = () => env.MAIN;
const bytes = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
async function identity() {
    const sign = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    const wrap = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    return { signingKey: bytes(await crypto.subtle.exportKey('raw', sign.publicKey)), wrappingKey: bytes(await crypto.subtle.exportKey('raw', wrap.publicKey)), sign: async (v: string) => bytes(await crypto.subtle.sign('Ed25519', sign.privateKey, new TextEncoder().encode(v))) };
}
const api = (path: string, body: unknown, headers: Record<string, string> = {}) => deviceFetch(new Request(origin + '/v1/devices/' + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) }), { MAIN: db(), AUTH_ORIGIN: origin, DEVICE_API_ORIGIN: origin, TRUSTED_AUTH_SOURCE: { resolve: async () => 'synthetic-device-source' } });
test('device authorization resolves the original ingress before consuming the body', async () => {
    const keys = await identity();
    const body = { signingKey: keys.signingKey, wrappingKey: keys.wrappingKey, platform: 'linux', proof: await keys.sign(enrollmentProof(keys.signingKey, keys.wrappingKey, 'linux')) };
    const request = new Request(origin + '/v1/devices/authorize', {method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify(body)});
    const clone = request.clone.bind(request);
    let calls = 0;
    Object.defineProperty(request, 'clone', {value: () => {
        if (request.bodyUsed) throw new TypeError('body already used');
        return clone();
    }});
    const response = await deviceFetch(request, {MAIN: db(), AUTH_ORIGIN: origin, DEVICE_API_ORIGIN: origin, TRUSTED_AUTH_SOURCE: {resolve: async () => {calls++; return 'synthetic-ingress-before-body';}}});
    expect(response.status).toBe(200);
    expect(calls).toBe(2);
    expect(request.bodyUsed).toBe(true);
});
async function account(account = 'a', tenant = 't') {
    const token = crypto.randomUUID(), csrf = crypto.randomUUID();
    const s: SessionRow = { digest: await digest(token), csrf_digest: await digest(csrf), account_id: account, tenant_id: tenant, absolute_expires: Math.floor(Date.now() / 1000) + 3600, step_up_digest: null, step_up_expires: null };
    await db().batch([db().prepare('INSERT INTO accounts VALUES(?)').bind(account), db().prepare('INSERT INTO tenants VALUES(?)').bind(tenant), db().prepare('INSERT INTO memberships VALUES(?,?,1)').bind(tenant, account), db().prepare('INSERT INTO vaults VALUES(?,?,0)').bind(tenant, 'v'), db().prepare('INSERT INTO browser_sessions(digest,csrf_digest,account_id,tenant_id,absolute_expires) VALUES(?,?,?,?,?)').bind(s.digest, s.csrf_digest, account, tenant, s.absolute_expires)]);
    return s;
}
async function authorize() {
    const k = await identity();
    const r = await api('authorize', { signingKey: k.signingKey, wrappingKey: k.wrappingKey, platform: 'linux', proof: await k.sign(enrollmentProof(k.signingKey, k.wrappingKey, 'linux')) });
    expect(r.status).toBe(200);
    const p = await r.json() as {
        deviceCode: string;
        verificationCode: string;
        phrase: string;
        deviceId: string;
        requestId: string;
    };
    return { ...p, ...k };
}
async function step(s: SessionRow, action: string, canonical: string) { await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(await actionDigest(action, canonical), s.digest).run(); }
async function enroll(s: SessionRow, issuer?: Awaited<ReturnType<typeof authorize>>) {
    const d = await authorize(), repo = deviceRepository(db());
    const p = await repo.pending(s, await digest(d.verificationCode), issuer?.deviceId ?? null);
    expect(p.phrase).toBe(d.phrase);
    await step(s, 'approve', p.canonical);
    await repo.approve(s, p.canonical, issuer ? await issuer.sign(p.canonical) : null);
    return d;
}
async function session(d: Awaited<ReturnType<typeof authorize>>) {
    const r = await api('challenge', { deviceId: d.deviceId });
    expect(r.status).toBe(200);
    const c = await r.json() as {
        challengeId: string;
        challenge: string;
        deviceId: string;
        vaultId: string;
        expiresAt: number;
    };
    const signature = await d.sign(challengeProof(c.challengeId, await digest(c.challenge), c.deviceId, c.vaultId, c.expiresAt));
    const token = await api('token', { challengeId: c.challengeId, signature });
    expect(token.status).toBe(200);
    return { ...await token.json() as {
            token: string;
            expiresIn: number;
        }, challenge: c, signature };
}
test('first enrollment requires exact browser step-up; second requires trusted device signature', async () => {
    const s = await account(), repo = deviceRepository(db()), d = await authorize();
    const p = await repo.pending(s, await digest(d.verificationCode), null);
    await expect(repo.approve(s, p.canonical, null)).rejects.toThrow();
    await step(s, 'approve', p.canonical);
    await repo.approve(s, p.canonical, null);
    await expect(repo.approve(s, p.canonical, null)).rejects.toThrow();
    const second = await authorize();
    const bootstrap = await repo.pending(s, await digest(second.verificationCode), null);
    await step(s, 'approve', bootstrap.canonical);
    await expect(repo.approve(s, bootstrap.canonical, null)).rejects.toThrow();
    const grant = await repo.pending(s, await digest(second.verificationCode), d.deviceId);
    await step(s, 'approve', grant.canonical);
    await expect(repo.approve(s, grant.canonical, await second.sign(grant.canonical))).rejects.toThrow('invalid_signature');
    await repo.approve(s, grant.canonical, await d.sign(grant.canonical));
    expect((await repo.list(s)).devices).toHaveLength(2);
});
test('tokens and codes are digest-only; challenges one-use; bearer alone fails; revocation retains keys', async () => {
    const s = await account(), d = await enroll(s), issued = await session(d);
    expect(issued.expiresIn).toBe(900);
    expect((await api('token', { challengeId: issued.challenge.challengeId, signature: issued.signature })).status).toBe(401);
    const stored = JSON.stringify((await db().prepare('SELECT * FROM device_requests').all()).results) + JSON.stringify((await db().prepare('SELECT * FROM device_sessions').all()).results);
    expect(stored).not.toContain(d.deviceCode);
    expect(stored).not.toContain(d.verificationCode);
    expect(stored).not.toContain(issued.token);
    await expect(authenticate(db(), new Request(origin + '/v1/devices/key-packages', { headers: { authorization: 'Bearer ' + issued.token } }), null, '')).rejects.toThrow('unauthorized');
    await enroll(s,d);
    const device = (await deviceRepository(db()).list(s)).devices.find(row=>row.id===d.deviceId)!;
    await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(device.revokeActionDigest, s.digest).run();
    await deviceRepository(db()).revoke(s, d.deviceId);
    expect(await db().prepare('SELECT active FROM device_sessions').first('active')).toBe(0);
    expect(await db().prepare('SELECT public_key FROM devices').first('public_key')).toBe(d.signingKey);
    await expect(db().prepare('UPDATE device_keys SET wrapping_key=?').bind(d.signingKey).run()).rejects.toThrow();
    await expect(db().prepare('INSERT OR REPLACE INTO device_keys VALUES(?,?,?)').bind('t', d.deviceId, d.signingKey).run()).rejects.toThrow();
});
test('revoked authorizer, tampered grant, foreign account, denied and rapid polls fail closed', async () => {
    const s = await account(), other = await account('b', 'u'), first = await enroll(s), d = await authorize(), repo = deviceRepository(db());
    const grant = await repo.pending(s, await digest(d.verificationCode), first.deviceId);
    await expect(repo.pending(other, await digest(d.verificationCode), null)).rejects.toThrow();
    await step(s, 'approve', grant.canonical);
    const changed = grant.canonical.replace(d.wrappingKey, first.wrappingKey);
    await expect(repo.approve(s, changed, await first.sign(changed))).rejects.toThrow();
    await db().prepare('UPDATE devices SET active=0 WHERE id=?').bind(first.deviceId).run();
    await expect(repo.approve(s, grant.canonical, await first.sign(grant.canonical))).rejects.toThrow();
    expect((await api('status', { deviceCode: d.deviceCode })).status).toBe(200);
    expect((await api('status', { deviceCode: d.deviceCode })).status).toBe(401);
    await step(s, 'deny', d.requestId);
    await repo.deny(s, d.requestId);
    await expect(repo.approve(s, grant.canonical, await first.sign(grant.canonical))).rejects.toThrow();
    expect((await repo.list(other)).devices).toHaveLength(0);
});
test('device request signature requires bounded timestamp even with a valid token and key', async () => {
    const s = await account(), d = await enroll(s), issued = await session(d), nonce = crypto.randomUUID(), time = Math.floor(Date.now() / 1000);
    const url = new URL(origin + '/v1/devices/key-packages');
    const headers = { authorization: 'Bearer ' + issued.token, 'x-device-nonce': nonce, 'x-device-timestamp': String(time), 'x-device-proof': await d.sign(requestProof('GET', url, await digest(''), time, nonce, await digest(issued.token))) };
    expect((await authenticate(db(), new Request(url, { headers }), null, '')).deviceId).toBe(d.deviceId);
    await expect(authenticate(db(), new Request(url, { headers: { ...headers, 'x-device-timestamp': String(time - 301) } }), null, '')).rejects.toThrow();
    expect(await verify(d.signingKey, headers['x-device-proof'], requestProof('GET', url, await digest(''), time, nonce, await digest(issued.token)))).toBe(true);
});
async function deviceRequest(d: Awaited<ReturnType<typeof authorize>>, token: string, path: string, body = '', time = Math.floor(Date.now() / 1000), nonce = crypto.randomUUID()) {
    const method = body ? 'POST' : 'GET', url = new URL(origin + path);
    return new Request(url, { method, headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', 'x-device-nonce': nonce, 'x-device-timestamp': String(time), 'x-device-proof': await d.sign(requestProof(method, url, await digest(body), time, nonce, await digest(token))) }, ...(body ? { body } : {}) });
}
test('key packages bind target, vault, epoch and issuer; immutable exact retries and isolated fetch', async () => {
    const s = await account(), first = await enroll(s), second = await enroll(s, first), a = await session(first), b = await session(second), repo = deviceRepository(db());
    const pkg = { version: 1, vaultId: 'v', targetDeviceId: second.deviceId, keyEpoch: 1, wrappedVDK: btoa('synthetic-ciphertext'.repeat(8)), issuerDeviceId: first.deviceId, grantId: second.requestId };
    const send = async (value: typeof pkg, issuer = first, token = a.token) => {
        const canonical = canonicalPackage(value), signature = await issuer.sign(canonical), body = JSON.stringify({ canonical, signature });
        const c = await authenticate(db(), await deviceRequest(issuer, token, '/v1/devices/enroll', body), null, body);
        return repo.putPackage(c, canonical, signature);
    };
    for (const value of [{ ...pkg, vaultId: 'foreign' }, { ...pkg, targetDeviceId: first.deviceId }, { ...pkg, keyEpoch: 2 }, { ...pkg, grantId: first.requestId }])
        await expect(send(value)).rejects.toThrow();
    await send(pkg);
    await send(pkg);
    await expect(send({ ...pkg, wrappedVDK: btoa('changed'.repeat(20)) })).rejects.toThrow('idempotency_conflict');
    await expect(send({ ...pkg, issuerDeviceId: second.deviceId }, second, b.token)).rejects.toThrow();
    const c = await authenticate(db(), await deviceRequest(second, b.token, '/v1/devices/key-packages'), null, '');
    expect((await repo.ownPackage(c)).canonical).toBe(canonicalPackage(pkg));
    await expect(repo.ownPackage(c)).rejects.toThrow('replayed_request');
    await expect(repo.ownPackage(await authenticate(db(), await deviceRequest(first, a.token, '/v1/devices/key-packages'), null, ''))).rejects.toThrow('not_found');
    const audit = JSON.stringify((await db().prepare('SELECT * FROM device_audit').all()).results);
    expect(audit).not.toContain(pkg.wrappedVDK);
    expect(audit).not.toContain(first.signingKey);
    expect(audit).not.toContain(a.token);
});
test.each(['method', 'path', 'query', 'body', 'timestamp', 'nonce', 'session'])('request proof rejects changed %s', async (field) => {
    const s = await account(), d = await enroll(s), issued = await session(d), path = '/v1/devices/enroll', body = '{}';
    const request = await deviceRequest(d, issued.token, path, body);
    let url = request.url, method = request.method, actualBody = body;
    const headers = new Headers(request.headers);
    if (field === 'method')
        method = 'PUT';
    if (field === 'path')
        url += '/changed';
    if (field === 'query')
        url += '?x=1';
    if (field === 'body')
        actualBody = '{"x":1}';
    if (field === 'timestamp')
        headers.set('x-device-timestamp', String(Math.floor(Date.now() / 1000) - 1));
    if (field === 'nonce')
        headers.set('x-device-nonce', 'different');
    if (field === 'session') {
        const next = await session(d);
        headers.set('authorization', 'Bearer ' + next.token);
    }
    await expect(authenticate(db(), new Request(url, { method, headers, body: actualBody }), null, actualBody)).rejects.toThrow('invalid_signature');
});
test('device codes are one-use after approval; unknown and expired codes have identical denials', async () => {
    const s = await account(), d = await enroll(s);
    const first = await api('status', { deviceCode: d.deviceCode });
    expect(first.status).toBe(200);
    expect((await first.json() as {
        state: string;
    }).state).toBe('approved');
    const replay = await api('status', { deviceCode: d.deviceCode }), unknown = await api('status', { deviceCode: 'z'.repeat(43) });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual(await unknown.json());
    // The private signing key, not the expired pairing code, permits reissuance.
    await session(d);
    await session(d);
});
test('nonce cleanup is bounded and retains every live-session nonce', async () => {
    const s = await account(), d = await enroll(s), issued = await session(d), repo = deviceRepository(db());
    const c = await authenticate(db(), await deviceRequest(d, issued.token, '/v1/devices/key-packages'), null, '');
    const stmt = (nonce: string) => db().prepare('INSERT INTO device_nonces VALUES(?,?,?,?,?,?)').bind(c.sessionDigest, c.tenantId, c.vaultId, c.deviceId, c.accountId, nonce);
    await db().batch(Array.from({ length: 70 }, (_, i) => stmt('n' + i)));
    await repo.cleanup();
    expect(await db().prepare('SELECT count(*) FROM device_nonces').first('count(*)')).toBe(70);
    await db().prepare('UPDATE device_sessions SET expires_at=unixepoch()-301').run();
    await repo.cleanup();
    expect(await db().prepare('SELECT count(*) FROM device_nonces').first('count(*)')).toBe(6);
    await repo.cleanup();
    expect(await db().prepare('SELECT count(*) FROM device_nonces').first('count(*)')).toBe(0);
});
test('approval audit failure rolls back device, keys, grant, action and step-up consumption', async () => {
    const s = await account(), d = await authorize(), repo = deviceRepository(db()), g = await repo.pending(s, await digest(d.verificationCode), null);
    await step(s, 'approve', g.canonical);
    await db().exec("CREATE TRIGGER fail_device_audit BEFORE INSERT ON device_audit WHEN NEW.event='approved' BEGIN SELECT RAISE(ABORT,'injected'); END");
    await expect(repo.approve(s, g.canonical, null)).rejects.toThrow();
    for (const table of ['devices', 'device_keys', 'enrollment_grants', 'device_actions'])
        expect(await db().prepare(`SELECT count(*) n FROM ${table}`).first('n')).toBe(0);
    expect(await db().prepare('SELECT step_up_digest FROM browser_sessions').first('step_up_digest')).toBe(await actionDigest('approve', g.canonical));
    await db().exec('DROP TRIGGER fail_device_audit');
    await repo.approve(s, g.canonical, null);
});
test('revocation or session expiry after request verification aborts package acceptance', async () => {
    const s = await account(), d = await enroll(s), issued = await session(d), repo = deviceRepository(db());
    const canonical = canonicalPackage({ version: 1, vaultId: 'v', targetDeviceId: d.deviceId, keyEpoch: 1, wrappedVDK: btoa('c'.repeat(80)), issuerDeviceId: d.deviceId, grantId: d.requestId }), signature = await d.sign(canonical), body = JSON.stringify({ canonical, signature });
    const c = await authenticate(db(), await deviceRequest(d, issued.token, '/v1/devices/enroll', body), null, body);
    await db().prepare('UPDATE device_sessions SET expires_at=0').run();
    await expect(repo.putPackage(c, canonical, signature)).rejects.toThrow('not_found');
    const next = await session(d), c2 = await authenticate(db(), await deviceRequest(d, next.token, '/v1/devices/enroll', body), null, body);
    await db().prepare('UPDATE devices SET active=0 WHERE id=?').bind(d.deviceId).run();
    await expect(repo.putPackage(c2, canonical, signature)).rejects.toThrow('not_found');
    expect(await db().prepare('SELECT count(*) n FROM device_key_packages').first('n')).toBe(0);
    expect((await api('challenge', { deviceId: d.deviceId })).status).toBe(404);
});
test('concurrent approvals consume exactly one action; revoked bootstrap cannot be reused', async () => {
    const s = await account(), d = await authorize(), repo = deviceRepository(db()), g = await repo.pending(s, await digest(d.verificationCode), null);
    await step(s, 'approve', g.canonical);
    const results = await Promise.allSettled([repo.approve(s, g.canonical, null), repo.approve(s, g.canonical, null)]);
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    await db().prepare('UPDATE devices SET active=0').run();
    const next = await authorize(), nextGrant = await repo.pending(s, await digest(next.verificationCode), null);
    await step(s, 'approve', nextGrant.canonical);
    await expect(repo.approve(s, nextGrant.canonical, null)).rejects.toThrow('approval_required');
});
test('expired pairing and challenge fail closed without issuing sessions', async () => {
    const s = await account(), d = await authorize(), repo = deviceRepository(db());
    const code = 'e'.repeat(43), verification = 'f'.repeat(43);
    await db().prepare("INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at) VALUES('expired',?,?,'00-00','expired',?,?,'linux',unixepoch()-1)").bind(await digest(code), await digest(verification), d.signingKey, d.wrappingKey).run();
    expect((await api('status', { deviceCode: code })).status).toBe(401);
    await expect(repo.pending(s, await digest(verification), null)).rejects.toThrow();
    const active = await enroll(s), r = await api('challenge', { deviceId: active.deviceId }), c = await r.json() as {
        challengeId: string;
    };
    await db().prepare('UPDATE device_challenges SET expires_at=0 WHERE id=?').bind(c.challengeId).run();
    expect((await api('token', { challengeId: c.challengeId, signature: await active.sign('wrong') })).status).toBe(401);
    expect(await db().prepare('SELECT count(*) n FROM device_sessions').first('n')).toBe(0);
});
test('concurrent revoke/approve linearizes against the trusted authorizer in D1', async () => {
    const s = await account(), first = await enroll(s), d = await authorize(), repo = deviceRepository(db());
    const g = await repo.pending(s, await digest(d.verificationCode), first.deviceId);
    const device = (await repo.list(s)).devices[0]!;
    const secondSession = { ...s, digest: await digest(crypto.randomUUID()) };
    await db().prepare('INSERT INTO browser_sessions(digest,csrf_digest,account_id,tenant_id,absolute_expires,step_up_digest,step_up_expires) VALUES(?,?,?,?,?,?,unixepoch()+300)').bind(secondSession.digest, s.csrf_digest, s.account_id, s.tenant_id, s.absolute_expires, device.revokeActionDigest).run();
    await step(s, 'approve', g.canonical);
    const signature = await first.sign(g.canonical);
    const [approved, revoked] = await Promise.allSettled([repo.approve(s, g.canonical, signature), repo.revoke(secondSession, first.deviceId)]);
    expect(revoked.status).toBe('fulfilled');
    const events = (await db().prepare("SELECT event,device_id FROM device_audit WHERE event IN('approved','revoked') ORDER BY id").all<{
        event: string;
        device_id: string;
    }>()).results;
    if (approved.status === 'fulfilled')
        expect(events.findIndex(e => e.event === 'approved' && e.device_id === d.deviceId)).toBeLessThan(events.findIndex(e => e.event === 'revoked'));
    else
        expect(await db().prepare('SELECT count(*) n FROM devices WHERE id=?').bind(d.deviceId).first('n')).toBe(0);
    await expect(repo.approve(s, g.canonical, signature)).rejects.toThrow();
});
test('control endpoints reject authority fields, oversize bodies and cookie authentication before state creation', async () => {
    const k = await identity(), body = { signingKey: k.signingKey, wrappingKey: k.wrappingKey, platform: 'linux', proof: await k.sign(enrollmentProof(k.signingKey, k.wrappingKey, 'linux')) };
    expect((await api('authorize', { ...body, accountId: 'attacker' })).status).toBe(400);
    expect((await api('authorize', body, { cookie: '__Host-akc_session=synthetic' })).status).toBe(401);
    expect((await api('authorize', { padding: 'x'.repeat(8193) })).status).toBe(413);
    expect(await db().prepare('SELECT count(*) n FROM device_requests').first('n')).toBe(0);
});
test('failed signing proofs exhaust challenge attempts; cross-account revocation fails', async () => {
    const s = await account(), d = await enroll(s), other = await account('b', 'u');
    await expect(deviceRepository(db()).revoke(other, d.deviceId)).rejects.toThrow('not_found');
    const response = await api('challenge', { deviceId: d.deviceId }), c = await response.json() as {
        challengeId: string;
        challenge: string;
        deviceId: string;
        vaultId: string;
        expiresAt: number;
    };
    for (let i = 0; i < 5; i++)
        expect((await api('token', { challengeId: c.challengeId, signature: await d.sign('invalid') })).status).toBe(401);
    const signature = await d.sign(challengeProof(c.challengeId, await digest(c.challenge), c.deviceId, c.vaultId, c.expiresAt));
    expect((await api('token', { challengeId: c.challengeId, signature })).status).toBe(401);
    expect(await db().prepare('SELECT count(*) n FROM device_sessions').first('n')).toBe(0);
});
test('short pairing code and three words, existing-device confirmation stays off the browser response',async()=>{
    const s=await account(),first=await enroll(s),issued=await session(first),next=await authorize();
    expect(next.verificationCode).toHaveLength(12);expect(next.phrase.split(' ')).toHaveLength(3);
    await deviceRepository(db()).pending(s,await digest(next.verificationCode),first.deviceId);
    const bindings={MAIN:db(),AUTH_ORIGIN:origin,DEVICE_API_ORIGIN:origin,TRUSTED_AUTH_SOURCE:{resolve:async()=> 'synthetic-device-source'}};
    const detail=await deviceFetch(await deviceRequest(first,issued.token,'/v1/devices/pairing-detail',JSON.stringify({id:next.requestId})),bindings);
    expect(detail.status).toBe(200);const {canonical}=await detail.json() as {canonical:string};
    const confirm=await deviceFetch(await deviceRequest(first,issued.token,'/v1/devices/pairing-confirm',JSON.stringify({id:next.requestId,signature:await first.sign(canonical)})),bindings);expect(confirm.status).toBe(200);
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const web=webRepository(db(),{} as import('../api-worker/browser-auth.ts').BrowserConfig,s);
    for(const view of ['devices','device']) assertSafeView(await web.query({view,...(view==='device'?{id:first.deviceId}:{})}));
    const safe=await web.pairing({code:next.verificationCode});expect(safe.confirmRef).toBeTypeOf('string');expect(JSON.stringify(safe)).not.toMatch(/canonical|signature|signingKey|wrappingKey/);
    const a=await web.resolve(safe.confirmRef);
    await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(a.action_digest,s.digest).run();
    expect(await web.execute(safe.confirmRef)).toEqual({approved:true});
    await expect(web.execute(safe.confirmRef)).rejects.toThrow();
});

test('trust delivery is target-only, issuer scoped, immutable and bound to approved grant',async()=>{
 const s=await account(),a=await enroll(s),b=await enroll(s,a),issued=await session(a),target=await session(b);
 const {trustRepository}=await import('../api-worker/trust-repository.ts');
 const context=async(d:typeof a,t:typeof issued)=>{
  const raw='{}',stamp=Math.floor(Date.now()/1000),nonce=crypto.randomUUID(),url=new URL(origin+'/v1/devices/trust-bundle');
  const headers={authorization:'Bearer '+t.token,'x-device-nonce':nonce,'x-device-timestamp':String(stamp),'x-device-proof':await d.sign(requestProof('POST',url,await digest(raw),stamp,nonce,await digest(t.token)))};
  return authenticate(db(),new Request(url,{method:'POST',headers,body:raw}),null,raw);
 };
 const repo=trustRepository(db()),sealed=btoa('opaque'.repeat(20));
 await repo.put(await context(a,issued),b.requestId,sealed);
 expect((await repo.own(await context(b,target))).sealed).toBe(sealed);
 await expect(repo.own(await context(a,issued))).rejects.toThrow();
 await expect(repo.put(await context(b,target),b.requestId,sealed)).rejects.toThrow();
 await expect(repo.put(await context(a,issued),b.requestId,btoa('changed'.repeat(20)))).rejects.toThrow();
});

test('signed enrollment resume recovers delivered identity without reusing bearer poll or accepting another key',async()=>{
 const s=await account(),d=await enroll(s),other=await identity();
 await deviceRepository(db()).poll(await digest(d.deviceCode));
 const timestamp=Math.floor(Date.now()/1000),request={requestId:d.requestId,deviceId:d.deviceId,timestamp};
 const message=JSON.stringify(['AgentKeychain-enrollment-resume-v1',request.requestId,request.deviceId,timestamp]);
 expect((await api('resume',{...request,signature:await other.sign(message)})).status).not.toBe(200);
 const result=await api('resume',{...request,signature:await d.sign(message)});
 expect(result.status).toBe(200);expect(await result.json()).toMatchObject({state:'approved',vaultId:'v',deviceId:d.deviceId,requestId:d.requestId});
 expect((await api('resume',{...request,timestamp:timestamp-301,signature:await d.sign(message)})).status).not.toBe(200);
 await expect(deviceRepository(db()).poll(await digest(d.deviceCode))).rejects.toThrow();
});

test('expired enrollment classification is signed, minimal and creates no activation authority',async()=>{
 const s=await account(),k=await identity(),timestamp=Math.floor(Date.now()/1000);
 const create=async (state:string,expiry:number)=>{
  const requestId=crypto.randomUUID(),deviceId=crypto.randomUUID();
  await db().prepare("INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at,state,account_id,tenant_id,vault_id) VALUES(?,?,?,'synthetic fixture',?,?,?,'linux',unixepoch()+?,?,?,?,?)")
   .bind(requestId,await digest('code:'+requestId),await digest('verify:'+requestId),deviceId,k.signingKey,k.wrappingKey,expiry,state,s.account_id,s.tenant_id,'v').run();
  return {requestId,deviceId};
 };
 const lookup=async (ids:{requestId:string;deviceId:string}, time=timestamp, wrappingKey=k.wrappingKey, sign=k.sign)=>
  api('enrollment-reconcile',{...ids,timestamp:time,signature:await sign(enrollmentReconcileProof(ids.requestId,ids.deviceId,k.signingKey,wrappingKey,time))});
 const expired=await create('bound',-1),live=await create('bound',300),ambiguous=await create('approved',-1),approved=await create('delivered',-1);
 const expiresAt=await db().prepare('SELECT expires_at FROM device_requests WHERE id=?').bind(approved.requestId).first<number>('expires_at');
 const grant={version:1,requestId:approved.requestId,accountId:s.account_id,tenantId:s.tenant_id,vaultId:'v',deviceId:approved.deviceId,signingKey:k.signingKey,wrappingKey:k.wrappingKey,issuerDeviceId:null,keyEpoch:1,expiresAt};
 await db().batch([
  db().prepare('INSERT INTO devices(tenant_id,id,account_id,public_key,active) VALUES(?,?,?,?,1)').bind(s.tenant_id,approved.deviceId,s.account_id,k.signingKey),
  db().prepare('INSERT INTO device_keys VALUES(?,?,?)').bind(s.tenant_id,approved.deviceId,k.wrappingKey),
  db().prepare('INSERT INTO vault_devices VALUES(?,?,?,1)').bind(s.tenant_id,'v',approved.deviceId),
  db().prepare('INSERT INTO enrollment_grants VALUES(?,?,?,?,?,?,?,NULL)').bind(approved.requestId,s.tenant_id,'v',approved.deviceId,null,1,canonicalGrant(grant)),
 ]);
 for(const [ids,state] of [[expired,'expired_unapproved'],[live,'not_expired'],[ambiguous,'unknown'],[approved,'expired_approved']] as const){
  const r=await lookup(ids);expect(r.status).toBe(200);expect(await r.json()).toEqual({...ids,state});
 }
 const other=await identity();
 for(const r of [await lookup(expired,timestamp,k.wrappingKey,other.sign),await lookup(expired,timestamp,other.wrappingKey),await lookup(expired,timestamp-301),await lookup({...expired,deviceId:live.deviceId})])
  expect(r.status).toBe(401);
 await db().prepare('DELETE FROM device_requests WHERE id=?').bind(expired.requestId).run();
 expect((await lookup(expired)).status).toBe(401);
 expect(await db().prepare('SELECT count(*) FROM enrollment_grants').first()).toEqual({'count(*)':1});
 expect(await db().prepare('SELECT count(*) FROM device_sessions').first()).toEqual({'count(*)':0});
});

test('signed retirement is terminal, idempotent and does not allocate a successor',async()=>{
 const keys=await identity(),timestamp=Math.floor(Date.now()/1000);
 const fresh=await authorize(),s=await account(),approved=await enroll(s);
 const make=async (state:string)=>{
  const requestId=crypto.randomUUID(),deviceId=crypto.randomUUID();
  await db().prepare("INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at,state) VALUES(?,?,?,'synthetic fixture',?,?,?,'linux',unixepoch()-90000,?)")
   .bind(requestId,await digest('retire:'+requestId),await digest('pair:'+requestId),deviceId,keys.signingKey,keys.wrappingKey,state).run();
  return {requestId,deviceId};
 };
 const target=await make('pending'),unknown=await make('approved');
 const payload=async (ids:{requestId:string;deviceId:string},who=keys,proof=enrollmentRetireProof)=>({
  requestId:ids.requestId,deviceId:ids.deviceId,timestamp,signature:await who.sign(proof(ids.requestId,ids.deviceId,who.signingKey,who.wrappingKey,timestamp)),
 });
 expect((await api('enrollment-retire',await payload(target,await identity()))).status).toBe(401);
 expect((await api('enrollment-retire',await payload(target,keys,enrollmentReconcileProof))).status).toBe(401);
 expect((await api('enrollment-retire',await payload(unknown))).status).toBe(404);
 expect((await api('enrollment-retire',await payload(fresh,fresh))).status).toBe(404);
 expect((await api('enrollment-retire',await payload(approved,approved))).status).toBe(404);
 // Drop the first JSON response deliberately; simultaneous and restarted
 // callers learn the same decision, without a second write.
 const proof=await payload(target);
 for (const response of await Promise.all([api('enrollment-retire',proof),api('enrollment-retire',proof)]))
  expect(response.status).toBe(200);
 expect(await (await api('enrollment-retire',proof)).json()).toEqual({...target,state:'retired_unapproved'});
 expect(await (await api('enrollment-reconcile',await payload(target,keys,enrollmentReconcileProof))).json()).toEqual({...target,state:'retired_unapproved'});
 expect(await db().prepare('SELECT count(*) n FROM enrollment_retirements').first('n')).toBe(1);
 expect(await db().prepare('SELECT count(*) n FROM device_requests').first('n')).toBe(4);
 expect(await db().prepare('SELECT count(*) n FROM enrollment_grants').first('n')).toBe(1);
 expect(await db().prepare('SELECT count(*) n FROM device_sessions').first('n')).toBe(0);
 expect(await db().prepare('SELECT state FROM device_requests WHERE id=?').bind(target.requestId).first('state')).toBe('denied');
 await deviceRepository(db()).cleanup();
 expect(await db().prepare('SELECT state FROM device_requests WHERE id=?').bind(target.requestId).first('state')).toBe('denied');
});

import {rosterRepository} from '../api-worker/roster-repository.ts';
import {canonicalRoster,rosterDigest,ROSTER_DOMAIN,type TrustedDeviceRoster} from '../shared/roster.ts';
async function rosterContext(d:Awaited<ReturnType<typeof authorize>>){const token=await session(d),raw='{}',nonce=crypto.randomUUID(),timestamp=Math.floor(Date.now()/1000),url=new URL(origin+'/v1/devices/roster-put');const request=new Request(url,{method:'POST',headers:{authorization:'Bearer '+token.token,'x-device-nonce':nonce,'x-device-timestamp':String(timestamp),'x-device-proof':await d.sign(requestProof('POST',url,await digest(raw),timestamp,nonce,await digest(token.token)))},body:raw});return authenticate(db(),request,null,raw);}
async function rosterFixture(){const s=await account(),a=await enroll(s),now=Math.floor(Date.now()/1000);const r:TrustedDeviceRoster={version:1,accountId:'a',tenantId:'t',vaultId:'v',revision:1,previousDigest:null,keyEpoch:1,active:[{deviceId:a.deviceId,signingKey:a.signingKey,wrappingKey:a.wrappingKey}],revoked:[],issuer:{kind:'device',id:a.deviceId},issuedAt:now,expiresAt:now+86400,checkpointKeys:[{keyId:'cp',publicKey:a.signingKey}],recoveryAuthorities:[],recovery:null};const sign=async(v:TrustedDeviceRoster)=>{const canonical=canonicalRoster(v);return {canonical,signature:await a.sign(ROSTER_DOMAIN+canonical)};};return {s,a,r,sign,repo:rosterRepository(db())};}
test('signed roster immutable storage, exact retry, conflicting revision and browser metadata only',async()=>{
 const {s,a,r,sign,repo}=await rosterFixture(),one=await sign(r);await repo.put(await rosterContext(a),one);await repo.put(await rosterContext(a),one);
 expect((await db().prepare('SELECT count(*) n FROM signed_rosters').first<number>('n'))).toBe(1);
 await expect(repo.put(await rosterContext(a),await sign({...r,expiresAt:r.expiresAt+1}))).rejects.toThrow('idempotency_conflict');
 await expect(db().prepare("UPDATE signed_rosters SET signature='tampered'").run()).rejects.toThrow('immutable_roster');
 await expect(db().prepare('DELETE FROM signed_rosters').run()).rejects.toThrow('immutable_roster');
 const view=JSON.stringify(await deviceRepository(db()).list(s));expect(view).not.toContain(a.signingKey);expect(view).not.toContain(a.wrappingKey);expect(view).not.toContain(one.signature);
});
test('concurrent roster issuers cannot fork or hide approved/revoked identities',async()=>{
 const {s,a,r,sign,repo}=await rosterFixture(),one=await sign(r);await repo.put(await rosterContext(a),one);const b=await enroll(s,a);
 const two={...r,revision:2,previousDigest:await rosterDigest(one),active:[...r.active,{deviceId:b.deviceId,signingKey:b.signingKey,wrappingKey:b.wrappingKey}]};
 await expect(repo.put(await rosterContext(a),await sign({...two,active:r.active}))).rejects.toThrow('idempotency_conflict');
 const ca=await rosterContext(a),cb=await rosterContext(b),sa=await sign(two),canonical=canonicalRoster({...two,issuer:{kind:'device',id:b.deviceId}}),sb={canonical,signature:await b.sign(ROSTER_DOMAIN+canonical)};
 // B was not trusted in the previous revision and cannot issue its own admission.
 await expect(repo.put(cb,sb)).rejects.toThrow();await repo.put(ca,sa);
 const ra={...two,revision:3,previousDigest:await rosterDigest(sa)},rb={...ra,issuer:{kind:'device' as const,id:b.deviceId}},bc=canonicalRoster(rb);
 const results=await Promise.allSettled([repo.put(await rosterContext(a),await sign(ra)),repo.put(await rosterContext(b),{canonical:bc,signature:await b.sign(ROSTER_DOMAIN+bc)})]);expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);
});
test('issuer revocation after authentication fails transaction; revoked possession can fetch but cannot publish',async()=>{
 const {s,a,r,sign,repo}=await rosterFixture(),one=await sign(r);await repo.put(await rosterContext(a),one);const c=await rosterContext(a),next=await sign({...r,revision:2,previousDigest:await rosterDigest(one)});
 await readyLastDevice();
 const device=(await deviceRepository(db()).list(s)).devices[0]!;await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(device.revokeActionDigest,s.digest).run();await deviceRepository(db()).revoke(s,a.deviceId);
 await expect(repo.put(c,next)).rejects.toThrow();
 const body={accountId:'a',tenantId:'t',vaultId:'v',deviceId:a.deviceId,after:0,timestamp:Math.floor(Date.now()/1000)},signature=await a.sign(JSON.stringify(['AgentKeychain-roster-fetch-v1',body]));expect((await repo.fetch({...body,signature})).revisions).toEqual([one]);await expect(repo.fetch({...body,accountId:'other',signature})).rejects.toThrow();
});

test('last trusted device without current recovery readiness cannot be revoked atomically',async()=>{
 const s=await account(),d=await enroll(s),repo=deviceRepository(db());
 await session(d);const sessionsBefore=(await db().prepare('SELECT * FROM device_sessions').all()).results,vaultBefore=(await db().prepare('SELECT * FROM vault_devices').all()).results;
 const listed=(await repo.list(s)).devices[0]!;
 const {webRepository}=await import('../api-worker/web-repository.ts');
 const view=await webRepository(db(),{} as never,s).query({view:'device',id:d.deviceId});assertSafeView(view);expect(view).toMatchObject({removeRef:null,lastDevice:true,recoveryReady:false});
 await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(listed.revokeActionDigest,s.digest).run();
 const before=await db().prepare('SELECT * FROM devices').all();
 await expect(repo.revoke(s,d.deviceId)).rejects.toThrow();
 expect(await db().prepare('SELECT * FROM devices').all()).toEqual(before);
 expect(await db().prepare("SELECT count(*) n FROM device_actions WHERE action='revoke'").first('n')).toBe(0);
 expect(await db().prepare('SELECT count(*) n FROM device_revocation_boundaries').first('n')).toBe(0);
 expect((await db().prepare('SELECT * FROM device_sessions').all()).results).toEqual(sessionsBefore);expect((await db().prepare('SELECT * FROM vault_devices').all()).results).toEqual(vaultBefore);
});

async function readyLastDevice(){
 await db().prepare("INSERT INTO recovery_packages_v1 VALUES('last-package','t','v','a',1,'{}','synthetic',1)").run();
 await db().prepare("INSERT INTO recovery_readiness VALUES('last-package',unixepoch()+600,0)").run();
}
test.each(['valid','expired','revoked'])('last-device readiness is rechecked atomically after action display: %s',async state=>{
 const s=await account(),d=await enroll(s),repo=deviceRepository(db());await readyLastDevice();
 const device=(await repo.list(s)).devices[0]!;expect(device.lastDevice).toBe(true);expect(device.canRemove).toBe(true);
 await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(device.revokeActionDigest,s.digest).run();
 if(state==='expired')await db().prepare('UPDATE recovery_readiness SET valid_until=unixepoch()-1').run();
 if(state==='revoked')await db().prepare('UPDATE recovery_readiness SET revoked=1').run();
 if(state==='valid'){
  expect(await repo.revoke(s,d.deviceId)).toEqual({revoked:false,enforced:true,witnessPending:true});
  expect((await repo.list(s)).devices[0]!.canRemove).toBe(false);
  expect(await db().prepare('SELECT warning FROM last_device_revocations').first('warning')).toBe('Access will require recovery');
 }else{
  await expect(repo.revoke(s,d.deviceId)).rejects.toThrow('recovery_required');
  expect(await db().prepare('SELECT active FROM devices').first('active')).toBe(1);
  expect(await db().prepare('SELECT count(*) n FROM last_device_revocations').first('n')).toBe(0);
 }
});

test.each(['expiry','revoke'])('concurrent readiness %s and last-device removal have one atomic ordering',async change=>{
 const s=await account(),d=await enroll(s),repo=deviceRepository(db());await readyLastDevice();
 const listed=(await repo.list(s)).devices[0]!;
 await step(s,'revoke',JSON.stringify(['t','a',d.deviceId,d.signingKey,d.wrappingKey]));
 await expect(repo.revoke(s,d.deviceId)).rejects.toThrow('approval_required');
 await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(listed.revokeActionDigest,s.digest).run();
 const [changed,removed]=await Promise.allSettled([db().prepare(change==='expiry'?'UPDATE recovery_readiness SET valid_until=unixepoch()-1':'UPDATE recovery_readiness SET revoked=1').run(),repo.revoke(s,d.deviceId)]);
 expect(changed.status).toBe('fulfilled');
 expect(await db().prepare('SELECT active FROM devices WHERE id=?').bind(d.deviceId).first('active')).toBe(removed.status==='fulfilled'?0:1);
 expect(await db().prepare('SELECT count(*) n FROM last_device_revocations').first('n')).toBe(removed.status==='fulfilled'?1:0);
});
