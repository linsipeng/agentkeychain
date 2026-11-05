import { rpcData } from '../shared/rpc-data.ts';
import { assertSafeView } from '../web/src/safe-view.ts';
import { random } from '../api-worker/webauthn.ts';
import { expect, test } from 'vitest';
import { splitRecoveryKey, joinRecoveryKey, seal, open, wrapVaultKey, unwrapVaultKey } from '../shared/recovery-crypto.ts';
test('2-of-2 shares and X25519 HKDF AES-GCM target wrapping bind context', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32)), [a, b] = splitRecoveryKey(key);
    expect(a).not.toEqual(key);
    expect(b).not.toEqual(key);
    expect(joinRecoveryKey(a, b)).toEqual(key);
    const target = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    const pub = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', target.publicKey))));
    const box = await seal(pub, a, 'case-target-epoch');
    expect(await open(target.privateKey, box, 'case-target-epoch')).toEqual(a);
    await expect(open(target.privateKey, box, 'wrong-case')).rejects.toThrow();
    const wrong = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    await expect(open(wrong.privateKey, box, 'case-target-epoch')).rejects.toThrow();
});
import { beforeEach } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, reset } from 'cloudflare:test';
import { recoveryRepository } from '../api-worker/recovery-repository.ts';
import { packageContext, releaseContext, recoveryAction, vaultKeyContext, cancelMessage, type CancelAuthorization, type RecoveryManifest, type RecoveryEvidence } from '../shared/recovery.ts';
import { encode64 } from '../shared/recovery-crypto.ts';
import type { RecoveryTestService } from './synthetic-recovery.ts';
import type { DeviceContext } from '../api-worker/auth.ts';
import type { SessionRow } from '../api-worker/browser-repository.ts';
const db = () => env.MAIN;
const s = { digest: 'browser', tenant_id: 't', account_id: 'a' } as SessionRow;
let ctx: DeviceContext;
let signing: CryptoKeyPair;
let target: CryptoKeyPair;
let targetSigning: CryptoKeyPair;
let recoveryKey: Uint8Array;
let vaultKey: Uint8Array;
const repo = () => recoveryRepository(db(), env);
const sign = async (pair: CryptoKeyPair, v: string) => encode64(new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, new TextEncoder().encode(v))));
const publicKey = async (pair: CryptoKeyPair) => encode64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
const trust = () => env.RECOVERY_AUTH as unknown as RecoveryTestService;
async function step(action: string, canonical: string) { await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300 WHERE digest=?').bind(await recoveryAction(action, canonical), s.digest).run(); }
beforeEach(async () => {
    await reset();
    await applyD1Migrations(db(), env.MIGRATIONS);
    await applyD1Migrations(env.CUSTODIAN_TEST, env.CUSTODIAN_MIGRATIONS);
    signing = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    target = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    targetSigning = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    const pub = await publicKey(signing);
    await db().batch([db().prepare("INSERT INTO accounts VALUES('a')"), db().prepare("INSERT INTO tenants VALUES('t')"), db().prepare("INSERT INTO memberships VALUES('t','a',1)"), db().prepare("INSERT INTO vaults VALUES('t','v',0)"), db().prepare("INSERT INTO devices VALUES('t','d','a',?,1)").bind(pub), db().prepare("INSERT INTO vault_devices VALUES('t','v','d',1)"), db().prepare("INSERT INTO device_sessions VALUES('device','t','v','d','a',unixepoch()+600,1)"), db().prepare("INSERT INTO browser_sessions(digest,csrf_digest,account_id,tenant_id,absolute_expires) VALUES('browser','csrf','a','t',unixepoch()+600)")]);
    ctx = { tenantId: 't', vaultId: 'v', accountId: 'a', deviceId: 'd', publicKey: pub, sessionDigest: 'device', nonce: crypto.randomUUID(), timestamp: Math.floor(Date.now() / 1000) } as DeviceContext;
    await trust().trust('a', 't', 'v', 'd', pub);
    await env.CUSTODIAN_TEST_TRUST.trust('a', 't', 'v', 'd', pub);
});
async function enrolled() {
    const keys = await repo().keys();
    recoveryKey = crypto.getRandomValues(new Uint8Array(32));
    const [a, b] = splitRecoveryKey(recoveryKey);
    const m = { version: 1, packageId: crypto.randomUUID(), accountId: 'a', tenantId: 't', vaultId: 'v', keyEpoch: 1, policy: 'two-party-24h', issuerDeviceId: 'd', apiKeyId: keys.api.keyId, custodianKeyId: keys.custodian.keyId, wrappedVDK: encode64(crypto.getRandomValues(new Uint8Array(48))) } as RecoveryManifest;
    vaultKey = crypto.getRandomValues(new Uint8Array(32));
    m.wrappedVDK = await wrapVaultKey(recoveryKey, vaultKey, vaultKeyContext(m));
    m.apiShare = await seal(keys.api.publicKey, a, packageContext(m, 'api'));
    m.custodianShare = await seal(keys.custodian.publicKey, b, packageContext(m, 'custodian'));
    const canonical = JSON.stringify(m);
    await repo().enroll({ ...ctx, nonce: crypto.randomUUID() }, canonical, await sign(signing, canonical));
    return m;
}
async function started() { const m = await enrolled(); const input = { id: crypto.randomUUID(), packageId: m.packageId, targetDeviceId: random(), signingKey: await publicKey(targetSigning), wrappingKey: await publicKey(target), nonce: crypto.randomUUID() }; await step('start', JSON.stringify(input)); return { ...await repo().start(s, input), input }; }
const cancelAuth = async (canonical: string): Promise<CancelAuthorization> => { const a: CancelAuthorization = { action: 'cancel', nonce: crypto.randomUUID(), expiresAt: Math.floor(Date.now() / 1000) + 300, deviceId: 'd', signature: '' }; a.signature = await sign(signing, cancelMessage(canonical, a)); return a; };
const evidence = async (canonical: string): Promise<RecoveryEvidence> => ({ mode: 'device', confirmerId: 'd', signature: await sign(signing, JSON.stringify(['AgentKeychain-recovery-confirm-v1', canonical])), proof: null });
test('two real Workers/two D1 release only target ciphertext; proof gates activation and revokes sessions', async () => {
    const c = await started();
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
    const released = await repo().release(s, c.input.id, await evidence(c.canonical));
    const a = await open(target.privateKey, released.api, releaseContext(c.canonical, 'api')), b = await open(target.privateKey, released.custodian, releaseContext(c.canonical, 'custodian'));
    expect(joinRecoveryKey(a, b)).toEqual(recoveryKey);
    const m = JSON.parse((await db().prepare('SELECT canonical FROM recovery_packages_v1').first('canonical')) as string) as RecoveryManifest;
    expect(await unwrapVaultKey(joinRecoveryKey(a, b), released.wrappedVDK, vaultKeyContext(m))).toEqual(vaultKey);
    expect(await repo().release(s, c.input.id, await evidence(c.canonical))).toEqual(released);
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
    const proof = encode64(await open(target.privateKey, c.challenge, releaseContext(c.canonical, 'api') + 'proof'));
    const signature = await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, proof]));
    await expect(repo().finish(s, c.input.id, encode64(crypto.getRandomValues(new Uint8Array(32))), signature)).rejects.toThrow();
    expect(await repo().finish(s, c.input.id, proof, signature)).toEqual({ completed: true, reviewRequired: true });
    expect(await db().prepare('SELECT revoked FROM browser_sessions').first('revoked')).toBe(1);
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(2);
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('completed');
    await expect(env.CUSTODIAN_TEST.prepare('SELECT * FROM devices').all()).rejects.toThrow();
    await expect(db().prepare('SELECT * FROM recovery_transitions').all()).rejects.toThrow();
});
test('independent custody authorization, wrong target and early cooldown fail closed', async () => {
    const c = await started();
    await env.CUSTODIAN_TEST_TRUST.trust('a', 't', 'v', 'd', null);
    await expect(repo().release(s, c.input.id, await evidence(c.canonical))).rejects.toThrow();
    await expect(repo().release(s, c.input.id, { mode: 'cooldown', confirmerId: null, signature: null, proof: await sign(signing, c.canonical) })).rejects.toThrow();
    const tamper = JSON.stringify({ ...JSON.parse(c.canonical), wrappingKey: await publicKey(signing) });
    const e = await evidence(c.canonical);
    await expect((async () => await env.RECOVERY.release(tamper, e))()).rejects.toThrow();
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
});
test.each(['prepared', 'released'])('cancellation at %s is durable and retryable', async (stage) => {
    const c = await started();
    if (stage === 'released')
        await repo().release(s, c.input.id, await evidence(c.canonical));
    await step('cancel', c.canonical);
    await repo().cancel(s, c.input.id, await cancelAuth(c.canonical));
    await repo().cancel(s, c.input.id, await cancelAuth(c.canonical));
    await expect(repo().release(s, c.input.id, await evidence(c.canonical))).rejects.toThrow();
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('cancelled');
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
});
test('partial RPC failure resumes without a second share or premature activation', async () => {
    const c = await started(), e = await evidence(c.canonical);
    const rpc = env.RECOVERY;
    const failing = recoveryRepository(db(), { ...env, RECOVERY: { key: () => rpc.key(), enroll: (a, b) => rpc.enroll(a, b), prepare: (a) => rpc.prepare(a), cancel: (a, b) => rpc.cancel(a, b), complete: (a, p, s) => rpc.complete(a, p, s), release: async (a, b) => { await rpcData(rpc.release(a, b)); throw new Error('synthetic_response_loss'); } } });
    await expect(failing.release(s, c.input.id, e)).rejects.toThrow('synthetic_response_loss');
    expect(await db().prepare('SELECT state FROM recovery_sagas').first('state')).toBe('confirmed');
    const first = await env.CUSTODIAN_TEST.prepare('SELECT release FROM recovery_sagas').first('release');
    const r = await repo().release(s, c.input.id, e);
    expect(JSON.stringify(r.custodian)).toBe(first);
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
});
test('aged no-device case needs independent account verification and succeeds after cooldown', async () => {
    const m = await enrolled(), now = Math.floor(Date.now() / 1000);
    const c = { version: 1, id: crypto.randomUUID(), packageId: m.packageId, accountId: 'a', tenantId: 't', vaultId: 'v', keyEpoch: 1, targetDeviceId: random(), signingKey: await publicKey(targetSigning), wrappingKey: await publicKey(target), createdAt: now - 90000, notBefore: now - 3600, expiresAt: now + 3600, nonce: crypto.randomUUID() };
    const canonical = JSON.stringify(c), proof = encode64(crypto.getRandomValues(new Uint8Array(32)));
    const { digest } = await import('../shared/contracts.ts');
    const challenge = await seal(c.wrappingKey, Uint8Array.from(atob(proof), v => v.charCodeAt(0)), releaseContext(canonical, 'api') + 'proof');
    await db().prepare("INSERT INTO recovery_sagas(id,tenant_id,vault_id,account_id,package_id,canonical,request_digest,session_digest,state,not_before,expires_at,proof_digest,challenge) VALUES(?,'t','v','a',?,?,?,'browser','prepared',?,?,?,?)").bind(c.id, m.packageId, canonical, await digest(canonical), c.notBefore, c.expiresAt, await digest(proof), JSON.stringify(challenge)).run();
    await env.RECOVERY.prepare(canonical);
    const verifier = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    await trust().verifier('a', await publicKey(verifier));
    await env.CUSTODIAN_TEST_TRUST.verifier('a', await publicKey(verifier));
    const e: RecoveryEvidence = { mode: 'cooldown', confirmerId: null, signature: null, proof: await sign(verifier, JSON.stringify(['AgentKeychain-recovery-account-verified-v1', canonical])) };
    await db().prepare("UPDATE devices SET active=0 WHERE id='d'").run();
    const release = await repo().release(s, c.id, e);
    expect(joinRecoveryKey(await open(target.privateKey, release.api, releaseContext(canonical, 'api')), await open(target.privateKey, release.custodian, releaseContext(canonical, 'custodian')))).toEqual(recoveryKey);
    await repo().finish(s, c.id, proof, await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', canonical, proof])));
    expect(await db().prepare('SELECT count(*) n FROM devices WHERE active=1').first('n')).toBe(1);
});
test('revoked confirming device after release prevents activation', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    await db().prepare("UPDATE devices SET active=0 WHERE id='d'").run();
    const proof = encode64(await open(target.privateKey, c.challenge, releaseContext(c.canonical, 'api') + 'proof'));
    await expect(repo().finish(s, c.input.id, proof, await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, proof])))).rejects.toThrow();
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
});
test('completion response loss resumes activating saga, and cross-account access is 404', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    await expect(repo().detail({ ...s, account_id: 'foreign' }, c.input.id)).rejects.toThrow('not_found');
    const rpc = env.RECOVERY;
    const failing = recoveryRepository(db(), { ...env, RECOVERY: { key: () => rpc.key(), enroll: (a, b) => rpc.enroll(a, b), prepare: (a) => rpc.prepare(a), release: (a, b) => rpc.release(a, b), cancel: (a, b) => rpc.cancel(a, b), complete: async (a, p, s) => { await rpcData(rpc.complete(a, p, s)); throw new Error('synthetic_loss'); } } });
    const proof = encode64(await open(target.privateKey, c.challenge, releaseContext(c.canonical, 'api') + 'proof')), signature = await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, proof]));
    await expect(failing.finish(s, c.input.id, proof, signature)).rejects.toThrow('synthetic_loss');
    expect(await db().prepare('SELECT state FROM recovery_sagas').first('state')).toBe('activating');
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(2);
    expect(await repo().cancel(s, c.input.id)).toEqual({ cancelled: false, state: 'activating' });
    await repo().finish(s, c.input.id, proof, signature);
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(2);
});
test('cancel tombstone survives delayed prepare after API-to-custodian interruption', async () => {
    const m = await enrolled(), now = Math.floor(Date.now() / 1000);
    const c = { version: 1, id: crypto.randomUUID(), packageId: m.packageId, accountId: 'a', tenantId: 't', vaultId: 'v', keyEpoch: 1, targetDeviceId: random(), signingKey: await publicKey(targetSigning), wrappingKey: await publicKey(target), createdAt: now, notBefore: now + 86400, expiresAt: now + 172800, nonce: crypto.randomUUID() };
    const canonical = JSON.stringify(c);
    await env.RECOVERY.cancel(canonical, await cancelAuth(canonical));
    await expect((async () => await env.RECOVERY.prepare(canonical))()).rejects.toThrow();
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('cancelled');
});
test('neither operator key can decrypt the other encrypted share', async () => {
    const m = await enrolled();
    await expect((async () => await env.RECOVERY_KEYS!.rewrap(m.apiKeyId, m.custodianShare, packageContext(m, 'custodian'), await publicKey(target), 'wrong-party'))()).rejects.toThrow();
    await expect((async () => await env.CUSTODIAN_TEST_TRUST.rewrap(m.custodianKeyId, m.apiShare, packageContext(m, 'api'), await publicKey(target), 'wrong-party'))()).rejects.toThrow();
});
test('recovery keyring supports explicit active-key rotation while retaining old decrypt key ID', async () => {
    const { recoveryKeyring } = await import('../shared/recovery-keyring.ts');
    const { digest } = await import('../shared/contracts.ts');
    const first = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    const next = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    const firstId = await digest(await publicKey(first)), nextId = await digest(await publicKey(next));
    const ring = await recoveryKeyring(new Map([[firstId, first], [nextId, next]]), nextId);
    expect((await ring.key()).keyId).toBe(nextId);
    const share = crypto.getRandomValues(new Uint8Array(32)), old = await seal(await publicKey(first), share, 'source');
    const wrapped = await ring.rewrap(firstId, old, 'source', await publicKey(target), 'target');
    expect(await open(target.privateKey, wrapped, 'target')).toEqual(share);
    await expect(ring.rewrap('unknown', old, 'source', await publicKey(target), 'target')).rejects.toThrow('unknown_key_id');
});
test('expired custodian case cannot prepare or release', async () => {
    const m = await enrolled(), now = Math.floor(Date.now() / 1000);
    const c = { version: 1, id: crypto.randomUUID(), packageId: m.packageId, accountId: 'a', tenantId: 't', vaultId: 'v', keyEpoch: 1, targetDeviceId: random(), signingKey: await publicKey(targetSigning), wrappingKey: await publicKey(target), createdAt: now - 172800, notBefore: now - 86400, expiresAt: now - 1, nonce: crypto.randomUUID() };
    const canonical = JSON.stringify(c);
    await expect((async () => await env.RECOVERY.prepare(canonical))()).rejects.toThrow('expired');
    await expect((async () => await env.RECOVERY.release(canonical, await evidence(canonical)))()).rejects.toThrow();
});
test('new recovery epoch invalidates an old case independently at both operators', async () => {
    const c = await started();
    const m = JSON.parse((await db().prepare('SELECT canonical FROM recovery_packages_v1').first('canonical')) as string) as RecoveryManifest;
    m.packageId = crypto.randomUUID();
    m.keyEpoch = 2;
    const keys = await repo().keys();
    const [a, b] = splitRecoveryKey(crypto.getRandomValues(new Uint8Array(32)));
    m.apiShare = await seal(keys.api.publicKey, a, packageContext(m, 'api'));
    m.custodianShare = await seal(keys.custodian.publicKey, b, packageContext(m, 'custodian'));
    const canonical = JSON.stringify(m);
    await repo().enroll({ ...ctx, nonce: crypto.randomUUID() }, canonical, await sign(signing, canonical));
    await expect(repo().release(s, c.input.id, await evidence(c.canonical))).rejects.toThrow();
    await expect((async () => await env.RECOVERY.release(c.canonical, await evidence(c.canonical)))()).rejects.toThrow();
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
});
test('activation intent prevents cancellation before custody completion', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const rpc = env.RECOVERY;
    const interrupted = recoveryRepository(db(), { ...env, RECOVERY: { key: () => rpc.key(), enroll: (a, b) => rpc.enroll(a, b), prepare: (a) => rpc.prepare(a), release: (a, b) => rpc.release(a, b), cancel: (a, b) => rpc.cancel(a, b), complete: async () => { throw new Error('synthetic_unavailable'); } } });
    const proof = encode64(await open(target.privateKey, c.challenge, releaseContext(c.canonical, 'api') + 'proof')), signature = await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, proof]));
    await expect(interrupted.finish(s, c.input.id, proof, signature)).rejects.toThrow('synthetic_unavailable');
    await step('cancel', c.canonical);
    await repo().cancel(s, c.input.id, await cancelAuth(c.canonical));
    expect((await repo().detail(s, c.input.id)).state).toBe('activating');
    await repo().finish(s, c.input.id, proof, signature);
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(2);
});
test.each([1, 0])('start rejects existing target identity, active=%s', async (active) => {
    const m = await enrolled(), id = random();
    await db().prepare('INSERT INTO devices VALUES(?,?,?,?,?)').bind('t', id, 'a', await publicKey(targetSigning), active).run();
    const input = { id: crypto.randomUUID(), packageId: m.packageId, targetDeviceId: id, signingKey: await publicKey(targetSigning), wrappingKey: await publicKey(target), nonce: crypto.randomUUID() };
    await step('start', JSON.stringify(input));
    await expect(repo().start(s, input)).rejects.toThrow();
    expect(await env.CUSTODIAN_TEST.prepare('SELECT count(*) n FROM recovery_sagas').first('n')).toBe(0);
});
test('activation failure after custody release rolls back and repair/retry converges', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const proof = encode64(await open(target.privateKey, c.challenge, releaseContext(c.canonical, 'api') + 'proof')), signature = await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, proof]));
    await db().exec("CREATE TRIGGER fail_activation BEFORE INSERT ON device_keys BEGIN SELECT RAISE(ABORT,'synthetic_activation_failure'); END");
    await expect(repo().finish(s, c.input.id, proof, signature)).rejects.toThrow();
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('released');
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
    await db().exec('DROP TRIGGER fail_activation');
    await repo().finish(s, c.input.id, proof, signature);
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('completed');
});
test('custody cancel needs independent exact signed authorization', async () => {
    const c = await started();
    await expect((async () => await env.RECOVERY.cancel(c.canonical))()).rejects.toThrow('unauthorized');
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('prepared');
});
async function targetProof(c: Awaited<ReturnType<typeof started>>) {
    const proof = encode64(await open(target.privateKey, c.challenge, releaseContext(c.canonical, 'api') + 'proof'));
    return { proof, signature: await sign(targetSigning, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, proof])) };
}
const wrappedRPC = () => { const r = env.RECOVERY; return { key: () => r.key(), enroll: (a: string, b: string) => r.enroll(a, b), prepare: (a: string) => r.prepare(a), release: (a: string, b: RecoveryEvidence) => r.release(a, b), cancel: (a: string, b?: CancelAuthorization) => r.cancel(a, b), complete: (a: string, p: string, s: string) => r.complete(a, p, s) }; };
test.each(['before_main', 'after_main', 'before_custody', 'after_custody', 'before_final', 'after_final'])('finish crash at %s retries to one completed outcome', async (stage) => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const p = await targetProof(c), rpc = wrappedRPC();
    if (stage === 'before_main')
        await db().exec("CREATE TRIGGER injected BEFORE UPDATE OF state ON recovery_sagas WHEN NEW.state='activating' BEGIN SELECT RAISE(ABORT,'injected'); END");
    if (stage === 'before_final')
        await db().exec("CREATE TRIGGER injected BEFORE UPDATE OF state ON recovery_sagas WHEN NEW.state='completed' BEGIN SELECT RAISE(ABORT,'injected'); END");
    const interrupted = recoveryRepository(db(), { ...env, RECOVERY: { ...rpc, complete: async (a, p, s) => {
                if (stage === 'after_main' || stage === 'before_custody')
                    throw new Error('injected');
                await rpcData(rpc.complete(a, p, s));
                if (stage === 'after_custody')
                    throw new Error('injected');
            } } });
    if (stage === 'after_final') {
        await interrupted.finish(s, c.input.id, p.proof, p.signature);
    }
    else
        await expect(interrupted.finish(s, c.input.id, p.proof, p.signature)).rejects.toThrow('injected');
    const state = await db().prepare('SELECT state FROM recovery_sagas').first('state');
    if (state === 'activating' || state === 'completed')
        expect(await repo().cancel(s, c.input.id)).toEqual({ cancelled: false, state });
    if (stage === 'before_main' || stage === 'before_final')
        await db().exec('DROP TRIGGER injected');
    await repo().finish(s, c.input.id, p.proof, p.signature);
    await repo().finish(s, c.input.id, p.proof, p.signature);
    expect(await db().prepare('SELECT state FROM recovery_sagas').first('state')).toBe('completed');
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('completed');
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(2);
});
test('concurrent finish/cancel chooses exactly one terminal outcome', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const p = await targetProof(c);
    await step('cancel', c.canonical);
    await Promise.allSettled([repo().finish(s, c.input.id, p.proof, p.signature), repo().cancel(s, c.input.id, await cancelAuth(c.canonical))]);
    const state = await db().prepare('SELECT state FROM recovery_sagas').first('state');
    if (state === 'activating')
        await repo().finish(s, c.input.id, p.proof, p.signature);
    if (state === 'cancelled')
        await repo().cancel(s, c.input.id);
    const final = await db().prepare('SELECT state FROM recovery_sagas').first('state');
    expect(['completed', 'cancelled']).toContain(final);
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe(final);
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(final === 'completed' ? 2 : 1);
});
test.each(['request', 'recovery'])('target %s collision rejected including historical recovery', async (kind) => {
    const c = await started();
    if (kind === 'recovery') {
        await step('cancel', c.canonical);
        await repo().cancel(s, c.input.id, await cancelAuth(c.canonical));
    }
    const id = kind === 'recovery' ? c.input.targetDeviceId : random();
    if (kind === 'request')
        await db().prepare("INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at,state) VALUES('request','code','verify','test',?,?,?,'other',0,'denied')").bind(id, await publicKey(targetSigning), await publicKey(target)).run();
    const input = { ...c.input, id: crypto.randomUUID(), targetDeviceId: id, nonce: crypto.randomUUID() };
    await step('start', JSON.stringify(input));
    await expect(repo().start(s, input)).rejects.toThrow('idempotency_conflict');
});
test('target collision after release prevents activation and repeated retries stay closed', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const p = await targetProof(c);
    await db().prepare('INSERT INTO devices VALUES(?,?,?,?,0)').bind('t', c.input.targetDeviceId, 'a', await publicKey(targetSigning)).run();
    for (let i = 0; i < 2; i++)
        await expect(repo().finish(s, c.input.id, p.proof, p.signature)).rejects.toThrow('idempotency_conflict');
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('released');
    expect(await db().prepare('SELECT state FROM recovery_sagas').first('state')).toBe('released');
});
test.each(['wrong_signature', 'wrong_case', 'wrong_action', 'expired', 'independent_denial'])('custody rejects %s cancel authorization', async (kind) => {
    const c = await started();
    const a = await cancelAuth(c.canonical);
    if (kind === 'wrong_signature')
        a.signature = await sign(targetSigning, cancelMessage(c.canonical, a));
    if (kind === 'wrong_case')
        a.signature = await sign(signing, cancelMessage(JSON.stringify({ ...JSON.parse(c.canonical), nonce: 'other' }), a));
    if (kind === 'wrong_action')
        Object.assign(a, { action: 'complete' });
    if (kind === 'expired') {
        a.expiresAt = Math.floor(Date.now() / 1000) - 1;
        a.signature = await sign(signing, cancelMessage(c.canonical, a));
    }
    if (kind === 'independent_denial')
        await env.CUSTODIAN_TEST_TRUST.trust('a', 't', 'v', 'd', null);
    await expect((async () => await env.RECOVERY.cancel(c.canonical, a))()).rejects.toThrow('unauthorized');
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('prepared');
});
test('cancel nonce cannot authorize a second case; exact committed retry is idempotent', async () => {
    const c = await started(), a = await cancelAuth(c.canonical);
    await env.RECOVERY.cancel(c.canonical, a);
    await env.RECOVERY.cancel(c.canonical, a);
    const canonical = JSON.stringify({ ...JSON.parse(c.canonical), id: crypto.randomUUID(), nonce: crypto.randomUUID() });
    const reused = { ...a, signature: await sign(signing, cancelMessage(canonical, a)) };
    await expect((async () => await env.RECOVERY.cancel(canonical, reused))()).rejects.toThrow('unauthorized');
    expect(await env.CUSTODIAN_TEST.prepare('SELECT count(*) n FROM recovery_cancellations').first('n')).toBe(1);
});
test('same-tenant foreign account cannot see notifications or acknowledge review', async () => {
    const c = await started(), other = { ...s, account_id: 'other' };
    expect((await repo().notifications(other, 0)).notifications).toEqual([]);
    await expect(repo().review(other, c.input.id)).rejects.toThrow('not_found');
    await expect(repo().cancel(other, c.input.id, await cancelAuth(c.canonical))).rejects.toThrow('not_found');
});
test('cancel delivery failure is durable and exact retry converges', async () => {
    const c = await started();
    await step('cancel', c.canonical);
    const rpc = wrappedRPC();
    const interrupted = recoveryRepository(db(), { ...env, RECOVERY: { ...rpc, cancel: async () => { throw new Error('injected'); } } });
    await expect(interrupted.cancel(s, c.input.id, await cancelAuth(c.canonical))).rejects.toThrow('injected');
    expect((await repo().detail(s, c.input.id)).state).toBe('cancelled');
    await repo().cancel(s, c.input.id);
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('cancelled');
});
test('cancel with lost response retries persisted receipt', async () => {
    const c = await started();
    await step('cancel', c.canonical);
    const rpc = wrappedRPC();
    const interrupted = recoveryRepository(db(), { ...env, RECOVERY: { ...rpc, cancel: async (a, b) => { await rpc.cancel(a, b); throw new Error('injected'); } } });
    await expect(interrupted.cancel(s, c.input.id, await cancelAuth(c.canonical))).rejects.toThrow('injected');
    expect(await repo().cancel(s, c.input.id)).toEqual({ cancelled: true });
});
test('fresh independent authorization repairs cancellation delivery after original expiry', async () => {
    const c = await started();
    await step('cancel', c.canonical);
    const rpc = wrappedRPC();
    const interrupted = recoveryRepository(db(), { ...env, RECOVERY: { ...rpc, cancel: async () => { throw new Error('injected'); } } });
    await expect(interrupted.cancel(s, c.input.id, await cancelAuth(c.canonical))).rejects.toThrow('injected');
    const expired = await cancelAuth(c.canonical);
    expired.expiresAt = 1;
    expired.signature = await sign(signing, cancelMessage(c.canonical, expired));
    await db().prepare('UPDATE recovery_sagas SET cancel_authorization=?').bind(JSON.stringify(expired)).run();
    await expect(repo().cancel(s, c.input.id)).rejects.toThrow('unauthorized');
    await repo().cancel(s, c.input.id, await cancelAuth(c.canonical));
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('cancelled');
});
test('both releases plus both target key proofs are required and audit omits cryptographic material', async () => {
    const c = await started(), p = await targetProof(c);
    await expect(repo().finish(s, c.input.id, p.proof, p.signature)).rejects.toThrow('invalid_transition');
    await repo().release(s, c.input.id, await evidence(c.canonical));
    await expect(repo().finish(s, c.input.id, p.proof, await sign(signing, JSON.stringify(['AgentKeychain-recovery-proof-v1', c.canonical, p.proof])))).rejects.toThrow('invalid_signature');
    expect(await db().prepare('SELECT count(*) n FROM devices').first('n')).toBe(1);
    await repo().finish(s, c.input.id, p.proof, p.signature);
    const audit = JSON.stringify((await db().prepare('SELECT * FROM activity').all()).results);
    for (const material of [p.proof, p.signature, encode64(recoveryKey), encode64(vaultKey), c.input.signingKey, c.input.wrappingKey])
        expect(audit).not.toContain(material);
});
test('custody completion needs target-signed authorization', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const p = await targetProof(c);
    await expect((async () => await env.RECOVERY.complete(c.canonical, p.proof, await sign(signing, c.canonical)))()).rejects.toThrow('unauthorized');
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('released');
});
test('cancel racing from a stale preactivation read returns completed status without mutation', async () => {
    const c = await started();
    await repo().release(s, c.input.id, await evidence(c.canonical));
    const p = await targetProof(c);
    await step('cancel', c.canonical);
    const auth = env.RECOVERY_AUTH!;
    const racing = recoveryRepository(db(), { ...env, RECOVERY_AUTH: { enrollment: (a, b) => auth.enrollment(a, b), authorize: (a, b) => auth.authorize(a, b), complete: (a, p, s) => auth.complete(a, p, s), cancel: async (a, b) => { const valid = await auth.cancel(a, b); await repo().finish(s, c.input.id, p.proof, p.signature); return valid; } } });
    expect(await racing.cancel(s, c.input.id, await cancelAuth(c.canonical))).toEqual({ cancelled: false, state: 'completed' });
    expect(await env.CUSTODIAN_TEST.prepare('SELECT state FROM recovery_sagas').first('state')).toBe('completed');
});
test('restricted recovery starts exact target once, cancels with independent authorization and never grants browser authority', async()=>{
    const m=await enrolled();
    const input={id:crypto.randomUUID(),packageId:m.packageId,targetDeviceId:random(),signingKey:await publicKey(targetSigning),wrappingKey:await publicKey(target),nonce:crypto.randomUUID()};
    const rs={...s,digest:'restricted'};
    await db().prepare("INSERT INTO recovery_sessions(digest,csrf_digest,bootstrap_digest,proof_digest,account_id,tenant_id,vault_id,case_id,request_digest,expires_at) VALUES('restricted','anti','boot','proof','a','t','v',?,?,unixepoch()+600)").bind(input.id,await recoveryAction('start',JSON.stringify(input))).run();
    const c=await repo().start(rs,input);
    expect(c.state).toBe('prepared');
    expect(await db().prepare("SELECT started FROM recovery_sessions WHERE digest='restricted'").first('started')).toBe(1);
    await expect(repo().start(rs,{...input,id:random(),nonce:random()})).rejects.toThrow();
    await expect(repo().cancel(rs,input.id)).rejects.toThrow();
    expect(await repo().cancel(rs,input.id,await cancelAuth(c.canonical))).toEqual({cancelled:true});
    expect(await repo().cancel(rs,input.id,await cancelAuth(c.canonical))).toEqual({cancelled:true});
    expect(await db().prepare("SELECT 1 FROM browser_sessions WHERE digest='restricted'").first()).toBeNull();
});
test('public email recovery completes through target-only HTTP delivery without a browser Passkey or browser share response',async()=>{
    const {createBrowserAuth,emailLookup}=await import('../api-worker/browser-auth.ts');
    const {deviceFetch}=await import('../api-worker/device-http.ts');
    const origin='https://local.invalid';
    const config={origin,rpId:'local.invalid',bootstrapKey:await crypto.subtle.generateKey({name:'HMAC',hash:'SHA-256'},false,['sign','verify']),lookupKey:await crypto.subtle.generateKey({name:'HMAC',hash:'SHA-256'},false,['sign','verify']),emailKey:await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),verifyEmail:async(e:string,p:string)=>['synthetic@example.invalid','other@example.invalid'].includes(e)&&p==='synthetic-independent-proof',trustedSource:async()=> 'synthetic-public-source',recovery:env};
    await db().prepare("INSERT INTO account_emails VALUES('a','synthetic-unread-email',?,1)").bind(await emailLookup(config,'synthetic@example.invalid')).run();
    const m=await enrolled(),input={id:random(),packageId:m.packageId,targetDeviceId:random(),signingKey:await publicKey(targetSigning),wrappingKey:await publicKey(target),nonce:random()};
    const deviceCall=(route:string,body:unknown,headers:Record<string,string>={})=>deviceFetch(new Request(origin+'/v1/devices/'+route,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)}),{...env,MAIN:db(),AUTH_ORIGIN:origin,TRUSTED_AUTH_SOURCE:{resolve:async()=> 'synthetic-public-target'}});
    const prepare = async(t: typeof input, signer: CryptoKeyPair) => {
        const signature=await sign(signer,JSON.stringify(['AgentKeychain-recovery-target-v1',t]));
        expect((await deviceCall('recovery-target-challenge',{target:t,signature},{origin})).status).toBe(401);
        const challenge=await deviceCall('recovery-target-challenge',{target:t,signature});expect(challenge.status).toBe(200);
        const {challengeRef,box}=await challenge.json() as {challengeRef:string;box:Parameters<typeof open>[1]};
        const context='AgentKeychain-recovery-target-possession-v1\0'+challengeRef+'\0'+JSON.stringify(t);
        const browser=await crypto.subtle.generateKey('X25519',true,['deriveBits']) as CryptoKeyPair;
        await expect(open(browser.privateKey,box,context)).rejects.toThrow();
        const proof=encode64(await open(target.privateKey,box,context));
        const body={target:t,signature,challengeRef,proof};
        expect((await deviceCall('recovery-target',{...body,proof:encode64(new Uint8Array(43))})).status).not.toBe(200);
        for(const headers of [{origin}, {'sec-fetch-site':'same-origin'}, {cookie:'browser=synthetic'}] as Record<string,string>[]) {
            expect((await deviceCall('recovery-target',body,headers)).status).toBe(401);
        }
        const prepared=await deviceCall('recovery-target',body);expect(prepared.status).toBe(200);
        expect((await deviceCall('recovery-target',body)).status).not.toBe(200);
        return await prepared.json() as {requestRef:string};
    };
    const substituted={...input,signingKey:await publicKey(signing)};
    await prepare(substituted,signing);
    const {requestRef}=await prepare(input,targetSigning);
    const auth=createBrowserAuth(db(),config);let cookies='',csrf='';
    const remember=(r:Response)=>{cookies=r.headers.getSetCookie().map(x=>x.split(';')[0]).join('; ');csrf=/__Host-akc_csrf=([^;]+)/.exec(cookies)![1]!;};
    const call=(route:string,body:unknown)=>auth(new Request(origin+'/v1/auth/'+route,{method:'POST',headers:{origin,cookie:cookies,'x-csrf-token':csrf,'content-type':'application/json'},body:JSON.stringify(body)}));
    await db().batch([db().prepare("INSERT INTO accounts VALUES('other')"),db().prepare("INSERT INTO tenants VALUES('other-tenant')"),db().prepare("INSERT INTO memberships VALUES('other-tenant','other',1)"),db().prepare("INSERT INTO vaults VALUES('other-tenant','other-vault',0)"),db().prepare("INSERT INTO account_emails VALUES('other','synthetic-unread-email',?,1)").bind(await emailLookup(config,'other@example.invalid'))]);
    remember(await auth(new Request(origin+'/v1/auth/bootstrap')));
    const browserSigning=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;
    const browserWrapping=await crypto.subtle.generateKey('X25519',true,['deriveBits']) as CryptoKeyPair;
    const browserTarget={...input,signingKey:await publicKey(browserSigning),wrappingKey:await publicKey(browserWrapping)};
    for(const extra of [{}, {requestRef}]) {
        expect((await call('recovery/verify',{email:'synthetic@example.invalid',proof:'synthetic-independent-proof',target:browserTarget,...extra})).status).not.toBe(200);
    }
    expect((await call('recovery/start',browserTarget)).status).not.toBe(200);
    expect(await db().prepare('SELECT count(*) n FROM recovery_sagas').first('n')).toBe(0);
    const foreign=await call('recovery/verify',{email:'other@example.invalid',proof:'synthetic-independent-proof',requestRef});expect(foreign.status).toBe(200);remember(foreign);
    expect((await call('recovery/start',{})).status).toBe(401);
    expect(await db().prepare('SELECT count(*) n FROM recovery_sagas').first('n')).toBe(0);
    remember(await auth(new Request(origin+'/v1/auth/bootstrap')));
    const verified=await call('recovery/verify',{email:'synthetic@example.invalid',proof:'synthetic-independent-proof',requestRef});expect(verified.status).toBe(200);remember(verified);
    expect((await call('recovery/start',input)).status).not.toBe(200);
    expect((await call('recovery/cancel',{id:input.id,confirmed:true,authorization:{}})).status).not.toBe(200);
    const start=await call('recovery/start',{});expect(start.status).toBe(200);assertSafeView(await start.clone().json());expect(await start.json()).toEqual({id:input.id,state:'prepared',reviewRequired:true});
    expect((await call('recovery/status',{id:random()})).status).toBe(401);
    expect((await call('recovery/release',{id:input.id,evidence:{}})).status).toBe(404);
    const targetCall=async(route:string,extra:Record<string,unknown>={})=>{const body={requestRef,...extra};return deviceCall(route,{...body,signature:await sign(targetSigning,JSON.stringify(['AgentKeychain-recovery-target-call-v1',route,body]))});};
    const detail=await targetCall('recovery-target-status');expect(detail.status).toBe(200);const c=await detail.json() as {canonical:string;challenge:Parameters<typeof open>[1]};
    expect((await deviceCall('recovery-target-status',{requestRef,signature:await sign(signing,'wrong')})).status).toBe(401);
    const early=await targetCall('recovery-target-release',{evidence:{mode:'cooldown',confirmerId:null,signature:null,proof:await sign(signing,'early')}});expect(early.status).not.toBe(200);
    for(const route of ['recovery-target-status','recovery-target-release','recovery-target-finish']) {
        const body={requestRef,...(route.endsWith('release')?{evidence:{}}:route.endsWith('finish')?{proof:'fake',completionSignature:'fake'}:{})};
        expect((await deviceCall(route,{...body,signature:await sign(browserSigning,JSON.stringify(['AgentKeychain-recovery-target-call-v1',route,body]))})).status).not.toBe(200);
    }
    const released=await targetCall('recovery-target-release',{evidence:await evidence(c.canonical)});expect(released.status).toBe(200);
    const delivery=await released.json() as {api:Parameters<typeof open>[1];custodian:Parameters<typeof open>[1];wrappedVDK:string};
    for(const party of ['api','custodian'] as const) await expect(open(browserWrapping.privateKey,delivery[party],releaseContext(c.canonical,party))).rejects.toThrow();
    const a=await open(target.privateKey,delivery.api,releaseContext(c.canonical,'api'));
    const b=await open(target.privateKey,delivery.custodian,releaseContext(c.canonical,'custodian'));
    await expect(unwrapVaultKey(joinRecoveryKey(a,crypto.getRandomValues(new Uint8Array(32))),delivery.wrappedVDK,vaultKeyContext(m))).rejects.toThrow();
    expect(await unwrapVaultKey(joinRecoveryKey(a,b),delivery.wrappedVDK,vaultKeyContext(m))).toEqual(vaultKey);
    const proof=encode64(await open(target.privateKey,c.challenge,releaseContext(c.canonical,'api')+'proof'));
    const finished=await targetCall('recovery-target-finish',{proof,completionSignature:await sign(targetSigning,JSON.stringify(['AgentKeychain-recovery-proof-v1',c.canonical,proof]))});expect(finished.status).toBe(200);
    expect((await call('recovery/status',{id:input.id})).status).toBe(401);
    expect(await db().prepare("SELECT count(*) n FROM browser_sessions WHERE revoked=0").first('n')).toBe(0);
    expect(await db().prepare('SELECT state FROM recovery_sagas WHERE id=?').bind(input.id).first('state')).toBe('completed');
});

test('recovery and account notification Web views expose bounded safe persisted metadata',async()=>{
    const c=await started();
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const web=webRepository(db(),{recovery:env} as unknown as import('../api-worker/browser-auth.ts').BrowserConfig,s);
    assertSafeView(await web.query({view:'recovery',id:c.input.id}));
    for(let i=0;i<25;i++) await db().prepare("INSERT INTO recovery_notifications(case_id,tenant_id,account_id,event) VALUES(?,'t','a','started')").bind(c.input.id).run();
    await db().prepare("INSERT INTO recovery_notifications(case_id,tenant_id,account_id,event) VALUES(?,'t','foreign','cancelled')").bind(c.input.id).run();
    const account=await web.query({view:'account'}) as {notifications:{event:string;createdAt:number}[]};
    assertSafeView(account);expect(account.notifications).toHaveLength(20);
    expect(account.notifications.every(n=>n.event==='started' && n.createdAt>0)).toBe(true);
});
test('RPC data ownership releases successful resources even when a later operation throws',async()=>{
    const {rpcData}=await import('../shared/rpc-data.ts');
    let disposed=0;
    const value={nested:{state:'released'},[Symbol.dispose](){disposed++;}};
    const result=await rpcData(Promise.resolve(value));
    expect(disposed).toBe(1);expect(result.nested).toEqual({state:'released'});
    expect(Symbol.dispose in result).toBe(false);
    await expect((async()=>{await rpcData(Promise.resolve(value));throw new Error('later failure');})()).rejects.toThrow('later failure');
    expect(disposed).toBe(2);
    await expect(rpcData(Promise.resolve({bad:()=>{},[Symbol.dispose](){disposed++;}}))).rejects.toThrow();
    expect(disposed).toBe(3);
});

test('device web status follows scoped backend progress and vault availability',async()=>{
    await db().prepare("INSERT INTO device_keys(tenant_id,device_id,wrapping_key) VALUES('t','d',?)").bind(await publicKey(target)).run();
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const web=webRepository(db(),{} as import('../api-worker/browser-auth.ts').BrowserConfig,s);
    const status=async()=>{const r=await web.query({view:'device',id:'d'}) as {status:string};assertSafeView(r);return r.status;};
    expect(await status()).toBe('waiting');
    await db().prepare("INSERT INTO device_sync_progress VALUES('t','v','d',unixepoch(),0)").run();
    expect(await status()).toBe('current');
    expect((await web.query({view:'status'}) as {status:string}).status).toBe('current');
    await db().prepare("UPDATE vaults SET sequence=1 WHERE id='v'").run();
    expect(await status()).toBe('updating');
    await db().prepare("UPDATE device_sync_progress SET last_seen=unixepoch()-301").run();
    expect(await status()).toBe('stale');
    await db().prepare("UPDATE vault_devices SET active=0 WHERE device_id='d'").run();
    expect(await status()).toBe('paused');
    await db().prepare("DELETE FROM device_sessions WHERE device_id='d'").run();
    await db().prepare("DELETE FROM vault_devices WHERE device_id='d'").run();
    expect(await status()).toBe('unavailable');
    await db().prepare("UPDATE devices SET active=0 WHERE id='d'").run();
    expect(await status()).toBe('removed');
    expect((await web.query({view:'status'}) as {status:string}).status).toBe('waiting');
});

test('web cancellation resolves only same-account confirmation and still requires exact step-up',async()=>{
    const c=await started();
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const {digest}=await import('../shared/contracts.ts');
    const web=webRepository(db(),{recovery:env} as unknown as import('../api-worker/browser-auth.ts').BrowserConfig,s);
    const view=await web.query({view:'recovery',id:c.input.id}) as {cancelRef:string};assertSafeView(view);
    const confirmation=random();
    await db().prepare("INSERT INTO recovery_cancel_confirmations VALUES(?,?,'a','t',?,unixepoch()+300)").bind(await digest(confirmation),c.input.id,JSON.stringify(await cancelAuth(c.canonical))).run();
    await expect(web.execute(view.cancelRef,random())).rejects.toThrow('approval_required');
    await expect(web.execute(view.cancelRef,confirmation)).rejects.toThrow('approval_required');
    await step('cancel',c.canonical);
    const result=await web.execute(view.cancelRef,confirmation);assertSafeView(result);
    expect(result).toMatchObject({id:c.input.id,state:'cancelled'});
    assertSafeView(await web.query({view:'recovery',id:c.input.id}));
});
