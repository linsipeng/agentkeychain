import type { DeviceContext } from '../api-worker/auth.ts';
import { syntheticSigner } from './synthetic-signer.ts';
const checkpointSigner = await syntheticSigner();
const createRepository = (db: D1Database, ctx: DeviceContext) => repository(db, ctx, checkpointSigner);
import { beforeEach, expect, test } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, reset } from 'cloudflare:test';
import { createRepository as repository } from '../api-worker/repository.ts';
import { authenticate } from '../api-worker/auth.ts';
import { canonicalOperation, type ManagedOperation } from '../../src/cloud/protocol.ts';
import { digest, approvalDigest, proofBytes } from '../shared/contracts.ts';
const db = () => env.MAIN;
let privateKey: CryptoKey;
let publicKey: string;
let token = crypto.randomUUID();
const op = (extra: Partial<ManagedOperation> = {}): ManagedOperation => ({ protocolVersion: 2, vaultId: 'v', deviceId: 'd', objectId: 'o', operationId: crypto.randomUUID(), kind: 'put', generation: 1, keyEpoch: 1, envelope: { nonce: btoa('n'.repeat(24)), ciphertext: btoa('c'.repeat(16)) }, approvalRef: null, ...extra });
async function sign(bytes: string) { return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(bytes))))); }
async function signed(operation: ManagedOperation) { const canonical = canonicalOperation(operation); return { canonical, signature: await sign(canonical) }; }
async function context(vault = 'v', body = '', path = `/v1/vaults/${vault}/sync/push`) {
    const nonce = crypto.randomUUID(), sessionDigest = await digest(token), timestamp = Math.floor(Date.now()/1000);
    const request = new Request('https://local.invalid' + path, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'x-device-timestamp': String(timestamp), 'x-device-nonce': nonce, 'x-device-proof': await sign(proofBytes('POST', path, await digest(body), nonce, sessionDigest, timestamp)) } });
    return authenticate(db(), request, vault, body);
}
async function push(operation = op()) { const s = await signed(operation); return createRepository(db(), await context(operation.vaultId, JSON.stringify(s))).push(s); }
async function count(table: string) {
    return (await db().prepare(`SELECT count(*) AS n FROM ${table}`).first<{
        n: number;
    }>())!.n;
}
beforeEach(async () => {
    token = crypto.randomUUID();
    await reset();
    await applyD1Migrations(db(), env.MIGRATIONS);
    const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    privateKey = keys.privateKey;
    publicKey = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))));
    await db().batch([
        db().prepare("INSERT INTO accounts VALUES ('a'),('b')"), db().prepare("INSERT INTO tenants VALUES ('t'),('u')"),
        db().prepare("INSERT INTO memberships VALUES ('t','a',1),('u','b',1)"),
        db().prepare("INSERT INTO vaults VALUES ('t','v',0),('t','v2',0),('u','foreign',0)"),
        db().prepare("INSERT INTO devices VALUES ('t','d','a',?,1),('u','e','b',?,1)").bind(publicKey, publicKey),
        db().prepare("INSERT INTO vault_devices VALUES ('t','v','d',1),('t','v2','d',1),('u','foreign','e',1)"),
        db().prepare("INSERT INTO device_sessions VALUES (?,'t','v','d','a',unixepoch()+600,1)").bind(await digest(token)),
    ]);
});
test('concurrent identical retry yields exact receipt; conflicting retry cannot mutate history', async () => {
    const operation = op();
    const receipts = await Promise.all([push(operation), push(operation)]);
    expect(receipts[0]).toEqual(receipts[1]);
    expect(await count('versions')).toBe(1);
    expect(await count('audit')).toBe(1);
    await expect(push({ ...operation, objectId: 'changed' })).rejects.toThrow('idempotency_conflict');
    expect(await count('versions')).toBe(1);
});
test('acceptance rechecks revocation after proof verification, including retries', async () => {
    const s = await signed(op());
    const ctx = await context('v', JSON.stringify(s));
    await db().prepare("UPDATE devices SET active=0 WHERE tenant_id='t' AND id='d'").run();
    await expect(createRepository(db(), ctx).push(s)).rejects.toThrow('not_found');
    expect(await count('versions')).toBe(0);
});
test('pinned device public key cannot be changed or deleted', async () => {
    await expect(db().prepare("UPDATE devices SET public_key='changed' WHERE id='d'").run()).rejects.toThrow();
    await expect(db().prepare("DELETE FROM devices WHERE id='d'").run()).rejects.toThrow();
});
test('two vault sequences are independent and session cannot select other vault or tenant', async () => {
    await push();
    await expect(context('v2')).rejects.toThrow('not_found');
    await expect(context('foreign')).rejects.toThrow('not_found');
    token = crypto.randomUUID();
    await db().prepare("INSERT INTO device_sessions VALUES (?,'t','v2','d','a',unixepoch()+600,1)").bind(await digest(token)).run();
    expect((await push(op({ vaultId: 'v2' }))).serverSequence).toBe(1);
});
async function approve(operation: ManagedOperation, tenant = 't', vault = 'v', expires = Math.floor(Date.now()/1000)+600) {
    await db().prepare('INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,NULL)').bind(tenant, vault, operation.approvalRef, 'a', 'd', operation.kind, operation.objectId, await approvalDigest(canonicalOperation(operation)), expires).run();
}
test('delete/restore are digest-bound, one-use; tombstone and key epoch barriers persist', async () => {
    await push();
    const del = op({ kind: 'delete', envelope: null, approvalRef: 'grant' });
    await expect(push(del)).rejects.toThrow('approval_required');
    await approve(del);
    await push(del);
    await expect(push()).rejects.toThrow('invalid_transition');
    await expect(push(op({ generation: 2 }))).rejects.toThrow('invalid_transition');
    const restore = op({ kind: 'restore', generation: 2, keyEpoch: 2, approvalRef: 'restore' });
    await approve(restore);
    await expect(push({ ...restore, objectId: 'swap' })).rejects.toThrow();
    await push(restore);
    await expect(push(op({ generation: 2, keyEpoch: 1 }))).rejects.toThrow('invalid_transition');
    await expect(push({ ...restore, operationId: 'reuse', generation: 3 })).rejects.toThrow('approval_required');
    expect(await count('versions')).toBe(3);
});
test('trigger failure rolls back nonce, sequence, approval, version, head and audit', async () => {
    await push();
    const del = op({ kind: 'delete', envelope: null, approvalRef: 'grant' });
    await approve(del);
    await db().exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected_failure'); END;");
    const s = await signed(del);
    const ctx = await context('v', JSON.stringify(s));
    const repo = createRepository(db(), ctx);
    await expect(repo.push(s)).rejects.toThrow();
    expect(await count('versions')).toBe(1);
    expect(await count('audit')).toBe(1);
    expect(await count('device_nonces')).toBe(1);
    expect(await db().prepare('SELECT sequence FROM heads').first('sequence')).toBe(1);
    expect(await db().prepare("SELECT sequence FROM vaults WHERE id='v'").first('sequence')).toBe(1);
    expect(await db().prepare("SELECT consumed_sequence FROM approvals WHERE id='grant'").first('consumed_sequence')).toBeNull();
    await db().exec('DROP TRIGGER fail_audit');
    expect((await repo.push(s)).serverSequence).toBe(2);
});
test('pull pagination has no gaps; cursors bound to tenant, vault, device; audit redacted and immutable', async () => {
    for (let i = 0; i < 5; i++)
        await push(op({objectId:'o'+i}));
    let cursor: string | null = null;
    const sequences: number[] = [];
    for (let i = 0; i < 3; i++) {
        const page = await createRepository(db(), await context()).pull(cursor, 2);
        sequences.push(...page.versions.map(v => v.serverSequence));
        cursor = page.nextCursor;
    }
    expect(sequences).toEqual([1, 2, 3, 4, 5]);
    const foreign = btoa(JSON.stringify(['u', 'foreign', 'e', 1]));
    await expect(createRepository(db(), await context()).pull(foreign, 2)).rejects.toThrow('not_found');
    const audit = JSON.stringify((await db().prepare('SELECT * FROM audit').all()).results);
    expect(audit).not.toContain('canonical');
    expect(audit).not.toContain('ciphertext');
    expect(audit).not.toContain(publicKey);
    await expect(db().prepare("UPDATE audit SET action='changed'").run()).rejects.toThrow();
    await expect(db().prepare('DELETE FROM audit').run()).rejects.toThrow();
});
test('private custodian binding is separate and public HTTP stays closed', async () => {
    expect('CUSTODIAN' in env).toBe(false);
    await expect(db().prepare('SELECT * FROM custodian_cases').all()).rejects.toThrow();
    expect(await env.RECOVERY.describe()).toEqual({ component: 'custodian', protocol: 1, recoveryEnabled: true, bindings: ['CUSTODIAN','RECOVERY_AUTH','RECOVERY_KEYS'] });
    expect((await env.RECOVERY.fetch('https://local.invalid/recovery')).status).toBe(404);
});
test.each([
    "UPDATE memberships SET active=0 WHERE tenant_id='t'",
    "UPDATE vault_devices SET active=0 WHERE tenant_id='t' AND vault_id='v'",
    "UPDATE device_sessions SET active=0 WHERE tenant_id='t'",
    "UPDATE device_sessions SET expires_at=0 WHERE tenant_id='t'",
])('all acceptance authorization checks fail closed: %s', async (sql) => {
    const operation = op();
    await push(operation);
    const s = await signed(operation), ctx = await context('v', JSON.stringify(s));
    await db().prepare(sql).run();
    await expect(createRepository(db(), ctx).push(s)).rejects.toThrow('not_found');
    await expect(createRepository(db(), ctx).pull(null, 1)).rejects.toThrow('not_found');
    expect(await count('versions')).toBe(1);
});
test('request proof is bound to method, path, body and nonce; bearer alone is insufficient', async () => {
    const request = new Request('https://local.invalid/v1/vaults/v/sync/push', { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    await expect(authenticate(db(), request, 'v', '')).rejects.toThrow('unauthorized');
    const nonce = 'nonce', sessionDigest = await digest(token), timestamp = Math.floor(Date.now()/1000);
    const headers = { authorization: `Bearer ${token}`, 'x-device-timestamp': String(timestamp), 'x-device-nonce': nonce, 'x-device-proof': await sign(proofBytes('POST', '/v1/vaults/v/sync/push', await digest('original'), nonce, sessionDigest, timestamp)) };
    await expect(authenticate(db(), new Request(request, { headers }), 'v', 'tampered')).rejects.toThrow('invalid_signature');
    const ctx = await context();
    await createRepository(db(), ctx).pull(null, 1);
    await expect(createRepository(db(), ctx).pull(null, 1)).rejects.toThrow('replayed_request');
});
test('foreign approval reference and same-tenant other-vault approval never authorize delete', async () => {
    await push();
    const del = op({ kind: 'delete', envelope: null, approvalRef: 'foreign-grant' });
    await db().prepare("INSERT INTO approvals VALUES ('u','foreign','foreign-grant','b','e','delete','o',?,unixepoch()+600,NULL)").bind(await approvalDigest(canonicalOperation(del))).run();
    await expect(push(del)).rejects.toThrow('approval_required');
    const other = op({ kind: 'delete', envelope: null, approvalRef: 'other-vault' });
    await approve(other, 't', 'v2');
    await expect(push(other)).rejects.toThrow('approval_required');
    expect(await count('versions')).toBe(1);
});
test('expired or changed approval never consumes state', async () => {
    await push();
    const del = op({ kind: 'delete', envelope: null, approvalRef: 'grant' });
    await approve(del,'t','v',0);
    await expect(push(del)).rejects.toThrow('approval_required');
    expect(await db().prepare('SELECT consumed_sequence FROM approvals').first('consumed_sequence')).toBeNull();
});
test('receive-order head ignores device operation naming; signature tampering fails', async () => {
    const first = op({ operationId: 'zzz' }), last = op({ operationId: 'aaa', approvalRef:'update' });
    await push(first);
    await approve(last);
    await push(last);
    expect(await db().prepare('SELECT sequence FROM heads').first('sequence')).toBe(2);
    const s = await signed(op());
    s.canonical = s.canonical.replace('"o"', '"other"');
    await expect(createRepository(db(), await context()).push(s)).rejects.toThrow('invalid_signature');
    expect(await count('versions')).toBe(2);
});
test('pull rejects future cursors, detects missing history, and caps serialized pages', async () => {
    const large = op({ envelope: { nonce: btoa('n'.repeat(24)), ciphertext: btoa('c'.repeat(200000)) } });
    await push(large);
    await push({ ...large, operationId: 'second',objectId:'other' });
    const page = await createRepository(db(), await context()).pull(null, 100);
    expect(page.versions).toHaveLength(1);
    expect(page.hasMore).toBe(true);
    expect(new TextEncoder().encode(JSON.stringify(page)).length).toBeLessThan(512 * 1024);
    const second = await createRepository(db(), await context()).pull(page.nextCursor, 100);
    expect(second.versions[0]!.serverSequence).toBe(2);
    await expect(createRepository(db(), await context()).pull(btoa(JSON.stringify(['t', 'v', 'd', 3])), 2)).rejects.toThrow('invalid_request');
    await db().prepare("UPDATE vaults SET sequence=3 WHERE id='v'").run();
    await expect(createRepository(db(), await context()).pull(second.nextCursor, 2)).rejects.toThrow('internal_error');
});
test('all data-bearing tables reject cross-tenant foreign keys', async () => {
    await push();
    const statements = [
        "INSERT INTO memberships VALUES ('missing','a',1)",
        "INSERT INTO vaults VALUES ('missing','bad',0)",
        "INSERT INTO devices VALUES ('u','bad','a','public',1)",
        "INSERT INTO vault_devices VALUES ('u','foreign','d',1)",
        "INSERT INTO device_sessions VALUES ('bad','u','foreign','e','a',9999999999,1)",
        "INSERT INTO device_nonces VALUES ('bad','u','foreign','e','a','nonce')",
        "INSERT INTO versions VALUES ('u','v',1,'d','x','o','put',1,1,'{}','sig')",
        "INSERT INTO heads VALUES ('u','foreign','o',1)",
        "INSERT INTO idempotency VALUES ('u','foreign','e','x',1,'{}')",
        "INSERT INTO approvals VALUES ('u','foreign','g','a','d','delete','o','digest',9999999999,NULL)",
        "INSERT INTO audit VALUES ('u','foreign',1,'b','e','put')",
        "INSERT INTO checkpoints VALUES ('u','foreign',1,'digest',NULL,'sig')",
        "INSERT INTO recovery_cases VALUES ('u','foreign','case','a','d','pending',0)",
        "INSERT INTO recovery_events VALUES ('u','foreign','case','event','pending')",
    ];
    for (const sql of statements)
        await expect(db().prepare(sql).run(), sql).rejects.toThrow();
});
test('SQLite REPLACE cannot bypass pinned-key or append-only guards', async () => {
    await push();
    await expect(db().prepare("INSERT OR REPLACE INTO devices VALUES ('t','d','a','replacement',1)").run()).rejects.toThrow();
    await expect(db().prepare("INSERT OR REPLACE INTO audit VALUES ('t','v',1,'a','d','delete')").run()).rejects.toThrow();
});
test('real HTTP push, retry, pull and cross-tenant IDs/cursors use authenticated context', async () => {
    const { SELF } = await import('cloudflare:test');
    async function call(path: string, method = 'GET', body = '') {
        const nonce = crypto.randomUUID(), timestamp = Math.floor(Date.now()/1000);
        return SELF.fetch('https://local.invalid' + path, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'x-device-timestamp': String(timestamp), 'x-device-nonce': nonce, 'x-device-proof': await sign(proofBytes(method, path, await digest(body), nonce, await digest(token), timestamp)) }, ...(body ? { body } : {}) });
    }
    const body = JSON.stringify(await signed(op()));
    const receipts = await Promise.all([call('/v1/vaults/v/sync/push', 'POST', body), call('/v1/vaults/v/sync/push', 'POST', body)]);
    expect(receipts.map(r => r.status)).toEqual([200, 200]);
    expect(await receipts[0]!.text()).toBe(await receipts[1]!.text());
    const response = await call('/v1/vaults/v/sync/pull?limit=1');
    expect(response.status).toBe(200);
    const page = await response.json() as {
        versions: unknown[];
        nextCursor: string;
    };
    expect(page.versions).toHaveLength(1);
    for (const path of ['/v1/vaults/foreign/sync/pull', '/v1/vaults/v2/sync/pull', `/v1/vaults/v/sync/pull?cursor=${encodeURIComponent(btoa(JSON.stringify(['u', 'foreign', 'e', 1])))}`]) {
        const result = await call(path);
        expect(result.status).toBe(404);
        expect(await result.json()).toEqual({ error: { code: 'not_found' } });
    }
    const foreignBody = JSON.stringify(await signed(op({ vaultId: 'foreign' })));
    expect((await call('/v1/vaults/v/sync/push', 'POST', foreignBody)).status).toBe(404);
    for (const path of ['/accounts/a', '/tenants/t', '/devices/d', '/approvals/grant', '/audit', '/recovery', '/checkpoints'])
        expect((await call(path)).status).toBe(404);
    expect(await count('versions')).toBe(1);
});
test('colliding tenant/vault/device/operation IDs cannot alias histories or receipts', async () => {
    const originalToken = token;
    const operation = op({ operationId: 'same-operation' });
    await push(operation);
    await db().batch([
        db().prepare("INSERT INTO vaults VALUES ('u','v',0)"),
        db().prepare("INSERT INTO devices VALUES ('u','d','b',?,1)").bind(publicKey),
        db().prepare("INSERT INTO vault_devices VALUES ('u','v','d',1)"),
    ]);
    token = crypto.randomUUID();
    await db().prepare("INSERT INTO device_sessions VALUES (?,'u','v','d','b',unixepoch()+600,1)").bind(await digest(token)).run();
    const foreignContext = await context();
    expect(foreignContext.accountId).toBe('b');
    expect(foreignContext.tenantId).toBe('u');
    await push(operation);
    await push(op({ objectId: 'foreign-object' }));
    const foreign = await createRepository(db(), await context()).pull(null, 100);
    expect(foreign.versions).toHaveLength(2);
    token = originalToken;
    const local = await createRepository(db(), await context()).pull(null, 100);
    expect(local.versions).toHaveLength(1);
    expect((await push(operation)).serverSequence).toBe(1);
    await expect(createRepository(db(), await context()).pull(foreign.nextCursor, 100)).rejects.toThrow('not_found');
    expect(await count('versions')).toBe(3);
    expect(await count('audit')).toBe(3);
});
test('concurrent distinct writes allocate contiguous sequences and receive-order head', async () => {
    await push();
    const operations = Array.from({ length: 12 }, (_,i) => op({approvalRef:'update'+i}));
    for(const operation of operations) await approve(operation);
    const receipts = await Promise.all(operations.map(operation => push(operation)));
    expect(receipts.map(r => r.serverSequence).sort((a, b) => a - b)).toEqual(Array.from({ length: 12 }, (_, i) => i + 2));
    const last = receipts.find(r => r.serverSequence === 13)!;
    expect(await db().prepare('SELECT v.operation_id FROM heads h JOIN versions v ON v.tenant_id=h.tenant_id AND v.vault_id=h.vault_id AND v.sequence=h.sequence').first('operation_id')).toBe(last.operationId);
});
test('checkpoint acceptance is atomic and roots bind every exact signed version', async () => {
    const { advanceRoot, genesisRoot, verifyCheckpointPage } = await import('../shared/checkpoints.ts');
    const first = op();
    await push(first);
    const before = await count('sync_checkpoints'), nonceBefore = await count('device_nonces');
    await db().exec("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON sync_checkpoints WHEN NEW.sequence>0 BEGIN SELECT RAISE(ABORT,'injected'); END");
    await expect(push(op({objectId:'other'}))).rejects.toThrow();
    expect(await count('versions')).toBe(1);
    expect(await count('sync_checkpoints')).toBe(before);
    expect(await count('device_nonces')).toBe(nonceBefore);
    await db().exec('DROP TRIGGER fail_checkpoint');
    await push(op({objectId:'other'}));
    const page = await createRepository(db(), await context()).pull(null, 100);
    const root = await genesisRoot('t', 'v');
    const verified = await verifyCheckpointPage(await checkpointSigner.key(), 't', 'v', 0, root, 2, page);
    let expected = root;
    for (const version of page.versions)
        expected = (await advanceRoot(expected, version.serverSequence, version.signed)).root;
    expect(verified.root).toBe(expected);
    const receipt = await push(first);
    expect(JSON.parse(receipt.checkpoint.canonical).sequence).toBe(1);
    await expect(repository(db(), await context(), await syntheticSigner()).pull(null, 100)).rejects.toThrow();
});

test('successful pull records only device-reported processed cursor, not newly delivered data',async()=>{
    await push();
    const first=await createRepository(db(),await context()).pull(null,100);
    expect(await db().prepare("SELECT acknowledged FROM device_sync_progress WHERE tenant_id='t' AND vault_id='v' AND device_id='d'").first('acknowledged')).toBe(0);
    await createRepository(db(),await context()).pull(first.nextCursor,100);
    const progress=await db().prepare("SELECT acknowledged,last_seen FROM device_sync_progress WHERE tenant_id='t' AND vault_id='v' AND device_id='d'").first<{acknowledged:number;last_seen:number}>();
    expect(progress!.acknowledged).toBe(1);expect(progress!.last_seen).toBeGreaterThan(Date.now()/1000-10);
    await expect(createRepository(db(),await context()).pull(btoa(JSON.stringify(['t','v','d',999])),100)).rejects.toThrow();
    expect(await db().prepare("SELECT acknowledged FROM device_sync_progress WHERE tenant_id='t' AND vault_id='v' AND device_id='d'").first('acknowledged')).toBe(1);
});
