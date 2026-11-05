import { assertSafeView } from '../web/src/safe-view.ts';
import { beforeEach, expect, test } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, reset } from 'cloudflare:test';
import { approvalRepository, decisionDigest } from '../api-worker/approval-repository.ts';
import type { DeviceContext } from '../api-worker/auth.ts';
import type { SessionRow } from '../api-worker/browser-repository.ts';
import { canonicalOperation } from '../../src/cloud/protocol.ts';
import { syntheticSigner } from './synthetic-signer.ts';
import { createRepository } from '../api-worker/repository.ts';
let key: CryptoKey;
let ctx: DeviceContext;
const s = { digest: 'session', account_id: 'a', tenant_id: 't' } as SessionRow;
const db = () => env.MAIN;
const repo = () => approvalRepository(db());
async function signed(kind: 'put' | 'delete' = 'delete', ref: string | null = 'r') {
    const canonical = canonicalOperation({ protocolVersion: 2, vaultId: 'v', deviceId: 'd', objectId: 'o', operationId: crypto.randomUUID(), kind, generation: 1, keyEpoch: 1, envelope: kind === 'delete' ? null : { nonce: btoa('n'.repeat(24)), ciphertext: btoa('c'.repeat(16)) }, approvalRef: ref });
    return { canonical, signature: btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(canonical))))) };
}
const fresh = () => ({ ...ctx, nonce: crypto.randomUUID() });
async function step(id = 'r', action = 'approve') { const r = await repo().detail(s, id); await db().prepare('UPDATE browser_sessions SET step_up_digest=?,step_up_expires=unixepoch()+300').bind(await decisionDigest(action, r)).run(); }
beforeEach(async () => {
    await reset();
    await applyD1Migrations(db(), env.MIGRATIONS);
    const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    key = pair.privateKey;
    const publicKey = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))));
    await db().batch([db().prepare("INSERT INTO accounts VALUES('a')"), db().prepare("INSERT INTO tenants VALUES('t')"), db().prepare("INSERT INTO memberships VALUES('t','a',1)"), db().prepare("INSERT INTO vaults VALUES('t','v',0)"), db().prepare("INSERT INTO devices VALUES('t','d','a',?,1)").bind(publicKey), db().prepare("INSERT INTO vault_devices VALUES('t','v','d',1)"), db().prepare("INSERT INTO device_sessions VALUES('ds','t','v','d','a',unixepoch()+600,1)"), db().prepare("INSERT INTO browser_sessions(digest,csrf_digest,account_id,tenant_id,absolute_expires) VALUES('session','csrf','a','t',unixepoch()+600)")]);
    ctx = { tenantId: 't', vaultId: 'v', accountId: 'a', deviceId: 'd', publicKey, sessionDigest: 'ds', nonce: crypto.randomUUID(), timestamp: Math.floor(Date.now() / 1000) } as DeviceContext;
});
test('pending exact approval is one-use and sync retry returns original receipt', async () => {
    const signer = await syntheticSigner();
    await createRepository(db(), fresh(), signer).push(await signed('put', null));
    const op = await signed();
    await repo().create(fresh(), op, 300);
    expect((await repo().list(s, 0, 20)).requests).toHaveLength(1);
    await expect(repo().decide(s, 'r', 'approve')).rejects.toThrow();
    await step();
    await repo().decide(s, 'r', 'approve');
    const receipt = await createRepository(db(), fresh(), signer).push(op);
    expect(await createRepository(db(), fresh(), signer).push(op)).toEqual(receipt);
    expect((await repo().detail(s, 'r')).consumed_sequence).toBe(2);
    await expect(repo().decide(s, 'r', 'approve')).rejects.toThrow();
});
test.each(['deny', 'cancel'] as const)('%s prevents grant creation', async (action) => {
    await repo().create(fresh(), await signed(), 300);
    await step('r', action);
    await repo().decide(s, 'r', action);
    await step();
    await expect(repo().decide(s, 'r', 'approve')).rejects.toThrow();
    expect(await db().prepare('SELECT count(*) AS n FROM approvals').first('n')).toBe(0);
});
test('automatic create, changed content, foreign account and nonce reuse fail closed', async () => {
    await expect(repo().create(fresh(), await signed('put', null), 300)).rejects.toThrow();
    const c = fresh(), op = await signed();
    await repo().create(c, op, 300);
    await expect(repo().create(c, op, 300)).rejects.toThrow();
    await expect(repo().create(fresh(), await signed(), 300)).rejects.toThrow();
    await expect(repo().detail({ ...s, account_id: 'other' }, 'r')).rejects.toThrow('not_found');
});
test('concurrent decisions create one grant and consume one step-up', async () => {
    await repo().create(fresh(), await signed(), 300);
    await step();
    const results = await Promise.allSettled([repo().decide(s, 'r', 'approve'), repo().decide(s, 'r', 'approve')]);
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect(await db().prepare('SELECT count(*) n FROM approvals').first('n')).toBe(1);
});
test('update requires exact approval and failures roll back consumption', async () => {
    const signer = await syntheticSigner();
    await createRepository(db(), fresh(), signer).push(await signed('put', null));
    const update = await signed('put', 'r');
    await expect(createRepository(db(), fresh(), signer).push(update)).rejects.toThrow('approval_required');
    await repo().create(fresh(), update, 300);
    await step();
    await repo().decide(s, 'r', 'approve');
    await db().exec("CREATE TRIGGER inject_activity BEFORE INSERT ON activity WHEN NEW.event='sync.put' BEGIN SELECT RAISE(ABORT,'injected'); END;");
    await expect(createRepository(db(), fresh(), signer).push(update)).rejects.toThrow();
    expect((await repo().detail(s, 'r')).consumed_sequence).toBeNull();
    await db().exec('DROP TRIGGER inject_activity');
    expect((await createRepository(db(), fresh(), signer).push(update)).serverSequence).toBe(2);
});
test('revoked requester cannot create pending approval after authentication', async () => {
    const c = fresh(), op = await signed();
    await db().prepare("UPDATE devices SET active=0 WHERE id='d'").run();
    await expect(repo().create(c, op, 300)).rejects.toThrow();
    expect((await repo().list(s, 0, 10)).requests).toHaveLength(0);
});
test('expired pending request is explicit and never produces a grant', async () => {
    const op = await signed();
    const { approvalDigest } = await import('../shared/contracts.ts');
    await db().prepare("INSERT INTO approval_requests(tenant_id,vault_id,id,account_id,device_id,action,object_id,request_digest,expires_at) VALUES('t','v','r','a','d','delete','o',?,0)").bind(await approvalDigest(op.canonical)).run();
    expect((await repo().detail(s, 'r')).state).toBe('expired');
    await step();
    await expect(repo().decide(s, 'r', 'approve')).rejects.toThrow();
    expect((await repo().list(s, 0, 10, 'pending')).requests).toHaveLength(0);
});
test('encrypted summary is device-signed and excluded from browser data', async () => {
    const op = await signed();
    const { approvalDigest } = await import('../shared/contracts.ts');
    const ciphertext = btoa('c'.repeat(48)), nonce = btoa('n'.repeat(12));
    const canonical = JSON.stringify(['AgentKeychain-approval-summary-v1', await approvalDigest(op.canonical), 300, nonce, ciphertext]);
    const signature = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(canonical)))));
    await repo().create(fresh(), op, 300, { ciphertext, nonce, signature });
    const detail = await repo().detail(s, 'r');
    expect(detail.summary_digest).toHaveLength(64);
    expect(JSON.stringify(detail)).not.toContain(ciphertext);
    expect(JSON.stringify(await repo().list(s, 0, 10))).not.toContain(ciphertext);
});
test('creation response loss retries exact request; changed TTL or content conflicts', async () => {
    const op = await signed(), first = await repo().create(fresh(), op, 300);
    expect(await repo().create(fresh(), op, 300)).toEqual(first);
    await expect(repo().create(fresh(), op, 301)).rejects.toThrow('idempotency_conflict');
    await expect(repo().create(fresh(), await signed(), 300)).rejects.toThrow('idempotency_conflict');
    expect(await db().prepare('SELECT count(*) n FROM approval_requests').first('n')).toBe(1);
});
test('same-tenant other account cannot list or decide approvals', async () => {
    await repo().create(fresh(), await signed(), 300);
    const other = { ...s, account_id: 'other' };
    for (const mode of ['all', 'pending', 'recent'] as const)
        expect((await repo().list(other, 0, 20, mode)).requests).toEqual([]);
    for (const action of ['approve', 'deny', 'cancel'] as const)
        await expect(repo().decide(other, 'r', action)).rejects.toThrow('not_found');
});
test('concurrent exact creation retries return one original request', async () => {
    const op = await signed();
    const results = await Promise.all([repo().create(fresh(), op, 300), repo().create(fresh(), op, 300)]);
    expect(results[0]).toEqual(results[1]);
    expect(await db().prepare('SELECT count(*) n FROM approval_requests').first('n')).toBe(1);
});
test('Web opaque approval references are account-bound, step-up-bound, one-use and omit internal fields',async()=>{
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const config={} as import('../api-worker/browser-auth.ts').BrowserConfig;
    await repo().create(fresh(),await signed(),300);
    const web=webRepository(db(),config,s);
    const result=await web.query({view:'request',id:'r'}) as {allowRef:string;denyRef:string};
    expect(JSON.stringify(result)).not.toMatch(/digest|ordinal|canonical|signature|ciphertext/);
    assertSafeView(result);
    for(const view of ['home','requests','requests-recent','devices','status','account']) assertSafeView(await web.query({view}));
    const other=webRepository(db(),config,{...s,account_id:'other'});
    await expect(other.resolve(result.allowRef)).rejects.toThrow('not_found');
    await expect(other.query({view:'request',id:'r'})).rejects.toThrow('not_found');
    await expect(web.execute(result.allowRef)).rejects.toThrow();
    await step();expect(await web.execute(result.allowRef)).toMatchObject({state:'approved'});
    await expect(web.execute(result.allowRef)).rejects.toThrow();
    await expect(web.execute(result.denyRef)).rejects.toThrow();
});
test('Web history returns concurrent versions and deleted current state without envelope data',async()=>{
    const signer=await syntheticSigner();
    await createRepository(db(),fresh(),signer).push(await signed('put',null));
    const removal=await signed();await repo().create(fresh(),removal,300);await step();await repo().decide(s,'r','approve');await createRepository(db(),fresh(),signer).push(removal);
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const config={} as import('../api-worker/browser-auth.ts').BrowserConfig;
    const result=await webRepository(db(),config,s).query({view:'history',id:'o'}) as {versions:{kind:string;current:boolean}[]};
    assertSafeView(result);
    expect(result.versions).toHaveLength(2);expect(result.versions[0]).toMatchObject({kind:'delete',current:true});
    expect(JSON.stringify(result)).not.toMatch(/canonical|envelope|ciphertext|sequence|signature/);
    await expect(webRepository(db(),config,{...s,account_id:'other'}).query({view:'history',id:'o'})).rejects.toThrow('not_found');
});
