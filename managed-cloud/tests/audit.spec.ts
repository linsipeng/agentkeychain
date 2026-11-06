import { assertSafeView } from '../web/src/safe-view.ts';
import { beforeEach, expect, test } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, reset } from 'cloudflare:test';
import { auditRepository, validateAuditEvent } from '../api-worker/audit-repository.ts';
import { syntheticSigner } from './synthetic-signer.ts';
import type { SessionRow } from '../api-worker/browser-repository.ts';
const s = { tenant_id: 't', account_id: 'a' } as SessionRow;
beforeEach(async () => { await reset(); await applyD1Migrations(env.MAIN, env.MIGRATIONS); });
test('strict normalized audit rejects secret-bearing metadata', () => {
    expect(() => validateAuditEvent({ event: 'sync.put', tenant_id: 't', account_id: 'a', device_id: 'd', vault_id: 'v', reference: 'r', metadata: { token: 's' } })).toThrow();
});
test('signed list/detail has explicit verification and immutable records', async () => {
    await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event,reference) VALUES('t','a','approval.pending','r')").run();
    const repo = auditRepository(env.MAIN, await syntheticSigner());
    const page = await repo.list(s, 0, 10, 0);
    expect(page.verification).toBe('verified');
    expect(page.events).toHaveLength(1);
    expect((await repo.detail(s, page.events[0]!.id, 0)).verification).toBe('verified');
    await expect(repo.detail({ ...s, tenant_id: 'foreign' }, page.events[0]!.id, 0)).rejects.toThrow('not_found');
    for (const sql of ["UPDATE activity SET event='approval.denied'", 'DELETE FROM activity', "INSERT OR REPLACE INTO activity(id,tenant_id,account_id,event,reference) VALUES(1,'t','a','approval.pending','r')", 'UPDATE activity_checkpoints SET root=\'bad\'', 'DELETE FROM activity_checkpoints'])
        await expect(env.MAIN.prepare(sql).run()).rejects.toThrow();
    await expect(repo.list(s, 0, 10, 'f'.repeat(32))).rejects.toThrow('not_found');
    expect((await auditRepository(env.MAIN, await syntheticSigner()).list(s, 0, 10, 0)).verification).toBe('failed');
});
test.each(['gap', 'substitution'])('checkpoint verification explicitly reports %s', async (kind) => {
    await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event,reference) VALUES('t','a','approval.pending','r')").run();
    const repo = auditRepository(env.MAIN, await syntheticSigner());
    expect((await repo.list(s, 0, 10, 0)).verification).toBe('verified');
    if (kind === 'gap') {
        await env.MAIN.exec('DROP TRIGGER activity_delete');
        await env.MAIN.prepare('DELETE FROM activity').run();
    }
    else {
        await env.MAIN.exec('DROP TRIGGER activity_update');
        await env.MAIN.prepare("UPDATE activity SET event='approval.denied'").run();
    }
    expect((await repo.list(s, 0, 10, 0)).verification).toBe('failed');
});
test('secret-pattern references are rejected before append and never returned on corruption', async () => {
    await expect(env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event,reference) VALUES('t','a','approval.pending','sk-synthetic-sensitive')").run()).rejects.toThrow('invalid_audit');
    await env.MAIN.exec('DROP TRIGGER activity_redaction');
    await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event,reference) VALUES('t','a','approval.pending','sk-synthetic-sensitive')").run();
    const repo = auditRepository(env.MAIN, await syntheticSigner());
    const page = await repo.list(s, 0, 10, 0);
    expect(page.verification).toBe('failed');
    expect(page.events).toEqual([]);
    expect((await repo.detail(s, (await env.MAIN.prepare('SELECT public_id FROM activity').first('public_id')) as string, 0)).event).toBeNull();
});
test('same-tenant activity is account scoped and public ids hide global gaps', async () => {
    await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES('t','other','approval.pending'),('foreign','other','approval.pending'),('t','a','approval.pending')").run();
    const repo = auditRepository(env.MAIN, await syntheticSigner()), page = await repo.list(s, 0, 10, 0);
    expect(page.events).toHaveLength(1);
    expect(typeof page.events[0]!.id).toBe('string');
    expect(typeof page.nextCursor).toBe('string');
    expect(JSON.stringify(page.checkpoint)).not.toContain('"t",');
});
test('250 account events form pending then cumulative multi-checkpoint chain despite foreign gaps', async () => {
    const statements = [];
    for (let i = 0; i < 250; i++) {
        statements.push(env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES('t','a','approval.pending')"));
        statements.push(env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES('t','other','approval.pending')"));
    }
    await env.MAIN.batch(statements);
    const repo = auditRepository(env.MAIN, await syntheticSigner());
    const first = await repo.list(s, 0, 100, 0);
    expect(first.verification).toBe('pending');
    expect(JSON.parse(first.checkpoint!.canonical)[5]).toBe(100);
    const second = await repo.list(s, first.nextCursor, 100, first.through as string);
    expect(second.verification).toBe('pending');
    const third = await repo.list(s, second.nextCursor, 100, second.through as string);
    expect(third.verification).toBe('verified');
    expect(third.events).toHaveLength(50);
    const cps = (await env.MAIN.prepare("SELECT * FROM activity_checkpoints WHERE account_id='a' ORDER BY through_id").all<{
        count: number;
        previous_id: number;
        through_id: number;
        canonical: string;
    }>()).results;
    expect(cps.map(c => c.count)).toEqual([100, 200, 250]);
    expect(cps[1]!.previous_id).toBe(cps[0]!.through_id);
    expect(cps[2]!.previous_id).toBe(cps[1]!.through_id);
    for (const cp of cps) {
        const v = JSON.parse(cp.canonical);
        expect(typeof v[4]).toBe('string');
        expect(v[3] === 0 || typeof v[3] === 'string').toBe(true);
    }
    await expect(repo.detail({ ...s, account_id: 'other' }, first.events[0]!.id, 0)).rejects.toThrow('not_found');
    await expect(repo.list({ ...s, account_id: 'other' }, first.nextCursor, 100, 0)).rejects.toThrow('not_found');
});
test('concurrent checkpoint creation serializes a single cumulative chain', async () => {
    await env.MAIN.batch(Array.from({ length: 205 }, () => env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES('t','a','approval.pending')")));
    const repo = auditRepository(env.MAIN, await syntheticSigner());
    const pages = await Promise.all(Array.from({ length: 5 }, () => repo.list(s, 0, 100, 0)));
    expect(pages.every(p => p.verification !== 'failed')).toBe(true);
    for (let i = 0; i < 3; i++)
        await repo.list(s, 0, 100, 0);
    expect((await repo.list(s, 0, 100, 0)).verification).toBe('verified');
    expect((await env.MAIN.prepare('SELECT count FROM activity_checkpoints ORDER BY through_id').all<{
        count: number;
    }>()).results.map(c => c.count)).toEqual([100, 200, 205]);
});

test('populated activity and event Web projections recursively exclude sensitive fields',async()=>{
    await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event,reference) VALUES('t','a','approval.pending','r')").run();
    const {webRepository}=await import('../api-worker/web-repository.ts');
    const web=webRepository(env.MAIN,{checkpointSigner:await syntheticSigner()} as import('../api-worker/browser-auth.ts').BrowserConfig,s);
    const page=await web.query({view:'activity'}) as {events:{id:string}[]};
    assertSafeView(page);expect(page.events).toHaveLength(1);
    assertSafeView(await web.query({view:'event',id:page.events[0]!.id}));
});
test('explicit signer rotation retains the original pin and verifies old activity checkpoints',async()=>{
 const old=await syntheticSigner(),next=await syntheticSigner();await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES('t','a','approval.pending')").run();
 expect((await auditRepository(env.MAIN,old).list(s,0,10,0)).verification).toBe('verified');
 await env.MAIN.prepare("INSERT INTO activity(tenant_id,account_id,event) VALUES('t','a','approval.pending')").run();
 const pins=[await old.key(),await next.key()];
 const rotated={...next,publicKeys:async()=>pins};
 expect((await auditRepository(env.MAIN,rotated).list(s,0,10,0)).verification).toBe('verified');
 expect((await auditRepository(env.MAIN,{...next,publicKeys:async()=>[pins[1]!]}).list(s,0,10,0)).verification).toBe('failed');
});
