import { expect, test } from 'vitest';
import { env } from 'cloudflare:workers';
import { applyD1Migrations, SELF } from 'cloudflare:test';
test('custodian schema is separate and enforces composite references and append-only evidence', async () => {
    const custodian = env.CUSTODIAN;
    await applyD1Migrations(custodian, env.MIGRATIONS);
    await custodian.prepare("INSERT INTO custodian_cases VALUES ('t','v','case','pending')").run();
    await expect(custodian.prepare("INSERT INTO release_evidence VALUES ('u','v','case','event','digest')").run()).rejects.toThrow();
    await custodian.prepare("INSERT INTO release_evidence VALUES ('t','v','case','event','digest')").run();
    await expect(custodian.prepare('DELETE FROM release_evidence').run()).rejects.toThrow();
    await expect(custodian.prepare("UPDATE release_evidence SET evidence_digest='swap'").run()).rejects.toThrow();
    await expect(custodian.prepare("INSERT OR REPLACE INTO release_evidence VALUES ('t','v','case','event','swap')").run()).rejects.toThrow();
    expect('MAIN' in env).toBe(false);
    await expect(custodian.prepare('SELECT * FROM versions').all()).rejects.toThrow();
});
test('default recovery HTTP entrypoint is closed', async () => { expect((await SELF.fetch('https://local.invalid/recovery')).status).toBe(404); });
