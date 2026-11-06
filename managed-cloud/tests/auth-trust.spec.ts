import {env,applyD1Migrations} from 'cloudflare:test';
import {beforeAll,beforeEach,expect,it} from 'vitest';
import {emailVerifier,sourceIdentity} from '../auth-trust-worker/service.ts';
import {emailProof} from '../shared/email-proof.ts';
const db=(env as unknown as {AUTH:D1Database}).AUTH;
const key=(n:number)=>btoa(String.fromCharCode(...new Uint8Array(32).fill(n)));
let delivered='';
const config=()=>({AUTH:db,EMAIL_HASH_KEY:key(1),CODE_HASH_KEY:key(2),SOURCE_HASH_KEY:key(3),EMAIL:{async sendCode(_recipient:string,code:string){delivered=code;}}});
const context='a'.repeat(64);
beforeAll(async()=>{await applyD1Migrations(db,(env as unknown as {AUTH_MIGRATIONS:Parameters<typeof applyD1Migrations>[1]}).AUTH_MIGRATIONS);});
beforeEach(async()=>{await db.exec('DELETE FROM email_codes; DELETE FROM email_rates; DELETE FROM email_audit;');delivered='';});
it('consumes once under concurrent attempts and stores no email or code',async()=>{
 const v=emailVerifier(config());expect(await v.request('person@example.com','invitation',context)).toEqual({accepted:true,retryAfter:60});
 expect(delivered).toMatch(/^\d{6}$/);
 const dump=JSON.stringify(await db.prepare('SELECT * FROM email_codes').all());expect(dump).not.toContain('person@example.com');expect(dump).not.toContain(delivered);
 const proof=emailProof('invitation',context,delivered);
 const results=await Promise.all(Array.from({length:8},()=>v.verify('person@example.com',proof)));
 expect(results.filter(Boolean)).toHaveLength(1);
});
it('binds purpose, context and email, bounds guesses, and blocks resend',async()=>{
 const v=emailVerifier(config());await v.request('person@example.com','invitation',context);const code=delivered;delivered='';
 await v.request('person@example.com','invitation',context);expect(delivered).toBe('');
 expect(await v.verify('other@example.com',emailProof('invitation',context,code))).toBe(false);
 expect(await v.verify('person@example.com',emailProof('recovery',context,code))).toBe(false);
 for(let i=0;i<5;i++)expect(await v.verify('person@example.com',emailProof('invitation',context,code==='000000'?'111111':'000000'))).toBe(false);
 expect(await v.verify('person@example.com',emailProof('invitation',context,code))).toBe(false);
});
it('rejects expired codes and malformed requests',async()=>{
 const v=emailVerifier(config());await v.request('person@example.com','recovery',context);await db.exec('UPDATE email_codes SET expires_at=0');
 expect(await v.verify('person@example.com',emailProof('recovery',context,delivered))).toBe(false);
 for(const email of [' Person@example.com','a\r\nb@example.com','a@localhost','.a@example.com','a..b@example.com','a.@example.com','a@'+'x'.repeat(64)+'.com'])await expect(v.request(email,'invitation',context)).rejects.toThrow();
 await expect(emailVerifier({...config(),CODE_HASH_KEY:key(1)}).request('person@example.com','invitation',context)).rejects.toThrow();
});
it('fails closed on missing metadata and spoof/duplicate/malformed IP',async()=>{
 for(const ip of ['', '1.2.3.4, 5.6.7.8','999.2.3.4','127.1','::ffff:999.0.0.1','fe80::1%eth0']){
 const r=new Request('https://example.com',{headers:{'cf-connecting-ip':ip}});Object.defineProperty(r,'cf',{value:{colo:'SJC'}});await expect(sourceIdentity(r,key(3))).rejects.toThrow();
 }
 const r=new Request('https://example.com',{headers:{'cf-connecting-ip':'192.0.2.1'}});await expect(sourceIdentity(r,key(3))).rejects.toThrow();
 Object.defineProperty(r,'cf',{value:{colo:'SJC'}});const result=await sourceIdentity(r,key(3));expect(result).toMatch(/^src:[a-f0-9]{64}$/);expect(result).not.toContain('192.0.2.1');
});
it('one concurrent request wins across purposes and contexts, without enumeration',async()=>{
 let sent=0;const v=emailVerifier({...config(),EMAIL:{async sendCode(){sent++;}}});
 const results=await Promise.all(Array.from({length:12},(_,i)=>v.request('nobody@example.com',i%2?'recovery':'invitation',String(i%10).repeat(64))));
 expect(sent).toBe(1);expect(results.every(r=>r.accepted&&r.retryAfter===60)).toBe(true);
});
it('fails closed when the sender is unavailable without retaining provider details',async()=>{
 const v=emailVerifier({...config(),EMAIL:{async sendCode(){throw new Error('private provider diagnostic');}}});
 await expect(v.request('person@example.com','invitation',context)).rejects.toThrow('unavailable');
 expect((await db.prepare('SELECT consumed FROM email_codes').first<{consumed:number}>())?.consumed).toBe(1);
 expect(JSON.stringify(await db.prepare('SELECT * FROM email_audit').all())).not.toContain('private provider');
});
it('enforces the hourly issuance cap across contexts',async()=>{
 let sent=0;const v=emailVerifier({...config(),EMAIL:{async sendCode(){sent++;}}});
 for(let i=0;i<7;i++){await v.request('person@example.com','invitation',String(i).repeat(64));await db.exec('UPDATE email_rates SET last_sent=last_sent-60');}
 expect(sent).toBe(5);
});
it('normalizes equivalent IPv6 representations and rejects client fallback headers',async()=>{
 const request=(ip:string)=>{const r=new Request('https://example.com',{headers:{'cf-connecting-ip':ip}});Object.defineProperty(r,'cf',{value:{colo:'SJC'}});return r;};
 expect(await sourceIdentity(request('2001:db8:0:0:0:0:0:1'),key(3))).toBe(await sourceIdentity(request('2001:db8::1'),key(3)));
 const r=new Request('https://example.com',{headers:{'x-forwarded-for':'192.0.2.1','x-real-ip':'192.0.2.1'}});Object.defineProperty(r,'cf',{value:{colo:'SJC'}});await expect(sourceIdentity(r,key(3))).rejects.toThrow();
 await expect(sourceIdentity(request('192.0.2.1'),'')).rejects.toThrow();
});
