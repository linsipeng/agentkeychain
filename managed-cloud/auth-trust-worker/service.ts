import {isIP} from 'node:net';
import {emailContext,normalizedEmail} from '../shared/email-proof.ts';
import {decode64,encode64} from '../shared/recovery-crypto.ts';
export interface CodeSender {sendCode(recipient:string,code:string):Promise<void>}
export interface AuthConfig {AUTH:D1Database;EMAIL_HASH_KEY:string;CODE_HASH_KEY:string;SOURCE_HASH_KEY:string;EMAIL:CodeSender}
const unavailable=()=>new Error('unavailable');
export async function hmac(material:string,value:string){
 if(typeof material!=='string')throw unavailable();
 const bytes=decode64(material);if(bytes.length!==32||encode64(bytes)!==material)throw unavailable();
 const key=await crypto.subtle.importKey('raw',bytes,{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
}
export async function sourceIdentity(request:Request,material:string){
 try{
 // Only the public API ingress may call this private binding. Request.cf cannot
 // be supplied over HTTP; CF-Connecting-IP is overwritten at that ingress.
 if(!request.cf||typeof request.cf.colo!=='string'||!/^[A-Z]{3}$/.test(request.cf.colo))throw unavailable();
 const ip=request.headers.get('cf-connecting-ip');
 if(!ip||ip.length>45||ip.trim()!==ip||ip.includes('%')||!isIP(ip))throw unavailable();
 const normalized=isIP(ip)===6?new URL('https://['+ip+']/').hostname.slice(1,-1):ip;
 return 'src:'+await hmac(material,'source-v1\0'+normalized);
 }catch{throw unavailable();}
}
function code(){const n=new Uint32Array(1);do{crypto.getRandomValues(n);}while(n[0]!>=4294000000);return String(n[0]!%1000000).padStart(6,'0');}
export async function cleanupAuth(db:D1Database){await db.batch([db.prepare('DELETE FROM email_codes WHERE expires_at<=unixepoch()'),db.prepare('DELETE FROM email_rates WHERE window<unixepoch()-7200'),db.prepare('DELETE FROM email_audit WHERE at<unixepoch()-604800')]);}
export function emailVerifier(env:AuthConfig){
 async function ready(){
  if(!env.EMAIL||typeof env.EMAIL.sendCode!=='function'||new Set([env.EMAIL_HASH_KEY,env.CODE_HASH_KEY,env.SOURCE_HASH_KEY]).size!==3)throw unavailable();
  await Promise.all([env.EMAIL_HASH_KEY,env.CODE_HASH_KEY,env.SOURCE_HASH_KEY].map(k=>hmac(k,'configuration')));
 }
 const cleanup=()=>cleanupAuth(env.AUTH);
 return {
 async request(email:string,purpose:unknown,context:string){
  await ready();email=normalizedEmail(email);emailContext(purpose,context);await cleanup();
  const identity=await hmac(env.EMAIL_HASH_KEY,'email-v1\0'+email),now=Math.floor(Date.now()/1000),window=Math.floor(now/3600)*3600;
  const allowed=await env.AUTH.prepare(`INSERT INTO email_rates VALUES(?,?,1,?) ON CONFLICT(identity) DO UPDATE SET window=excluded.window,count=CASE WHEN email_rates.window=excluded.window THEN email_rates.count+1 ELSE 1 END,last_sent=excluded.last_sent WHERE email_rates.last_sent<=excluded.last_sent-60 AND (email_rates.window<>excluded.window OR email_rates.count<5) RETURNING identity`).bind(identity,window,now).first();
  if(allowed){
   const value=code(),hash=await hmac(env.CODE_HASH_KEY,JSON.stringify([identity,purpose,context,value]));
   await env.AUTH.batch([env.AUTH.prepare('INSERT INTO email_codes VALUES(?,?,?,?,?,0,0) ON CONFLICT(email_hash,purpose,context_digest) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,consumed=0').bind(identity,purpose,context,hash,now+600),env.AUTH.prepare("INSERT INTO email_audit(event,at) VALUES('requested',?)").bind(now)]);
   try{await env.EMAIL.sendCode(email,value);}catch{await env.AUTH.prepare('UPDATE email_codes SET consumed=1 WHERE email_hash=? AND code_hash=?').bind(identity,hash).run();throw unavailable();}
  }
  return {accepted:true,retryAfter:60};
 },
 async verify(email:string,proof:string){
  try{
   await ready();email=normalizedEmail(email);if(typeof proof!=='string'||proof.length>256)return false;
   const parsed:unknown=JSON.parse(proof);if(!Array.isArray(parsed)||parsed.length!==3)return false;
   const [purpose,context,value]=parsed;emailContext(purpose,context);if(typeof value!=='string'||!/^\d{6}$/.test(value))return false;
   const identity=await hmac(env.EMAIL_HASH_KEY,'email-v1\0'+email),hash=await hmac(env.CODE_HASH_KEY,JSON.stringify([identity,purpose,context,value]));
   // One conditional write both spends a guess and consumes a matching code.
   // Concurrent correct requests can have at most one winner.
   const row=await env.AUTH.prepare('UPDATE email_codes SET attempts=attempts+1,consumed=CASE WHEN code_hash=? THEN 1 ELSE 0 END WHERE email_hash=? AND purpose=? AND context_digest=? AND consumed=0 AND attempts<5 AND expires_at>unixepoch() RETURNING consumed').bind(hash,identity,purpose,context).first<{consumed:number}>();
   await env.AUTH.prepare('INSERT INTO email_audit(event,at) VALUES(?,unixepoch())').bind(row?.consumed===1?'verified':'rejected').run();await cleanup();return row?.consumed===1;
  }catch{return false;}
 }
 };
}
