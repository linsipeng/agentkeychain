import {env} from 'cloudflare:workers';
import {applyD1Migrations,reset} from 'cloudflare:test';
import {expect,test} from 'vitest';
import {genesisReadback,genesisReadbackIntent} from '../auth-trust-worker/experimental/genesis-readback.ts';
import {genesisIssuer} from '../auth-trust-worker/experimental/genesis-issuer.ts';
import {virtualAuthenticator} from './virtual-authenticator.ts';
import {encode,random,webauthn} from '../api-worker/webauthn.ts';
import {digest} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {verifyGenesisApproval} from '../shared/genesis-approval.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest} from '../shared/roster.ts';

const bytes=(input:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(input)));
async function pair(){
 const keys=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 const publicKey=bytes(await crypto.subtle.exportKey('raw',keys.publicKey));
 const pin={keyId:await digest(publicKey),publicKey};
 return {pin,sign:async (m:string)=>bytes(await crypto.subtle.sign('Ed25519',keys.privateKey,new TextEncoder().encode(m)))};
}

test('Auth-owned credentials approve one exact first-device decision, not a Main assertion',async()=>{
 await reset();
 const {AUTH:db,GENESIS_ISSUER_SCHEMA:schema}=env as unknown as {AUTH:D1Database;GENESIS_ISSUER_SCHEMA:Parameters<typeof applyD1Migrations>[1]};
 await applyD1Migrations(db,schema);
 const identity={origin:'https://auth.local.invalid',rpId:'auth.local.invalid'};
 const now=Math.floor(Date.now()/1000);
 const [authority,device,checkpoint,recovery,wrapping]=await Promise.all([pair(),pair(),pair(),pair(),crypto.subtle.generateKey('X25519',true,['deriveBits']) as Promise<CryptoKeyPair>]);
 const policy={authority:authority.pin,checkpointKeys:[checkpoint.pin],recoveryAuthorities:[recovery.pin]};
 const issuer=genesisIssuer(db,identity,policy,{key:async()=>authority.pin,sign:authority.sign});
 const grant:EnrollmentGrant={version:1,requestId:'request',accountId:'account',tenantId:'tenant',vaultId:'vault',deviceId:'device',signingKey:device.pin.publicKey,wrappingKey:bytes(await crypto.subtle.exportKey('raw',wrapping.publicKey)),issuerDeviceId:null,keyEpoch:1,expiresAt:now+120};
 const canonical=canonicalRoster({version:1,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,revision:1,previousDigest:null,keyEpoch:grant.keyEpoch,active:[{deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey}],revoked:[],issuer:{kind:'device',id:grant.deviceId},issuedAt:now,expiresAt:now+150,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities,recovery:null});
 const roster={canonical,signature:await device.sign(ROSTER_DOMAIN+canonical)}, grantBytes=canonicalGrant(grant);
 await expect(issuer.begin(grantBytes,roster)).rejects.toThrow('genesis_approval_unavailable');
 // Seed only the outcome of a synthetic, independently validated Auth ceremony.
 const authentic=await virtualAuthenticator(), handle=random(), signup=random();
 const authOrigin={origin:identity.origin,rpId:identity.rpId};
 const credential=await webauthn.registration(identity,await digest(signup),await authentic.register(signup,authOrigin));
 await db.prepare('INSERT INTO auth_genesis_pins VALUES(?,?,?,?,?,?,?,1)').bind(grant.accountId,grant.tenantId,grant.vaultId,handle,credential.id,encode(credential.publicKey),credential.counter).run();
 const challenge=await issuer.begin(grantBytes,roster);
 expect(challenge.options.userVerification).toBe('required');
 const proof=await authentic.assert(challenge.options.challenge,{...authOrigin,counter:1,userHandle:handle});
 await expect(issuer.complete(challenge.id,canonicalGrant({...grant,requestId:'wrong'}),roster,proof)).rejects.toThrow('genesis_approval_unavailable');
 const signed=await Promise.allSettled([issuer.complete(challenge.id,grantBytes,roster,proof),issuer.complete(challenge.id,grantBytes,roster,proof)]);
 const only=signed.filter(r=>r.status==='fulfilled');
 expect(only).toHaveLength(1);
 expect(await verifyGenesisApproval(only[0]!.value,grantBytes,roster,policy)).toMatchObject({decisionId:challenge.id});
 expect(await db.prepare('SELECT count(*) FROM auth_genesis_decisions').first('count(*)')).toBe(1);
 expect(await db.prepare('SELECT counter FROM auth_genesis_pins').first('counter')).toBe(1);
 // Auth-only harness: production does not yet issue these session/intent rows.
 const lookup=genesisReadback(db,identity.origin,policy);
 const cookie=random(),anti=random(),session=await digest(cookie);
 const intent=await genesisReadbackIntent(challenge.id,await digest(grantBytes),await rosterDigest(roster));
 const read=(change:Record<string,unknown>={},requestHeaders:Record<string,string>={})=>lookup(new Request(identity.origin+'/v1/auth/first-device-receipt',{
  method:'POST',headers:{origin:identity.origin,'content-type':'application/json','x-csrf-token':anti,
    cookie:'__Host-akc_genesis_session='+cookie+'; __Host-akc_genesis_csrf='+anti,...requestHeaders},
  body:JSON.stringify({decisionId:challenge.id,grant:grantBytes,roster,...change}),
 }));
 expect((await read()).status).toBe(401);
 await db.prepare('INSERT INTO auth_genesis_view_sessions VALUES(?,?,?,?,?,1,0,?)').bind(session,await digest(anti),grant.accountId,grant.tenantId,grant.vaultId,now+110).run();
 expect((await read()).status).toBe(401);
 await db.prepare('INSERT INTO auth_genesis_view_grants VALUES(?,?,?,?)').bind(session,intent,now,now+100).run();
 const first=await read(), repeated=await read();
 expect(first.status).toBe(200);
 expect(first.headers.get('cache-control')).toBe('no-store');
 expect(await first.json()).toEqual(only[0]!.value);
 expect(await repeated.json()).toEqual(only[0]!.value);
 for(const headers of [{origin:'https://elsewhere.invalid'},{'x-csrf-token':random()},{'sec-fetch-site':'cross-site'}] as Record<string,string>[])
  expect((await read({},headers)).status).toBe(401);
 expect((await read({decisionId:random()})).status).toBe(401);
 expect((await read({grant:canonicalGrant({...grant,requestId:'altered'})})).status).toBe(401);
 await db.prepare('UPDATE auth_genesis_view_sessions SET approval_reader=0').run();
 expect((await read()).status).toBe(401);
 await db.prepare('UPDATE auth_genesis_view_sessions SET approval_reader=1,revoked=1').run();
 expect((await read()).status).toBe(401);
 await db.prepare('UPDATE auth_genesis_view_sessions SET revoked=0').run();
 await db.prepare('UPDATE auth_genesis_view_grants SET issued=?,expires=?').bind(now-60,now-1).run();
 expect((await read()).status).toBe(401);
 expect(await db.prepare('SELECT count(*) FROM auth_genesis_decisions').first('count(*)')).toBe(1);
});
