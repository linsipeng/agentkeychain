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

import {continuationReadback,continuationReadbackIntent} from '../auth-trust-worker/experimental/continuation-readback.ts';
import {continuationApprovalUi} from '../auth-trust-worker/experimental/continuation-ui.ts';
import {continuationIssuer} from '../auth-trust-worker/experimental/continuation-issuer.ts';
import {enrollmentFixture,signingFixture} from './synthetic-genesis-approval.ts';
import {canonicalPackage} from '../shared/device-protocol.ts';
import {canonicalContinuationIntent,verifyContinuationApproval} from '../shared/enrollment-continuation.ts';
import {genesisRoot} from '../shared/checkpoints.ts';
import {WITNESS_DOMAIN} from '../shared/roster-witness.ts';

test('Auth requires a newly verified ceremony for the exact continuation stage and issues once',async()=>{
 await reset();
 const {AUTH:db,GENESIS_ISSUER_SCHEMA:schema}=env as unknown as {AUTH:D1Database;GENESIS_ISSUER_SCHEMA:Parameters<typeof applyD1Migrations>[1]};
 await applyD1Migrations(db,schema);
 const identity={origin:'https://auth.local.invalid',rpId:'auth.local.invalid'},now=Math.floor(Date.now()/1000);
 const f=await enrollmentFixture(now-500), [authority,custody]=await Promise.all([signingFixture(),signingFixture()]);
 const g=f.grant,oldGrantCanonical=canonicalGrant(g),head=await rosterDigest(f.roster),grantDigest=await digest(oldGrantCanonical);
 const signed=await f.approval({issuedAt:now-400,expiresAt:now-350},oldGrantCanonical,f.roster);
 const authentic=await virtualAuthenticator(),handle=random(),signup=random();
 const cred=await webauthn.registration(identity,await digest(signup),await authentic.register(signup,identity));
 const pin=({keyId,publicKey}:{keyId:string;publicKey:string})=>({keyId,publicKey});
 let latest:{canonical:string;signature:string}|null=null, headReadsBeforeLoss:number|undefined;
 const policy={genesis:f.policy,authority:pin(authority),witnesses:[pin(custody)]};
 const issuer=continuationIssuer(db,identity,policy,{key:async()=>authority,sign:authority.sign},async()=>headReadsBeforeLoss!==undefined&&headReadsBeforeLoss--<=0?null:latest);
 const make=async (change={})=>{
  const cipher=canonicalPackage({version:1,vaultId:g.vaultId,targetDeviceId:g.deviceId,keyEpoch:g.keyEpoch,wrappedVDK:btoa('x'.repeat(80)),issuerDeviceId:g.deviceId,grantId:g.requestId});
  const keyPackage={canonical:cipher,signature:await f.device.sign(cipher)};
  const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',cipher,keyPackage.signature]));
  const c=canonicalContinuationIntent({version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id:random(),originalGrantDigest:grantDigest,
   requestId:g.requestId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,keyEpoch:g.keyEpoch,deviceId:g.deviceId,signingKey:g.signingKey,wrappingKey:g.wrappingKey,
   issuerDeviceId:null,stage:'put-key-package',payloadDigest,rosterDigest:head,witnessHead:{revision:1,digest:head},expiresAt:now+100,...change});
  return {input:{oldGrantCanonical,target:{canonical:c,signature:await f.device.sign(c)},roster:f.roster,keyPackage},payloadDigest};
 };
 const exact=await make();
 await expect(issuer.begin(exact.input)).rejects.toThrow('continuation_approval_unavailable');
 const w=JSON.stringify({version:1,keyId:custody.keyId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,event:1,revision:1,digest:head,sequence:0,
  root:await genesisRoot(g.tenantId,g.vaultId),checkpointDigest:await digest('checkpoint')});
 latest={canonical:w,signature:await custody.sign(WITNESS_DOMAIN+w)};
 await db.batch([
  db.prepare('INSERT INTO auth_genesis_pins VALUES(?,?,?,?,?,?,?,1)').bind(g.accountId,g.tenantId,g.vaultId,handle,cred.id,encode(cred.publicKey),0),
  db.prepare('INSERT INTO auth_genesis_challenges VALUES(?,?,?,?,?,?,?,?,?)').bind(signed.data.decisionId,await digest('historical fixture'),g.accountId,g.tenantId,g.vaultId,cred.id,grantDigest,head,now-350),
  db.prepare('INSERT INTO auth_genesis_decisions VALUES(?,?,?,?)').bind(signed.data.decisionId,grantDigest,signed.proof.canonical,signed.proof.signature),
 ]);
 await expect(issuer.begin((await make({stage:'publish-roster'})).input)).rejects.toThrow('continuation_approval_unavailable');
 const challenge=await issuer.begin(exact.input);
 expect(challenge.options.userVerification).toBe('required');
 const assertion=await authentic.assert(challenge.options.challenge,{...identity,counter:1,userHandle:handle});
 await expect(issuer.complete(challenge.id,(await make()).input,assertion)).rejects.toThrow('continuation_approval_unavailable');
 const parked=latest;latest=null;
 await expect(issuer.complete(challenge.id,exact.input,assertion)).rejects.toThrow('continuation_approval_unavailable');
 latest=parked;
 await db.prepare('UPDATE auth_genesis_pins SET active=0').run();
 await expect(issuer.complete(challenge.id,exact.input,assertion)).rejects.toThrow('continuation_approval_unavailable');
 await db.prepare('UPDATE auth_genesis_pins SET active=1').run();
 // The Auth UI can establish this exact scope before the final POST, so a
 // committed response loss never depends on a second signer call or grant mint.
 const cookie=random(),anti=random(),session=await digest(cookie),origin=identity.origin;
 const read=continuationReadback(db,origin,policy.authority);
 const base={decisionId:challenge.id,oldGrantCanonical,target:exact.input.target};
 const ask=(change:Record<string,unknown>={},requestHeaders:Record<string,string>={})=>read(new Request(origin+'/v1/auth/continuation-receipt',{
  method:'POST',headers:{origin,'content-type':'application/json','x-csrf-token':anti,
   cookie:'__Host-akc_genesis_session='+cookie+'; __Host-akc_genesis_csrf='+anti,...requestHeaders},
  body:JSON.stringify({...base,...change}),
 }));
 expect((await ask()).status).toBe(401);
 await db.prepare('INSERT INTO auth_genesis_view_sessions VALUES(?,?,?,?,?,1,0,?)').bind(session,await digest(anti),g.accountId,g.tenantId,g.vaultId,now+80).run();
 expect((await ask()).status).toBe(401);
 const action=await continuationReadbackIntent(challenge.id,grantDigest,await digest(exact.input.target.canonical));
 await db.prepare('INSERT INTO auth_genesis_view_grants VALUES(?,?,?,?)').bind(session,action,now,now+60).run();
 expect((await ask()).status).toBe(401); // The old purpose cannot be used.
 await db.prepare('INSERT INTO auth_continuation_view_grants VALUES(?,?,?,?,?)').bind(session,action,cred.id,now,now+60).run();
 expect((await ask()).status).toBe(401); // Exact grant exists, but Auth has not committed approval.
 const outcomes=await Promise.allSettled([issuer.complete(challenge.id,exact.input,assertion),issuer.complete(challenge.id,exact.input,assertion)]);
 const success=outcomes.filter(r=>r.status==='fulfilled');
 expect(success).toHaveLength(1);
 await expect(verifyContinuationApproval(exact.input.target,success[0]!.value,{oldGrantCanonical,stage:'put-key-package',payloadDigest:exact.payloadDigest,
  rosterDigest:head,witnessHead:{revision:1,digest:head},authority:policy.authority,issuer:null,now:Math.floor(Date.now()/1000)})).resolves.toBeUndefined();
 await expect(issuer.complete(challenge.id,exact.input,assertion)).rejects.toThrow('continuation_approval_unavailable');
 expect(await db.prepare('SELECT count(*) n FROM auth_continuation_decisions').first('n')).toBe(1);
 expect(await db.prepare('SELECT counter FROM auth_genesis_pins').first('counter')).toBe(1);
 const receipts=await Promise.all([ask(),ask()]);
 for(const r of receipts){
  expect(r.status).toBe(200);expect(r.headers.get('cache-control')).toBe('no-store');expect(await r.json()).toEqual(success[0]!.value);
 }
 expect((await ask({decisionId:random()})).status).toBe(401);
 expect((await ask({target:(await make()).input.target})).status).toBe(401);
 expect((await ask({target:{...exact.input.target,signature:signed.proof.signature}})).status).toBe(401);
 expect((await ask({}, {origin:'https://foreign.invalid'})).status).toBe(401);
 expect((await ask({}, {'x-csrf-token':random()})).status).toBe(401);
 await db.prepare('UPDATE auth_genesis_view_sessions SET revoked=1').run();
 expect((await ask()).status).toBe(401);
 await db.prepare('UPDATE auth_genesis_view_sessions SET revoked=0').run();
 await db.prepare('UPDATE auth_continuation_view_grants SET issued=?,expires=?').bind(now-60,now-1).run();
 expect((await ask()).status).toBe(401);
 expect(await db.prepare('SELECT count(*) n FROM auth_continuation_decisions').first('n')).toBe(1);

 const stage=(await make()).input,ui=continuationApprovalUi(identity.origin,issuer);
 const post=(path:string,value:unknown,extra:Record<string,string>={})=>ui(new Request(identity.origin+'/v1/auth/continuation-approval/'+path,{
  method:'POST',headers:{origin:identity.origin,'content-type':'application/json',...extra},body:JSON.stringify(value),
 }));
 const begin=await post('begin',{stage},{cookie:'__Host-akc_genesis_session='+random()});
 expect(begin.status).toBe(200);
 const setCookie=begin.headers.get('set-cookie')!;
 const token=/__Host-akc_genesis_session=([A-Za-z0-9_-]{43})/.exec(setCookie)![1]!,csrf=/__Host-akc_genesis_csrf=([A-Za-z0-9_-]{43})/.exec(setCookie)![1]!;
 expect(setCookie).toMatch(/__Host-akc_genesis_session=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=120/);
 expect(setCookie).not.toContain('Domain=');
 const opened=await begin.json() as {id:string;options:{challenge:string};display:{purpose:string;deviceId:string}};
 expect(opened.display).toMatchObject({purpose:'continue-original-device-key-package',deviceId:g.deviceId});
 const cookieHeaders={cookie:'__Host-akc_genesis_session='+token+'; __Host-akc_genesis_csrf='+csrf,'x-csrf-token':csrf};
 const recover=()=>read(new Request(identity.origin+'/v1/auth/continuation-receipt',{
  method:'POST',headers:{origin:identity.origin,'content-type':'application/json',...cookieHeaders},
  body:JSON.stringify({decisionId:opened.id,oldGrantCanonical,target:stage.target}),
 }));
 expect(await db.prepare('SELECT count(*) n FROM auth_genesis_view_sessions WHERE session_digest=?').bind(await digest(token)).first('n')).toBe(0);
 expect((await recover()).status).toBe(401);
 const freshAssertion=await authentic.assert(opened.options.challenge,{...identity,counter:2,userHandle:handle});
 const body={id:opened.id,stage,assertion:freshAssertion};
 expect((await post('complete',body)).status).toBe(401);
 expect((await post('complete',body,{...cookieHeaders,'x-csrf-token':random()})).status).toBe(401);
 expect((await post('complete',body,{...cookieHeaders,origin:'https://another.invalid'})).status).toBe(401);
 headReadsBeforeLoss=1; // Known head during lookup, unavailable after Passkey verification.
 expect((await post('complete',body,cookieHeaders)).status).toBe(401);
 headReadsBeforeLoss=undefined;
 expect((await recover()).status).toBe(401);
 expect(await db.prepare('SELECT counter FROM auth_genesis_pins').first('counter')).toBe(1);
 const completed=await post('complete',body,cookieHeaders);expect(completed.status).toBe(200);
 // Pretend the approval response was lost. Return the committed bytes, not a new signature.
 const recovered=await recover();expect(recovered.status).toBe(200);
 expect(await recovered.json()).toEqual(await db.prepare('SELECT canonical,signature FROM auth_continuation_decisions WHERE id=?').bind(opened.id).first());
 expect((await post('complete',body,cookieHeaders)).status).toBe(401);
 expect(await db.prepare('SELECT counter FROM auth_genesis_pins').first('counter')).toBe(2);

});
