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
import {continuationDevicePoll} from '../auth-trust-worker/experimental/continuation-device-poll.ts';
import {handoffDevicePollProof} from '../shared/continuation-handoff-wire.ts';
import {continuationHandoff,handoffCodeDigest,handoffPrepareProof,handoffStageDigest} from '../auth-trust-worker/experimental/continuation-handoff.ts';
import {continuationApprovalUi} from '../auth-trust-worker/experimental/continuation-ui.ts';
import {continuationIssuer} from '../auth-trust-worker/experimental/continuation-issuer.ts';
import {enrollmentFixture,signingFixture} from './synthetic-genesis-approval.ts';
import {canonicalPackage} from '../shared/device-protocol.ts';
import {canonicalContinuationIntent,verifyContinuationApproval} from '../shared/enrollment-continuation.ts';
import {canonicalContinuationAuthReadiness,CONTINUATION_AUTH_READY_DOMAIN} from '../shared/continuation-auth-readiness.ts';
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
 let readinessFault:'nonce'|'stale'|'signature'|undefined;
 const seenNonces=new Set<string>();
 const policy={genesis:f.policy,authority:pin(authority),witnesses:[pin(custody)]};
 const issuer=continuationIssuer(db,identity,policy,{key:async()=>authority,sign:authority.sign},async request=>{
  expect(seenNonces.has(request.nonce)).toBe(false);seenNonces.add(request.nonce);
  if(!latest||headReadsBeforeLoss!==undefined&&headReadsBeforeLoss--<=0)return null;
  const now=Math.floor(Date.now()/1000),t=JSON.parse(request.target.canonical);
  const canonical=canonicalContinuationAuthReadiness({version:1,domain:CONTINUATION_AUTH_READY_DOMAIN,keyId:custody.keyId,
   nonce:readinessFault==='nonce'?'x'.repeat(43):request.nonce,grantDigest:await digest(request.oldGrantCanonical),
   intentDigest:await digest(request.target.canonical),witnessDigest:await digest(JSON.stringify([latest.canonical,latest.signature])),
   payloadDigest:t.payloadDigest,rosterDigest:t.rosterDigest,requestId:g.requestId,accountId:g.accountId,tenantId:g.tenantId,vaultId:g.vaultId,
   deviceId:g.deviceId,keyEpoch:g.keyEpoch,issuedAt:readinessFault==='stale'?now-30:now,expiresAt:readinessFault==='stale'?now-1:now+20});
  return {witness:latest,readiness:{canonical,signature:await (readinessFault==='signature'?authority:custody).sign(canonical)}};
 });
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
 for(const fault of ['nonce','stale','signature'] as const){
  readinessFault=fault;
  await expect(issuer.begin(exact.input)).rejects.toThrow('continuation_approval_unavailable');
 }
 readinessFault=undefined;
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

 const handoff=continuationHandoff(db,identity.origin,await crypto.subtle.generateKey({name:'HMAC',hash:'SHA-256',length:256},false,['sign']),issuer.assertStageForHandoff);
 const priorStage=(await make()).input;
 const routing=random(),pairCode='12345678',codeDigest=await handoffCodeDigest(routing,pairCode),expiresAt=now+70;
 const signature=await f.device.sign(handoffPrepareProof(routing,codeDigest,await handoffStageDigest(priorStage),expiresAt));
 const request=(route:string,input:unknown,extra:Record<string,string>={})=>handoff(new Request(identity.origin+'/v1/auth/continuation-handoff/'+route,{
  method:'POST',headers:{'content-type':'application/json',...(route==='prepare'?{}:{origin:identity.origin}),...extra},body:JSON.stringify(input),
 }));
 const preparation={locator:routing,codeDigest,stage:priorStage,expiresAt,signature};
 expect((await request('prepare',{...preparation,locator:random()})).status).toBe(401);
 expect((await request('prepare',preparation)).status).toBe(200);
 expect(await (await request('prepare',preparation)).json()).toEqual({locator:routing});
 expect(await db.prepare('SELECT attempts FROM auth_continuation_handoffs WHERE locator=?').bind(routing).first('attempts')).toBe(0);
 expect((await request('claim',{locator:routing,pairCode})).status).toBe(401);
 const browser=async()=>{
  const r=await request('browser',{locator:routing});expect(r.status).toBe(200);
  const h=r.headers.get('set-cookie')!,session=/__Host-akc_handoff=([A-Za-z0-9_-]{43})/.exec(h)![1]!,csrf=/__Host-akc_handoff_csrf=([A-Za-z0-9_-]{43})/.exec(h)![1]!;
  expect(h).toMatch(/__Host-akc_handoff=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Strict/);
  expect(h).not.toContain('Domain=');
  return {cookie:'__Host-akc_handoff='+session+'; __Host-akc_handoff_csrf='+csrf,'x-csrf-token':csrf};
 };
 const original=await browser(),competitor=await browser();
 expect((await request('claim',{locator:routing,pairCode:'00000000'},original)).status).toBe(401);
 expect((await request('claim',{locator:routing,pairCode},{...original,'x-csrf-token':random()})).status).toBe(401);
 // Drop the first exact response; refresh browser initialization and retry.
 expect((await request('claim',{locator:routing,pairCode},original)).status).toBe(200);
 expect((await request('browser',{locator:routing},original)).status).toBe(200);
 expect(await (await request('claim',{locator:routing,pairCode},original)).json()).toEqual({stage:priorStage});
 expect((await request('claim',{locator:routing,pairCode},competitor)).status).toBe(401);
 expect((await request('browser',{locator:routing})).status).toBe(401);
 expect(await db.prepare('SELECT attempts FROM auth_continuation_handoffs').first('attempts')).toBe(2);
 // Claiming the package does not create a generic approval/readback session.
 expect(await db.prepare('SELECT count(*) n FROM auth_genesis_view_sessions').first('n')).toBe(2);

 const poll=continuationDevicePoll(db,identity.origin,policy.authority,issuer.assertStageForHandoff);
 const intentDigest=await digest(priorStage.target.canonical),stageDigest=await handoffStageDigest(priorStage);
 const pollRequest=async(change:Record<string,unknown>={},headers:Record<string,string>={},sign=f.device.sign)=>{
  const fields={locator:routing,intentDigest,stageDigest,nonce:random(),timestamp:Math.floor(Date.now()/1000),...change};
  const signed=await sign(handoffDevicePollProof(fields.locator,fields.intentDigest,fields.stageDigest,fields.nonce,fields.timestamp));
  return poll(new Request(identity.origin+'/v1/auth/continuation-handoff/poll',{
   method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify({...fields,signature:signed}),
  }));
 };
 expect((await pollRequest({}, {},authority.sign)).status).toBe(401);
 expect((await pollRequest({intentDigest:'a'.repeat(64)})).status).toBe(401);
 expect((await pollRequest({stageDigest:'a'.repeat(64)})).status).toBe(401);
 expect((await pollRequest({timestamp:now-60})).status).toBe(401);
 expect((await pollRequest({},original)).status).toBe(401);
 const pending=await pollRequest();expect(pending.status).toBe(202);expect(await pending.json()).toEqual({status:'pending'});
 const finalBegin=await post('begin',{stage:priorStage});expect(finalBegin.status).toBe(200);
 const finalCookies=finalBegin.headers.get('set-cookie')!;
 const finalSession=/__Host-akc_genesis_session=([A-Za-z0-9_-]{43})/.exec(finalCookies)![1]!,finalCsrf=/__Host-akc_genesis_csrf=([A-Za-z0-9_-]{43})/.exec(finalCookies)![1]!;
 const finalChallenge=await finalBegin.json() as {id:string;options:{challenge:string}};
 const finalAssertion=await authentic.assert(finalChallenge.options.challenge,{...identity,counter:3,userHandle:handle});
 const committed=await post('complete',{id:finalChallenge.id,stage:priorStage,assertion:finalAssertion},{
  cookie:'__Host-akc_genesis_session='+finalSession+'; __Host-akc_genesis_csrf='+finalCsrf,'x-csrf-token':finalCsrf,
 });
 expect(committed.status).toBe(200);
 const stored=await db.prepare('SELECT canonical,signature FROM auth_continuation_decisions WHERE id=?').bind(finalChallenge.id).first();
 for(const result of await Promise.all([pollRequest(),pollRequest()])){
  expect(result.status).toBe(200);expect(await result.json()).toEqual({status:'approved',approval:stored});
 }
 const liveWitness=latest;latest=null;
 expect((await pollRequest()).status).toBe(401);
 latest=liveWitness;
 await db.prepare('UPDATE auth_genesis_view_sessions SET revoked=1 WHERE session_digest=?').bind(await digest(finalSession)).run();
 expect((await pollRequest()).status).toBe(401);
 expect(await db.prepare('SELECT count(*) n FROM auth_continuation_decisions').first('n')).toBe(3);

});

test('pilot independently registers once and approves only invited exact original intent in the same scoped browser',async()=>{
 await reset();
 const {AUTH:db,GENESIS_ISSUER_SCHEMA,PILOT_GENESIS_SCHEMA}=env as unknown as {AUTH:D1Database;GENESIS_ISSUER_SCHEMA:Parameters<typeof applyD1Migrations>[1];PILOT_GENESIS_SCHEMA:Parameters<typeof applyD1Migrations>[1]};
 await applyD1Migrations(db,GENESIS_ISSUER_SCHEMA);
 // Distinct migration ledger; the pilot set is never part of the normal experimental or deployed migrations.
 await applyD1Migrations(db,PILOT_GENESIS_SCHEMA,'pilot_migrations');
 const {pilotGenesisRegistration,PILOT_GENESIS_INVITE_DOMAIN}=await import('../auth-trust-worker/experimental/pilot-genesis-registration.ts');
 const identity={origin:'https://auth-pilot-genesis.rehearsal.invalid',rpId:'auth-pilot-genesis.rehearsal.invalid'},now=Math.floor(Date.now()/1000);
 const [authority,inviteKey,device,wrapping,checkpoint]=await Promise.all(Array.from({length:5},pair));
 const policy={authority:authority!.pin,checkpointKeys:[checkpoint!.pin],recoveryAuthorities:[]};
 const grant:EnrollmentGrant={version:1,requestId:'request',accountId:'account',tenantId:'tenant',vaultId:'vault',deviceId:'device',
  signingKey:device!.pin.publicKey,wrappingKey:wrapping!.pin.publicKey,issuerDeviceId:null,keyEpoch:1,expiresAt:now+150};
 const {requestId,accountId,tenantId,vaultId,deviceId,keyEpoch,signingKey,wrappingKey}=grant;
 const canonical=canonicalRoster({version:1,accountId,tenantId,vaultId,revision:1,previousDigest:null,keyEpoch,active:[{deviceId,signingKey,wrappingKey}],revoked:[],
  issuer:{kind:'device',id:deviceId},issuedAt:now,expiresAt:now+150,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:[],recovery:null});
 const roster={canonical,signature:await device!.sign(ROSTER_DOMAIN+canonical)},grantBytes=canonicalGrant(grant),browser=await digest(random());
 const inviteBody={version:1,domain:PILOT_GENESIS_INVITE_DOMAIN,keyId:inviteKey!.pin.keyId,origin:identity.origin,rpId:identity.rpId,id:random(),
  accountId,tenantId,vaultId,deviceId,requestId,keyEpoch,grantDigest:await digest(grantBytes),rosterDigest:await rosterDigest(roster),issuedAt:now,expiresAt:now+100};
 const inviteBytes=JSON.stringify(inviteBody),invite={canonical:inviteBytes,signature:await inviteKey!.sign(inviteBytes)};
 const registration=pilotGenesisRegistration(db,identity,policy,inviteKey!.pin);
 const wrongGrant=canonicalGrant({...grant,requestId:'other'});
 await expect(registration.begin(invite,wrongGrant,roster,browser)).rejects.toThrow('pilot_genesis_registration_unavailable');
 const wrongRole=pilotGenesisRegistration(db,identity,policy,authority!.pin);
 await expect(wrongRole.begin(invite,grantBytes,roster,browser)).rejects.toThrow('pilot_genesis_registration_unavailable');
 const {pilotGenesisRegistrationHttp,PILOT_GENESIS_REGISTER_PATH}=await import('../auth-trust-worker/experimental/pilot-genesis-registration-http.ts');
 const http=pilotGenesisRegistrationHttp(identity.origin,now+110,registration);
 const body={invite,oldGrantCanonical:grantBytes,roster};
 const post=(part:string,input:unknown,extra:Record<string,string>={})=>http(new Request(identity.origin+PILOT_GENESIS_REGISTER_PATH+'/'+part,{
  method:'POST',headers:{origin:identity.origin,'sec-fetch-site':'same-origin','content-type':'application/json',...extra},body:JSON.stringify(input),
 }));
 expect((await post('begin',body,{origin:'https://untrusted.example'})).status).toBe(401);
 expect((await post('begin',body,{'sec-fetch-site':'cross-site'})).status).toBe(401);
 const opened=await post('begin',body);
 expect(opened.status).toBe(200);
 const setCookie=opened.headers.get('set-cookie')!;
 expect(setCookie).toMatch(/^__Host-akc_pilot_genesis_registration=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=120$/);
 const session=setCookie.split(';')[0]!;
 const {options:option,csrf}=await opened.json() as {options:{challenge:string};csrf:string};
 const sessionDigest=await digest(JSON.stringify([session.split('=')[1]!,csrf]));
 await expect(registration.begin(invite,grantBytes,roster,browser)).rejects.toThrow('pilot_genesis_registration_unavailable');
 const auth=await virtualAuthenticator(),response=await auth.register(option.challenge,identity);
 await expect(registration.complete(invite,grantBytes,roster,await digest(random()),response)).rejects.toThrow('pilot_genesis_registration_unavailable');
 await expect(registration.complete(invite,grantBytes,roster,sessionDigest,await auth.register(option.challenge,{...identity,uv:false}))).rejects.toThrow('pilot_genesis_registration_unavailable');
 expect((await post('complete',{...body,response},{cookie:session,'x-csrf-token':random()})).status).toBe(401);
 const attempts=await Promise.all(Array.from({length:2},()=>post('complete',{...body,response},{cookie:session,'x-csrf-token':csrf})));
 expect(attempts.map(x=>x.status).sort()).toEqual([204,401]);
 expect(await db.prepare('SELECT COUNT(*) n FROM auth_genesis_pins').first('n')).toBe(1);
 expect(await db.prepare('SELECT COUNT(*) n FROM auth_genesis_decisions').first('n')).toBe(0);
 const signer={key:async()=>authority!.pin,sign:authority!.sign};
 await expect(genesisIssuer(db,identity,policy,signer,sessionDigest).begin(wrongGrant,roster)).rejects.toThrow('genesis_approval_unavailable');
 await expect(genesisIssuer(db,identity,policy,signer,await digest(random())).begin(grantBytes,roster)).rejects.toThrow('genesis_approval_unavailable');
 const issuer=genesisIssuer(db,identity,policy,signer,sessionDigest),challenge=await issuer.begin(grantBytes,roster);
 await expect(issuer.complete(challenge.id,grantBytes,roster,await auth.assert(challenge.options.challenge,{...identity,uv:false}))).rejects.toThrow('genesis_approval_unavailable');
 const assertion=await auth.assert(challenge.options.challenge,{...identity,counter:1});
 // The legacy kernel, even if miswired to this pilot DB, cannot commit a scoped pilot challenge.
 expect(()=>genesisIssuer(db,identity,policy,signer)).toThrow('genesis_approval_unavailable');
 const proof=await issuer.complete(challenge.id,grantBytes,roster,assertion);
 await expect(verifyGenesisApproval(proof,grantBytes,roster,policy)).resolves.toBeTruthy();
});
