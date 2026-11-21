import type {CloudFetch} from '../src/cloud/http.ts';
import {URL} from 'node:url';
import {test,expect,spyOn} from 'bun:test';
import {Database} from 'bun:sqlite';
import {MemorySecureStore,type SecureAccount} from '../src/platform/secure-store.ts';
import {createCloudKeys} from '../src/cloud/crypto.ts';
import {CloudStore} from '../src/cloud/persistence.ts';
import {protectEnrollmentKeys,restoreEnrollmentKeys} from '../src/cloud/enrollment-intent.ts';
test('protected enrollment intent repairs each missing secure key slot without generating keys',async()=>{
 for(const slot of ['csk','signing-private','wrapping-private'] as const){
  const secure=new MemorySecureStore(),keys=await createCloudKeys();await protectEnrollmentKeys(secure,keys);await secure.remove(slot);
  const restored=await restoreEnrollmentKeys(secure);expect(restored).not.toBeNull();expect(Buffer.from(restored!.csk).equals(Buffer.from(keys.csk))).toBe(true);expect(Buffer.from(restored!.vdk).equals(Buffer.from(keys.vdk))).toBe(true);
  const expected=slot==='csk'?keys.csk:slot==='signing-private'?keys.signingPrivate:keys.wrappingPrivate;expect(Buffer.from((await secure.get(slot))!).equals(Buffer.from(expected))).toBe(true);
  const db=new Database(':memory:'),store=new CloudStore(db,restored!.csk);expect(store.get('state','enrollment')).toBeNull();db.close();
 }
});
test('protected enrollment intent refuses a conflicting existing secure key',async()=>{
 const secure=new MemorySecureStore(),keys=await createCloudKeys();await protectEnrollmentKeys(secure,keys);await secure.put('csk',new Uint8Array(32));await expect(restoreEnrollmentKeys(secure)).rejects.toThrow('cloud_enrollment_intent_conflict');
});
test('secure activation repairs absent SQLite journal and profile; conflicts remain isolated',async()=>{
 const sodium=(await import('libsodium-wrappers-sumo')).default;
 const {canonicalManifest,verifyReleaseManifest}=await import('../src/cloud/config.ts');
 const {selfAnchor}=await import('../src/cloud/enrollment.ts');
 const {prepareEnrollmentActivation,resumeEnrollmentActivation}=await import('../src/cloud/enrollment-intent.ts');
 const {RosterStore}=await import('../src/cloud/roster.ts');
 const keys=await createCloudKeys(),secure=new MemorySecureStore(),b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
 const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://api.local.invalid',webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[{keyId:'one',publicKey:b64(keys.signingPublic)}]});
 const policy=verifyReleaseManifest({canonical,signature:b64(sodium.crypto_sign_detached(canonical,keys.signingPrivate))},keys.signingPublic);
 const grant={version:1 as const,requestId:'req',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,issuerDeviceId:null,signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:Math.floor(Date.now()/1000)+300};
 const trust=selfAnchor(grant,keys,policy,true),enrollment={accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,signingPublic:grant.signingKey,wrappingPublic:grant.wrappingKey,vdk:b64(keys.vdk),roster:trust.roster,checkpointKeys:policy.checkpointKeys,releaseId:policy.releaseId,apiOrigin:policy.apiOrigin};
 const {sealKeyPackage}=await import('../src/cloud/crypto.ts');
 const evidence={grant,keyPackage:sealKeyPackage(keys.vdk,{vaultId:'v',targetDeviceId:'d',keyEpoch:1,issuerDeviceId:'d',grantId:'req'},keys.wrappingPublic,keys.signingPrivate),acceptedAt:Math.floor(Date.now()/1000)};
 const db=new Database(':memory:'),store=new CloudStore(db,keys.csk);
 await protectEnrollmentKeys(secure,keys);await prepareEnrollmentActivation(secure,store,keys,{enrollment,signedRoster:trust.signedRoster,evidence});
 await new RosterStore(store,secure).initialize(trust.signedRoster);
 // Simulate losing all local enrollment rows after the secure anchor was published.
 db.run('DELETE FROM cloud_state');db.run('DELETE FROM cloud_pins');
 expect(await resumeEnrollmentActivation(secure,store,policy)).toBe(true);expect(store.get('state','enrollment')).toEqual(enrollment);expect(await secure.get('enrollment-intent')).toBeNull();
 expect(await new RosterStore(store,secure).check()).toMatchObject({vaultId:'v'});
 await prepareEnrollmentActivation(secure,store,keys,{enrollment,signedRoster:trust.signedRoster,evidence});store.put('state','enrollment',{...enrollment,vaultId:'foreign'});
 await expect(resumeEnrollmentActivation(secure,store,policy)).rejects.toThrow('cloud_enrollment_intent_conflict');expect(await secure.get('enrollment-intent')).not.toBeNull();db.close();
});
test('first device keeps the same request, keys and roster when publish fails and local approval expires',async()=>{
 const sodium=(await import('libsodium-wrappers-sumo')).default;
 const {canonicalManifest,verifyReleaseManifest}=await import('../src/cloud/config.ts');
 const {canonicalGrant}=await import('../managed-cloud/shared/device-protocol.ts');
 const {loginCloud}=await import('../src/cloud/login.ts');
 const b64=(v:Uint8Array)=>Buffer.from(v).toString('base64'),keys=await createCloudKeys(),secure=new MemorySecureStore();
 const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://api.local.invalid',webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[{keyId:'one',publicKey:b64(keys.signingPublic)}]});
 const policy=verifyReleaseManifest({canonical,signature:b64(sodium.crypto_sign_detached(canonical,keys.signingPrivate))},keys.signingPublic);
 const db=new Database(':memory:'),store=new CloudStore(db,keys.csk);
 const authorization={requestId:'req',deviceId:'d',deviceCode:'fixture',browserUri:'https://local.invalid/app/devices/add',verificationUri:'https://local.invalid/v1/auth/devices/verification',phrase:'red green blue',interval:5,expiresIn:300,deadline:Date.now()+300000};
 const grant={version:1 as const,requestId:'req',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,issuerDeviceId:null,signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:Math.floor(Date.now()/1000)+300};
 const paths:string[]=[],opened:string[]=[];
 const ui={open:async(url:string)=>{opened.push(url);},confirmPhrase:async()=>false,wait:async()=>{}};
 try{
  await protectEnrollmentKeys(secure,keys);
  store.put('state','pending',authorization);
  await expect(loginCloud(db,ui,{policy,secure,network:async url=>{
   const path=new URL(url).pathname;paths.push(path);
   switch(path){
    case '/v1/devices/resume':return Response.json({state:'approved',deviceId:'d',requestId:'req',vaultId:'v'});
    case '/v1/devices/challenge':return Response.json({challengeId:'test-challenge',challenge:'fixture',deviceId:'d',vaultId:'v',expiresAt:Math.floor(Date.now()/1000)+60});
    case '/v1/devices/token':return Response.json({token:'fixture',tokenType:'DeviceProof',expiresIn:60,deviceId:'d',vaultId:'v'});
    case '/v1/devices/enrollment-grant':return Response.json({canonical:canonicalGrant(grant)});
    case '/v1/devices/roster-put':return Response.json({error:{code:'unavailable'}},{status:503});
    default:throw new Error('unexpected local fixture route');
   }
  }})).rejects.toThrow('cloud_request_failed');
  expect(paths.at(-1)).toBe('/v1/devices/roster-put');
  const savedRoster=store.get('state','pending-self-roster'),savedKeys=store.get('state','pending-keys');
  expect(savedRoster).not.toBeNull();expect(savedKeys).not.toBeNull();
  expect(store.get('state','pending-approved')).toEqual({requestId:'req',deviceId:'d',vaultId:'v'});
  store.put('state','pending',{...authorization,deadline:0});paths.length=0;
  await expect(loginCloud(db,ui,{policy,secure,network:async url=>{paths.push(new URL(url).pathname);throw new Error('unexpected network');}})).rejects.toThrow('cloud_partial_activation_requires_resume');
  expect(paths).toEqual([]);expect(opened).toEqual([]);
  expect(store.get('state','pending')).toEqual({...authorization,deadline:0});
  expect(store.get('state','pending-self-roster')).toEqual(savedRoster);
  expect(store.get('state','pending-keys')).toEqual(savedKeys);
  // An older interrupted client might have missed the approval response entirely.
  store.remove('state','pending-approved');store.remove('state','pending-self-roster');
  const {enrollmentReconcileProof}=await import('../managed-cloud/shared/device-protocol.ts');
  for(const [state,expected] of [
   ['expired_approved','cloud_enrollment_expired_approved_requires_reapproval'],

   ['unknown','cloud_enrollment_expired_requires_reconcile'],
   ['mismatched','cloud_enrollment_expired_requires_reconcile'],
   ['missing','cloud_enrollment_expired_requires_reconcile'],
  ] as const){
   paths.length=0;
   await expect(loginCloud(db,ui,{policy,secure,network:async (url,init)=>{
    const path=new URL(url).pathname;paths.push(path);
    expect(path).toBe('/v1/devices/enrollment-reconcile');
    const body=JSON.parse(String(init.body));
    expect(body.requestId).toBe('req');expect(body.deviceId).toBe('d');
    expect(sodium.crypto_sign_verify_detached(Buffer.from(body.signature,'base64'),enrollmentReconcileProof(body.requestId,body.deviceId,b64(keys.signingPublic),b64(keys.wrappingPublic),body.timestamp),keys.signingPublic)).toBe(true);
    if(state==='missing')return Response.json({error:{code:'unauthorized'}},{status:401});
    return Response.json({state:state==='mismatched'?'expired_unapproved':state,requestId:state==='mismatched'?'other':'req',deviceId:'d'});
   }})).rejects.toThrow(expected);
   expect(paths).toEqual(['/v1/devices/enrollment-reconcile']);expect(opened).toEqual([]);
  }
  expect(store.get('state','pending')).toEqual({...authorization,deadline:0});
  expect(store.get('state','pending-keys')).toEqual(savedKeys);
  const {enrollmentReplaceProof,enrollmentRetireProof}=await import('../managed-cloud/shared/device-protocol.ts');
  const {digest}=await import('../managed-cloud/shared/contracts.ts');
  let retired=false,successorCalls=0;const proposals:string[]=[];
  const nextRequest='r'.repeat(43),nextDevice='d'.repeat(43),expiresAt=Math.floor(Date.now()/1000)+500;
  const restarting={policy,secure,network:async (url:Parameters<CloudFetch>[0],init:Parameters<CloudFetch>[1])=>{
   const body=JSON.parse(String(init.body));
   switch(new URL(url).pathname){
    case '/v1/devices/enrollment-reconcile':return Response.json({state:retired?'retired_unapproved':'expired_unapproved',requestId:'req',deviceId:'d'});
    case '/v1/devices/enrollment-retire':
     expect(sodium.crypto_sign_verify_detached(Buffer.from(body.signature,'base64'),enrollmentRetireProof('req','d',b64(keys.signingPublic),b64(keys.wrappingPublic),body.timestamp),keys.signingPublic)).toBe(true);
     retired=true;return Response.json({state:'retired_unapproved',requestId:'req',deviceId:'d'});
    case '/v1/devices/enrollment-replace':{
     const intent=store.get<{deviceCode:string;verificationCode:string}>('state','pending-successor')!;
     expect(body.deviceCode).toBeUndefined();expect(body.verificationCode).toBeUndefined();
     expect(body.codeDigest).toBe(await digest(intent.deviceCode));expect(body.verificationDigest).toBe(await digest(intent.verificationCode));
     expect(sodium.crypto_sign_verify_detached(Buffer.from(body.signature,'base64'),enrollmentReplaceProof('req','d',b64(keys.signingPublic),b64(keys.wrappingPublic),body.timestamp,body.codeDigest,body.verificationDigest),keys.signingPublic)).toBe(true);
     proposals.push(body.codeDigest+body.verificationDigest);
     if(++successorCalls===1)throw new Error('synthetic lost response');
     return Response.json({requestId:nextRequest,deviceId:nextDevice,expiresAt,phrase:'red green blue',interval:5});
    }
    case '/v1/devices/resume':
     expect(body.requestId).toBe(nextRequest);expect(body.deviceId).toBe(nextDevice);
     return Response.json({state:'pending'});
    default:throw new Error('unexpected network');
   }
  }};
  const stopBeforeBrowser={...ui,open:async(url:string)=>{opened.push(url);throw new Error('synthetic stop at browser boundary');}};
  await expect(loginCloud(db,stopBeforeBrowser,restarting)).rejects.toThrow('cloud_network_unavailable');
  expect(store.get('state','pending')).toEqual({...authorization,deadline:0});expect(opened).toEqual([]);
  const intent=store.get<{deviceCode:string;verificationCode:string}>('state','pending-successor')!;
  await expect(loginCloud(db,stopBeforeBrowser,restarting)).rejects.toThrow('synthetic stop at browser boundary');
  expect(proposals).toHaveLength(2);expect(proposals[1]).toBe(proposals[0]);
  expect(store.get('state','pending-successor')).toBeNull();
  expect(store.get('state','pending')).toMatchObject({requestId:nextRequest,deviceId:nextDevice,deviceCode:intent.deviceCode});
  expect(opened).toEqual(['https://local.invalid/app/devices/add?code='+intent.verificationCode]);
  expect(store.get('state','pending-keys')).toEqual(savedKeys);
 }finally{store.destroy();db.close();}
});

test('read-only first-device continuation preflight keeps the protected intent and cannot activate an expired grant',async()=>{
 const sodium=(await import('libsodium-wrappers-sumo')).default;
 const {canonicalManifest,verifyReleaseManifest}=await import('../src/cloud/config.ts');
 const {canonicalGrant}=await import('../managed-cloud/shared/device-protocol.ts');
 const {digest}=await import('../managed-cloud/shared/contracts.ts');
 const {canonicalContinuationIntent,canonicalContinuationReceipt}=await import('../managed-cloud/shared/enrollment-continuation.ts');
 const {rosterDigest}=await import('../managed-cloud/shared/roster.ts');
 const {WITNESS_DOMAIN}=await import('../managed-cloud/shared/roster-witness.ts');
 const {genesisRoot}=await import('../managed-cloud/shared/checkpoints.ts');
 const {verifyGenesisContinuationPreflight,newContinuationReadbackNonce,CONTINUATION_HEAD_DOMAIN,prepareEnrollmentActivation,resumeEnrollmentActivation,stageGenesisContinuation,readStagedGenesisContinuation}=await import('../src/cloud/enrollment-intent.ts');
 const {selfAnchor}=await import('../src/cloud/enrollment.ts');
 const {sealKeyPackage,destroyCloudKeys}=await import('../src/cloud/crypto.ts');
 const keys=await createCloudKeys(),secure=new MemorySecureStore(), b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
 const now=Math.floor(Date.now()/1000),root=sodium.crypto_sign_keypair(),auth=sodium.crypto_sign_keypair(),witnessKey=sodium.crypto_sign_keypair(),checkpoint=sodium.crypto_sign_keypair();
 const sign=(bytes:string,key:Uint8Array)=>b64(sodium.crypto_sign_detached(bytes,key));
 const manifest=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://api.local.invalid',webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,
  checkpointKeys:[{keyId:'checkpoint',publicKey:b64(checkpoint.publicKey)}],witnessKeys:[{keyId:'witness',publicKey:b64(witnessKey.publicKey)}]});
 const policy=verifyReleaseManifest({canonical:manifest,signature:sign(manifest,root.privateKey)},root.publicKey);
 const appendix=JSON.stringify({version:1,domain:'AgentKeychain-continuation-release-pin-v1',manifestDigest:await digest(manifest),keyId:'approval',publicKey:b64(auth.publicKey)});
 const authorityAppendix={canonical:appendix,signature:sign(appendix,root.privateKey)};
 const fresh={version:1 as const,requestId:'original',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'d',keyEpoch:1,issuerDeviceId:null,
  signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:now+300};
 const grant={...fresh,expiresAt:now-5},trust=selfAnchor(fresh,keys,policy,true),roster=trust.signedRoster,head=await rosterDigest(roster);
 const keyPackage=sealKeyPackage(keys.vdk,{vaultId:grant.vaultId,targetDeviceId:grant.deviceId,keyEpoch:grant.keyEpoch,issuerDeviceId:grant.deviceId,grantId:grant.requestId},keys.wrappingPublic,keys.signingPrivate);
 const payloadDigest=await digest(JSON.stringify(['AgentKeychain-enrollment-continuation-package-v1',keyPackage.canonical,keyPackage.signature]));
 const exact=canonicalContinuationIntent({version:1,domain:'AgentKeychain-enrollment-continuation-intent-v1',id:'a'.repeat(43),
  originalGrantDigest:await digest(canonicalGrant(grant)),requestId:grant.requestId,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,
  deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey,issuerDeviceId:null,keyEpoch:1,stage:'put-key-package',
  payloadDigest,rosterDigest:head,witnessHead:{revision:1,digest:head},expiresAt:now+60});
 const target={canonical:exact,signature:sign(exact,keys.signingPrivate)};
 const receipt=canonicalContinuationReceipt({version:1,domain:'AgentKeychain-enrollment-continuation-approval-v1',intentDigest:await digest(exact),authorityKeyId:'approval',approvedAt:now,expiresAt:now+60});
 const approval={canonical:receipt,signature:sign(receipt,auth.privateKey)};
 const w=JSON.stringify({version:1,keyId:'witness',accountId:'a',tenantId:'t',vaultId:'v',event:1,revision:1,digest:head,sequence:0,root:await genesisRoot('t','v'),checkpointDigest:await digest('cp')});
 const witness={canonical:w,signature:sign(WITNESS_DOMAIN+w,witnessKey.privateKey)};
 const nonce=newContinuationReadbackNonce();
 const f=JSON.stringify({domain:CONTINUATION_HEAD_DOMAIN,keyId:'witness',nonce,requestId:grant.requestId,
  witnessDigest:await digest(JSON.stringify([w,witness.signature])),approvalDigest:await digest(JSON.stringify([receipt,approval.signature])),
  payloadDigest,issuedAt:now,expiresAt:now+30});
 const freshHead={canonical:f,signature:sign(f,witnessKey.privateKey)};
 const input={grant,target,approval,authorityAppendix,witness,freshHead,roster,keyPackage};
 const db=new Database(':memory:'),store=new CloudStore(db,keys.csk);
 try{
  await protectEnrollmentKeys(secure,keys);
  store.put('state','pending',{requestId:grant.requestId,deviceId:grant.deviceId});
  store.put('state','pending-approved',{requestId:grant.requestId,deviceId:grant.deviceId,vaultId:grant.vaultId});
  store.put('state','pending-self-roster',roster);store.put('state','pending-package',keyPackage);
  const before=await secure.get('enrollment-intent');
  await verifyGenesisContinuationPreflight(secure,store,policy,nonce,input);
  expect(store.get('state','enrollment')).toBeNull();
  expect(Buffer.from((await secure.get('enrollment-intent'))!).equals(Buffer.from(before!))).toBe(true);
  await expect(verifyGenesisContinuationPreflight(secure,store,policy,newContinuationReadbackNonce(),input)).rejects.toThrow('cloud_invalid_continuation_readback');
  await expect(verifyGenesisContinuationPreflight(secure,store,policy,nonce,{...input,authorityAppendix:{canonical:appendix,signature:sign(appendix,auth.privateKey)}})).rejects.toThrow('invalid_continuation_authority_pin');
  await expect(verifyGenesisContinuationPreflight(secure,store,policy,nonce,{...input,grant:{...grant,keyEpoch:2}})).rejects.toThrow('cloud_enrollment_intent_conflict');
  const advanced=JSON.stringify({...JSON.parse(w),event:2,sequence:1,root:await digest('advanced')});
  const advancedWitness={canonical:advanced,signature:sign(WITNESS_DOMAIN+advanced,witnessKey.privateKey)};
  const advancedHead=JSON.stringify({...JSON.parse(f),witnessDigest:await digest(JSON.stringify([advanced,advancedWitness.signature]))});
  await expect(verifyGenesisContinuationPreflight(secure,store,policy,nonce,{...input,witness:advancedWitness,
   freshHead:{canonical:advancedHead,signature:sign(advancedHead,witnessKey.privateKey)}})).rejects.toThrow('cloud_invalid_continuation_readback');
  // On a separate protected store, stage only the exact signed Main commit plus
  // the already-proven independent head. Never use them as activation.
  const owner=sodium.crypto_sign_keypair(),ownerAppendix=JSON.stringify({version:1,domain:'AgentKeychain-continuation-main-commit-release-pin-v1',
   manifestDigest:await digest(manifest),keyId:'owner',publicKey:b64(owner.publicKey)});
  const commitAppendix={canonical:ownerAppendix,signature:sign(ownerAppendix,root.privateKey)};
  const commitBytes=JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-main-commit-v1',keyId:'owner',nonce,
   continuationId:'a'.repeat(43),requestId:grant.requestId,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,deviceId:grant.deviceId,
   keyEpoch:1,stage:'put-key-package',intentDigest:await digest(exact),approvalDigest:await digest(JSON.stringify([receipt,approval.signature])),
   payloadDigest,witnessDigest:await digest(JSON.stringify([w,witness.signature])),custodyFreshHeadDigest:await digest(JSON.stringify([f,freshHead.signature])),
   issuedAt:now,expiresAt:now+20});
  const commit={canonical:commitBytes,signature:sign(commitBytes,owner.privateKey)},verified={...input,commitAppendix,commit};
  class InterruptibleStore extends MemorySecureStore {
   dropAfterPut=false;
   override async put(account:SecureAccount,value:Uint8Array){
    await super.put(account,value);
    if(account==='enrollment-intent'&&this.dropAfterPut){this.dropAfterPut=false;throw new Error('test_stopped_after_secure_save');}
   }
  }
  const journal=new InterruptibleStore();
  await protectEnrollmentKeys(journal,keys);
  expect(await readStagedGenesisContinuation(journal,store,policy)).toBeNull();
  const wrong=JSON.stringify({...JSON.parse(commitBytes),deviceId:'unrelated'});
  await expect(stageGenesisContinuation(journal,store,policy,nonce,{...verified,commit:{canonical:wrong,signature:sign(wrong,owner.privateKey)}}))
   .rejects.toThrow('cloud_invalid_continuation_commit');
  const notOwner={...verified,commit:{canonical:commitBytes,signature:sign(commitBytes,auth.privateKey)}};
  await expect(stageGenesisContinuation(journal,store,policy,nonce,notOwner)).rejects.toThrow('cloud_invalid_continuation_commit');
  expect(await readStagedGenesisContinuation(journal,store,policy)).toBeNull();
  journal.dropAfterPut=true;
  await expect(stageGenesisContinuation(journal,store,policy,nonce,verified)).rejects.toThrow('test_stopped_after_secure_save');
  const later=spyOn(Date,'now').mockReturnValue((now+65)*1000);
  try{
   expect(await readStagedGenesisContinuation(journal,store,policy)).toMatchObject({kind:'genesis-package-continuation-v1',requestId:grant.requestId,deviceId:grant.deviceId});
   await stageGenesisContinuation(journal,store,policy,nonce,verified);
   expect(await resumeEnrollmentActivation(journal,store,policy)).toBe(false);
  }finally{later.mockRestore();}
  expect(store.get('state','enrollment')).toBeNull();
  expect(await journal.get('roster-anchor')).toBeNull();
  // An out-of-band preflight never exempts the old activation contract.
  const enrollment={accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,deviceId:grant.deviceId,keyEpoch:grant.keyEpoch,
   signingPublic:grant.signingKey,wrappingPublic:grant.wrappingKey,vdk:b64(keys.vdk),roster:trust.roster,
   checkpointKeys:policy.checkpointKeys,releaseId:policy.releaseId,apiOrigin:policy.apiOrigin};
  await prepareEnrollmentActivation(secure,store,keys,{enrollment,signedRoster:roster,evidence:{grant,keyPackage,witness,acceptedAt:now}});
  await expect(resumeEnrollmentActivation(secure,store,policy)).rejects.toThrow('cloud_enrollment_intent_conflict');
  expect(store.get('state','enrollment')).toBeNull();
  before?.fill(0);
 }finally{destroyCloudKeys(keys);store.destroy();db.close();}
});
