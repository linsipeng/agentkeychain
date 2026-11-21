import {URL} from 'node:url';
import {test,expect} from 'bun:test';
import {Database} from 'bun:sqlite';
import {MemorySecureStore} from '../src/platform/secure-store.ts';
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
   ['expired_unapproved','cloud_enrollment_expired_unapproved_requires_retirement'],
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
 }finally{store.destroy();db.close();}
});
