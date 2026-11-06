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
 const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[{keyId:'one',publicKey:b64(keys.signingPublic)}]});
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
