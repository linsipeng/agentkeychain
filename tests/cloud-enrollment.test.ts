import {signRoster} from '../src/cloud/roster.ts';
import {type TrustedDeviceRoster} from '../managed-cloud/shared/roster.ts';
import { expect, test } from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import { createCloudKeys } from '../src/cloud/crypto.ts';
import { canonicalManifest, verifyReleaseManifest } from '../src/cloud/config.ts';
import { sealTrustedEnrollment, openTrustedEnrollment, enrollmentPhrase, selfAnchor } from '../src/cloud/enrollment.ts';
const b64 = (v:Uint8Array)=>Buffer.from(v).toString('base64');
test('human-authenticated bundle binds request, keys, issuer, roster, release pins and expiry',async()=>{
  const a=await createCloudKeys(),b=await createCloudKeys(),root=sodium.crypto_sign_keypair();
  const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,recoveryAuthorities:[{keyId:'recovery',publicKey:b64(a.signingPublic)}],checkpointKeys:[{keyId:'one',publicKey:b64(root.publicKey)}]});
  const policy=verifyReleaseManifest({canonical,signature:b64(sodium.crypto_sign_detached(canonical,root.privateKey))},root.publicKey);
  const request={version:1 as const,requestId:'request',accountId:'account',tenantId:'tenant',vaultId:'vault',deviceId:'b',signingKey:b64(b.signingPublic),wrappingKey:b64(b.wrappingPublic),issuerDeviceId:'a',keyEpoch:1,expiresAt:Math.floor(Date.now()/1000)+300};
  const roster:TrustedDeviceRoster={version:1,accountId:'account',tenantId:'tenant',vaultId:'vault',revision:2,previousDigest:'0'.repeat(64),keyEpoch:1,active:[a,b].map((k,i)=>({deviceId:i?'b':'a',signingKey:b64(k.signingPublic),wrappingKey:b64(k.wrappingPublic)})),revoked:[],issuer:{kind:'device',id:'a'},issuedAt:request.expiresAt-300,expiresAt:request.expiresAt+1000,checkpointKeys:[...policy.checkpointKeys],recoveryAuthorities:[...policy.recoveryAuthorities!],recovery:null};
  const bundle={signedRoster:signRoster(roster,a.signingPrivate),version:1 as const,kind:'enrollment' as const,request,issuerKey:b64(a.signingPublic),roster:[{vaultId:'vault',deviceId:'a',publicKey:b64(a.signingPublic),revoked:false},{vaultId:'vault',deviceId:'b',publicKey:b64(b.signingPublic),revoked:false}],checkpointKeys:policy.checkpointKeys,nonce:'nonce',recoveryCase:null};
  const sealed=sealTrustedEnrollment(bundle,a.signingPrivate);
  const substitution={...bundle,issuerKey:b64(b.signingPublic),roster:[{...bundle.roster[0]!,publicKey:b64(b.signingPublic)},bundle.roster[1]!]};
  expect(()=>sealTrustedEnrollment(substitution,b.signingPrivate)).toThrow();
  const certificate=JSON.stringify({version:1,caseId:'completed-case',accountId:'account',tenantId:'tenant',vaultId:'vault',revision:2,previousDigest:roster.previousDigest,targetDeviceId:'b',signingKey:request.signingKey,wrappingKey:request.wrappingKey,completedAt:roster.issuedAt});
  const recovery={...bundle,signedRoster:signRoster({...roster,issuer:{kind:'recovery',id:'recovery'},recovery:{canonical:certificate,signature:b64(sodium.crypto_sign_detached('AgentKeychain-roster-recovery-completed-v1\0'+certificate,a.signingPrivate))}},a.signingPrivate),kind:'recovery' as const,recoveryCase:'completed-case'};
  const recovered=sealTrustedEnrollment(recovery,a.signingPrivate);
  expect(()=>openTrustedEnrollment(recovered,b,{request,phraseConfirmed:true,phrase:enrollmentPhrase(recovery),policy})).toThrow();
  expect(openTrustedEnrollment(recovered,b,{request,phraseConfirmed:true,phrase:enrollmentPhrase(recovery),policy,recovery:{completedCase:'completed-case',authorityPublicKey:b64(a.signingPublic)}}).recoveryCase).toBe('completed-case');
  expect(()=>openTrustedEnrollment(recovered,b,{request,phraseConfirmed:true,phrase:enrollmentPhrase(recovery),policy,recovery:{completedCase:'other-case',authorityPublicKey:b64(a.signingPublic)}})).toThrow();
  const local={request,phraseConfirmed:true,phrase:enrollmentPhrase(bundle),policy};
  expect(openTrustedEnrollment(sealed,b,local).roster.length).toBe(2);
  expect(()=>openTrustedEnrollment(sealed,b,{...local,phraseConfirmed:false})).toThrow();
  expect(()=>openTrustedEnrollment(sealed,b,{...local,request:{...request,requestId:'other'}})).toThrow();
  for(const changed of [{issuerKey:b64(b.signingPublic)},{roster:[bundle.roster[1]!]},{checkpointKeys:[{keyId:'one',publicKey:b64(b.signingPublic)}]}]){
    const substituted={...bundle,...changed};
    expect(()=>openTrustedEnrollment(sealTrustedEnrollment(substituted,b.signingPrivate),b,local)).toThrow();
  }
  expect(()=>openTrustedEnrollment(sealed,a,local)).toThrow();
  expect(()=>selfAnchor(request,b,policy,false)).toThrow();
  expect(selfAnchor({...request,issuerDeviceId:null},b,policy,true).roster[0]?.publicKey).toBe(b64(b.signingPublic));
});
test('replacement authorization discards request-specific packages and self trust',async()=>{
 const {Database}=await import('bun:sqlite'),{CloudStore}=await import('../src/cloud/persistence.ts'),{replaceEnrollmentRequest}=await import('../src/cloud/login.ts');
 const db=new Database(':memory:'),keys=await createCloudKeys(),store=new CloudStore(db,keys.csk);
 for(const id of ['pending','pending-package','pending-self-roster'])store.put('state',id,{old:true});
 store.put('state','pending-keys',{retained:true});
 replaceEnrollmentRequest(store,{requestId:'new'});
 expect(store.get('state','pending')).toEqual({requestId:'new'});expect(store.get('state','pending-package')).toBeNull();expect(store.get('state','pending-self-roster')).toBeNull();expect(store.get('state','pending-keys')).toEqual({retained:true});
 store.put('state','roster-current',{anchored:true});expect(()=>replaceEnrollmentRequest(store,{requestId:'another'})).toThrow('cloud_partial_activation_requires_resume');
 expect(store.get('state','pending')).toEqual({requestId:'new'});db.close();
});
