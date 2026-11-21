import {test,expect} from 'bun:test';
import {Database} from 'bun:sqlite';
import sodium from 'libsodium-wrappers-sumo';
import {createCloudKeys,destroyCloudKeys,sealKeyPackage} from '../src/cloud/crypto.ts';
import {CloudStore} from '../src/cloud/persistence.ts';
import {MemorySecureStore} from '../src/platform/secure-store.ts';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import {protectEnrollmentKeys} from '../src/cloud/enrollment-intent.ts';
import {selfAnchor} from '../src/cloud/enrollment.ts';
import {prepareContinuationBrowserHandoff} from '../src/cloud/continuation-handoff.ts';
import type {CloudFetch} from '../src/cloud/http.ts';
import {canonicalGrant} from '../managed-cloud/shared/device-protocol.ts';
import {digest,verify} from '../managed-cloud/shared/contracts.ts';
import {handoffCodeDigest,handoffPrepareProof,handoffStageDigest} from '../managed-cloud/shared/continuation-handoff-wire.ts';

test('CLI restarts with the same protected handoff; no plaintext pair code in network or URL',async()=>{
 await sodium.ready;
 const keys=await createCloudKeys(),root=sodium.crypto_sign_keypair(),witness=sodium.crypto_sign_keypair(),checkpoint=sodium.crypto_sign_keypair();
 const b64=(x:Uint8Array)=>Buffer.from(x).toString('base64'),sign=(x:string)=>b64(sodium.crypto_sign_detached(x,root.privateKey));
 const manifest=canonicalManifest({version:1,releaseId:'fixture',apiOrigin:'https://api.local.invalid',webOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,
  checkpointKeys:[{keyId:'checkpoint',publicKey:b64(checkpoint.publicKey)}],witnessKeys:[{keyId:'witness',publicKey:b64(witness.publicKey)}]});
 const policy=verifyReleaseManifest({canonical:manifest,signature:sign(manifest)},root.publicKey);
 const proof=async(authOrigin:string)=>{const canonical=JSON.stringify({version:1,domain:'AgentKeychain-continuation-auth-origin-pilot-v1',manifestDigest:await digest(manifest),authOrigin});return {canonical,signature:sign(canonical)};};
 const authOrigin='https://auth.local.invalid',authOriginAppendix=await proof(authOrigin),now=Math.floor(Date.now()/1000);
 const fresh={version:1 as const,requestId:'original',accountId:'a',tenantId:'t',vaultId:'v',deviceId:'device',keyEpoch:1,issuerDeviceId:null,
  signingKey:b64(keys.signingPublic),wrappingKey:b64(keys.wrappingPublic),expiresAt:now+150};
 const g={...fresh,expiresAt:now-20},oldGrantCanonical=canonicalGrant(g),roster=selfAnchor(fresh,keys,policy,true).signedRoster;
 const keyPackage=sealKeyPackage(keys.vdk,{vaultId:g.vaultId,targetDeviceId:g.deviceId,keyEpoch:g.keyEpoch,issuerDeviceId:g.deviceId,grantId:g.requestId},keys.wrappingPublic,keys.signingPrivate);
 const secure=new MemorySecureStore(),db=new Database(':memory:'),store=new CloudStore(db,keys.csk);
 const key='pending-continuation-browser-handoff',bodies:string[]=[],shown:string[]=[];
 const wire:CloudFetch=async(url,options)=>{
  expect(url).toBe(authOrigin+'/v1/auth/continuation-handoff/prepare');
  expect(options).toMatchObject({method:'POST',redirect:'error',credentials:'omit'});
  const raw=String(options.body),input=JSON.parse(raw);bodies.push(raw);
  expect(Object.keys(input).sort()).toEqual(['codeDigest','expiresAt','locator','signature','stage']);
  expect(await verify(g.signingKey,input.signature,handoffPrepareProof(input.locator,input.codeDigest,await handoffStageDigest(input.stage),input.expiresAt))).toBe(true);
  if(bodies.length===1)throw new Error('simulated lost commit response');
  if(bodies.length===2)return Response.json({locator:'m'.repeat(43)});
  return Response.json({locator:input.locator});
 };
 const options={secure,store,policy,authOriginAppendix,oldGrantCanonical,roster,keyPackage,network:wire,displayPairCode:(code:string)=>{shown.push(code);}};
 try{
  await protectEnrollmentKeys(secure,keys);
  store.put('state','pending',{requestId:g.requestId,deviceId:g.deviceId});
  store.put('state','pending-approved',{requestId:g.requestId,deviceId:g.deviceId,vaultId:g.vaultId});
  store.put('state','pending-self-roster',roster);store.put('state','pending-package',keyPackage);
  await expect(prepareContinuationBrowserHandoff({...options,authOriginAppendix:await proof(policy.webOrigin)})).rejects.toThrow('invalid_continuation_auth_origin');
  expect(bodies).toHaveLength(0);
  await expect(prepareContinuationBrowserHandoff(options)).rejects.toThrow('cloud_continuation_handoff_unavailable');
  const saved=store.get<{locator:string;code:string;expiresAt:number;codeDigest:string}>('state',key)!;
  expect(await handoffCodeDigest(saved.locator,saved.code)).toBe(saved.codeDigest);expect(shown).toEqual([]);
  const restarted=new CloudStore(db,keys.csk);
  try{
   await expect(prepareContinuationBrowserHandoff({...options,store:restarted})).rejects.toThrow('cloud_continuation_handoff_unavailable');
   expect(shown).toEqual([]);
   const result=await prepareContinuationBrowserHandoff({...options,store:restarted});
   expect(result.browserUrl).toBe(authOrigin+'/continuation/approve#handoff='+saved.locator);
   expect(shown).toEqual([saved.code]);expect(bodies).toHaveLength(3);expect(new Set(bodies).size).toBe(1);
   expect(bodies[0]).not.toContain('"code":"'+saved.code+'"');
   expect(restarted.get('state','enrollment')).toBeNull();
   const raw=db.query('SELECT ciphertext FROM cloud_state WHERE id=?').get(key) as {ciphertext:Uint8Array};
   expect(Buffer.from(raw.ciphertext).includes(Buffer.from(saved.code))).toBe(false);
   const state=restarted.get<Record<string,unknown>>('state',key)!;
   restarted.put('state',key,{...state,expiresAt:now-1});
   await expect(prepareContinuationBrowserHandoff({...options,store:restarted})).rejects.toThrow('cloud_continuation_handoff_expired');
   expect(bodies).toHaveLength(3);
  }finally{restarted.destroy();}
 }finally{destroyCloudKeys(keys);store.destroy();db.close();}
});
