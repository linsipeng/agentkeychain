import { URL } from "node:url";
import {expect,test} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {Database} from 'bun:sqlite';
import {randomBytes} from 'node:crypto';
import {migrate} from '../src/db/migrate.ts';
import {createCloudKeys} from '../src/cloud/crypto.ts';
import {CloudStore} from '../src/cloud/persistence.ts';
import {VaultMutationCoordinator} from '../src/cloud/coordinator.ts';
import {DurableSync} from '../src/cloud/durable.ts';
import {MemorySecureStore} from '../src/platform/secure-store.ts';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import {checkpoint,genesisRoot,advanceRoot} from '../managed-cloud/shared/checkpoints.ts';
import {parseCanonicalOperation,type SignedManagedOperation,type ManagedVersion} from '../src/cloud/protocol.ts';
test('durable retry reuses signed bytes, two stores converge, anchor rejects database rollback',async()=>{
 const a=await createCloudKeys(),b=await createCloudKeys();b.vdk.set(a.vdk);const cp=sodium.crypto_sign_keypair(),b64=(v:Uint8Array)=>Buffer.from(v).toString('base64');
 const pin={keyId:'test',publicKey:b64(cp.publicKey)},signer={key:async()=>pin,sign:async(c:string)=>b64(sodium.crypto_sign_detached(c,cp.privateKey))};
 const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[pin]});
 const policy=verifyReleaseManifest({canonical,signature:b64(sodium.crypto_sign_detached(canonical,cp.privateKey))},cp.publicKey);
 const roster=[a,b].map((k,i)=>({vaultId:'vault',deviceId:i?'b':'a',publicKey:b64(k.signingPublic),revoked:false}));
 const dbs=[new Database(':memory:'),new Database(':memory:')];dbs.forEach(migrate);
 const stores=[new CloudStore(dbs[0]!,a.csk),new CloudStore(dbs[1]!,b.csk)],secure=[new MemorySecureStore(),new MemorySecureStore()];
 const coordinators=[a,b].map((k,i)=>new VaultMutationCoordinator(stores[i]!,k,roster[i]!,randomBytes(32),1));
 const versions:ManagedVersion[]=[];let root=await genesisRoot('tenant','vault'),latest=await checkpoint(signer,'tenant','vault',0,root,null,null),lose=true;
 const remote={policy,async call(path:string,body?:unknown){
  if(path.endsWith('/approvals'))return {state:'pending'};
  if(path.endsWith('/push')){const signed=body as SignedManagedOperation,op=parseCanonicalOperation(signed.canonical);if(op.approvalRef)throw new Error('approval_required');let v=versions.find(v=>v.signed.canonical===signed.canonical);if(!v){v={signed,serverSequence:versions.length+1};const chain=await advanceRoot(root,v.serverSequence,signed);latest=await checkpoint(signer,'tenant','vault',v.serverSequence,chain.root,root,chain.operationDigest);root=chain.root;versions.push(v);}if(lose){lose=false;throw new Error('response_lost');}return {vaultId:'vault',deviceId:op.deviceId,operationId:op.operationId,serverSequence:v.serverSequence,checkpoint:latest};}
  const url=new URL(path,'https://local.invalid'),cursor=url.searchParams.get('cursor'),after=cursor?(JSON.parse(Buffer.from(cursor,'base64').toString()) as unknown[])[3] as number:0;
  return {versions:versions.slice(after),checkpoint:latest,pageCheckpoint:latest,nextCursor:Buffer.from(JSON.stringify(['tenant','vault',url.pathname.includes('vault')?'a':'a',versions.length])).toString('base64'),hasMore:false};
 }};
 const initialAnchor={sequence:0,root:await genesisRoot('tenant','vault')};for(let i=0;i<2;i++)await stores[i]!.checkAnchor(secure[i]!,initialAnchor,[initialAnchor],true);
 const engines=coordinators.map((c,i)=>new DurableSync(stores[i]!,secure[i]!,c,remote,'tenant',roster));
 coordinators[0]!.mutate({name:'synthetic',value:globalThis.crypto.randomUUID(),scopes:['test'],metadata:null,localVersion:1},'put');
 await expect(engines[0]!.sync()).rejects.toThrow('response_lost');expect(stores[0]!.all('outbox').length).toBe(1);
 await engines[0]!.sync();expect(versions.length).toBe(1);expect(stores[0]!.all('outbox').length).toBe(0);
 await engines[1]!.sync();expect(dbs[1]!.query('SELECT name FROM secrets').get()).toEqual({name:'synthetic'});
 coordinators[0]!.requestApproval({name:'synthetic',value:'replacement',scopes:['test'],metadata:null,localVersion:2},'put','rotate');
 coordinators[1]!.mutate({name:'while-pending',value:'synthetic',scopes:['test'],metadata:null,localVersion:1},'put');await engines[1]!.sync();
 await expect(engines[0]!.sync()).rejects.toThrow('approval_required');
 expect(dbs[0]!.query("SELECT name FROM secrets WHERE name='while-pending'").get()).toEqual({name:'while-pending'});
 expect(stores[0]!.all('outbox')).toHaveLength(1);
 stores[1]!.remove('state','cursor');for(const row of stores[1]!.all('history'))stores[1]!.remove('history',row.id);for(const row of stores[1]!.all('heads'))stores[1]!.remove('heads',row.id);
 await expect(engines[1]!.sync()).rejects.toThrow('cloud_rollback_detected');dbs.forEach(d=>d.close());
});

import {RosterStore,signRoster,rosterPins} from '../src/cloud/roster.ts';
import {rosterDigest,type TrustedDeviceRoster} from '../managed-cloud/shared/roster.ts';
import type {ManagedHttpClient} from '../src/cloud/http.ts';
test('revoked signer history needs the exact pre-revocation checkpoint; later writes and truncated proof never apply',async()=>{
 const a=await createCloudKeys(),b=await createCloudKeys();b.vdk.set(a.vdk);const cp=sodium.crypto_sign_keypair(),b64=(v:Uint8Array)=>Buffer.from(v).toString('base64'),pin={keyId:'cp',publicKey:b64(cp.publicKey)},signer={key:async()=>pin,sign:async(c:string)=>b64(sodium.crypto_sign_detached(c,cp.privateKey))};
 const manifest=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://local.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[pin]}),policy=verifyReleaseManifest({canonical:manifest,signature:b64(sodium.crypto_sign_detached(manifest,cp.privateKey))},cp.publicKey),now=Math.floor(Date.now()/1000);
 const dbB=new Database(':memory:');migrate(dbB);const storeB=new CloudStore(dbB,b.csk),deviceB={vaultId:'v',deviceId:'b',publicKey:b64(b.signingPublic),revoked:false},source=new VaultMutationCoordinator(storeB,b,deviceB,randomBytes(32),1);
 source.mutate({name:'old',value:'synthetic',scopes:['test'],metadata:null,localVersion:1},'put');source.mutate({name:'new',value:'synthetic',scopes:['test'],metadata:null,localVersion:1},'put');
 const versions=storeB.all<{signed:SignedManagedOperation}>('outbox').map((e,i)=>({signed:e.value.signed,serverSequence:i+1}));let root=await genesisRoot('t','v');const checkpoints=[await checkpoint(signer,'t','v',0,root,null,null)];for(const v of versions){const chain=await advanceRoot(root,v.serverSequence,v.signed);checkpoints.push(await checkpoint(signer,'t','v',v.serverSequence,chain.root,root,chain.operationDigest));root=chain.root;}
 const initial:TrustedDeviceRoster={version:1,accountId:'account',tenantId:'t',vaultId:'v',revision:1,previousDigest:null,keyEpoch:1,active:[a,b].map((k,i)=>({deviceId:i?'b':'a',signingKey:b64(k.signingPublic),wrappingKey:b64(k.wrappingPublic)})),revoked:[],issuer:{kind:'device',id:'a'},issuedAt:now,expiresAt:now+1000,checkpointKeys:[pin],recoveryAuthorities:[],recovery:null};
 for(const mode of ['historical','later','truncated','fork'] as const){
  const one=signRoster(initial,a.signingPrivate);let boundary=checkpoints[mode==='truncated'?2:1]!;
  if(mode==='fork')boundary=await checkpoint(signer,'t','v',1,'f'.repeat(64),(JSON.parse(checkpoints[1]!.canonical) as {previousRoot:string}).previousRoot,'e'.repeat(64));
  const r={...initial,revision:2,previousDigest:await rosterDigest(one),active:[initial.active[0]!],revoked:[{...initial.active[1]!,revokedRevision:2,acceptedThrough:boundary}]},signed=signRoster(r,a.signingPrivate);
  const db=new Database(':memory:');migrate(db);const store=new CloudStore(db,a.csk),secure=new MemorySecureStore();await new RosterStore(store,secure).initialize(signed);
  const initialAnchor={sequence:0,root:await genesisRoot('t','v')};await store.checkAnchor(secure,initialAnchor,[initialAnchor],true);
  const own=rosterPins(r)[0]!,coordinator=new VaultMutationCoordinator(store,a,own,randomBytes(32),1),count=mode==='later'?2:1;
  const http={policy,logout(){},publicCall:async()=>({revisions:[],head:{revision:2,digest:await rosterDigest(signed)}}),call:async()=>({revocations:[]})} as unknown as ManagedHttpClient;
  const remote={policy,call:async()=>({versions:versions.slice(0,count),checkpoint:checkpoints[count],pageCheckpoint:checkpoints[count],nextCursor:'unused',hasMore:false})};
  const engine=new DurableSync(store,secure,coordinator,remote,'t',rosterPins(r),{http,keys:a});
  if(mode==='historical'){await engine.sync();expect(store.all('history')).toHaveLength(1);}else{await expect(engine.sync()).rejects.toThrow();expect(store.all('history')).toHaveLength(0);expect(db.query('SELECT count(*) n FROM secrets').get()).toEqual({n:0});}
  db.close();
 }
 dbB.close();
});
