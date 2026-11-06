import {URL} from 'node:url';
import {test,expect} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalRoster,verifyRoster,rosterDigest,ROSTER_DOMAIN,issueRecoveryRoster,type TrustedDeviceRoster} from '../managed-cloud/shared/roster.ts';
await sodium.ready;
const k=sodium.crypto_sign_keypair(),w=sodium.crypto_box_keypair(),b=(v:Uint8Array)=>Buffer.from(v).toString('base64');
const now=Math.floor(Date.now()/1000);
const first=():TrustedDeviceRoster=>({version:1,accountId:'a',tenantId:'t',vaultId:'v',revision:1,previousDigest:null,keyEpoch:1,active:[{deviceId:'a',signingKey:b(k.publicKey),wrappingKey:b(w.publicKey)}],revoked:[],issuer:{kind:'device',id:'a'},issuedAt:now,expiresAt:now+86400,checkpointKeys:[{keyId:'cp',publicKey:b(sodium.crypto_sign_keypair().publicKey)}],recoveryAuthorities:[],recovery:null});
const sign=(r:TrustedDeviceRoster)=>{const canonical=canonicalRoster(r);return {canonical,signature:b(sodium.crypto_sign_detached(ROSTER_DOMAIN+canonical,k.privateKey))};};
test('strict signed roster genesis, chain and exact signature',async()=>{const r=first(),s=sign(r);expect(await verifyRoster(s,null)).toEqual(r);const next={...r,revision:2,previousDigest:await rosterDigest(s)};expect((await verifyRoster(sign(next),s)).revision).toBe(2);await expect(verifyRoster(sign(next),null)).rejects.toThrow();await expect(verifyRoster({...s,signature:b(new Uint8Array(64))},null)).rejects.toThrow();});
test('reject unknown suffix, duplicate identity/key, changed pins, hidden devices, replacement and rollback',async()=>{const r=first(),s=sign(r),next={...r,revision:2,previousDigest:await rosterDigest(s)};expect(()=>canonicalRoster({...r,extra:true} as TrustedDeviceRoster)).toThrow();expect(()=>canonicalRoster({...r,active:[...r.active,...r.active]})).toThrow();for(const bad of [{...next,active:[]},{...next,active:[{...r.active[0]!,wrappingKey:b(sodium.crypto_box_keypair().publicKey)}]},{...next,checkpointKeys:[{keyId:'other',publicKey:r.checkpointKeys[0]!.publicKey}]},{...next,revision:1},{...next,previousDigest:'0'.repeat(64)}])await expect((async()=>verifyRoster(sign(bad),s))()).rejects.toThrow();});
import {Database} from 'bun:sqlite';
import {CloudStore} from '../src/cloud/persistence.ts';
import {MemorySecureStore} from '../src/platform/secure-store.ts';
import {RosterStore,signRoster} from '../src/cloud/roster.ts';
import {checkpoint,genesisRoot} from '../managed-cloud/shared/checkpoints.ts';
async function revokedChain(){
 const cp=sodium.crypto_sign_keypair(),other=sodium.crypto_sign_keypair(),wrap=sodium.crypto_box_keypair();const a=first();a.checkpointKeys=[{keyId:'cp',publicKey:b(cp.publicKey)}];
 const one=sign(a),two=sign({...a,revision:2,previousDigest:await rosterDigest(one),active:[...a.active,{deviceId:'b',signingKey:b(other.publicKey),wrappingKey:b(wrap.publicKey)}]});
 const acceptedThrough=await checkpoint({key:async()=>a.checkpointKeys[0]!,sign:async c=>b(sodium.crypto_sign_detached(c,cp.privateKey))},'t','v',0,await genesisRoot('t','v'),null,null);
 const r:TrustedDeviceRoster={...a,revision:3,previousDigest:await rosterDigest(two),revoked:[{...JSON.parse(two.canonical).active[1],revokedRevision:3,acceptedThrough}]};
 return {a,one,two,r,three:sign(r),other,checkpointSigner:{key:async()=>a.checkpointKeys[0]!,sign:async(c:string)=>b(sodium.crypto_sign_detached(c,cp.privateKey))}};
}
test('revocation retains immutable history, blocks reactivation, hidden revoked identities and revoked issuers',async()=>{
 const {two,r,three,other}=await revokedChain();await expect(verifyRoster(three,two)).resolves.toEqual(r);
 const next={...r,revision:4,previousDigest:await rosterDigest(three)};
 for(const bad of [{...next,revoked:[]},{...next,revoked:[],active:[...r.active,((({deviceId,signingKey,wrappingKey})=>({deviceId,signingKey,wrappingKey}))(r.revoked[0]!))]},{...next,revoked:r.revoked.map(d=>({...d,revokedRevision:4}))}])await expect((async()=>verifyRoster(sign(bad),three))()).rejects.toThrow();
 await expect(verifyRoster(signRoster({...next,issuer:{kind:'device',id:'b'}},other.privateKey),three)).rejects.toThrow('issuer');
});
test('CSK encrypted history, DB-ahead repair and anchor-ahead/fork/missing anchor fail closed',async()=>{
 const {one,two,three}=await revokedChain(),db=new Database(':memory:'),store=new CloudStore(db,sodium.randombytes_buf(32)),secure=new MemorySecureStore(),local=new RosterStore(store,secure);
 await local.initialize(one);const initial=await secure.get('roster-anchor');await local.accept(two);expect((await local.check()).revision).toBe(2);
 const encrypted=db.query("SELECT ciphertext FROM cloud_state WHERE id='roster-current'").get() as {ciphertext:Uint8Array};expect(Buffer.from(encrypted.ciphertext).includes(Buffer.from(two.canonical))).toBe(false);
 await secure.put('roster-anchor',initial!);expect((await new RosterStore(store,secure).check()).revision).toBe(2);
 await local.accept(three);store.put('state','roster-current',two);store.remove('state','roster-history:3');await expect(local.check()).rejects.toThrow('rollback');
 await secure.remove('roster-anchor');await expect(local.check()).rejects.toThrow('anchor_missing');store.destroy();db.close();
});
test('bootstrap crash retries only the identical authenticated roster',async()=>{
 const {one,two}=await revokedChain(),db=new Database(':memory:'),store=new CloudStore(db,sodium.randombytes_buf(32)),secure=new MemorySecureStore();
 await secure.put('roster-anchor',Buffer.from(JSON.stringify({revision:1,digest:await rosterDigest(one)})));
 const local=new RosterStore(store,secure);await expect(local.initialize(two)).rejects.toThrow('rollback');await local.initialize(one);expect((await local.check()).revision).toBe(1);db.close();
});
test('completed recovery evidence binds pinned authority, context, previous root, revision and target',async()=>{
 const authority=sodium.crypto_sign_keypair(),a=first();a.recoveryAuthorities=[{keyId:'recovery',publicKey:b(authority.publicKey)}];const prior=sign(a);
 const e={version:1,caseId:'completed',accountId:'a',tenantId:'t',vaultId:'v',revision:2,previousDigest:await rosterDigest(prior),targetDeviceId:'a',signingKey:a.active[0]!.signingKey,wrappingKey:a.active[0]!.wrappingKey,completedAt:now};
 const canonical=JSON.stringify(e),recovery={canonical,signature:b(sodium.crypto_sign_detached('AgentKeychain-roster-recovery-completed-v1\0'+canonical,authority.privateKey))};
 const next:TrustedDeviceRoster={...a,revision:2,previousDigest:e.previousDigest,issuer:{kind:'recovery',id:'recovery'},recovery};
 const issued=await issueRecoveryRoster(prior,next,{key:async()=>({keyId:'recovery',publicKey:b(authority.publicKey)}),sign:async c=>b(sodium.crypto_sign_detached(c,authority.privateKey))});
 await expect(verifyRoster(issued,prior)).resolves.toEqual(next);
 for(const bad of [{...next,recovery:null},{...next,issuer:{kind:'recovery' as const,id:'untrusted'}},{...next,recovery:{...recovery,canonical:JSON.stringify({...e,caseId:'other'})}}])await expect((async()=>verifyRoster(signRoster(bad,authority.privateKey),prior))()).rejects.toThrow();
});
import {refreshRoster} from '../src/cloud/roster.ts';
import type {ManagedHttpClient} from '../src/cloud/http.ts';
import {createCloudKeys} from '../src/cloud/crypto.ts';
test('fetch rejects rollback, forks, unknown/truncated suffix and never trusts server bootstrap',async()=>{
 const {one,two}=await revokedChain();
 for(const response of [{revisions:[],head:{revision:0,digest:'0'.repeat(64)}},{revisions:[],head:{revision:2,digest:await rosterDigest(two)}},{revisions:[two],head:{revision:2,digest:'0'.repeat(64)}},{revisions:[two],head:{revision:2,digest:await rosterDigest(two)},unknown:true}]){
  const db=new Database(':memory:'),store=new CloudStore(db,sodium.randombytes_buf(32)),secure=new MemorySecureStore(),keys=await createCloudKeys();await new RosterStore(store,secure).initialize(one);
  const http={publicCall:async()=>response} as unknown as ManagedHttpClient;await expect(refreshRoster(store,secure,http,keys,'a',false)).rejects.toThrow();db.close();
 }
 const history=await revokedChain(),pageDB=new Database(':memory:'),pageStore=new CloudStore(pageDB,sodium.randombytes_buf(32)),pageSecure=new MemorySecureStore(),pageKeys=await createCloudKeys();await new RosterStore(pageStore,pageSecure).initialize(history.one);let calls=0;
 const paged={publicCall:async()=>++calls===1?{revisions:[history.two],head:{revision:3,digest:await rosterDigest(history.three)}}:{revisions:[],head:{revision:2,digest:await rosterDigest(history.two)}}} as unknown as ManagedHttpClient;
 await expect(refreshRoster(pageStore,pageSecure,paged,pageKeys,'a',false)).rejects.toThrow('rollback');await expect(refreshRoster(pageStore,pageSecure,paged,pageKeys,'a',false)).rejects.toThrow('rollback');pageDB.close();
 const db=new Database(':memory:'),store=new CloudStore(db,sodium.randombytes_buf(32));await expect(refreshRoster(store,new MemorySecureStore(),{} as ManagedHttpClient,await createCloudKeys(),'a',false)).rejects.toThrow('roster_missing');db.close();
});
test('protected bootstrap repairs a stale SQLite roster only through the exact secure-anchored successor',async()=>{
 const {one,two,three}=await revokedChain(),db=new Database(':memory:'),store=new CloudStore(db,sodium.randombytes_buf(32)),secure=new MemorySecureStore(),local=new RosterStore(store,secure);
 await local.initialize(one);await secure.put('roster-anchor',Buffer.from(JSON.stringify({revision:2,digest:await rosterDigest(two)})));
 await expect(local.initialize(three)).rejects.toThrow();await local.initialize(two);expect((await local.check()).revision).toBe(2);db.close();
});
test('independent witness rejects valid historical prefixes, omitted revocations, forks and stale checkpoints; retries and races preserve head',async()=>{
 const {rosterWitness,verifyWitness}=await import('../managed-cloud/shared/roster-witness.ts'),{readFileSync}=await import('node:fs');
 const db=new Database(':memory:');db.exec(readFileSync(new URL('../managed-cloud/recovery-worker/migrations/0004_roster_witness.sql',import.meta.url),'utf8'));db.exec(readFileSync(new URL('../managed-cloud/recovery-worker/migrations/0007_witness_suffixes.sql',import.meta.url),'utf8'));
 const adapter={prepare:(sql:string)=>({bind:(...values:unknown[])=>({first:async()=>db.query(sql).get(...values as never[]),run:async()=>db.query(sql).run(...values as never[])})})} as unknown as Parameters<typeof rosterWitness>[0];
 const {a,one,two,three,r,checkpointSigner}=await revokedChain(),cp=r.revoked[0]!.acceptedThrough,key=sodium.crypto_sign_keypair(),signer={key:async()=>({keyId:'witness',publicKey:b(key.publicKey)}),sign:async(c:string)=>b(sodium.crypto_sign_detached(c,key.privateKey))};
 const witness=rosterWitness(adapter,signer,a.checkpointKeys,async row=>row.canonical===one.canonical);
 const first=await witness.accept({rosters:[one],checkpoints:[cp]});expect(first).toEqual(await witness.accept({rosters:[one],checkpoints:[cp]}));
 await expect(witness.accept({rosters:[one,two,three],checkpoints:[cp]})).rejects.toThrow('witness_prior');
 const [left,right]=await Promise.all([witness.accept({prior:first,rosters:[one,two,three],checkpoints:[cp]}),witness.accept({prior:first,rosters:[one,two,three],checkpoints:[cp]})]);expect(left).toEqual(right);
 await expect(witness.accept({rosters:[one,two],checkpoints:[cp]})).rejects.toThrow('rollback');
 await expect(witness.requireLatest([one],cp)).rejects.toThrow('not_latest');
 const omitted=sign({...r,revision:4,previousDigest:await rosterDigest(three),revoked:[]});await expect(witness.accept({rosters:[one,two,three,omitted],checkpoints:[cp]})).rejects.toThrow();
 expect((await verifyWitness(left,[await signer.key()],{accountId:'a',tenantId:'t',vaultId:'v',revision:3,digest:await rosterDigest(three)},cp)).event).toBe(2);
 await expect(verifyWitness(left,a.checkpointKeys,{accountId:'a',tenantId:'t',vaultId:'v',revision:3,digest:await rosterDigest(three)},cp)).rejects.toThrow();
 expect(db.query('SELECT count(*) n FROM roster_witness').get()).toEqual({n:2});
 const {advanceRoot}=await import('../managed-cloud/shared/checkpoints.ts'),root=JSON.parse(cp.canonical).root,advanced=await advanceRoot(root,1,three);
 const nextCheckpoint=await checkpoint(checkpointSigner,'t','v',1,advanced.root,root,advanced.operationDigest);
 const advancedReceipt=await witness.accept({prior:left,rosters:[three],checkpoints:[cp,nextCheckpoint]});
 await expect(witness.accept({prior:first,rosters:[one,two,three],checkpoints:[cp]})).rejects.toThrow('stale_checkpoint');
 await expect(witness.requireLatest([one,two,three],cp)).rejects.toThrow('not_latest');
 const candidates=await Promise.all([1,2].map(async offset=>sign({...r,revision:4,previousDigest:await rosterDigest(three),expiresAt:r.expiresAt+offset})));
 const race=await Promise.allSettled(candidates.map(candidate=>witness.accept({prior:advancedReceipt,rosters:[three,candidate],checkpoints:[nextCheckpoint]})));
 expect(race.filter(result=>result.status==='fulfilled')).toHaveLength(1);expect(race.filter(result=>result.status==='rejected')).toHaveLength(1);db.close();
 const {consistentWitnessSnapshot}=await import('../managed-cloud/shared/roster-witness.ts');let reads=0,acks=0;
 const snapshot=await consistentWitnessSnapshot(async()=>({head:{revision:++reads===1?1:2,digest:'current'}}),async()=>({canonical:JSON.stringify({revision:++acks===1?1:2,digest:'current'}),signature:'synthetic'}));
 expect(snapshot.head.revision).toBe(2);expect(acks).toBe(2);
 await expect(consistentWitnessSnapshot(async()=>({head:{revision:2,digest:'current'}}),async()=>({canonical:JSON.stringify({revision:1,digest:'old'}),signature:'synthetic'}))).rejects.toThrow('concurrent_change');
});

test('incremental witness crosses 257 revisions and 10000 checkpoints with bounded pages and restart',async()=>{
 const {rosterWitness}=await import('../managed-cloud/shared/roster-witness.ts'),{readFileSync}=await import('node:fs');
 const db=new Database(':memory:');db.exec(readFileSync(new URL('../managed-cloud/recovery-worker/migrations/0004_roster_witness.sql',import.meta.url),'utf8'));db.exec(readFileSync(new URL('../managed-cloud/recovery-worker/migrations/0007_witness_suffixes.sql',import.meta.url),'utf8'));
 const adapter={prepare:(sql:string)=>({bind:(...values:unknown[])=>({first:async()=>db.query(sql).get(...values as never[]),run:async()=>db.query(sql).run(...values as never[])})})} as unknown as Parameters<typeof rosterWitness>[0];
 const {a,one,checkpointSigner}=await revokedChain(),key=sodium.crypto_sign_keypair(),signer={key:async()=>({keyId:'witness',publicKey:b(key.publicKey)}),sign:async(c:string)=>b(sodium.crypto_sign_detached(c,key.privateKey))};
 const fresh=()=>rosterWitness(adapter,signer,a.checkpointKeys,async row=>row.canonical===one.canonical);
 let roster=one,cp=await checkpoint(checkpointSigner,'t','v',0,await genesisRoot('t','v'),null,null),prior=await fresh().accept({rosters:[roster],checkpoints:[cp]});
 for(let revision=2;revision<=258;revision++){
  const next=sign({...JSON.parse(roster.canonical),revision,previousDigest:await rosterDigest(roster)});
  prior=await fresh().accept({prior,rosters:[roster,next],checkpoints:[cp]});roster=next;
 }
 const {advanceRoot}=await import('../managed-cloud/shared/checkpoints.ts');
 for(let start=1;start<=10001;){
  const page=[cp];
  for(let n=0;n<127&&start<=10001;n++,start++){
   const root=JSON.parse(cp.canonical).root,advanced=await advanceRoot(root,start,roster);
   cp=await checkpoint(checkpointSigner,'t','v',start,advanced.root,root,advanced.operationDigest);page.push(cp);
  }
  const request={prior,rosters:[roster],checkpoints:page};prior=await fresh().accept(request);
  expect(await fresh().accept(request)).toEqual(prior);
 }
 const h=await fresh().head('t','v');expect(h?.revision).toBe(258);expect(h?.sequence).toBe(10001);
 await expect(fresh().accept({prior,rosters:[roster],checkpoints:[JSON.parse(h!.checkpoint),await checkpoint(checkpointSigner,'t','v',10003,'a'.repeat(64),h!.root,'b'.repeat(64))]})).rejects.toThrow();
 db.close();
});

test('Main paginates independent witness suffixes and resumes a lost response from Custodian heads',async()=>{
 const {rosterWitness}=await import('../managed-cloud/shared/roster-witness.ts'),{acknowledgeRoster}=await import('../managed-cloud/api-worker/roster-witness.ts'),{readFileSync}=await import('node:fs');
 const db=new Database(':memory:');
 for(const name of ['0004_roster_witness.sql','0007_witness_suffixes.sql'])db.exec(readFileSync(new URL('../managed-cloud/recovery-worker/migrations/'+name,import.meta.url),'utf8'));
 db.exec('CREATE TABLE signed_rosters(tenant_id TEXT,vault_id TEXT,revision INTEGER,canonical TEXT,signature TEXT);CREATE TABLE sync_checkpoints(tenant_id TEXT,vault_id TEXT,sequence INTEGER,canonical TEXT,signature TEXT);CREATE TABLE roster_witness_sagas(tenant_id TEXT,vault_id TEXT,revision INTEGER,digest TEXT,state TEXT,receipt TEXT)');
 const adapter={prepare:(sql:string)=>({bind:(...values:unknown[])=>({first:async(field?:string)=>{const row=db.query(sql).get(...values as never[]) as Record<string,unknown>|null;return field?row?.[field]??null:row;},all:async()=>({results:db.query(sql).all(...values as never[])}),run:async()=>db.query(sql).run(...values as never[])})})};
 const {a,one,checkpointSigner}=await revokedChain(),key=sodium.crypto_sign_keypair(),signer={key:async()=>({keyId:'witness',publicKey:b(key.publicKey)}),sign:async(c:string)=>b(sodium.crypto_sign_detached(c,key.privateKey))};
 const witness=rosterWitness(adapter as unknown as Parameters<typeof rosterWitness>[0],signer,a.checkpointKeys,async row=>row.canonical===one.canonical);
 let roster=one;
 for(let revision=1;revision<=258;revision++){
  if(revision>1)roster=sign({...JSON.parse(roster.canonical),revision,previousDigest:await rosterDigest(roster)});
  db.run('INSERT INTO signed_rosters VALUES(?,?,?,?,?)',['t','v',revision,roster.canonical,roster.signature]);db.run('INSERT INTO roster_witness_sagas VALUES(?,?,?,?,?,NULL)',['t','v',revision,await rosterDigest(roster),'pending']);
 }
 const {advanceRoot}=await import('../managed-cloud/shared/checkpoints.ts');let root=await genesisRoot('t','v');
 for(let sequence=0;sequence<=260;sequence++){
  const advanced=sequence?await advanceRoot(root,sequence,roster):null,cp=await checkpoint(checkpointSigner,'t','v',sequence,advanced?.root??root,sequence?root:null,advanced?.operationDigest??null);root=JSON.parse(cp.canonical).root;
  db.run('INSERT INTO sync_checkpoints VALUES(?,?,?,?,?)',['t','v',sequence,cp.canonical,cp.signature]);
 }
 let lose=true,pages=0;
 const rpc={head:async()=>{const h=await witness.head('t','v');return h?JSON.parse(h.receipt):null;},witness:async(input:Parameters<typeof witness.accept>[0])=>{pages++;expect(input.rosters.length).toBeLessThanOrEqual(128);expect(input.checkpoints.length).toBeLessThanOrEqual(128);const result=await witness.accept(input);if(lose){lose=false;throw new Error('response_lost');}return result;}};
 await expect(acknowledgeRoster(adapter as unknown as Parameters<typeof acknowledgeRoster>[0],'t','v',rpc,checkpointSigner)).rejects.toThrow('response_lost');
 const receipt=await acknowledgeRoster(adapter as unknown as Parameters<typeof acknowledgeRoster>[0],'t','v',rpc,checkpointSigner);
 expect(JSON.parse(receipt.canonical)).toMatchObject({revision:258,sequence:260});expect(pages).toBeGreaterThan(3);
 expect(await acknowledgeRoster(adapter as unknown as Parameters<typeof acknowledgeRoster>[0],'t','v',rpc,checkpointSigner)).toEqual(receipt);db.close();
});
