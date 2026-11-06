/* global RequestInit */
import {test,expect} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalManifest,verifyReleaseManifest} from '../src/cloud/config.ts';
import {canonicalRecoveryRelease,RECOVERY_RELEASE_DOMAIN} from '../managed-cloud/shared/recovery-release.ts';
import {recoverVaultKey} from '../src/cloud/recovery.ts';
import {seal,splitRecoveryKey,wrapVaultKey} from '../managed-cloud/shared/recovery-crypto.ts';
import {releaseContext,vaultKeyContext,type RecoveryCase,type RecoveryManifest} from '../managed-cloud/shared/recovery.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';
await sodium.ready;
const b=(v:Uint8Array)=>Buffer.from(v).toString('base64');
async function fixture(){
 const api=sodium.crypto_sign_keypair(),custodian=sodium.crypto_sign_keypair(),root=sodium.crypto_sign_keypair(),authority=sodium.crypto_sign_keypair(),target=sodium.crypto_box_keypair(),signing=sodium.crypto_sign_keypair();
 const pins={api:{keyId:'api',publicKey:b(api.publicKey)},custodian:{keyId:'custodian',publicKey:b(custodian.publicKey)}};
 const canonical=canonicalManifest({version:1,releaseId:'test',apiOrigin:'https://synthetic.invalid',protocolMin:2,protocolMax:2,checkpointKeys:[pins.api],recoveryAuthorities:[{keyId:'authority',publicKey:b(authority.publicKey)}],recoveryServices:pins});
 const policy=verifyReleaseManifest({canonical,signature:b(sodium.crypto_sign_detached(canonical,root.privateKey))},root.publicKey);
 const now=Math.floor(Date.now()/1000),c:RecoveryCase={version:1,id:'case',packageId:'package',accountId:'a',tenantId:'t',vaultId:'v',keyEpoch:1,targetDeviceId:'x'.repeat(43),signingKey:b(signing.publicKey),wrappingKey:b(target.publicKey),createdAt:now,notBefore:now+86400,expiresAt:now+172800,nonce:'nonce'};
 const recoveryKey=sodium.randombytes_buf(32),vdk=sodium.randombytes_buf(32),shares=splitRecoveryKey(recoveryKey),empty=await seal(b(target.publicKey),shares[0],'unused');
 const m:RecoveryManifest={version:1,packageId:c.packageId,accountId:'a',tenantId:'t',vaultId:'v',keyEpoch:1,policy:'two-party-24h',issuerDeviceId:'issuer',apiKeyId:'api',custodianKeyId:'custodian',wrappedVDK:'',apiShare:empty,custodianShare:empty};
 m.wrappedVDK=await wrapVaultKey(recoveryKey,vdk,vaultKeyContext(m));
 const caseCanonical=JSON.stringify(c),manifestCanonical=JSON.stringify(m),evidence={mode:'device' as const,confirmerId:'issuer',signature:b(new Uint8Array(64)),proof:null};
 const releases=await Promise.all((['api','custodian'] as const).map(async(p,i)=>{const canonical=canonicalRecoveryRelease({version:1,party:p,keyId:p,caseCanonical,manifestDigest:await digest(manifestCanonical),evidenceDigest:await digest(JSON.stringify(evidence)),expiresAt:c.expiresAt,box:await seal(b(target.publicKey),shares[i]!,releaseContext(caseCanonical,p))});return {canonical,signature:b(sodium.crypto_sign_detached(RECOVERY_RELEASE_DOMAIN+canonical,(p==='api'?api:custodian).privateKey))};}));
 shares.forEach(s=>s.fill(0));recoveryKey.fill(0);
 return {policy,c,target,vdk,evidence,authority,signing,api,input:{caseCanonical,manifestCanonical,api:releases[0]!,custodian:releases[1]!},pins};
}
test('reconstructs only independently authenticated target-bound releases',async()=>{
 const f=await fixture();const result=await recoverVaultKey(f.input,f.c,f.evidence,f.target.privateKey,f.policy);expect(result).toEqual(f.vdk);result.fill(0);
});
test('rejects target, epoch, authority, evidence, expiry, share and manifest substitution',async()=>{
 const f=await fixture();
 for(const changed of [{...f.c,keyEpoch:2},{...f.c,wrappingKey:b(sodium.crypto_box_keypair().publicKey)},{...f.c,id:'other'}])await expect(recoverVaultKey(f.input,changed,f.evidence,f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(recoverVaultKey(f.input,f.c,{...f.evidence,confirmerId:'other'},f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(recoverVaultKey(f.input,f.c,f.evidence,sodium.crypto_box_keypair().privateKey,f.policy)).rejects.toThrow();
 await expect(recoverVaultKey({...f.input,api:f.input.custodian},f.c,f.evidence,f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(recoverVaultKey({...f.input,manifestCanonical:f.input.manifestCanonical.replace('"keyEpoch":1','"keyEpoch":2')},f.c,f.evidence,f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(recoverVaultKey(f.input,f.c,f.evidence,f.target.privateKey,f.policy,f.c.expiresAt)).rejects.toThrow();
 await expect(recoverVaultKey(f.input,f.c,f.evidence,f.target.privateKey,{...f.policy})).rejects.toThrow();
});
test('release manifests require independent API and Custodian role pins',async()=>{
 const f=await fixture();expect(()=>canonicalManifest({...f.policy,recoveryServices:{api:f.pins.api,custodian:f.pins.api}})).toThrow();
});
import {Database} from 'bun:sqlite';
import {MemorySecureStore,type SecureAccount} from '../src/platform/secure-store.ts';
import {RecoveryJournal} from '../src/cloud/recovery-journal.ts';
test('secure-first intent survives SQLite failure and resumes exactly without regenerating keys',async()=>{
 const secure=new MemorySecureStore(),db=new Database(':memory:');
 const journal=await RecoveryJournal.begin(db,secure,'package');const first=journal.snapshot();
 db.exec("CREATE TRIGGER reject_recovery BEFORE UPDATE ON cloud_state BEGIN SELECT RAISE(ABORT,'injected'); END");
 await expect(journal.advance('awaiting_verification',{requestRef:'x'.repeat(43)})).rejects.toThrow('injected');journal.close();
 db.exec('DROP TRIGGER reject_recovery');
 const resumed=await RecoveryJournal.resume(db,secure);
 expect(resumed!.snapshot().stage).toBe('awaiting_verification');
 expect(resumed!.snapshot().target).toEqual(first.target);
 const row=db.query("SELECT ciphertext FROM cloud_state WHERE id='recovery-intent'").get() as {ciphertext:Uint8Array};
 expect(Buffer.from(row.ciphertext).includes(Buffer.from(first.target.signingKey))).toBe(false);
 resumed!.close();db.close();
});
test('secure-store failure leaves original recoverable intent and conflicting enrollment fails closed',async()=>{
 class Failing extends MemorySecureStore {fail=false;override async put(a:SecureAccount,v:Uint8Array){if(this.fail)throw new Error('injected');return super.put(a,v);}}
 const secure=new Failing(),db=new Database(':memory:'),journal=await RecoveryJournal.begin(db,secure,'package');secure.fail=true;
 await expect(journal.advance('awaiting_verification',{requestRef:'x'.repeat(43)})).rejects.toThrow('injected');secure.fail=false;journal.close();
 const resumed=await RecoveryJournal.resume(db,secure);expect(resumed!.snapshot().stage).toBe('created');resumed!.close();
 await expect(RecoveryJournal.begin(db,secure,'other')).rejects.toThrow('conflict');
 db.close();
});
test('secure-store committed response loss resumes the committed stage and rejects stale writer reuse',async()=>{
 class Lost extends MemorySecureStore {lose=false;override async put(a:SecureAccount,v:Uint8Array){await super.put(a,v);if(this.lose)throw new Error('response_lost');}}
 const secure=new Lost(),db=new Database(':memory:'),journal=await RecoveryJournal.begin(db,secure,'package');secure.lose=true;
 await expect(journal.advance('awaiting_verification',{requestRef:'x'.repeat(43)})).rejects.toThrow('response_lost');
 await expect(journal.advance('awaiting_verification',{})).rejects.toThrow('closed');secure.lose=false;
 const resumed=await RecoveryJournal.resume(db,secure);expect(resumed!.snapshot().stage).toBe('awaiting_verification');resumed!.close();db.close();
});

import {RecoveryTarget} from '../src/cloud/recovery-target.ts';
test('target registration persists reference before HTTP and resumes response loss with the same keys and reference',async()=>{
 const f=await fixture(),secure=new MemorySecureStore(),db=new Database(':memory:');
 let journal=await RecoveryJournal.begin(db,secure,'package'),lost=true,registered:string|undefined;
 const initial=journal.snapshot().target;
 const network=async(url:string,init:RequestInit)=>{
  const body=JSON.parse(init.body as string);
  if(url.endsWith('recovery-target-challenge')){
   expect(sodium.crypto_sign_verify_detached(Buffer.from(body.signature,'base64'),JSON.stringify(['AgentKeychain-recovery-target-v1',body.target]),Buffer.from(initial.signingKey,'base64'))).toBe(true);
   const challengeRef='c'.repeat(43),box=await seal(initial.wrappingKey,new TextEncoder().encode('p'.repeat(43)),'AgentKeychain-recovery-target-possession-v1\0'+challengeRef+'\0'+JSON.stringify(initial));
   return Response.json({challengeRef,box});
  }
  expect(sodium.crypto_sign_verify_detached(Buffer.from(body.signature,'base64'),JSON.stringify(['AgentKeychain-recovery-target-request-v1',body.target,body.requestRef]),Buffer.from(initial.signingKey,'base64'))).toBe(true);
  expect(body.requestRef).toBe(journal.snapshot().data.requestRef);
  if(registered)expect(body.requestRef).toBe(registered);registered=body.requestRef;
  if(lost){lost=false;throw new Error('lost');}
  return Response.json({requestRef:registered,expiresIn:172800});
 };
 await expect(new RecoveryTarget(journal,{policy:f.policy,secure,network}).register()).rejects.toThrow('cloud_network_unavailable');
 expect(journal.snapshot().stage).toBe('created');journal.close();journal=(await RecoveryJournal.resume(db,secure))!;
 expect(journal.snapshot().target).toEqual(initial);
 await new RecoveryTarget(journal,{policy:f.policy,secure,network}).register();
 expect(journal.snapshot().stage).toBe('awaiting_verification');journal.close();db.close();
});
import {issueRecoveryTrust} from '../managed-cloud/shared/recovery-trust.ts';
import {openRecoveryTrust} from '../src/cloud/recovery-trust.ts';
import {signRoster} from '../src/cloud/roster.ts';
import {checkpoint,genesisRoot} from '../managed-cloud/shared/checkpoints.ts';
async function trustFixture(revoke=false,witness=false){
 const f=await fixture(),signer={key:async()=>f.policy.recoveryAuthorities![0]!,sign:async(s:string)=>b(sodium.crypto_sign_detached(s,f.authority.privateKey))};
 const witnessKey=sodium.crypto_sign_keypair();
 if(witness){const root=sodium.crypto_sign_keypair(),canonical=canonicalManifest({...JSON.parse(canonicalManifest(f.policy)),witnessKeys:[{keyId:'witness',publicKey:b(witnessKey.publicKey)}]});f.policy=verifyReleaseManifest({canonical,signature:b(sodium.crypto_sign_detached(canonical,root.privateKey))},root.publicKey);}
 const previous=signRoster({version:1,accountId:'a',tenantId:'t',vaultId:'v',revision:1,previousDigest:null,keyEpoch:1,active:[{deviceId:'issuer',signingKey:b(f.signing.publicKey),wrappingKey:b(sodium.crypto_box_keypair().publicKey)}],revoked:[],issuer:{kind:'device',id:'issuer'},issuedAt:f.c.createdAt,expiresAt:f.c.createdAt+2592000,checkpointKeys:[...f.policy.checkpointKeys],recoveryAuthorities:[...f.policy.recoveryAuthorities!],recovery:null},f.signing.privateKey);
 // The recovered target has a distinct signing key from its confirmer.
 f.c.signingKey=b(sodium.crypto_sign_keypair().publicKey);f.input.caseCanonical=JSON.stringify(f.c);
 const cp=await checkpoint({key:async()=>f.pins.api,sign:async(s:string)=>b(sodium.crypto_sign_detached(s,f.api.privateKey))},'t','v',0,await genesisRoot('t','v'),null,null);
 const witnessReceipt=async(rows:import('../src/cloud/protocol.ts').SignedManagedOperation[])=>{const {rosterDigest}=await import('../managed-cloud/shared/roster.ts'),head=rows.at(-1)!,r=JSON.parse(head.canonical),c=JSON.parse(cp.canonical),canonical=JSON.stringify({version:1,keyId:'witness',accountId:'a',tenantId:'t',vaultId:'v',event:r.revision,revision:r.revision,digest:await rosterDigest(head),sequence:c.sequence,root:c.root,checkpointDigest:await digest(JSON.stringify(cp))});return {canonical,signature:b(sodium.crypto_sign_detached('AgentKeychain-independent-roster-witness-v1\0'+canonical,witnessKey.privateKey))};};
 const issued=await issueRecoveryTrust({caseCanonical:f.input.caseCanonical,manifestCanonical:f.input.manifestCanonical,packageSignature:b(sodium.crypto_sign_detached(f.input.manifestCanonical,f.signing.privateKey)),rosters:[previous],checkpoint:cp,...(revoke?{revocations:[{deviceId:'issuer',acceptedThrough:cp}]}:{})},canonicalManifest(f.policy),signer,witness?witnessReceipt:undefined);
 return {...f,...issued,witnessReceipt};
}
test('authority-encrypted trust binds release, case, target, epoch, chain and checkpoint',async()=>{
 const f=await trustFixture(),expected={caseCanonical:f.input.caseCanonical,manifestCanonical:f.input.manifestCanonical};
 const accepted=await openRecoveryTrust(f.sealed,expected,f.target.privateKey,f.policy);
 expect(accepted.roster.revision).toBe(2);expect(accepted.checkpoint.sequence).toBe(0);
 for(const c of [{...f.c,id:'substituted'},{...f.c,keyEpoch:2},{...f.c,signingKey:b(sodium.crypto_sign_keypair().publicKey)}])await expect(openRecoveryTrust(f.sealed,{...expected,caseCanonical:JSON.stringify(c)},f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(openRecoveryTrust(f.sealed,{...expected,manifestCanonical:'substituted'},f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(openRecoveryTrust(f.sealed,{...expected,rosterAnchor:{revision:3,digest:'0'.repeat(64)}},f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(openRecoveryTrust(f.sealed,{...expected,checkpointAnchor:{sequence:1,root:'0'.repeat(64)}},f.target.privateKey,f.policy)).rejects.toThrow();
 await expect(openRecoveryTrust(f.sealed,expected,sodium.crypto_box_keypair().privateKey,f.policy)).rejects.toThrow();
});
test('terminal recovery replaces key material with a durable nonsecret tombstone',async()=>{
 for(const stage of ['cancelled','expired','conflict'] as const){
  const secure=new MemorySecureStore(),db=new Database(':memory:'),j=await RecoveryJournal.begin(db,secure,'package');
  await j.update({vdk:b(sodium.randombytes_buf(32))});await j.advance(stage);j.close();
  const bytes=await secure.get('recovery-intent');const intent=JSON.parse(Buffer.from(bytes!).toString());bytes!.fill(0);
  expect(Object.values(intent.keys).every(v=>v==='')).toBe(true);expect(Object.keys(intent.snapshot.data).length).toBe(0);
  await expect(RecoveryJournal.resume(db,secure)).rejects.toThrow('cloud_recovery_'+stage);
  expect(db.query("SELECT 1 FROM cloud_state WHERE id='recovery-intent'").get()).toBeNull();
  await RecoveryJournal.clearTerminal(db,secure);const fresh=await RecoveryJournal.begin(db,secure,'package');expect(fresh.snapshot().stage).toBe('created');fresh.close();await expect(RecoveryJournal.clearTerminal(db,secure)).rejects.toThrow('not_terminal');db.close();
 }
});

test('recovery authority carries signed historical revocation boundaries into the recovered roster',async()=>{
 const f=await trustFixture(true);const result=await openRecoveryTrust(f.sealed,{caseCanonical:f.input.caseCanonical,manifestCanonical:f.input.manifestCanonical},f.target.privateKey,f.policy);expect(result.roster.revoked.map(d=>d.deviceId)).toEqual(['issuer']);expect(result.roster.active.map(d=>d.deviceId)).toEqual([f.c.targetDeviceId]);
});

test('activation binding verifies exact signed/sealed bytes and every field before accepting trust',async()=>{
 const f=await trustFixture(false,true),{trustActivationBinding}=await import('../managed-cloud/shared/trust-activation.ts');
 const expected={caseCanonical:f.input.caseCanonical,manifestCanonical:f.input.manifestCanonical};
 const binding=await trustActivationBinding(f.input.caseCanonical,1,{signedDigest:f.signedDigest,sealed:f.sealed,refreshDigest:f.bundle.refreshDigest,roster:f.bundle.rosters.at(-1)!,witness:f.bundle.witness!,checkpoint:f.bundle.checkpoint});
 expect((await openRecoveryTrust(f.sealed,{...expected,activation:binding},f.target.privateKey,f.policy)).bundle.refreshDigest).toBe(binding.refreshDigest);
 for(const field of Object.keys(binding)){
  const old=binding[field as keyof typeof binding],changed={...binding,[field]:typeof old==='number'?old+1:'substituted'};
  await expect(openRecoveryTrust(f.sealed,{...expected,activation:changed},f.target.privateKey,f.policy)).rejects.toThrow('cloud_invalid_recovery_trust');
 }
});

test('compact recovery accepts a latest independently witnessed head and preserves existing anchor checks',async()=>{
 const f=await trustFixture(false,true),{rosterDigest}=await import('../managed-cloud/shared/roster.ts'),{trustActivationBinding}=await import('../managed-cloud/shared/trust-activation.ts');
 const prior=f.bundle.rosters.at(-1)!,next=signRoster({...JSON.parse(prior.canonical),revision:3,previousDigest:await rosterDigest(prior),issuer:{kind:'device',id:'issuer'},recovery:null},f.signing.privateKey);
 const bundle={...f.bundle,rosters:[next],witness:await f.witnessReceipt([next])},canonical=JSON.stringify(bundle),signed={canonical,signature:b(sodium.crypto_sign_detached('AgentKeychain-recovery-trust-v1\0'+canonical,f.authority.privateKey))};
 const sealed=await seal(f.c.wrappingKey,Buffer.from(JSON.stringify(signed)),'AgentKeychain-recovery-trust-v1\0'+f.input.caseCanonical);
 const binding=await trustActivationBinding(f.input.caseCanonical,1,{signedDigest:await digest(JSON.stringify(signed)),sealed,refreshDigest:bundle.refreshDigest,roster:next,witness:bundle.witness,checkpoint:bundle.checkpoint});
 const expected={caseCanonical:f.input.caseCanonical,manifestCanonical:f.input.manifestCanonical,activation:binding};
 expect((await openRecoveryTrust(sealed,expected,f.target.privateKey,f.policy)).roster.revision).toBe(3);
 await expect(openRecoveryTrust(sealed,{...expected,rosterAnchor:{revision:2,digest:await rosterDigest(prior)}},f.target.privateKey,f.policy)).rejects.toThrow();
 const wrongWitness={...bundle.witness,signature:b(new Uint8Array(64))},bad={...bundle,witness:wrongWitness},body=JSON.stringify(bad),badSealed=await seal(f.c.wrappingKey,Buffer.from(JSON.stringify({canonical:body,signature:b(sodium.crypto_sign_detached('AgentKeychain-recovery-trust-v1\0'+body,f.authority.privateKey))})),'AgentKeychain-recovery-trust-v1\0'+f.input.caseCanonical);
 await expect(openRecoveryTrust(badSealed,{caseCanonical:f.input.caseCanonical,manifestCanonical:f.input.manifestCanonical},f.target.privateKey,f.policy)).rejects.toThrow();
});
