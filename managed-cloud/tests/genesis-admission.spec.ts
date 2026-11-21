import {beforeEach,expect,test,vi} from 'vitest';
import {applyD1Migrations} from 'cloudflare:test';
import {env} from 'cloudflare:workers';
import {checkpoint,genesisRoot} from '../shared/checkpoints.ts';
import {canonicalGrant} from '../shared/device-protocol.ts';
import {deviceRepository} from '../api-worker/device-repository.ts';
import {stagePilotGenesisMainBinding} from '../api-worker/genesis-main-binding-stage.ts';
import {admitGenesis} from '../shared/genesis-admission.ts';
import {MAIN_BIND_GENESIS,mainGenesisBindingDeviceProof,readExactMainGenesisAdmission,verifyMainGenesisBinding} from '../shared/genesis-main-binding.ts';
import {custodyAbsenceHeadRequestProof,proveCustodyAbsenceHead} from '../custody-trust-worker/package-absence-head.ts';
import {digest,verify} from '../shared/contracts.ts';
import {rosterDigest} from '../shared/roster.ts';
import {rosterWitness,verifyWitness} from '../shared/roster-witness.ts';
import {hasExactHistoricalGenesisApproval} from '../auth-trust-worker/experimental/historical-genesis-reconciliation.ts';
import {enrollmentFixture,signingFixture} from './synthetic-genesis-approval.ts';

const db=env.CUSTODIAN;
beforeEach(async()=>{await applyD1Migrations(db,env.MIGRATIONS);});
const count=(table:'genesis_admissions'|'roster_witness',vaultId:string)=>db.prepare('SELECT count(*) n FROM '+table+' WHERE vault_id=?').bind(vaultId).first<number>('n');
const current=()=>Math.floor(Date.now()/1000);
async function attempt(now:number,vaultId:string,decisionId='approval-'+vaultId){
 const f=await enrollmentFixture(now,vaultId),w=await signingFixture();
 const {tenantId}=f.grant;
 const cp=await checkpoint({key:async()=>f.policy.checkpointKeys[0]!,sign:f.checkpoint.sign},tenantId,vaultId,0,await genesisRoot(tenantId,vaultId),null,null);
 const grant=canonicalGrant(f.grant),{proof}=await f.approval({decisionId},grant);
 const sign=vi.fn(w.sign),witness={keyId:w.keyId,publicKey:w.publicKey,signer:{key:async()=>({keyId:w.keyId,publicKey:w.publicKey}),sign}};
 return {f,witness,sign,request:{proof,grant,roster:f.roster,checkpoint:cp}};
}
test('commits an independently approved genesis and reloads its initial witness on exact stale retry',async()=>{
 const {f,witness,request,sign}=await attempt(current(),'success');
 const result=await admitGenesis(db,request,f.policy,witness);
 const data=JSON.parse(result.canonical);
 expect(data).toMatchObject({vaultId:f.grant.vaultId,event:1,revision:1,sequence:0});
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(1);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(1);
 // A restarted client can present the exact prior operation. A fresh signature is not required.
 const future=vi.spyOn(Date,'now').mockReturnValue((current()+100)*1000);
 try{expect(await admitGenesis(db,JSON.parse(JSON.stringify(request)),f.policy,witness)).toEqual(result);}
 finally{future.mockRestore();}
 expect(sign).toHaveBeenCalledTimes(1);
});
test('serializes retries of the exact same genesis to one record',async()=>{
 const {f,witness,request}=await attempt(current(),'concurrent');
 const present=()=>admitGenesis(db,request,f.policy,witness);
 const [a,b]=await Promise.all([present(),present()]);
 expect(a).toEqual(b);
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(1);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(1);
});
test('does not consume an approval when first witness storage fails',async()=>{
 const {f,witness,request}=await attempt(current(),'witness-error');
 await db.prepare("CREATE TRIGGER test_witness_write_failure BEFORE INSERT ON roster_witness WHEN NEW.vault_id='witness-error' BEGIN SELECT RAISE(ABORT,'fixture_io_failure'); END").run();
 await expect(admitGenesis(db,request,f.policy,witness)).rejects.toThrow('genesis_admission_conflict');
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(0);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(0);
});
test('does not leave a witness when the admission write fails',async()=>{
 const {f,witness,request}=await attempt(current(),'admission-error');
 await db.prepare("CREATE TRIGGER test_admission_write_failure BEFORE INSERT ON genesis_admissions WHEN NEW.vault_id='admission-error' BEGIN SELECT RAISE(ABORT,'fixture_io_failure'); END").run();
 await expect(admitGenesis(db,request,f.policy,witness)).rejects.toThrow('genesis_admission_conflict');
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(0);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(0);
});
test('checks expiry again at commit using the custody database clock',async()=>{
 // The JS verifier clock is abstract; D1 must reject if its clock already passed expiry.
 const now=current()-120,{f,witness,request}=await attempt(now,'expired');
 const clock=vi.spyOn(Date,'now').mockReturnValue(now*1000);
 try{await expect(admitGenesis(db,request,f.policy,witness)).rejects.toThrow('genesis_admission_conflict');}
 finally{clock.mockRestore();}
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(0);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(0);
});
test('two valid distinct approvals cannot create a second initial witness, even concurrently',async()=>{
 const {f,witness,request}=await attempt(current(),'explicit-race');
 const another=await f.approval({decisionId:'another-decision'});
 const results=await Promise.allSettled([admitGenesis(db,request,f.policy,witness),admitGenesis(db,{...request,proof:another.proof},f.policy,witness)]);
 expect(results.filter(r=>r.status==='fulfilled')).toHaveLength(1);
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(1);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(1);
});
test('rejects a second admission with the same decision ID and leaves its vault unwitnessed',async()=>{
 const first=await attempt(current(),'first-vault','duplicate-decision'),next=await attempt(current(),'next-vault','duplicate-decision');
 await admitGenesis(db,first.request,first.f.policy,first.witness);
 await expect(admitGenesis(db,next.request,next.f.policy,next.witness)).rejects.toThrow('genesis_admission_conflict');
 expect(await count('genesis_admissions',first.f.grant.vaultId)).toBe(1);
 expect(await count('genesis_admissions',next.f.grant.vaultId)).toBe(0);
 expect(await count('roster_witness',first.f.grant.vaultId)).toBe(1);
 expect(await count('roster_witness',next.f.grant.vaultId)).toBe(0);
});

async function absence(vaultId:string){
 const initialTime=current(),{f,witness,request}=await attempt(initialTime,vaultId);
 const accepted=await admitGenesis(db,request,f.policy,witness);
 const [live,other]=await Promise.all([signingFixture(),signingFixture()]);
 const policy={...f.policy,witness:{keyId:witness.keyId,publicKey:witness.publicKey},currentHead:live,otherReleaseKeys:[other]};
 const signer={key:async()=>live,sign:vi.fn(live.sign)};
 const {grant:originalGrant,proof:initialApproval,roster}=request;
 const requestedAt=f.grant.expiresAt+1,nonce='A'.repeat(43);
 const deviceSignature=await f.device.sign(custodyAbsenceHeadRequestProof(nonce,requestedAt,f.grant.requestId,await digest(originalGrant),await rosterDigest(roster)));
 return {f,accepted,signer,live,policy,request,input:{nonce,requestedAt,deviceSignature,originalGrant,initialApproval,roster}};
}
test('Custody signs the current independently admitted origin after historical grant expiry, without writes',async()=>{
 const {f,accepted,signer,policy,input}=await absence('bound-current-head');
 const clock=vi.spyOn(Date,'now').mockReturnValue(input.requestedAt*1000);
 try{
  const {witness,head}=await proveCustodyAbsenceHead(db,input,policy,signer);
  expect(witness).toEqual(accepted);
  const {requestId,accountId,tenantId,vaultId,deviceId,keyEpoch}=f.grant;
  expect(head.canonical).toBe(JSON.stringify({version:1,domain:'AgentKeychain-enrollment-continuation-package-absence-current-head-v1',
   keyId:policy.currentHead.keyId,nonce:input.nonce,requestId,grantDigest:await digest(input.originalGrant),rosterDigest:await rosterDigest(input.roster),
   accountId,tenantId,vaultId,deviceId,keyEpoch,rosterRevision:1,witnessDigest:await digest(JSON.stringify([witness.canonical,witness.signature])),
   status:'current',issuedAt:input.requestedAt,expiresAt:input.requestedAt+30}));
  expect(await verify(policy.currentHead.publicKey,head.signature,head.canonical)).toBe(true);
  expect(await count('roster_witness',vaultId)).toBe(1);
  expect(await count('genesis_admissions',vaultId)).toBe(1);
 }finally{clock.mockRestore();}
});
test('Custody denies missing independent provenance, wrong scopes, expired challenge and same historical sign role',async()=>{
 const {f,signer,policy,input}=await absence('bound-provenance');
 const clock=vi.spyOn(Date,'now').mockReturnValue(input.requestedAt*1000);
 const deny=()=>expect(signer.sign).not.toHaveBeenCalled();
 try{
  const alternate=await f.approval({decisionId:'disjoint-decision'});
  await expect(proveCustodyAbsenceHead(db,{...input,initialApproval:alternate.proof},policy,signer)).rejects.toThrow('continuation_absence_head_unavailable');
  await expect(proveCustodyAbsenceHead(db,{...input,nonce:'B'+'A'.repeat(42)},policy,signer)).rejects.toThrow('continuation_absence_head_unavailable');
  await expect(proveCustodyAbsenceHead(db,input,{...policy,witness:policy.currentHead},signer)).rejects.toThrow('continuation_absence_head_unavailable');
  // Legacy genesis form can have the exact current witness but no independent admission record.
  const legacy=await enrollmentFixture(current()-600,'legacy-no-admission'),legacyWitness=await signingFixture();
  const {tenantId,vaultId}=legacy.grant;
  const cp=await checkpoint({key:async()=>legacy.policy.checkpointKeys[0]!,sign:legacy.checkpoint.sign},tenantId,vaultId,0,await genesisRoot(tenantId,vaultId),null,null);
  const originalGrant=canonicalGrant(legacy.grant),{proof}=await legacy.approval();
  const nonce=input.nonce,requestedAt=input.requestedAt,roster=legacy.roster;
  const hash=await rosterDigest(roster);
  await rosterWitness(db,{key:async()=>legacyWitness,sign:legacyWitness.sign},legacy.policy.checkpointKeys,async()=>true,legacy.policy.recoveryAuthorities)
   .accept({rosters:[roster],checkpoints:[cp]});
  expect(await count('roster_witness',vaultId)).toBe(1);
  expect(await count('genesis_admissions',vaultId)).toBe(0);
  const deviceSignature=await legacy.device.sign(custodyAbsenceHeadRequestProof(nonce,requestedAt,legacy.grant.requestId,await digest(originalGrant),hash));
  await expect(proveCustodyAbsenceHead(db,{nonce,requestedAt,deviceSignature,originalGrant,initialApproval:proof,roster},
   {...policy,...legacy.policy,witness:legacyWitness},signer)).rejects.toThrow('continuation_absence_head_unavailable');
  clock.mockReturnValue((input.requestedAt+30)*1000);
  await expect(proveCustodyAbsenceHead(db,input,policy,signer)).rejects.toThrow('continuation_absence_head_unavailable');
  deny();
 }finally{clock.mockRestore();}
});
test('Custody suppresses signed response if an immutable revocation arrives during signing',async()=>{
 const {f,signer,live,policy,input}=await absence('during-signer-veto');
 const clock=vi.spyOn(Date,'now').mockReturnValue(input.requestedAt*1000);
 const {tenantId,vaultId,deviceId}=f.grant;
 try{
  signer.sign.mockImplementationOnce(async bytes=>{
   await db.prepare("INSERT INTO recovery_revocation_witness(tenant_id,vault_id,device_id,package_id,checkpoint,canonical,receipt) VALUES(?,?,?,'test','test','test','test')")
    .bind(tenantId,vaultId,deviceId).run();
   return live.sign(bytes);
  });
  await expect(proveCustodyAbsenceHead(db,input,policy,signer)).rejects.toThrow('continuation_absence_head_unavailable');
  expect(signer.sign).toHaveBeenCalledTimes(1);
  signer.sign.mockClear();
  await expect(proveCustodyAbsenceHead(db,input,policy,signer)).rejects.toThrow('continuation_absence_head_unavailable');
  expect(signer.sign).not.toHaveBeenCalled();
 }finally{clock.mockRestore();}
});

test('an exact already-admitted genesis can be reconciled from independently retained Auth and Custody records',async()=>{
 const {f,input,policy,signer,accepted,request}=await absence('lost-main-ack');
 const auth=env.RECONCILIATION_AUTH_TEST;
 await applyD1Migrations(auth,env.RECONCILIATION_AUTH_SCHEMA);
 const {accountId,tenantId,vaultId}=f.grant,proof=input.initialApproval,decision=JSON.parse(proof.canonical);
 const {decisionId,grantDigest,rosterDigest:rosterHash,expiresAt}=decision;
 const clock=vi.spyOn(Date,'now').mockReturnValue(input.requestedAt*1000);
 const hasApproval=()=>hasExactHistoricalGenesisApproval(auth,input.originalGrant,input.roster,proof,f.policy);
 // Composition exists only in this test. No Main read/source and no Main ACK write.
 const reconcile=async(cp=request.checkpoint)=>{
  if(!await hasApproval())return null;
  const result=await proveCustodyAbsenceHead(db,input,policy,signer);
  await verifyWitness(result.witness,[policy.witness],{accountId,tenantId,vaultId,revision:1,digest:rosterHash},cp);
  return await hasApproval()?result:null;
 };
 try{
  // Custody provenance alone cannot replace independently retained Auth bytes.
  expect(await reconcile()).toBeNull();
  expect(signer.sign).not.toHaveBeenCalled();
  // Synthetic historical material is populated separately; this is not a registration flow.
  await auth.batch([
   auth.prepare('INSERT INTO auth_genesis_pins VALUES(?,?,?,?,?,?,0,1)').bind(accountId,tenantId,vaultId,'handle','credential','cose'),
   auth.prepare('INSERT INTO auth_genesis_challenges VALUES(?,?,?,?,?,?,?,?,?)').bind(decisionId,'challenge',accountId,tenantId,vaultId,'credential',grantDigest,rosterHash,expiresAt),
   auth.prepare('INSERT INTO auth_genesis_decisions VALUES(?,?,?,?)').bind(decisionId,grantDigest,proof.canonical,proof.signature),
  ]);
  const audit=async()=>Promise.all([
   auth.prepare('SELECT * FROM auth_genesis_decisions').all(),db.prepare('SELECT * FROM genesis_admissions').all(),
   db.prepare('SELECT * FROM roster_witness').all(),
  ]).then(rows=>rows.map(r=>r.results));
  const before=await audit();
  expect((await reconcile())?.witness).toEqual(accepted);
  await expect(reconcile({...request.checkpoint,signature:proof.signature})).rejects.toThrow();
  expect(await audit()).toEqual(before);
  await auth.prepare('UPDATE auth_genesis_decisions SET signature=?').bind(accepted.signature).run();
  expect(await reconcile()).toBeNull();
 }finally{clock.mockRestore();}
});

test('first-device Main bind readback requires exact independent admission, not the same generic witness',async()=>{
 const {f,witness,request}=await attempt(current(),'main-bind');
 const policy={...f.policy,witness:{keyId:witness.keyId,publicKey:witness.publicKey}},nonce='A'.repeat(43),requestedAt=current();
 const body=async(input:typeof request,keys=f.device)=>{
  const {proof,grant,roster,checkpoint}=input;
  const hash=await digest(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',proof,grant,roster,checkpoint]));
  const deviceSignature=await keys.sign(mainGenesisBindingDeviceProof(nonce,requestedAt,hash));
  return {hash,text:JSON.stringify({version:1,domain:MAIN_BIND_GENESIS,nonce,requestedAt,proof,grant,roster,checkpoint,deviceSignature})};
 };
 const requestBody=await body(request),reject='genesis_main_binding_unavailable';
 expect((await verifyMainGenesisBinding(requestBody.text,policy)).attemptDigest).toBe(requestBody.hash);
 await expect(readExactMainGenesisAdmission(db,requestBody.text,policy)).rejects.toThrow(reject);
 const receipt=await admitGenesis(db,request,f.policy,witness);
 expect(await readExactMainGenesisAdmission(db,requestBody.text,policy)).toMatchObject({nonce,attemptDigest:requestBody.hash,receipt});
 expect(await readExactMainGenesisAdmission(db,requestBody.text,policy)).toMatchObject({receipt});
 expect(await count('genesis_admissions',f.grant.vaultId)).toBe(1);
 expect(await count('roster_witness',f.grant.vaultId)).toBe(1);

 const alternate=await f.approval({decisionId:'independently-signed-other-decision'},request.grant);
 const changed=await body({...request,proof:alternate.proof});
 expect((await verifyMainGenesisBinding(changed.text,policy)).attemptDigest).not.toBe(requestBody.hash);
 await expect(readExactMainGenesisAdmission(db,changed.text,policy)).rejects.toThrow(reject);
 await expect(readExactMainGenesisAdmission(db,requestBody.text,{...policy,witness:f.policy.authority})).rejects.toThrow(reject);
 await expect(verifyMainGenesisBinding((await body(request,await signingFixture())).text,policy)).rejects.toThrow(reject);
 await expect(verifyMainGenesisBinding(' '+requestBody.text,policy)).rejects.toThrow(reject);
 const future=vi.spyOn(Date,'now').mockReturnValue((requestedAt+31)*1000);
 try{await expect(readExactMainGenesisAdmission(db,requestBody.text,policy)).rejects.toThrow(reject);}
 finally{future.mockRestore();}
});

test('first-device readback denies a valid legacy genesis head without independent provenance',async()=>{
 const {f,witness,request}=await attempt(current(),'legacy-main-bind');
 const policy={...f.policy,witness:{keyId:witness.keyId,publicKey:witness.publicKey}};
 const legacy=await rosterWitness(db,witness.signer,f.policy.checkpointKeys,async()=>true,f.policy.recoveryAuthorities)
  .accept({rosters:[request.roster],checkpoints:[request.checkpoint]});
 expect(legacy.signature).toBeTruthy();
 const nonce='A'.repeat(43),requestedAt=current(),{proof,grant,roster,checkpoint}=request;
 const hash=await digest(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',proof,grant,roster,checkpoint]));
 const deviceSignature=await f.device.sign(mainGenesisBindingDeviceProof(nonce,requestedAt,hash));
 await expect(readExactMainGenesisAdmission(db,JSON.stringify({version:1,domain:MAIN_BIND_GENESIS,nonce,requestedAt,proof,grant,roster,
  checkpoint,deviceSignature}),policy)).rejects.toThrow('genesis_main_binding_unavailable');
});

test('stages one independently approved Main link atomically without standard device or token eligibility',async()=>{
 const main=env.GENESIS_BIND_MAIN_TEST;
 await applyD1Migrations(main,env.GENESIS_BIND_MAIN_SCHEMA);
 await applyD1Migrations(main,env.GENESIS_BIND_STAGE_SCHEMA);
 const {f,witness,request}=await attempt(current(),'main-stage-cas'),g=f.grant;
 const policy={...f.policy,witness:{keyId:witness.keyId,publicKey:witness.publicKey}};
 const {proof,grant,roster,checkpoint}=request;
 const attemptDigest=await digest(JSON.stringify(['AgentKeychain-genesis-admission-attempt-v1',proof,grant,roster,checkpoint]));
 const make=async(nonce:string,requestedAt=current())=>JSON.stringify({version:1,domain:MAIN_BIND_GENESIS,nonce,requestedAt,
  proof,grant,roster,checkpoint,deviceSignature:await f.device.sign(mainGenesisBindingDeviceProof(nonce,requestedAt,attemptDigest))});
 const port={MAIN:main,PILOT_CUSTODY_GENESIS_BIND:{read:(raw:string)=>readExactMainGenesisAdmission(db,raw,policy)}};
 const reject='pilot_genesis_binding_stage_unavailable',raw=await make('A'.repeat(43));
 const countMain=(table:'pilot_genesis_main_binding_stage'|'devices'|'device_keys'|'vault_devices'|'device_sessions'|'enrollment_grants'|'device_challenges'|'accounts')=>
  main.prepare('SELECT count(*) n FROM '+table).first<number>('n');
 // A genuine approved Custody ledger cannot synthesize a Main account or a
 // pending device identity. Only test-owned existing auth metadata is seeded.
 await admitGenesis(db,request,f.policy,witness);
 await expect(stagePilotGenesisMainBinding(port,policy,raw)).rejects.toThrow(reject);
 expect(await countMain('accounts')).toBe(0);
 await main.batch([
  main.prepare('INSERT INTO accounts VALUES(?)').bind(g.accountId),
  main.prepare('INSERT INTO tenants VALUES(?)').bind(g.tenantId),
  main.prepare('INSERT INTO memberships VALUES(?,?,1)').bind(g.tenantId,g.accountId),
  main.prepare('INSERT INTO vaults(tenant_id,id,sequence) VALUES(?,?,0)').bind(g.tenantId,g.vaultId),
  main.prepare(`INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,
   expires_at,state,account_id,tenant_id,vault_id,key_epoch) VALUES(?,'test-code','test-verify','test-phrase',?,?,?,'linux',?,'bound',?,?,?,?)`)
   .bind(g.requestId,g.deviceId,g.signingKey,g.wrappingKey,g.expiresAt,g.accountId,g.tenantId,g.vaultId,g.keyEpoch),
 ]);
 const mismatched={...port,PILOT_CUSTODY_GENESIS_BIND:{read:async(s:string)=>({...await port.PILOT_CUSTODY_GENESIS_BIND.read(s),nonce:'c'.repeat(43)})}};
 await expect(stagePilotGenesisMainBinding(mismatched,policy,raw)).rejects.toThrow(reject);
 await expect(stagePilotGenesisMainBinding(port,policy,await make('A'.repeat(43),current()-31))).rejects.toThrow(reject);
 expect(await countMain('pilot_genesis_main_binding_stage')).toBe(0);
 const expected={state:'binding-staged-not-session',attemptDigest};
 expect(await Promise.all([stagePilotGenesisMainBinding(port,policy,raw),stagePilotGenesisMainBinding(port,policy,raw)])).toEqual([expected,expected]);
 expect(await stagePilotGenesisMainBinding(port,policy,await make('E'.repeat(43)))).toEqual(expected);
 expect(await countMain('pilot_genesis_main_binding_stage')).toBe(1);
 for(const t of ['devices','device_keys','vault_devices','device_sessions','enrollment_grants','device_challenges'] as const)
  expect(await countMain(t)).toBe(0);
 expect(await main.prepare('SELECT state FROM device_requests WHERE id=?').bind(g.requestId).first('state')).toBe('bound');
 await expect(deviceRepository(main).challenge(g.deviceId,'non-secret-test-digest')).rejects.toThrow();
 await expect(main.prepare('UPDATE pilot_genesis_main_binding_stage SET grant=?').bind('foreign').run()).rejects.toThrow('pilot_genesis_binding_immutable');
 await expect(main.prepare('INSERT OR REPLACE INTO pilot_genesis_main_binding_stage SELECT * FROM pilot_genesis_main_binding_stage').run())
  .rejects.toThrow('pilot_genesis_binding_immutable');
 // A change in Main eligibility even after an exact stage is not a replay authorization.
 await main.prepare('UPDATE memberships SET active=0 WHERE tenant_id=? AND account_id=?').bind(g.tenantId,g.accountId).run();
 await expect(stagePilotGenesisMainBinding(port,policy,raw)).rejects.toThrow(reject);
 expect(await countMain('pilot_genesis_main_binding_stage')).toBe(1);
 expect(await countMain('device_challenges')).toBe(0);
});
