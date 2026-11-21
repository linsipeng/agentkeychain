import {beforeEach,expect,test,vi} from 'vitest';
import {applyD1Migrations} from 'cloudflare:test';
import {env} from 'cloudflare:workers';
import {checkpoint,genesisRoot} from '../shared/checkpoints.ts';
import {canonicalGrant} from '../shared/device-protocol.ts';
import {admitGenesis} from '../shared/genesis-admission.ts';
import {custodyAbsenceHeadRequestProof,proveCustodyAbsenceHead} from '../custody-trust-worker/package-absence-head.ts';
import {digest,verify} from '../shared/contracts.ts';
import {rosterDigest} from '../shared/roster.ts';
import {rosterWitness} from '../shared/roster-witness.ts';
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
 return {f,accepted,signer,live,policy,input:{nonce,requestedAt,deviceSignature,originalGrant,initialApproval,roster}};
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
