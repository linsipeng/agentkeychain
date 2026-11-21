import {beforeEach,expect,test,vi} from 'vitest';
import {applyD1Migrations} from 'cloudflare:test';
import {env} from 'cloudflare:workers';
import {checkpoint,genesisRoot} from '../shared/checkpoints.ts';
import {canonicalGrant} from '../shared/device-protocol.ts';
import {admitGenesis} from '../shared/genesis-admission.ts';
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
