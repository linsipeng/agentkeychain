import {describe,expect,it} from 'vitest';
import {canonicalGrant} from '../shared/device-protocol.ts';
import {canonicalGenesisApproval,verifyGenesisApproval} from '../shared/genesis-approval.ts';
import {enrollmentFixture as enrollmentFixtureAt} from './synthetic-genesis-approval.ts';

const enrollmentFixture=()=>enrollmentFixtureAt(now);
const now=2_000_000_000;

describe('independent genesis approval verifier',()=>{
 it('verifies the exact initial grant and roster against an explicitly pinned authority',async()=>{
  const f=await enrollmentFixture(),{proof,data}=await f.approval();
  const actual=await verifyGenesisApproval(proof,canonicalGrant(f.grant),f.roster,f.policy,now);
  expect(actual).toEqual(data);
  expect(Object.isFrozen(actual)).toBe(true);
 });
 it('requires an exact authority pin and canonical signed receipt',async()=>{
  const f=await enrollmentFixture(),{proof}=await f.approval();
  const check=(value:unknown,policy=f.policy)=>verifyGenesisApproval(value,canonicalGrant(f.grant),f.roster,policy,now);
  await expect(check(null)).rejects.toThrow('invalid_genesis_approval');
  await expect(check({...proof,canonical:' '+proof.canonical})).rejects.toThrow('invalid_genesis_approval');
  await expect(check(proof,{...f.policy,authority:{keyId:f.authority.keyId,publicKey:f.device.publicKey}})).rejects.toThrow('invalid_genesis_approval');
 });
 it('uses an exclusive expiry, no future timestamp and bounded authorization windows',async()=>{
  const f=await enrollmentFixture();
  for(const change of [{expiresAt:now},{issuedAt:now+1},{expiresAt:f.grant.expiresAt+1}]){
   const {proof}=await f.approval(change);
   await expect(verifyGenesisApproval(proof,canonicalGrant(f.grant),f.roster,f.policy,now)).rejects.toThrow('invalid_genesis_approval');
  }
  const {data}=await f.approval();
  expect(()=>canonicalGenesisApproval({...data,expiresAt:now+601})).toThrow('invalid_genesis_approval');
 });
 it('requires exact version, purpose and fields',async()=>{
  const f=await enrollmentFixture(),{data}=await f.approval();
  for(const input of [{...data,version:2},{...data,audience:'other'},{...data,extra:true}]){
   expect(()=>canonicalGenesisApproval(input)).toThrow('invalid_genesis_approval');
  }
 });
 it('does not apply an approval to an updated request or roster',async()=>{
  const f=await enrollmentFixture(),{proof}=await f.approval();
  await expect(verifyGenesisApproval(proof,canonicalGrant({...f.grant,requestId:'other'}),f.roster,f.policy,now)).rejects.toThrow('invalid_genesis_approval');
  await expect(verifyGenesisApproval(proof,canonicalGrant(f.grant),await f.signedRoster({expiresAt:now+721}),f.policy,now)).rejects.toThrow('invalid_genesis_approval');
 });
 it('requires consistency of approved grant identity, scope, key epoch and expected policy',async()=>{
  const f=await enrollmentFixture();
  for(const change of [{accountId:'other'},{tenantId:'other'},{vaultId:'other'},{deviceId:'other'},{keyEpoch:2},{issuerDeviceId:'other'},{wrappingKey:f.policy.checkpointKeys[0]!.publicKey}]){
   const grant=canonicalGrant({...f.grant,...change}),{proof}=await f.approval({},grant);
   await expect(verifyGenesisApproval(proof,grant,f.roster,f.policy,now)).rejects.toThrow('invalid_genesis_approval');
  }
  const {proof}=await f.approval();
  await expect(verifyGenesisApproval(proof,canonicalGrant(f.grant),f.roster,{...f.policy,recoveryAuthorities:[]},now)).rejects.toThrow('invalid_genesis_approval');
 });
});
