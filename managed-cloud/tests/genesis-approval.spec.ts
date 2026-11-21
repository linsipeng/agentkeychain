import {describe,expect,it} from 'vitest';
import {digest} from '../shared/contracts.ts';
import {canonicalGrant,type EnrollmentGrant} from '../shared/device-protocol.ts';
import {canonicalGenesisApproval,GENESIS_APPROVAL_DOMAIN,type GenesisApproval,verifyGenesisApproval} from '../shared/genesis-approval.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest,type TrustedDeviceRoster} from '../shared/roster.ts';

const now=2_000_000_000;
const bytes=(value:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(value)));
async function signingFixture(){
 const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 const publicKey=bytes(await crypto.subtle.exportKey('raw',pair.publicKey));
 const sign=async (message:string)=>bytes(await crypto.subtle.sign('Ed25519',pair.privateKey,new TextEncoder().encode(message)));
 return {publicKey,keyId:await digest(publicKey),sign};
}

async function enrollmentFixture(){
 const [authority,device,checkpoint,recovery]=await Promise.all([signingFixture(),signingFixture(),signingFixture(),signingFixture()]);
 const wrapping=await crypto.subtle.generateKey('X25519',true,['deriveBits']) as CryptoKeyPair;
 const grant:EnrollmentGrant={version:1,requestId:'request',accountId:'account',tenantId:'tenant',vaultId:'vault',deviceId:'device',signingKey:device.publicKey,wrappingKey:bytes(await crypto.subtle.exportKey('raw',wrapping.publicKey)),issuerDeviceId:null,keyEpoch:1,expiresAt:now+480};
 const keyPin=({keyId,publicKey}:{keyId:string;publicKey:string})=>({keyId,publicKey});
 const policy={authority:keyPin(authority),checkpointKeys:[keyPin(checkpoint)],recoveryAuthorities:[keyPin(recovery)]};
 const initial:TrustedDeviceRoster={version:1,accountId:grant.accountId,tenantId:grant.tenantId,vaultId:grant.vaultId,revision:1,previousDigest:null,keyEpoch:grant.keyEpoch,active:[{deviceId:grant.deviceId,signingKey:grant.signingKey,wrappingKey:grant.wrappingKey}],revoked:[],issuer:{kind:'device',id:grant.deviceId},issuedAt:now,expiresAt:now+720,checkpointKeys:policy.checkpointKeys,recoveryAuthorities:policy.recoveryAuthorities,recovery:null};
 const signedRoster=async (change:Partial<TrustedDeviceRoster>={})=>{const canonical=canonicalRoster({...initial,...change});return {canonical,signature:await device.sign(ROSTER_DOMAIN+canonical)};};
 const roster=await signedRoster();
 const approval=async (change:Partial<GenesisApproval>={},grantBytes=canonicalGrant(grant),signed=roster)=>{
  const data:GenesisApproval={version:1,audience:'custodian:roster-genesis',decisionId:'approval',authorityKeyId:authority.keyId,grantDigest:await digest(grantBytes),rosterDigest:await rosterDigest(signed),issuedAt:now-1,expiresAt:now+60,...change};
  const canonical=canonicalGenesisApproval(data);
  return {proof:{canonical,signature:await authority.sign(GENESIS_APPROVAL_DOMAIN+canonical)},data};
 };
 return {authority,device,grant,policy,roster,signedRoster,approval};
}

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
