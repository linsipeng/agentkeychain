import {expect,test} from 'bun:test';
import sodium from 'libsodium-wrappers-sumo';
import {canonicalGrant} from '../managed-cloud/shared/device-protocol.ts';
import {canonicalRoster,ROSTER_DOMAIN,rosterDigest} from '../managed-cloud/shared/roster.ts';
import {WITNESS_DOMAIN} from '../managed-cloud/shared/roster-witness.ts';
import {digest} from '../managed-cloud/shared/contracts.ts';
import {genesisRoot} from '../managed-cloud/shared/checkpoints.ts';
import {MAIN_PACKAGE_ABSENCE_DOMAIN,CUSTODY_PACKAGE_ABSENCE_HEAD_DOMAIN,verifyMissingPackageEvidence} from '../src/cloud/missing-package-evidence.ts';

async function fixture(){
 await sodium.ready;
 const key=(keyId:string)=>{
  const k=sodium.crypto_sign_keypair(),publicKey=Buffer.from(k.publicKey).toString('base64');
  return {pin:{keyId,publicKey},sign:(value:string,prefix='')=>({canonical:value,signature:Buffer.from(sodium.crypto_sign_detached(prefix+value,k.privateKey)).toString('base64')})};
 };
 const device=key('device'),historical=key('historical'),checkpoint=key('checkpoint'),main=key('main'),current=key('current'),auth=key('auth');
 const now=2_000_000_000,requestedAt=now-3,nonce='a'.repeat(43);
 const {accountId,tenantId,vaultId,requestId,deviceId,keyEpoch,...rest}={version:1,accountId:'account',tenantId:'tenant',vaultId:'vault',requestId:'request',deviceId:'device',
  keyEpoch:1,signingKey:device.pin.publicKey,wrappingKey:Buffer.from(sodium.crypto_box_keypair().publicKey).toString('base64'),issuerDeviceId:null,expiresAt:now-4};
 const oldGrantCanonical=canonicalGrant({accountId,tenantId,vaultId,requestId,deviceId,keyEpoch,...rest});
 const originalDevice={signingKey:rest.signingKey,wrappingKey:rest.wrappingKey};
 const roster=device.sign(canonicalRoster({version:1,accountId,tenantId,vaultId,revision:1,previousDigest:null,keyEpoch,active:[{deviceId,...originalDevice}],
  revoked:[],issuer:{kind:'device',id:deviceId},issuedAt:now-60,expiresAt:now+720,checkpointKeys:[checkpoint.pin],recoveryAuthorities:[],recovery:null}),ROSTER_DOMAIN);
 const rosterHash=await rosterDigest(roster);
 const witnessBody={version:1,keyId:historical.pin.keyId,accountId,tenantId,vaultId,event:1,revision:1,digest:rosterHash,sequence:0,
  root:await genesisRoot(tenantId,vaultId),checkpointDigest:await digest('genesis checkpoint')};
 const witness=historical.sign(JSON.stringify(witnessBody),WITNESS_DOMAIN);
 const witnessDigest=await digest(JSON.stringify([witness.canonical,witness.signature]));
 const body={version:1,domain:MAIN_PACKAGE_ABSENCE_DOMAIN,keyId:main.pin.keyId,nonce,requestId,grantDigest:await digest(oldGrantCanonical),rosterDigest:rosterHash,
  accountId,tenantId,vaultId,deviceId,keyEpoch,rosterRevision:1,witnessDigest,status:'absent',issuedAt:now-2,expiresAt:now+25};
 const signMain=(change={})=>main.sign(JSON.stringify({...body,...change}));
 const signCurrent=(change={})=>current.sign(JSON.stringify({...body,domain:CUSTODY_PACKAGE_ABSENCE_HEAD_DOMAIN,keyId:current.pin.keyId,status:'current',expiresAt:now+20,...change}));
 const pins={mainAbsence:main.pin,custodyCurrentHead:current.pin,historicalWitness:[historical.pin],checkpoint:[checkpoint.pin],recovery:[],otherAuthorities:[auth.pin]};
 return {body,witnessBody,historical,round:{now,nonce,requestedAt,oldGrantCanonical,roster,originalDevice,pins},signMain,signCurrent,
  input:{mainAbsence:signMain(),custodyCurrentHead:signCurrent(),witness}};
}

test('both independent exact genesis proofs yield only a bounded read observation',async()=>{
 const f=await fixture();
 expect(await verifyMissingPackageEvidence(f.input,f.round)).toEqual({expiresAt:f.round.now+20});
});

test('fails closed on mixed scope, round, roles, status, timestamps or noncanonical bytes',async()=>{
 const f=await fixture(),deny='cloud_invalid_missing_package_evidence';
 for(const change of [{nonce:'b'.repeat(43)},{grantDigest:'b'.repeat(64)},{witnessDigest:'a'.repeat(64)},{rosterDigest:'b'.repeat(64)},
  {accountId:'other'},{tenantId:'other'},{vaultId:'other'},{deviceId:'other'},{keyEpoch:2},{requestId:'other'},{rosterRevision:2},{status:'unknown'},
  {issuedAt:f.round.now+1},{issuedAt:f.round.requestedAt-1},{expiresAt:f.round.now},{expiresAt:f.round.now+31},{extra:true}]){
  await expect(verifyMissingPackageEvidence({...f.input,mainAbsence:f.signMain(change)},f.round)).rejects.toThrow(deny);
  await expect(verifyMissingPackageEvidence({...f.input,custodyCurrentHead:f.signCurrent(change)},f.round)).rejects.toThrow(deny);
 }
 await expect(verifyMissingPackageEvidence({...f.input,custodyCurrentHead:f.input.mainAbsence},f.round)).rejects.toThrow(deny);
 await expect(verifyMissingPackageEvidence({...f.input,mainAbsence:f.body},f.round)).rejects.toThrow(deny);
});

test('requires original local keys and a pinned historical pristine genesis witness',async()=>{
 const f=await fixture(),deny='cloud_invalid_missing_package_evidence';
 const {pins,originalDevice}=f.round;
 for(const change of [{originalDevice:{...originalDevice,signingKey:pins.mainAbsence.publicKey}},
  {pins:{...pins,custodyCurrentHead:{...pins.custodyCurrentHead,publicKey:pins.mainAbsence.publicKey}}},
  {pins:{...pins,mainAbsence:pins.historicalWitness[0]!}},
  {pins:{...pins,otherAuthorities:[{...pins.mainAbsence,publicKey:pins.custodyCurrentHead.publicKey}]}},
  {now:f.round.now+21}]){
  await expect(verifyMissingPackageEvidence(f.input,{...f.round,...change})).rejects.toThrow(deny);
 }
 const witness=f.historical.sign(JSON.stringify({...f.witnessBody,event:2}),WITNESS_DOMAIN);
 const witnessDigest=await digest(JSON.stringify([witness.canonical,witness.signature]));
 await expect(verifyMissingPackageEvidence({witness,mainAbsence:f.signMain({witnessDigest}),custodyCurrentHead:f.signCurrent({witnessDigest})},f.round)).rejects.toThrow(deny);
});
