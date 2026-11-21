import {generateKeyPairSync,sign} from 'node:crypto';
import {expect,test} from 'bun:test';
import {digest} from '../managed-cloud/shared/contracts.ts';
import {canonicalGrant} from '../managed-cloud/shared/device-protocol.ts';
import {PILOT_SESSION_CHALLENGE,pilotSessionReviewCompletion,verifySyntheticPilotSessionReview} from '../managed-cloud/shared/pilot-session-review.ts';

const hex=(c:string)=>c.repeat(64);
const authNonce='A'.repeat(43),challengeNonce='E'.repeat(43);
function key(){
 const p=generateKeyPairSync('ed25519'),publicKey=p.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 return {publicKey,sign:(m:string)=>sign(null,Buffer.from(m),p.privateKey).toString('base64')};
}
async function fixture(){
 const [device,installation,challengeRole,authRole,reserved,wrong]=[key(),key(),key(),key(),key(),key()];
 const pin=async(k:ReturnType<typeof key>)=>({publicKey:k.publicKey,keyId:await digest(k.publicKey)});
 const signed=async(k:ReturnType<typeof key>,fields:object)=>{const canonical=JSON.stringify(fields);return {canonical,signature:k.sign(canonical)};};
 const hash=(e:{canonical:string;signature:string})=>digest(JSON.stringify([e.canonical,e.signature]));
 const at=Math.floor(Date.now()/1000),deadline=at+20;
 const grantCanonical=canonicalGrant({version:1,requestId:'fixture-request',accountId:'fixture-a',tenantId:'fixture-t',vaultId:'fixture-v',
  deviceId:'fixture-d',signingKey:device.publicKey,wrappingKey:Buffer.alloc(32,17).toString('base64'),issuerDeviceId:null,keyEpoch:1,expiresAt:at+45});
 const owner={grantCanonical,stageAttemptDigest:hex('1'),custodyReceiptDigest:hex('2'),installDigest:hex('3'),profileDigest:hex('4'),
  validUntil:deadline+2,authRequestDigest:hex('5'),authNonce,inviteDigest:hex('6'),authApprovalDigest:hex('7'),mainLinkDigest:hex('8'),
  challengeAuthority:await pin(challengeRole),authConsumptionAuthority:await pin(authRole),installedTestProof:await pin(installation),reservedRolePins:[await pin(reserved)]};
 const auth=await signed(authRole,{version:1,domain:'AgentKeychain-pilot-auth-invite-consumption-readback-v1',keyId:owner.authConsumptionAuthority.keyId,
  nonce:authNonce,requestDigest:owner.authRequestDigest,inviteDigest:owner.inviteDigest,authApprovalDigest:owner.authApprovalDigest,
  mainLinkDigest:owner.mainLinkDigest,installationDigest:owner.installDigest,profileDigest:owner.profileDigest,issuedAt:at-1,expiresAt:deadline});
 const authConsumptionDigest=await hash(auth);
 const challenge={version:1,domain:PILOT_SESSION_CHALLENGE,keyId:owner.challengeAuthority.keyId,purpose:'inspect-staged-binding',
  nonce:challengeNonce,stageAttemptDigest:owner.stageAttemptDigest,grantDigest:await digest(grantCanonical),custodyReceiptDigest:owner.custodyReceiptDigest,
  authConsumptionDigest,installationDigest:owner.installDigest,profileDigest:owner.profileDigest,originalDeviceKeyId:await digest(device.publicKey),
  installedTestKeyId:owner.installedTestProof.keyId,issuedAt:at,expiresAt:deadline};
 const make=async(fields:object=challenge,issuer=challengeRole,original=device,installed=installation)=>{
  const envelope=await signed(issuer,fields),challengeDigest=await hash(envelope);
  return JSON.stringify({challenge:envelope,authConsumption:auth,
   originalDeviceSignature:original.sign(pilotSessionReviewCompletion(challengeDigest,'original-device')),
   installedTestSignature:installed.sign(pilotSessionReviewCompletion(challengeDigest,'installed-test'))});
 };
 return {owner:{...owner,authConsumptionDigest},make,challenge,wrong,device,installation};
}
const denied='pilot_session_review_unavailable';

test('exact proof stays synthetic pending and exact replay never issues anything',async()=>{
 const {owner,make}=await fixture(),raw=await make(),completionDigest=await digest(raw);
 expect(await verifySyntheticPilotSessionReview(raw,owner)).toEqual({state:'pending-installed-pin-provenance',completionDigest,replay:'not-compared'});
 expect(await verifySyntheticPilotSessionReview(raw,{...owner,previousCompletionDigest:completionDigest})).toEqual({
  state:'pending-installed-pin-provenance',completionDigest,replay:'exact-match'});
 await expect(verifySyntheticPilotSessionReview(raw,{...owner,previousCompletionDigest:hex('f')})).rejects.toThrow(denied);
});

test('never permits a changed scope, substituted signer, synthetic role clash or extended time',async()=>{
 const {owner,make,challenge,wrong,device,installation}=await fixture(),raw=await make();
 for(const changed of [{stageAttemptDigest:hex('9')},{custodyReceiptDigest:hex('9')},{authConsumptionDigest:hex('9')},
  {installationDigest:hex('9')},{profileDigest:hex('9')},{grantDigest:hex('9')},{nonce:authNonce},
  {purpose:'issue-session'},{expiresAt:challenge.expiresAt+1},{issuedAt:challenge.issuedAt+60}]){
  await expect(verifySyntheticPilotSessionReview(await make({...challenge,...changed}),owner)).rejects.toThrow(denied);
 }
 await expect(verifySyntheticPilotSessionReview(await make(challenge,wrong),owner)).rejects.toThrow(denied);
 await expect(verifySyntheticPilotSessionReview(await make(challenge,undefined,wrong,installation),owner)).rejects.toThrow(denied);
 await expect(verifySyntheticPilotSessionReview(await make(challenge,undefined,device,wrong),owner)).rejects.toThrow(denied);
 await expect(verifySyntheticPilotSessionReview(raw,{...owner,authConsumptionAuthority:owner.challengeAuthority})).rejects.toThrow(denied);
 await expect(verifySyntheticPilotSessionReview(raw,{...owner,authRequestDigest:hex('a')})).rejects.toThrow(denied);
 for(const invalid of [raw.replace(/^\{/,'{"challenge":null,'),raw+' ',JSON.stringify({...JSON.parse(raw),staged:true})])
  await expect(verifySyntheticPilotSessionReview(invalid,owner)).rejects.toThrow(denied);
});
