import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {compileSyntheticContinuationPreview} from '../provisioning/continuation-preview.ts';
import {canonicalManifest} from '../../src/cloud/config.ts';

const sha=s=>createHash('sha256').update(s).digest('hex');
function key(){
 const k=generateKeyPairSync('ed25519'),raw=k.publicKey.export({format:'der',type:'spki'}).subarray(-32),publicKey=raw.toString('base64');
 return {raw,pin:{keyId:sha(publicKey),publicKey},sign:canonical=>({canonical,signature:sign(null,Buffer.from(canonical),k.privateKey).toString('base64')})};
}
const domains={approval:'AgentKeychain-continuation-release-pin-v1',main:'AgentKeychain-continuation-main-commit-release-pin-v1',
 rollout:'AgentKeychain-continuation-rollout-release-pin-v1'};
function fixture(site='rehearsal.fixture.invalid',id='fixture-v07'){
 const root=key(),approval=key(),main=key(),rollout=key(),checkpoint=key(),witness=key(),recovery=key();
 const canonical=canonicalManifest({version:1,releaseId:id,webOrigin:'https://'+site,apiOrigin:'https://api.'+site,
  protocolMin:2,protocolMax:2,checkpointKeys:[checkpoint.pin],witnessKeys:[witness.pin],recoveryAuthorities:[recovery.pin],
  recoveryServices:{api:key().pin,custodian:key().pin}});
 const appendix=(role,pin,manifestDigest=sha(canonical))=>root.sign(JSON.stringify({version:1,domain:domains[role],manifestDigest,...pin}));
 const input={scope:'local-synthetic',authOrigin:'https://auth.'+site,manifest:root.sign(canonical),
  approvalAppendix:appendix('approval',approval.pin),mainCommitAppendix:appendix('main',main.pin),rolloutAppendix:appendix('rollout',rollout.pin)};
 return {input,root,approval,main,rollout,witness,appendix};
}
test('exact signed synthetic pins produce only a closed role review matrix',async()=>{
 const {root,input,approval,main,witness,rollout}=fixture(),rendered=await compileSyntheticContinuationPreview(input,root.raw);
 assert.equal(rendered.deployable,false);
 assert.equal(rendered.publicIngress,false);
 assert.deepEqual(rendered.roles,{
  main:{store:'main-fixture',commitKeyId:main.pin.keyId,custodyCapability:'post-commit-proof-only'},
  auth:{store:'auth-fixture',approvalKeyId:approval.pin.keyId,custodyCapability:'preapproval-readiness-only'},
  custody:{store:'custody-fixture',witnessKeyIds:[witness.pin.keyId],ingress:'private-only'},
  rollout:{keyId:rollout.pin.keyId,authorizes:'none-without-separate-fixture-permit'},
 });
 assert.ok(Object.isFrozen(rendered)&&Object.isFrozen(rendered.roles.auth));
 assert.ok(!JSON.stringify(rendered).includes('signature'));
});
test('rejects signed nonfixture origins, mismatched RP, and external deployment fields',async()=>{
 const web=fixture('example.com'),noMarker=fixture('rehearsal.fixture.invalid','v07'),{root,input}=fixture();
 for(const [bad,trust] of [[web.input,web.root.raw],[noMarker.input,noMarker.root.raw],[{...input,authOrigin:'https://auth.somewhere.invalid'},root.raw],
   [{...input,scope:'remote'},root.raw],[{...input,account_id:'fixture-account'},root.raw],[{...input,rootPublicKey:root.raw.toString('base64')},root.raw]]){
  await assert.rejects(compileSyntheticContinuationPreview(bad,trust),/invalid_synthetic_continuation_preview/);
 }
});
test('rejects a substituted trust root, mixed manifests, swapped roles or shared role keys',async()=>{
 const {root,input,appendix,approval,rollout,witness}=fixture();
 for(const [bad,trust] of [[input,key().raw],[{...input,rolloutAppendix:appendix('rollout',rollout.pin,'1'.repeat(64))},root.raw],
  [{...input,rolloutAppendix:input.approvalAppendix},root.raw],[{...input,rolloutAppendix:appendix('rollout',approval.pin)},root.raw],
  [{...input,rolloutAppendix:appendix('rollout',witness.pin)},root.raw],[{...input,rolloutAppendix:undefined},root.raw]]){
  await assert.rejects(compileSyntheticContinuationPreview(bad,trust),/invalid_synthetic_continuation_preview/);
 }
});
