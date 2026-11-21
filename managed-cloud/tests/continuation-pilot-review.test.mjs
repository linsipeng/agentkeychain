import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID,sign} from 'node:crypto';
import {mkdtemp,rm,stat,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {reviewContinuationPilotTarget,PILOT_TARGET_DOMAIN} from '../provisioning/continuation-pilot-review.ts';
import {canonicalManifest} from '../../src/cloud/config.ts';
import {INSTALLED_PILOT_CONTRACT} from '../../src/cloud/continuation-pilot-build.ts';
const sha=x=>createHash('sha256').update(x).digest('hex'),hash=x=>sha(JSON.stringify([x.canonical,x.signature]));
const pair=()=>{
 const k=generateKeyPairSync('ed25519'),publicKey=k.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 return {publicKey,pin:{keyId:sha(publicKey),publicKey},
  sign:canonical=>({canonical,signature:sign(null,Buffer.from(canonical),k.privateKey).toString('base64')})};
};
function fixture(zone='synthetic-pilot-renderer.net'){
 // Synthetic strings only: no DNS lookup or live resources.
 const root=pair(),target='linux-x64',namespace='test-2026',webOrigin='https://web-pilot-'+namespace+'.'+zone,
  apiOrigin='https://api.web-pilot-'+namespace+'.'+zone,authOrigin='https://auth-pilot-'+namespace+'.'+zone;
 const manifest=root.sign(canonicalManifest({version:1,releaseId:'continuation-pilot-renderer-fixture',apiOrigin,webOrigin,
  protocolMin:2,protocolMax:2,checkpointKeys:[pair().pin],witnessKeys:[pair().pin],recoveryAuthorities:[pair().pin],
  recoveryServices:{api:pair().pin,custodian:pair().pin}}));
 const appendix=(domain,value)=>root.sign(JSON.stringify({version:1,domain,manifestDigest:sha(manifest.canonical),...value}));
 const authOriginAppendix=appendix('AgentKeychain-continuation-auth-origin-pilot-v1',{authOrigin});
 const authAppendix=appendix('AgentKeychain-continuation-release-pin-v1',pair().pin);
 const commitAppendix=appendix('AgentKeychain-continuation-main-commit-release-pin-v1',pair().pin);
 const rolloutAppendix=appendix('AgentKeychain-continuation-rollout-release-pin-v1',pair().pin);
 const issuedAt=Math.floor(Date.now()/1000),expiresAt=issuedAt+300;
 const installation=root.sign(JSON.stringify({version:1,domain:'AgentKeychain-continuation-installed-pilot-build-v1',
  mode:'disposable-only',contract:INSTALLED_PILOT_CONTRACT,target,manifestDigest:hash(manifest),authOriginDigest:hash(authOriginAppendix),
  authPinDigest:hash(authAppendix),mainPinDigest:hash(commitAppendix),rolloutPinDigest:hash(rolloutAppendix),genesisPin:pair().pin,issuedAt,expiresAt}));
 const artifact={manifest,authOriginAppendix,authAppendix,commitAppendix,rolloutAppendix,installation};
 const protectedDatabaseIds=Array.from({length:3},randomUUID),databases={auth:randomUUID(),main:randomUUID(),custody:randomUUID()};
 const claim={version:1,domain:PILOT_TARGET_DOMAIN,mode:'same-account-disposable-only',installationDigest:hash(installation),
  namespace,accountId:'1'.repeat(32),zoneId:'2'.repeat(32),zone,webOrigin,apiOrigin,authOrigin,databases,expiresAt};
 const stamp=(edits={})=>root.sign(JSON.stringify({...claim,...edits}));
 return {trusted:{pilotRootPublicKey:root.publicKey,target,protectedDatabaseIds},claim,stamp,input:{installation:artifact,targetClaim:stamp()}};
}
test('exact signed target yields only closed role fragments and private review output',async()=>{
 const f=fixture(),result=await reviewContinuationPilotTarget(f.input,f.trusted);
 assert.equal(result.deployable,false);assert.equal(result.ownershipVerified,false);
 assert.deepEqual(result.privateRoles.auth.services.map(s=>s.entrypoint),['PilotCustodyReadiness']);
 assert.deepEqual(result.privateRoles.main.services.map(s=>s.entrypoint),['PilotCustodyFresh','PilotCustodyPost']);
 assert.equal(result.privateRoles.custody.services.length,0);
 for(const role of Object.values(result.privateRoles)){
  assert.equal(role.workers_dev,false);assert.equal(role.preview_urls,false);assert.equal(role.ingress,'unbound');
  assert.equal(Object.hasOwn(role,'routes'),false);
  assert.ok(Object.keys(role.vars).every(k=>!/_MODE$/.test(k)));
 }
 const dir=await mkdtemp(join(tmpdir(),'akc-pilot-review-'));
 try{
  const file=join(dir,'role-review.json'),bytes=JSON.stringify(result);
  assert.doesNotMatch(bytes,/PKCS8|HMAC|signature/i);
  await writeFile(file,bytes,{mode:0o600,flag:'wx'});
  assert.equal((await stat(file)).mode&0o777,0o600);
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('refuses foreign hosts, protected or duplicate DB ids, extra bindings, and mixed signed artifacts',async()=>{
 const f=fixture(),d=f.claim.databases,edits=[{namespace:'other'},{extraServices:[]},{accountId:'fixture'},
  {apiOrigin:'https://api.agentkeychain.soupsam.com'},{expiresAt:f.claim.expiresAt+1},{installationDigest:'1'.repeat(64)},
  {databases:{...d,auth:f.trusted.protectedDatabaseIds[0]}},{databases:{...d,auth:d.main}},{databases:{...d,extra:randomUUID()}}];
 for(const edit of edits)await assert.rejects(reviewContinuationPilotTarget({...f.input,targetClaim:f.stamp(edit)},f.trusted),/invalid_continuation_pilot_target/);
 const old=fixture('agentkeychain.soupsam.com');
 await assert.rejects(reviewContinuationPilotTarget(old.input,old.trusted),/invalid_continuation_pilot_target/);
 await assert.rejects(reviewContinuationPilotTarget(f.input,{...f.trusted,pilotRootPublicKey:pair().publicKey}),/invalid_continuation_pilot_target/);
 await assert.rejects(reviewContinuationPilotTarget(f.input,{...f.trusted,protectedDatabaseIds:[]}),/invalid_continuation_pilot_target/);
});
