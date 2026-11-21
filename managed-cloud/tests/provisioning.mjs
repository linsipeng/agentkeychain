import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {manifests,validate,releaseManifest,plan} from '../provisioning/render.mjs';
const input={main:'11111111-1111-4111-8111-111111111111',custodian:'22222222-2222-4222-8222-222222222222',auth:'33333333-3333-4333-8333-333333333333',emailFrom:'verify@agentkeychain.soupsam.com'};
const configs=manifests(input);assert.equal(Object.keys(configs).length,5);assert.deepEqual(manifests(input),configs);
for(const [folder,c] of Object.entries(configs)){assert.equal(c.name,plan.workers[folder]);assert.equal(c.routes?.length??0,folder==='api-worker'?2:0);for(const s of c.services??[])assert.ok(Object.values(configs).some(v=>v.name===s.service));}
const recoveryConfig=configs['recovery-worker'];
const exactGenesis={binding:'GENESIS_AUTH',service:plan.workers['api-trust-worker'],entrypoint:'RosterGenesisAuthority'};
assert.deepEqual(recoveryConfig.services.filter(s=>s.binding==='GENESIS_AUTH'),[exactGenesis]);
const otherServices=recoveryConfig.services.filter(s=>s.binding!=='GENESIS_AUTH');
for(const wrong of [[],[{...exactGenesis,entrypoint:'RecoveryAuthority'}],[{...exactGenesis,service:plan.workers['custody-trust-worker']}],[exactGenesis,exactGenesis]])assert.throws(()=>validate({...recoveryConfig,services:[...otherServices,...wrong]}),/invalid_genesis_binding/);
for(const invalid of [{...input,auth:input.main},{...input,main:'REPLACE_ME'},{...input,apiDomain:'evil.test'},{...input,webDomain:'https://bad.test'},{...input,emailFrom:'a\r\nb@example.com'}])assert.throws(()=>manifests(invalid));
assert.throws(()=>validate({...configs['auth-trust-worker'],routes:[{pattern:'x.test'}]}));
assert.throws(()=>validate({...configs['api-worker'],compatibility_flags:[]}));
assert.throws(()=>releaseManifest({},plan.apiDomain,plan.webDomain,{}));
const pin=()=>{const publicKey=randomBytes(32).toString('base64');return {publicKey,keyId:createHash('sha256').update(publicKey).digest('hex')};};
const checkpoint=pin(),apiRelease=pin(),witness=pin(),authority=pin(),custodyRelease=pin();
const pins={releaseId:'synthetic',checkpointKeys:[checkpoint],witnessKeys:[witness],recoveryAuthorities:[authority],recoveryServices:{api:apiRelease,custodian:custodyRelease}};
const ownership={api:[checkpoint.publicKey,apiRelease.publicKey],custodian:[witness.publicKey,authority.publicKey,custodyRelease.publicKey]};
assert.equal(releaseManifest(pins,plan.apiDomain,plan.webDomain,ownership).checkpointKeys[0].keyId,checkpoint.keyId);
assert.throws(()=>releaseManifest(pins,plan.apiDomain,plan.webDomain,{api:[apiRelease.publicKey],custodian:[checkpoint.publicKey,...ownership.custodian]}),/api_pin_mismatch/);
assert.throws(()=>releaseManifest(pins,plan.apiDomain,plan.webDomain,{api:[witness.publicKey,...ownership.api],custodian:[authority.publicKey,custodyRelease.publicKey]}),/custody_pin_mismatch/);
assert.throws(()=>releaseManifest(pins,plan.apiDomain,plan.webDomain,{api:[authority.publicKey,...ownership.api],custodian:[witness.publicKey,custodyRelease.publicKey]}),/custody_pin_mismatch/);
const unsigned=releaseManifest(pins,plan.apiDomain,plan.webDomain,ownership);assert.equal('signature' in unsigned,false);assert.equal('active' in unsigned,false);
console.log('Provisioning: deterministic five-Worker plan and cross-operator authority rejection passed.');

assert.equal(unsigned.apiOrigin,'https://'+plan.apiDomain);
assert.equal(unsigned.webOrigin,'https://'+plan.webDomain);
for(const [api,web] of [[plan.webDomain,plan.webDomain],['evil.test',plan.webDomain],[plan.apiDomain,undefined],[plan.apiDomain,plan.webDomain+'/'],[plan.apiDomain,plan.webDomain+'?x']])assert.throws(()=>releaseManifest(pins,api,web,ownership));
