import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
import { build } from 'esbuild';
import {createHash,generateKeyPairSync} from 'node:crypto';
function ephemeralTransportKey(){
 const key=generateKeyPairSync('ed25519');
 const publicKey=key.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 return {pin:{keyId:createHash('sha256').update(publicKey).digest('hex'),publicKey},privateKey:key.privateKey.export({format:'der',type:'pkcs8'}).toString('base64')};
}
const transportMain=ephemeralTransportKey(),transportCustody=ephemeralTransportKey(),transportApproval=ephemeralTransportKey(),transportCheckpoint=ephemeralTransportKey();
const transportGenesis=ephemeralTransportKey();
const transportPins=JSON.stringify({main:transportMain.pin,witness:transportCustody.pin,approval:transportApproval.pin,checkpoint:transportCheckpoint.pin,genesis:transportGenesis.pin});
const pilotMainOrigin='https://api.web-pilot-device.fixture.invalid';
const pilotCustodyPins=JSON.stringify({authority:transportApproval.pin,witness:transportCustody.pin,
 mainCommitAuthority:transportMain.pin,checkpointKeys:[transportCheckpoint.pin],recoveryAuthorities:[],otherReleaseKeys:[transportGenesis.pin]});
await build({entryPoints:['custody-trust-worker/pilot-continuation.ts'],outfile:'dist/test-pilot-custody.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({entryPoints:['api-worker/pilot-continuation-main.ts'],outfile:'dist/test-pilot-main-post.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({entryPoints:['custody-trust-worker/continuation-readiness.ts'],outfile:'dist/test-custody-continuation-readiness.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
const readinessPins=JSON.stringify({authority:transportApproval.pin,witness:transportCustody.pin,checkpointKeys:[transportCheckpoint.pin],recoveryAuthorities:[]});
await build({entryPoints:['tests/auth-continuation-preview.fixture.ts'],outfile:'dist/test-auth-continuation-preview.mjs',bundle:true,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({entryPoints:['tests/continuation-transport.fixture.ts'],outfile:'dist/test-continuation-transport.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
await build({
    entryPoints: ['recovery-worker/index.ts'], outfile: 'dist/recovery.mjs',
    bundle: true, format: 'esm', platform: 'neutral',
    external: ['cloudflare:workers','node:buffer'], target: 'es2022',
});
await build({ entryPoints: ['tests/synthetic-checkpoint.ts'], outfile: 'dist/test-checkpoint.mjs', bundle: true, format: 'esm', platform: 'neutral', external: ['cloudflare:workers', 'node:buffer'], target: 'es2022' });
await build({entryPoints:['tests/synthetic-recovery.ts'],outfile:'dist/test-recovery.mjs',bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:buffer'],target:'es2022'});
export default defineConfig({
    test: {
        projects: [
            {test:{name:'auth-trust',include:['tests/auth-trust.spec.ts','tests/trust-support.spec.ts','tests/genesis-approval.spec.ts','tests/auth-genesis-issuer.spec.ts']},plugins:[cloudflareTest({remoteBindings:false,miniflare:{compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],d1Databases:{AUTH:'auth-db'},bindings:{AUTH_MIGRATIONS:await readD1Migrations('auth-trust-worker/migrations'),GENESIS_ISSUER_SCHEMA:await readD1Migrations('auth-trust-worker/experimental'),PILOT_GENESIS_SCHEMA:await readD1Migrations('auth-trust-worker/pilot-migrations')}}})]},
            {
                test: { name: 'api', include: ['tests/foundation.spec.ts', 'tests/transaction.spec.ts', 'tests/browser-auth.spec.ts', 'tests/device-control.spec.ts', 'tests/checkpoints.spec.ts', 'tests/approvals.spec.ts', 'tests/audit.spec.ts', 'tests/recovery.spec.ts'] },
                plugins: [cloudflareTest({
                        main: 'api-worker/index.ts', remoteBindings: false,
                        miniflare: {
                            compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'],
                            d1Databases: { MAIN: 'main-db', CUSTODIAN_TEST: 'custodian-db', TRANSPORT_AUTH_DB:'fixture-continuation-auth-db' },
                            bindings: { TRANSPORT_PINS:transportPins, TRANSPORT_GENESIS_FIXTURE_KEY:transportGenesis.privateKey, TRANSPORT_AUTH_SCHEMA:await readD1Migrations('auth-trust-worker/experimental'),TRANSPORT_APPROVAL_FIXTURE_KEY:transportApproval.privateKey,TRANSPORT_CHECKPOINT_FIXTURE_KEY:transportCheckpoint.privateKey,MIGRATIONS: await readD1Migrations('api-worker/migrations'), GENESIS_PACKAGE_SCHEMA: await readD1Migrations('api-worker/experimental'), CUSTODIAN_MIGRATIONS: await readD1Migrations('recovery-worker/migrations') },
                            serviceBindings: { PILOT_MAIN_POST:'fixture-pilot-main-post', PILOT_MAIN_OFF:'fixture-pilot-main-off', TRANSPORT_AUTH:{name:'fixture-continuation-auth',entrypoint:'AuthContinuationPreview'},TRANSPORT_MAIN:{name:'fixture-continuation-main',entrypoint:'MainContinuationTransport'},TRANSPORT_CUSTODY:{name:'fixture-continuation-custody',entrypoint:'CustodyContinuationTransport'},TRANSPORT_CUSTODY_READY:{name:'fixture-continuation-custody-readiness',entrypoint:'CustodyContinuationReadinessTransport'},CUSTODIAN_TEST_WITNESS_SIGNER:{name:'custody-recovery',entrypoint:'RosterWitnessSigner'}, CUSTODIAN_TEST_TRUST_SIGNER:{name:'custody-recovery',entrypoint:'RecoveryTrustSigner'}, RECOVERY_RELEASE_SIGNER:{name:'api-recovery',entrypoint:'RecoveryReleaseSigner'},CUSTODIAN_TEST_RELEASE:{name:'custody-recovery',entrypoint:'RecoveryReleaseSigner'}, RECOVERY_AUTH:{name:'api-recovery',entrypoint:'RecoveryTestService'},RECOVERY_KEYS:{name:'api-recovery',entrypoint:'RecoveryTestService'}, CUSTODIAN_TEST_TRUST:{name:'custody-recovery',entrypoint:'RecoveryTestService'}, CHECKPOINT_SIGNER: { name: 'checkpoint', entrypoint: 'CheckpointSigner' }, RECOVERY: { name: 'custodian', entrypoint: 'Custodian' } },
                            workers: [
                                {name:'fixture-pilot-main-post',modules:true,scriptPath:'dist/test-pilot-main-post.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
                                 bindings:{PILOT_MAIN_MODE:'continuation-v1',PILOT_MAIN_ORIGIN:pilotMainOrigin,PILOT_MAIN_EXPIRES_AT:String(Math.floor(Date.now()/1000)+3600),PILOT_CUSTODY_WITNESS:JSON.stringify(transportCustody.pin),PILOT_MAIN_APPROVAL_PIN:JSON.stringify(transportApproval.pin),PILOT_MAIN_COMMIT_PIN:JSON.stringify(transportMain.pin)},
                                 d1Databases:{MAIN:'main-db'},serviceBindings:{PILOT_CUSTODY_POST:{name:'fixture-pilot-custody',entrypoint:'PilotCustodyPost'},PILOT_CUSTODY_FRESH:{name:'fixture-pilot-custody',entrypoint:'PilotCustodyFresh'},PILOT_MAIN_SIGNER:{name:'fixture-continuation-main',entrypoint:'PilotMainSignerFixture'}}},
                                {name:'fixture-pilot-main-off',modules:true,scriptPath:'dist/test-pilot-main-post.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat']},
                                {name:'fixture-continuation-auth',modules:true,scriptPath:'dist/test-auth-continuation-preview.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
                                 bindings:{ROLE_KEY:transportApproval.privateKey,PINS:transportPins},d1Databases:{AUTH:'fixture-continuation-auth-db'},
                                 serviceBindings:{CUSTODY_READY:{name:'fixture-continuation-custody-readiness',entrypoint:'CustodyContinuationReadinessTransport'}}},
                                {name:'fixture-continuation-main',modules:true,scriptPath:'dist/test-continuation-transport.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
                                 bindings:{ROLE_KEY:transportMain.privateKey,PINS:transportPins},d1Databases:{MAIN:'main-db'},serviceBindings:{CUSTODY:{name:'fixture-continuation-custody',entrypoint:'CustodyContinuationTransport'}}},
                                {name:'fixture-continuation-custody-readiness',modules:true,scriptPath:'dist/test-custody-continuation-readiness.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
                                 bindings:{CONTINUATION_WITNESS_PKCS8_B64:transportCustody.privateKey,CONTINUATION_READINESS_PINS:readinessPins},d1Databases:{CUSTODIAN:'custodian-db'}},
                                {name:'fixture-pilot-custody',modules:true,scriptPath:'dist/test-pilot-custody.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
                                 bindings:{PILOT_CUSTODY_MODE:'continuation-v1',PILOT_CUSTODY_EXPIRES_AT:String(Math.floor(Date.now()/1000)+3600),PILOT_CUSTODY_PINS:pilotCustodyPins,PILOT_CUSTODY_WITNESS_PKCS8_B64:transportCustody.privateKey},d1Databases:{CUSTODIAN:'custodian-db'}},
                                {name:'fixture-continuation-custody',modules:true,scriptPath:'dist/test-continuation-transport.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],
                                 bindings:{ROLE_KEY:transportCustody.privateKey,PINS:transportPins},d1Databases:{CUSTODIAN:'custodian-db'}},
                                {name:'api-recovery',modules:true,scriptPath:'dist/test-recovery.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat']},{name:'custody-recovery',modules:true,scriptPath:'dist/test-recovery.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat']},{ name: 'checkpoint', modules: true, scriptPath: 'dist/test-checkpoint.mjs', compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'] }, {
                                    name: 'custodian', modules: true, scriptPath: 'dist/recovery.mjs',
                                    compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'], d1Databases: { CUSTODIAN: 'custodian-db' }, serviceBindings:{ROSTER_WITNESS_SIGNER:{name:'custody-recovery',entrypoint:'RosterWitnessSigner'},RECOVERY_TRUST_SIGNER:{name:'custody-recovery',entrypoint:'RecoveryTrustSigner'},RECOVERY_TRUST_POLICY:{name:'custody-recovery',entrypoint:'RecoveryTrustSigner'},RECOVERY_RELEASE_SIGNER:{name:'custody-recovery',entrypoint:'RecoveryReleaseSigner'},RECOVERY_AUTH:{name:'custody-recovery',entrypoint:'RecoveryTestService'},GENESIS_AUTH:{name:'api-recovery',entrypoint:'RosterGenesisAuthority'},RECOVERY_KEYS:{name:'custody-recovery',entrypoint:'RecoveryTestService'}},
                                }],
                        },
                    })],
            },
            {
                test: { name: 'custodian', include: ['tests/custodian.spec.ts','tests/genesis-admission.spec.ts','tests/continuation-fresh-head.spec.ts'] },
                plugins: [cloudflareTest({
                        main: 'recovery-worker/index.ts', remoteBindings: false,
                        miniflare: {
                            compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'],
                            d1Databases: { CUSTODIAN: 'custodian-db', RECONCILIATION_AUTH_TEST:'reconciliation-auth-db', GENESIS_BIND_MAIN_TEST:'genesis-bind-main-db' },
                            bindings: { GENESIS_BIND_MAIN_SCHEMA:await readD1Migrations('api-worker/migrations'), GENESIS_BIND_STAGE_SCHEMA:await readD1Migrations('api-worker/experimental/genesis-main-binding-stage'), RECONCILIATION_AUTH_SCHEMA:await readD1Migrations('auth-trust-worker/experimental'), MIGRATIONS: await readD1Migrations('recovery-worker/migrations') },
                        },
                    })],
            },
        ],
    },
});
