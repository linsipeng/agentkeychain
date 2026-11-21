import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
import { build } from 'esbuild';
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
            {test:{name:'auth-trust',include:['tests/auth-trust.spec.ts','tests/trust-support.spec.ts','tests/genesis-approval.spec.ts','tests/auth-genesis-issuer.spec.ts']},plugins:[cloudflareTest({remoteBindings:false,miniflare:{compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat'],d1Databases:{AUTH:'auth-db'},bindings:{AUTH_MIGRATIONS:await readD1Migrations('auth-trust-worker/migrations'),GENESIS_ISSUER_SCHEMA:await readD1Migrations('auth-trust-worker/experimental')}}})]},
            {
                test: { name: 'api', include: ['tests/foundation.spec.ts', 'tests/transaction.spec.ts', 'tests/browser-auth.spec.ts', 'tests/device-control.spec.ts', 'tests/checkpoints.spec.ts', 'tests/approvals.spec.ts', 'tests/audit.spec.ts', 'tests/recovery.spec.ts'] },
                plugins: [cloudflareTest({
                        main: 'api-worker/index.ts', remoteBindings: false,
                        miniflare: {
                            compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'],
                            d1Databases: { MAIN: 'main-db', CUSTODIAN_TEST: 'custodian-db' },
                            bindings: { MIGRATIONS: await readD1Migrations('api-worker/migrations'), CUSTODIAN_MIGRATIONS: await readD1Migrations('recovery-worker/migrations') },
                            serviceBindings: { CUSTODIAN_TEST_WITNESS_SIGNER:{name:'custody-recovery',entrypoint:'RosterWitnessSigner'}, CUSTODIAN_TEST_TRUST_SIGNER:{name:'custody-recovery',entrypoint:'RecoveryTrustSigner'}, RECOVERY_RELEASE_SIGNER:{name:'api-recovery',entrypoint:'RecoveryReleaseSigner'},CUSTODIAN_TEST_RELEASE:{name:'custody-recovery',entrypoint:'RecoveryReleaseSigner'}, RECOVERY_AUTH:{name:'api-recovery',entrypoint:'RecoveryTestService'},RECOVERY_KEYS:{name:'api-recovery',entrypoint:'RecoveryTestService'}, CUSTODIAN_TEST_TRUST:{name:'custody-recovery',entrypoint:'RecoveryTestService'}, CHECKPOINT_SIGNER: { name: 'checkpoint', entrypoint: 'CheckpointSigner' }, RECOVERY: { name: 'custodian', entrypoint: 'Custodian' } },
                            workers: [{name:'api-recovery',modules:true,scriptPath:'dist/test-recovery.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat']},{name:'custody-recovery',modules:true,scriptPath:'dist/test-recovery.mjs',compatibilityDate:'2026-07-16',compatibilityFlags:['nodejs_compat']},{ name: 'checkpoint', modules: true, scriptPath: 'dist/test-checkpoint.mjs', compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'] }, {
                                    name: 'custodian', modules: true, scriptPath: 'dist/recovery.mjs',
                                    compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'], d1Databases: { CUSTODIAN: 'custodian-db' }, serviceBindings:{ROSTER_WITNESS_SIGNER:{name:'custody-recovery',entrypoint:'RosterWitnessSigner'},RECOVERY_TRUST_SIGNER:{name:'custody-recovery',entrypoint:'RecoveryTrustSigner'},RECOVERY_TRUST_POLICY:{name:'custody-recovery',entrypoint:'RecoveryTrustSigner'},RECOVERY_RELEASE_SIGNER:{name:'custody-recovery',entrypoint:'RecoveryReleaseSigner'},RECOVERY_AUTH:{name:'custody-recovery',entrypoint:'RecoveryTestService'},GENESIS_AUTH:{name:'api-recovery',entrypoint:'RosterGenesisAuthority'},RECOVERY_KEYS:{name:'custody-recovery',entrypoint:'RecoveryTestService'}},
                                }],
                        },
                    })],
            },
            {
                test: { name: 'custodian', include: ['tests/custodian.spec.ts','tests/genesis-admission.spec.ts'] },
                plugins: [cloudflareTest({
                        main: 'recovery-worker/index.ts', remoteBindings: false,
                        miniflare: {
                            compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'],
                            d1Databases: { CUSTODIAN: 'custodian-db' },
                            bindings: { MIGRATIONS: await readD1Migrations('recovery-worker/migrations') },
                        },
                    })],
            },
        ],
    },
});
