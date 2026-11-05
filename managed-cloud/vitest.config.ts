import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';
import { build } from 'esbuild';
await build({
    entryPoints: ['recovery-worker/index.ts'], outfile: 'dist/recovery.mjs',
    bundle: true, format: 'esm', platform: 'neutral',
    external: ['cloudflare:workers'], target: 'es2022',
});
export default defineConfig({
    test: {
        projects: [
            {
                test: { name: 'api', include: ['tests/foundation.spec.ts', 'tests/transaction.spec.ts'] },
                plugins: [cloudflareTest({
                    main: 'api-worker/index.ts', remoteBindings: false,
                    miniflare: {
                        compatibilityDate: '2026-07-16', compatibilityFlags: ['nodejs_compat'],
                        d1Databases: { MAIN: 'main-db' },
                        bindings: { MIGRATIONS: await readD1Migrations('api-worker/migrations') },
                        serviceBindings: { RECOVERY: { name: 'custodian', entrypoint: 'Custodian' } },
                        workers: [{
                            name: 'custodian', modules: true, scriptPath: 'dist/recovery.mjs',
                            compatibilityDate: '2026-07-16', d1Databases: { CUSTODIAN: 'custodian-db' },
                        }],
                    },
                })],
            },
            {
                test: { name: 'custodian', include: ['tests/custodian.spec.ts'] },
                plugins: [cloudflareTest({
                    main: 'recovery-worker/index.ts', remoteBindings: false,
                    miniflare: {
                        compatibilityDate: '2026-07-16',
                        d1Databases: { CUSTODIAN: 'custodian-db' },
                        bindings: { MIGRATIONS: await readD1Migrations('recovery-worker/migrations') },
                    },
                })],
            },
        ],
    },
});
