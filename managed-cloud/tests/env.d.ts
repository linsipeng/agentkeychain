import type { D1Migration } from '@cloudflare/vitest-plugin';
import type { Env } from '../api-worker/index.ts';
declare global {
    namespace Cloudflare {
        interface Env extends importEnv {
            CUSTODIAN: D1Database;
            CUSTODIAN_TEST:D1Database;
            CUSTODIAN_MIGRATIONS:D1Migration[];
            CUSTODIAN_TEST_TRUST:import('./synthetic-recovery.ts').RecoveryTestService;
            MIGRATIONS: D1Migration[];
        }
    }
}
interface importEnv extends Env {
}
