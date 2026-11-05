import type { D1Migration } from '@cloudflare/vitest-pool-workers';
import type { Env } from '../api-worker/index.ts';
declare global {
    namespace Cloudflare {
        interface Env extends importEnv {
            CUSTODIAN: D1Database;
            MIGRATIONS: D1Migration[];
        }
    }
}
interface importEnv extends Env {
}
