import type { D1Migration } from '@cloudflare/vitest-plugin';
import type { Env } from '../api-worker/index.ts';
declare global {
    namespace Cloudflare {
        interface Env extends importEnv {
            CUSTODIAN: D1Database;
            CUSTODIAN_TEST_WITNESS_SIGNER:import('./synthetic-recovery.ts').RosterWitnessSigner;
            CUSTODIAN_TEST_TRUST_SIGNER:import('./synthetic-recovery.ts').RecoveryTrustSigner;
            CUSTODIAN_TEST_RELEASE:import('../shared/recovery-release.ts').RecoveryReleaseSigner;
            CUSTODIAN_TEST:D1Database;
            TRANSPORT_MAIN:import('./continuation-transport.fixture.ts').MainContinuationTransport;
            TRANSPORT_CUSTODY:import('./continuation-transport.fixture.ts').CustodyContinuationTransport;
            TRANSPORT_CUSTODY_READY:import('./continuation-transport.fixture.ts').CustodyContinuationReadinessTransport;
            TRANSPORT_PINS:string;
            TRANSPORT_APPROVAL_FIXTURE_KEY:string;
            TRANSPORT_CHECKPOINT_FIXTURE_KEY:string;
            CUSTODIAN_MIGRATIONS:D1Migration[];
            CUSTODIAN_TEST_TRUST:import('./synthetic-recovery.ts').RecoveryTestService;
            MIGRATIONS: D1Migration[];
        }
    }
}
interface importEnv extends Env {
}
