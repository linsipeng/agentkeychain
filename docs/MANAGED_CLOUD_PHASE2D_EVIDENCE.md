# Phase 2D repair evidence — independent-review blockers

Date: 2026-11-05. Branch: `feat/managed-cloud-v0.7`. HEAD: `986e495`.
This record supersedes the earlier Phase 2D self-validation report. The independent
review found real release blockers despite its passing tests. This is local repair
and test evidence, not independent certification or production approval. All changes
remain dirty/uncommitted; no deployment, remote migration, push or real-data access.

## Repaired contracts

### Recovery finish/cancel boundary

Main now follows `prepared → confirmed → released → activating → completed`.
`proven` remains a recognized pre-activation state in the local schema. The immutable
canonical case pins both target keys; signature verification precedes a conditional
Main update that rechecks the persisted proof digest. Its activation trigger checks
both releases, expiry, membership, latest package epoch, live confirmer and target
uniqueness. The update, durable activation intent, device/key/request creation and
audit events share one Main transaction. Trigger failure rolls all of them back.

Only after that commit does Main call Custodian completion. Custodian's independent
authorization service verifies the exact target-signed proof and its completion is
idempotent. Main's final completed transition is also idempotent and revokes browser
sessions. A retry observing `activating` skips activation and resumes completion;
expiry does not invalidate an already committed activation intent. The caller retains
the same target proof; final session revocation requires re-login for further browser
requests. Repeated completed finish reports the persisted review-required flag.

Cancellation is limited to prepared/confirmed/released/proven. A call observing
activating/completed returns `{cancelled:false,state}` and sends no cancel RPC.
The Main transaction chooses the finish/cancel winner. A stale cancellation read
that races with completion also returns the durable status, even if completion
revoked the browser session before the cancellation authorization batch ran.

These are separate D1 transactions coordinated by the private API orchestrator.
No cross-D1 atomicity is claimed. Custodian RPC is not exposed publicly and there is
no independent public endpoint that bypasses Main's cancellation decision.

### Target uniqueness and cancellation authorization

Start and activation both reject target IDs found in devices, device_keys,
vault_devices, device_requests, legacy recovery_cases or another recovery saga.
Historical/revoked/cancelled identities remain reserved. Request ID collisions are
also rejected before activation. Exact start retries retain their own reservation.

Cancellation requires `{action:"cancel",nonce,expiresAt,deviceId,signature}` signed
over the entire canonical case, action, nonce, expiration and signer identity under
the `AgentKeychain-recovery-cancel-v1` domain. A trusted current device or an
independently provisioned account verifier signs it. Main and Custodian each invoke
their separate authorization service; browser step-up is not independent evidence.
Admission rejects missing, wrong, expired or excessively future authorization.
Custodian atomically records the nonce/digest receipt with its cancellation or
pre-prepare tombstone. A different case/content cannot reuse that nonce. An exact
committed retry is an idempotent receipt and does not consume authorization again.

Main persists cancellation authorization with its decision before delivery. If the
RPC never committed and that authorization expires, a fresh independent signature
can resume delivery; the cancelled Main case never reopens. Therefore there is no
unconditional claim that every partial recovery failure resumes without renewed
authorization. Before activation, expired/revoked/stale-epoch cases remain fail-closed;
a transient activation failure is retryable only while eligibility still holds.

### Activity, approvals and isolation

Browser activity list/detail and checkpoint chains are tenant **and account** scoped.
Public event IDs/cursors are random opaque 128-bit identifiers. Global AUTOINCREMENT
IDs remain internal and are absent from event JSON and checkpoint canonical bytes.
Signed checkpoints bind the account scope digest, opaque previous/through boundaries,
account cumulative count and event root. A conditional insert serializes concurrent
checkpoint creation; a losing creator verifies the winning chain without signing
another chunk. At most 100 new events are checkpointed per request, with explicit
pending/verified/failed results. Historical verification still scans retained history.

Approval creation records an immutable digest of signed operation, TTL and optional
signed encrypted summary. An exact retry with a fresh transport nonce returns the
same request without extending expiry; changed content under the same ID conflicts.
Concurrent exact creation converges to one request. Existing one-use decisions and
atomic approval consumption in sync remain intact. Approval lists/actions, recovery
notifications/review and activity list/detail all reject same-tenant other-account
access. Fixed-schema audit excludes proof/signature/key/release material.

## TDD and adversarial evidence

Observed RED runs before their respective fixes:

- Five failing tests reproduced existing active/historical target acceptance,
  Custodian completed after Main activation-trigger failure, approval creation retry
  conflict and tenant-wide activity leakage. Thirty existing/new checks passed.
- A delayed cancellation test failed when its original authorization expired before
  custody delivery; fresh independent authorization now repairs that case.
- A controlled stale-read cancel/finish race failed with `approval_required` after
  finish revoked the session; it now returns deterministic completed status.

Final managed suite includes:

- Failure before Main activation, rollback within activation, after Main activation,
  before/after Custodian completion, before final Main transition and final-response
  loss. Retrying converges both databases to completed with one device activation.
- Concurrent finish/cancel and deterministic stale-read boundary; cancellation before
  release/after release, delayed prepare, cancelled delivery failure and response loss.
- Existing active/revoked devices, historical cancelled recovery, device-request
  collisions, and collision introduced after custody release; activation retries fail
  closed on collision. Repairing an injected activation trigger permits a safe retry.
- Missing/wrong-case/wrong-signature/wrong-action/expired cancellation authorization,
  independent Custodian denial, nonce replay, exact receipt retry, and independently
  authorized target completion. Both releases and both target-key proofs are required.
- Target-only 2-of-2 VDK reconstruction, cross-operator key isolation, cooldown,
  confirmer revocation, epoch substitution, session revocation and retained-key rotation.
- 250 own-account events interleaved with foreign events: pending → pending → verified,
  three cumulative checkpoints (100/200/250), opaque boundaries, and foreign cursor/
  detail denial. Concurrent creation verifies one 100/200/205 chain.
- Cross-account approval list/decisions, recovery notifications/review/cancel, and
  activity visibility. Audit corruption/redaction and immutable history gates remain.
- Approval response-loss and concurrent exact retries, changed TTL/content conflict,
  unchanged original one-use grant, rollback and Phase 2A/B/C regression gates.

Expected negative RPC calls print generic workerd errors (unauthorized, expired,
not_found, invalid_transition, AES authentication failure), never secret bytes.
The expanded focused run also emitted a workerd RPC disposal warning once; it was
not reported as an unhandled test failure. No real credentials were involved.

## Actual final gates

| Gate | Result |
| --- | --- |
| `CI=1 WRANGLER_SEND_METRICS=false npm test --prefix managed-cloud` | PASS: **227 tests, 9 files** |
| `npm run typecheck --prefix managed-cloud` | PASS |
| `CI=1 WRANGLER_SEND_METRICS=false npm run test:bundle --prefix managed-cloud` | PASS: builds and executes actual generated API/Custodian bundles with both migrated local D1 databases |
| `bun run lint` | PASS |
| `bun run typecheck` | PASS |
| `bun test` | PASS: **111 tests, 509 assertions, 25 files** |
| `bun run build` | PASS: 325 modules; ignored local binary |
| `npm audit --json --prefix managed-cloud` | PASS: online registry report, **0 vulnerabilities** |
| `npm audit --omit=dev --json --prefix managed-cloud` | PASS: online registry report, **0 vulnerabilities** |
| `git diff --check`, changed/new-file whitespace and secret scan | PASS |
| Frozen PRDs/plans, Phase 2A/B/C evidence, dependency manifests/lockfiles | Unchanged |
| HEAD / commits / deployment / real data | `986e495`; no commits, deployment or real-data access |

The initial sandbox test run could not bind loopback (`EPERM`); local tests were
rerun with approved loopback access. Root tests use the checked-in isolated-vault
and Keychain-stub guards. Online auditing was the only external network activity.

The generated bundle additionally verifies actual HTTP opaque activity IDs/detail,
rejection of numeric event IDs, no foreign-account activity/count advancement, and
exact approval creation retry. Extra synthetic requests initially exhausted the
unchanged 30/minute account budget; the harness now starts its independent recovery
scenario with a fresh synthetic rate window. Production limits and their tests were
not relaxed. Worker outbound fetch is blocked; all local Workers are disposed.

## Limits and handoff

- Built-in Chrome/DevTools is not exposed by current tool discovery. No browser UI,
  physical/platform authenticator or Chrome interaction was verified; prohibited
  Hermes/external Chrome adapters were not used. Browser-contract evidence is local
  workerd plus synthetic WebAuthn wire ceremonies and the actual generated bundle.
- No ordinary-user UI, persistent local client, email delivery, production trust
  registry/operator key infrastructure, remote D1, Cloudflare or real account was used.
  Independent production provider/registry provisioning and security review remain
  deployment gates. The synthetic account-verifier keys are not real email evidence.
- These Phase 2D migrations were already uncommitted/local-only and were repaired in
  place. They are not a live migration/backfill procedure for a deployed older schema.
  Prior-phase migrations, evidence and frozen plans were preserved.
- Cancellation cannot erase a key already reconstructed from two released shares.
  No power-loss, multi-region failover, production load/SLO or cross-D1 atomicity claim.
- An unknown newer checkpoint cannot be inferred from replay of an old valid signature;
  retained trusted pins/high-water marks are still needed. Verification cost grows
  with retained account history; no constant-cost archival claim.
- English/Chinese READMEs, managed-cloud JSON contracts and SYNC_GUIDE are synchronized.
  The full dirty tree is left for independent review; no commit or release approval
  is implied by the passing local gates.
