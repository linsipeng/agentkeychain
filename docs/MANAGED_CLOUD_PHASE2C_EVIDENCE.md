# Phase 2C implementation and local evidence

Date: 2026-11-05. Branch: `feat/managed-cloud-v0.7`. Starting commit: `0760b2d`.
The starting worktree was clean. Changes are intentionally uncommitted for the controller.

**Status:** device control-plane and signed durable-sync implementation delivered locally;
all local functional/build gates and controller-run online full/runtime vulnerability audits
pass. This remains local evidence, not production/security release approval.

## Scope and trust boundaries

Read the frozen Concept, Slice 1 technical plan, complete managed-cloud plan, v0.7/V1
PRDs, architecture/integration documents, current managed-cloud README, Phase 2A/B code
and evidence, and Slice 1 protocol/client code. Frozen plans and prior evidence remain
unchanged. The legacy Worker, local Vault/CLI/MCP implementation and dependency lockfile
remain unchanged. Current contracts are in [managed-cloud/README.md](../managed-cloud/README.md).
English/Chinese root READMEs and the sync guide are synchronized.

- `0004_devices.sql`: digest-only pairing capabilities, immutable public-key extension,
  signed enrollment grants, one-use browser actions, challenges, session acceptance,
  immutable key packages, metadata-only device audit and timestamp-bound nonce acceptance.
- `0005_checkpoints.sql`: immutable service key binding, per-vault genesis/sequence roots,
  immutable signed checkpoints and redacted checkpoint event metadata.
- Browser device routes reuse the reviewed session/Origin/CSRF/source/account-rate/Passkey
  pipeline. Authenticated GET verification landing is read-only JSON, not a future 404 UI.
  Approve/deny/revoke require explicit confirmation and exact action-bound step-up.
- First device uses an explicit bootstrap grant and requires no historical device. A later
  device additionally requires the exact canonical grant signed by an active trusted
  device of the same account/vault. Activation, grant persistence, step-up consumption
  and audit are one D1 trigger transaction. Revoke atomically invalidates all sessions.
- Device endpoints reject cookies. The server issues 15-minute random sessions after
  private-key challenge proof; only token digests are stored. Requests sign normalized
  method/path/query, exact body digest, Unix timestamp, nonce and token digest. D1 rechecks
  lifetime/membership/revocation and timestamp when accepting a one-use session nonce.
- Packages bind vault, target, epoch, issuer and accepted grant. The issuer is rechecked
  inside the same D1 transaction as request nonce acceptance. Exact retries only; target
  fetch has no caller-selectable target/account/vault. The service never decrypts a VDK.
- Sync adds deterministic chain roots binding previous root, sequence and exact signed
  operation digest. Checkpoint insert shares the version/head/approval/nonce/audit batch.
  Optimistic predecessor conflicts roll the whole batch back before bounded recomputation.
  Pull gets versions, latest checkpoint and page-end checkpoint from one D1 snapshot.
- Checkpoint signer is a mandatory private Service Binding. Production composition has
  no fallback key. Synthetic tests generate keys only in memory, inside their test signer
  or test Worker. No private key enters D1, checked-in fixtures, stdout or logs.

## TDD and adversarial evidence

- Protocol tests first failed on missing `device-protocol.ts`, then passed after strict
  grant/package canonicalization and domain-separated proofs were implemented.
- Timestamp regression was RED (`invalid_signature` for the new valid proof); implementation
  added mandatory timestamp headers and transactional skew checking. The 28-device/sync
  regression set then passed.
- Checkpoint tests first failed on missing `checkpoints.ts`; implementation validates key
  pins, signatures, roots, lower bounds and page/head consistency.
- Browser verification landing regression was RED (404 instead of 200); the authenticated
  read-only JSON route then passed, including the generated-bundle end-to-end flow.
- Real D1 cases cover bootstrap vs subsequent enrollment, absent/wrong step-up, missing
  confirmation/CSRF/Origin, exact action digest, wrong signing device, grant tampering,
  revoked authorizer, concurrent approvals and concurrent revoke/approve linearization.
- Device-code tests cover digest-only storage, unknown/expired/denied/replayed capabilities,
  five-second polling, one-use approved delivery, and independent high-entropy verification
  codes with a matching human-readable phrase.
- Challenge tests cover wrong signatures, five-attempt exhaustion, expiry, replay, reissuance,
  digest-only sessions, bearer-only theft, and revocation/session expiry after proof validation.
- Proof mutation tests independently change method, path, query, body, timestamp, nonce and
  session token. Duplicate accepted nonces fail; cleanup retains all live-session nonces and
  deletes exactly 64 of 70 eligible expired nonces in one bounded sweep.
- Key/package tests cover immutable wrapping/signing keys including SQLite REPLACE, wrong
  target/vault/epoch/issuer/grant, exact retry, changed ciphertext rejection, target-only fetch,
  cross-account list/revoke, and audit exclusion of public keys/tokens/package ciphertext.
- Audit failure injection rolls approval back without device, wrapping key, grant, action or
  step-up consumption. Existing sync audit rollback remains green. Checkpoint failure injection
  rolls version/head/nonce/checkpoint acceptance back. Concurrent distinct writes preserve
  contiguous sequences; exact concurrent retries return the original signed checkpoint.
- Checkpoint tests independently verify exact chain roots and reject service-key substitution,
  rollback below a retained lower bound, a hidden suffix inconsistent with the signed head,
  and page/ciphertext changes inconsistent with the page-end root.
- Every prior Phase 2A/2B test remains present and green. Existing sync fixtures now sign the
  stronger timestamp-bound request contract; timestamps are explicit to avoid clock-edge flakes.

## Generated bundle

`test:bundle` builds the actual API and Custodian modules and executes them in standalone
Miniflare/workerd. Compatibility date/flags, service entrypoint names and D1 bindings come
from the checked-in Wrangler manifests, including the new `CHECKPOINT_SIGNER` binding.
All migrations run locally. Outbound fetch is blocked. No Vitest loader or test-only
production bypass is present in the application bundle.

The harness executes real ES256 Passkey registration/login/step-up/logout, device authorize,
the live verification URI, browser pending/approve, device challenge/token, signed sync push
and pull, signed encrypted-package acceptance and target fetch. It checks checkpoint identity
between push and pull. An initial harness run incorrectly selected the synthetic signer as
Miniflare's first/public Worker; moving the API back to the first slot fixed the harness.
All service workers are disposed afterward; there is no deployment or remote binding.

## Gates

| Gate | Result |
| --- | --- |
| Managed focused device/checkpoint/transaction suite | PASS: 47 tests / 3 files |
| Managed full suite | PASS: 158 tests / 6 files |
| Managed typecheck | PASS |
| Managed build and `test:bundle` | PASS: generated modules, exact manifests and synthetic control-plane/sync flow |
| Root lint | PASS |
| Root typecheck | PASS |
| Root full tests | PASS: 111 tests, 509 assertions, 25 files |
| Root build | PASS: 325 modules; ignored local binary |
| Full/runtime npm vulnerability audits | PASS: controller-run current registry audit, 0 vulnerabilities in both reports |
| Dependency/lockfile changes | NONE |
| Diff/whitespace and changed-file secret/debug scan | PASS |

## Vulnerability audit

The implementation worker correctly refused to count offline npm output as advisory evidence.
The controller subsequently executed current registry-backed audits:

```sh
npm audit --json --prefix managed-cloud
npm audit --omit=dev --json --prefix managed-cloud
```

Both commands returned exit code 0 with zero info, low, moderate, high or critical findings.
The Phase 2B lockfile remained unchanged during Phase 2C.

## Limits

No built-in Chrome/DevTools interface was exposed. The prohibited Hermes browser adapter
was not used. Actual workerd HTTP contracts and virtual authenticators were exercised;
no real browser/platform-authenticator or ordinary-user UI validation is claimed.

No real keys, Vault, Keychain, sync.json, network service, Cloudflare account, deployment,
.env or user data was accessed. Tests used the existing temporary-home/Keychain-stub guards.
No commit, push, PR, migration of real data, provider provisioning or release occurred.

Service key rotation, nonempty legacy-history checkpoint backfill, multi-vault browser
selection, local client persistence/daemon, UI and recovery remain explicit later boundaries.
A replayed old signed snapshot needs an independently retained trusted anchor to prove
staleness; signatures alone cannot discover an unknown newer head. No power-loss,
multi-region, throughput/SLO or independent security-review certification is claimed.
