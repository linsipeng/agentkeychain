# Phase 4/5 local implementation acceptance and external gates

Date: 2026-11-06. HEAD remains `8cdd4a5ea2a125e157d9b9555eab1ed703a8a832`.
All changes are uncommitted. Original Phase45 prompt files were not located in the
repository; the continuation used the explicit five-item request and existing evidence. This replaces the previous trust-bootstrap blocker
report with evidence for the current working tree.

**The final three local implementation gaps are complete.** Protected enrollment
intent recovery, issuer/daemon interruption acceptance and directory-relative export
publication are implemented and verified. The current evidence and counts are in
[PHASE45_FINAL_CONTINUATION.md](PHASE45_FINAL_CONTINUATION.md); the implementation
notes and older counts below remain historical context. Only provisioning,
native-platform/browser acceptance and release/deployment gates remain.

## Implemented boundaries

- `src/cloud/config.ts` and `release.generated.ts`: exact HTTPS origin, release ID,
  protocol range, multiple checkpoint pins; strict canonicalization and Ed25519
  verification. Verified policy objects are provenance-checked. Production has no
  URL/pin environment or ordinary-flag override, and the default artifact is null:
  `cloud_unavailable_not_provisioned`. No production hostname/key was invented.
- `scripts/build-release.ts`: requires a signed manifest and an independently
  supplied public release root at build time, verifies before compilation, embeds
  immutable public material and builds the macOS native helper. Missing input
  fails; a synthetic signed release compiles and rejects runtime URL flags.
  This is build verification, not a claim of published or platform-signed releases.
- `src/cloud/enrollment.ts`: canonical `TrustedEnrollmentBundle`, target sealed-box
  encryption, account/tenant/vault/request/signing/wrapping/issuer/epoch/expiry/nonce
  bindings, signed roster and exact release pins. The locally computed 80-bit SAS
  commits to the whole canonical bundle. Preview cannot activate trust; acceptance
  requires local phrase confirmation plus decryption, canonical and signature checks.
  First-device anchoring uses the local device and verified release pins after the
  account authorization flow. Recovery-bundle validation requires an independently
  supplied authority pin and completed-case binding. Native recovery now uses the
  dedicated `recovery-trust.ts` / `recovery-activation.ts` path documented in
  [LOCAL_RECOVERY_ACTIVATION.md](LOCAL_RECOVERY_ACTIVATION.md).
- `src/cloud/login.ts`: device proof/authorization/browser opening/polling, existing
  device confirmation, key packages and encrypted enrollment persistence. Trust
  delivery precedes VDK delivery: the issuer sends the non-VDK bundle, both native
  flows compare its SAS, and only then does the issuer send the VDK package.
- Backend migration `0013` and `trust-repository.ts`: immutable, opaque, target-only
  trust delivery scoped to approved grants and authenticated active issuers.
- `src/platform/secure-store.ts` and `native/secure-store.swift`: path-isolated cloud
  namespace; separate CSK/signing/wrapping/refresh/anchor accounts; bounded private
  pipes, timeout and redacted failures. macOS uses Security.framework; Linux uses
  secret-tool stdin. Memory stores are injected, never selected by production env.
  Test mode refuses host access. Legacy master-password writes now also use the
  native stdin boundary while retaining the original service/account tuple.
- Cloud crypto retains independent VDK/CSK/device keys, keyed opaque object IDs,
  whole-payload AEAD with exact operation-header AAD and strictly pinned key packages.
  Mutable temporary key/plaintext buffers are cleared where practical. JavaScript
  strings/runtime copies are not reliably erasable; no stronger claim is made.

## Persistence, controls and transport

- `CloudStore`: lazy additive tables in the existing vault.db, WAL, busy timeout,
  foreign keys and CSK-encrypted state/outbox/heads/history/pins/shadow/audit records.
  Row AEAD binds table, primary key and schema. Lease fencing metadata is intentionally
  plaintext and contains no credential/account content. Symlink/hard-link databases
  are refused; legacy secret rows are not rewritten by enrollment/migration.
- Independent secure-store checkpoint anchors reject rollback/equal-sequence forks.
  Missing anchors fail closed; initialization is explicit. DB-ahead repair requires
  verified history containing the prior anchor. Unknown cloud schemas disable cloud
  integration while local-only CRUD remains usable.
- `VaultMutationCoordinator`: local creation plus signed encrypted outbox in one
  SQLite transaction; validated remote page application/history/heads/shadow/cursor
  in one transaction; no echo. Reconciler queues previously unseen legacy creates,
  detects changed/deleted tracked rows, and never uploads high-risk changes silently.
  Concurrent local edits block conflicting remote apply rather than being overwritten.
- Existing store/Secure Capture/MCP mutation paths use the coordinator when enrolled.
  Managed deletion/overwrite cannot use `--yes` to bypass approval. New managed
  import entries go through the coordinator; overwrite requires approval.
- Exact rotation, scope-change, deletion and restore requests are staged without
  changing the local value until accepted sync. Migration `0014` binds signed safe
  rotation/scope intents to exact operation bytes and includes the intent signature
  in browser decision binding. Unlabelled `put` requests remain unavailable for
  browser approval. Secret values never enter Web views.
- `ManagedHttpClient`: exact policy origin, request proofs, private-key challenge
  renewal, bounded request/response sizes, deadline, no redirects/cookies, redacted
  errors and bounded retry hints. Phase 2C renewal uses a new signing-key challenge;
  no invented bearer-refresh endpoint or credential is introduced. The secure-store
  refresh account is reserved, not populated with a fabricated token.
- `DurableSync`: exact retry bytes retained until verified pull commit, receipt and
  checkpoint checks, signature/history/replay/transition checks and independent
  anchors. A busy writer reports `cloud_sync_busy` instead of false success.
  Signed roster revocation now stops writes, invalidates local sessions and preserves
  the encrypted queue. The possession-only roster fetch channel remains accessible
  to revoked devices. Other unproven `not_found` responses remain `auth_required`.
- Daemon: fenced process/sync leases, periodic pulls, full-jitter backoff, private
  wake/stop Unix socket, launchd/systemd artifacts and CLI controls. Successful login
  launches the compiled daemon. Host service installation was not executed here.
- CLI: cloud login/status/compatibility/logout/devices/approve-device/revoke-device/
  sync-now/rotate/request-approval/service controls. Device removal opens the account
  browser for explicit approval. MCP preserves existing tool names and adds safe
  cloud status plus delete/restore/scope approval requests. Raw scoped reads still
  return plaintext to trusted local clients; no downstream payment/publish guarantee.
- Installer: destination-filesystem staging, executable permissions and metadata probe
  before rename; native helper checksum; restart only for an installed running service.
  Public AI installation instructions remain pinned to the released v0.6.2 binary.

## Real compiled-process acceptance

`tests/cloud-process.test.ts` builds the actual CLI entrypoint with a separate,
synthetic build composition. It runs two isolated Vault homes and simultaneous
compiled daemons against a separate loopback service process using the actual API,
repositories, SQL triggers and migrations with persistent SQLite/D1-compatible calls.

The test-only composition substitutes endpoint transport, in-memory secure-store RPC,
private password input and browser-confirmation UI. Private material is generated
at runtime and supplied over pipes/in-memory loopback; it is not compiled into the
binary, passed in argv, stored in fixture files or printed in assertions. Production
CLI/environment cannot select this composition. The helper itself is compiled and
stub-tested, not executed against a real user Keychain.

The passing process matrix contains **84 assertions**, covering:

1. First/second device HTTP authorization, local key possession, exact SAS comparison,
   trusted bundle and VDK delivery. Clients do not receive a shortcut enrollment pin.
2. Pre-enrollment legacy store rows remain byte-identical after enrollment. A compiled
   process exits after browser approval; a new process resumes with the same persisted
   keys through `/v1/devices/resume`, signed by that device. The original one-use poll
   remains one-use. Missing CSK fails without changing existing encrypted state.
3. Real Secure Capture input, durable encrypted queue, HTTP push/pull and B-side CLI
   retrieval; actual MCP stdio initialization and `akc_get` on B.
4. Service acceptance followed by an injected failed response: exact retry produces
   one accepted version per operation. This injects a 503 after commit, not a physical
   TCP reset; the client's uncertain-acceptance retry behavior is exercised.
5. Forced compiled-client exit inside the pull transaction: history/cursor remain
   unchanged, then recover after lease expiry. Only test-build lease duration is reduced.
6. Rotation retains old local value before approval; approved rotation/delete/restore
   synchronize; ordinary store cannot resurrect a tombstone.
7. Two compiled daemons automatically synchronize a new value, use wake-up IPC and
   stop via CLI over the private socket.
8. Offline queue persists across separate CLI processes; server restart preserves
   accepted history; checkpoint restart succeeds; revoked B cannot upload and keeps
   its encrypted queue.

The process service simulates the already-authenticated Passkey approval boundary.
It does not implement a fake authenticator inside the CLI or claim native Passkey
acceptance. Existing generated-workerd-bundle tests separately exercise real protocol
WebAuthn with synthetic ES256 authenticators and the two-Worker recovery saga.

## Verification results

| Gate | Result |
| --- | --- |
| Root `bun test` | **147 passed, 0 failed; 787 assertions, 41 files** |
| Managed backend full tests | **278 passed, 9 files** |
| Web full tests | **90 passed, 3 files** |
| Root lint and root/managed/Web typechecks | Passed |
| CLI and native helper build | Passed |
| Signed synthetic release build; absent-manifest release failure | Passed |
| Managed/Web build and generated bundle acceptance | Passed |
| Recovery resource diagnostics | **7 passed, 41 intentionally skipped**, no undisposed-resource warning |
| Managed full/runtime npm audit | **0 / 0 vulnerabilities** |
| Root Bun audit | Empty vulnerability map |
| Diff whitespace | Passed |

The final full root run includes the 84-assertion process test. Additional process
coverage exercises issuer process exit after accepted key-package delivery and restart
without generating another ciphertext or requiring another phrase confirmation;
managed export refusal before approval (including `--yes`), consumption response loss,
retry and reuse refusal; and older-client metadata/version edits approved and pulled
by the other compiled client. Existing target-resume tests remain present.

The continuation added failing tests before the issuer journal, legacy reconciliation
and export implementation. Focused red runs demonstrated missing modules/methods,
local conflict during original-create acceptance, and output-directory substitution.
The initial sandboxed process/Worker launches failed because loopback listening was
blocked; reruns used approved local test execution. No external service was used.

Behavior changes began with failing focused tests (missing modules, missing trust
repository/intent behavior, installer ordering, capture completion text, master
password argv). The first signed-release test timed out during a cold Swift compile;
its timeout was raised to 60 seconds and the full root suite subsequently passed.
The process suite exposed and fixed premature CLI async exit, a capture response
shutdown race and falsely successful busy-sync reporting.

## Continuation implementation and acceptance

### Approved export

- `managed-cloud/shared/export.ts` defines an exact canonical export intent binding
  action, request ID, account, tenant, vault, device, expiry, encrypted-row snapshot
  digest and output intent digest. The latter includes the real destination directory
  and its device/inode identity. Paths and credential values are not sent to the service.
- Migration `0016` and `export-repository.ts` provide separate export decisions and
  atomic consumption behind active device proofs, account membership, live browser
  sessions and action-bound step-up. Exact retry returns the same logical acceptance;
  a different canonical intent or signature does not. Mutation and export requests
  share a durable pagination index and the ordinary browser approval views.
- `cloud request-export <path>` persists and sends the signed request. After account
  approval, `export --out <path>` consumes it before decrypting export entries or
  writing a bundle. `--yes` does not bypass. Local-only export retains its format and
  existing behavior. Managed export refuses to overwrite unrelated existing output.
- The CSK-encrypted local journal retains prepared bundle bytes before file delivery.
  A flushed encrypted staging file is linked exclusively into the destination and
  the journal is marked completed. A process interruption can leave an encrypted
  staging file; journal-bound startup/resume cleanup is now implemented. Eleven
  compiled export crash boundaries are covered by the latest continuation. This is
  not an exhaustive filesystem/power-failure recovery claim.
- Tests cover pending/deny/cancel/expiry, foreign/revoked devices, changed intent and
  content, directory substitution, concurrent local permits, accepted-response loss,
  no output before acceptance and completed-request reuse. Compiled-process checks
  confirm output contains no plaintext test credential. The source scan found no
  embedded production credentials or raw KEK assignments.

### Issuer retry

- `src/cloud/issuer.ts` journals exact grant, signed/sealed trust bundle, SAS, sealed
  key package and local confirmation in CSK-encrypted state before network delivery.
  Concurrent callers for the same request use one transactional journal. A changed
  grant fails closed; expiry is enforced locally and by migration `0015`.
- Pairing detail can resume approved/delivered requests only for the original issuer;
  exact pairing confirmation is idempotent. The VDK package remains gated by explicit
  local phrase confirmation. Production has no test confirmation flag.
- A compiled issuer is terminated after the service accepts its package, then another
  compiled process retries the same journal successfully. This does not prove every
  expiry/deny/revocation/concurrent-issuer interruption combination.

### Legacy-edit reconciliation

- `cloud reconcile` lists encrypted local reconciliation records; `cloud reconcile
  <name>` stages exact signed rotation/scope/delete/restore approval without uploading
  the edit as an ordinary create. Metadata, scopes, version and encrypted-row changes
  participate in the shadow fingerprint; physical deletion can produce an approved
  tombstone retaining the last encrypted cloud payload for restore.
- Acceptance checks the exact staged fingerprint again. A changed row blocks apply.
  An older binary editing an original queued create during service acceptance does
  not deadlock the queue or lose the edit: the accepted head advances while the edit
  remains pending for a separate approval. Successful remote apply updates shadow and
  removes the matching outbox/reconciliation record without an echo.
- Tests cover local restart, changed-content rejection, scope/metadata/version edits,
  physical deletion, resurrection and original-create acceptance races. Compiled
  clients also exercise metadata/version reconciliation through real API approval.
  Pending deny/cancel/expiry states and replacement requests now have local handling;
  compiled denial/cancellation/replacement cases are included in the continuation.
  The final compiled interruption/action matrix supersedes this earlier coverage; see the current continuation record.

## Signed roster continuation

The earlier roster continuation implemented signed roster/revocation propagation and
preserved the prior export, reconciliation and issuer delivery journals. Detailed
contract, trust boundaries, limitations and evidence: [SIGNED_ROSTER.md](SIGNED_ROSTER.md).
New focused red test first failed on the absent roster module. Subsequent process
runs exposed pending-enrollment delivery ordering and synthetic test clients sharing
one source rate bucket; the production rate limits were preserved and the isolated
clients now have separate synthetic source identities. Compiled issuer interruption
also observes its fencing lease expiry before restart.

That original root run passed 147 tests / 787 assertions; backend 278; Web 90. The compiled
process flow passes 84 assertions, including signed revoke propagation, terminal B
daemon state, byte-identical encrypted queue preservation and restart acceptance.
CSK history and independent anchor crash tests, authority-certificate issuance,
concurrent revision/issuer race tests and revoked-operation checkpoint proof tests
are included. No production endpoints/keys, real Vault/Keychain, deployment or commit.

## Final local acceptance

The final continuation closes the three internal gaps previously listed here:

- Issuer intent/confirmation/delivery/receipt interruptions, terminal requests,
  replacement without SAS reuse and concurrent canonical delivery; local/outbox,
  push/pull/cursor/anchor, daemon lease, roster revocation and reconciliation crashes.
- Protected enrollment intent before secure slots, exact signed/encrypted evidence
  revalidation, missing/stale SQLite repair and fail-closed conflicting/unknown anchors.
- POSIX directory-descriptor-relative exclusive publication and cleanup, durable
  output inode receipts, hostile parent replacement, fsync failures and artifact scans.

See [final evidence](PHASE45_FINAL_CONTINUATION.md) and its
[machine-readable audit](PHASE45_FINAL_CONTINUATION_AUDIT.json) for current counts,
implementation details and reproducible test entrypoints. Earlier counts above are
historical, not claims about the final tree.

## External gates

Independently provisioned production domains and signing/service/operator bindings;
actual OS secure-store and launchd/systemd acceptance; Linux/native packaging and
signing; built-in Chrome/native Passkey acceptance; explicit release/deployment and
production acceptance. Windows export intentionally fails closed. No real vault,
credential, Keychain or deployed service was used. No commit, push or deployment.

中文：最终三项内部缺口已完成本地实现与验收：签发端/守护进程中断与并发矩阵、受保护
注册意图及部分锚恢复、基于已打开目录描述符的排他导出发布。现仅保留外部生产配置、
原生平台/浏览器验收及发布部署门槛。最新计数与证据见上述续作记录；历史记录不覆盖它。
