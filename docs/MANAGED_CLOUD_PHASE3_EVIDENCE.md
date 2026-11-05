# Phase 3 local implementation evidence / 本地实现证据

Starting/current HEAD: `67b0da6`; branch: `feat/managed-cloud-v0.7`.
All changes remain uncommitted. This record includes the independent-review repair
pass. Controller browser acceptance remains outstanding; this is not a full Phase 3
acceptance claim. The former Phase 3 blocker investigation is
superseded by this implementation and the repairs below. Its useful tests are retained as security
regressions with the now-supported contracts, rather than assertions that routes
must remain missing.

The original Phase 3 request was recovered from the local conversation record and
checked against `CONCEPT.md`, `TECH_PLAN_MANAGED_CLOUD_COMPLETE.md`, the Web spec,
and the verified Phase 2 repositories. No commit, push, PR, deploy, real account,
real email, real browser credential, production Vault/Keychain/configuration or
user data was used. npm registry access was limited to pinned dependencies/audits.

## Implemented files and boundaries

- `api-worker/migrations/0009_public_recovery.sql`: encrypted invitation display
  metadata, digest-only restricted/decoy recovery credentials, immutable exact
  target binding, one-use proof/bootstrap reservation, transaction authorization,
  expiry and membership/completion revocation. Local-only additive migration.
- `api-worker/invitations.ts`: provisioning with existing email AES-GCM/HMAC keys,
  exact-capability masked lookup, generic missing/expired/used/corrupt rejection.
  Legacy hash-only invitations fail display closed; no fabricated email/backfill.
- `api-worker/public-recovery.ts`, `browser-auth.ts`, `browser-repository.ts`,
  `recovery-repository.ts`: existing-account independent email verification,
  restricted start/status/cancel, scoped rate limits and bounded retention. No
  normal session is issued by recovery. Existing cooldown, two-party authorization,
  target proof, cancellation lock and final revocation remain authoritative.
- `api-worker/migrations/0010_web.sql`, `web-repository.ts`: bounded safe projections,
  scoped opaque action/continuation references, exact Passkey step-up resolution,
  device/request/history/account/activity views, recovery review and server readback.
  No browser response from this facade contains an envelope, private key, share,
  wrapped data key, signature, canonical grant or internal approval digest.
- `device-http.ts`: signed target-device recovery transport and existing-device
  pairing confirmation, independent cancellation handoff, 12-character/72-bit pairing
  codes and three 2048-list words (33 comparison bits). Old full-length codes remain
  accepted. Recovery handoff references last 48 hours; restricted browser sessions
  last ten minutes. Target transport requires both capability and target signature.
- `web/src/App.tsx`, `api.ts`, `i18n.ts`, `style.css`, `main.tsx`: Vite + React +
  Router + TanStack Query, complete English/Chinese dictionary parity, all public
  and signed-in routes in the frozen spec, same-origin CSRF API client, native
  `navigator.credentials` adapter, confirm dialogs, keyboard focus management,
  mobile More sheet, loading/empty/error/stale states, scoped continuation controls,
  persistent activity warnings and in-memory rollback receipts. No external fonts,
  analytics, scripts, endpoint input, password fallback or public signup.
- `index.ts`, `wrangler.toml`, `build.mjs`: Worker-served built SPA/deep links and API,
  no-store/CSP/no-referrer/nosniff headers, source/source-map rejection.
- `web/tests/*`, expanded workerd suites and `tests/generated-bundle.mjs`: component,
  route, API, accessibility, security, real two-Worker and exact built-artifact tests.
- Workspace/lock files contain exact Web dependency pins. `@scure/bip39@2.0.1` is
  used only for its fixed English word list; no mnemonic/seed generation is used.
  Installation used `--ignore-scripts`. ESLint now includes Web TSX.
- English/Chinese READMEs, `docs/SYNC_GUIDE.md` and `managed-cloud/README.md` are
  synchronized with these local implementation boundaries and endpoint contracts.

## RED → GREEN evidence

1. Modified characterization tests first expected masked invitation detail and a
   public recovery verification contract. Actual workerd RED: **2 failed / 106
   passed**; the prior endpoints returned 404.
2. Added recovery response parity, restricted-route, proof/bootstrap replay and
   cross-case assertions. Actual workerd RED: **3 failed / 111 passed** before
   recovery verification existed. Implemented separate restricted credentials;
   subsequent focused auth GREEN: **114 passed**.
3. Added Web read-model authentication/projection tests before implementing the
   facade. Workerd RED: **1 failed / 158 passed** across auth/recovery; `web/query`
   was absent. Scoped projections made the suite green.
4. Web API/i18n tests initially failed to import the absent implementation. Native
   adapter, official relative API client and dictionaries were then implemented.
   A subsequent CSRF assertion caught the test environment failing to accept a
   `__Host-` Secure cookie; HTTPS JSDOM and exact cookie attributes fixed the fixture.
5. Adversarial same-case/different-target regression was deliberately added before
   fixing target lookup. Actual workerd RED: **1 failed / 43 skipped**: the earlier
   ID-only lookup selected a different signed target and legitimate start returned
   401. Verification now stores immutable exact target bytes; start and target
   delivery check that binding. GREEN includes both substitution and foreign-account
   verification against the same target, followed by real two-Worker completion.
6. Additional regressions cover encrypted/legacy invitation metadata, concurrent
   public proof consumption, expiry, restricted route denial, origin/CSRF, generic
   known/unknown/failed-proof verification responses, audit redaction, scoped opaque
   approval references, no mutation before step-up, one-use decisions, preserved
   deleted-current history, existing-device signatures and target-only recovery data.

The sandbox initially refused loopback listeners (`EPERM 127.0.0.1`). Managed and
root loopback suites were rerun with approved local listener access. These failures
were test-environment restrictions, not reported as product test passes.

## Final gates

| Gate | Actual result |
| --- | --- |
| `CI=1 WRANGLER_SEND_METRICS=false npm test --prefix managed-cloud` | **268 passed**, 9 files |
| `npm test --prefix managed-cloud/web` | **90 passed**, 3 files |
| `npm run typecheck --prefix managed-cloud` | Passed |
| `npm run typecheck --prefix managed-cloud/web` | Passed |
| Web Vite production build, standalone and through managed build | Passed |
| `npm run build --prefix managed-cloud` | Passed, SPA and both Workers |
| `npm run test:bundle --prefix managed-cloud` | Passed, actual generated workerd artifacts |
| `bun run lint` | Passed, includes Web TSX |
| `bun run typecheck` | Passed |
| `bun test` | **111 passed**, 25 files, 509 assertions |
| `bun run build` | Passed, CLI compile |
| Full/runtime `npm audit --prefix managed-cloud` | **0 / 0 vulnerabilities** |
| `npm run test:recovery-resources --prefix managed-cloud` | **7 passed**, 41 intentionally skipped; host output contains no undisposed-resource warning |
| Root `bun audit --json` | PASS: 0 vulnerabilities after exact dependency updates and reviewed overrides |
| `git diff --check` | Passed |
| New implementation secret/debug/storage/unsafe-HTML scan | No hits |

Audit responses are retained in
[`MANAGED_CLOUD_PHASE3_AUDIT.json`](./MANAGED_CLOUD_PHASE3_AUDIT.json).
The workerd recovery negatives intentionally exercise failed RPC calls; the runner
prints expected rejected-RPC diagnostics. These are distinct from disposal warnings:
no undisposed-resource message appeared in the final full backend, isolated resource
regression, or generated-bundle output. See the resource ownership details below.
Root dependencies were updated only after the controller reproduced the advisory set.
`@modelcontextprotocol/sdk` is pinned to 1.32.2; ESLint/tooling and affected transitive
HTTP/URI/schema packages are pinned through reviewed exact versions/overrides. The
final `bun audit --json` returns an empty vulnerability map, and all root tests,
typecheck, lint and compiled-binary build pass with the updated lockfile.

The generated-bundle test serves real built HTML/JS for `/sign-in`, signed-in deep
links and recovery deep links, asserts security/no-store headers and rejects source
maps/source paths. It also runs ES256 registration/login/step-up/logout, device
registration, signed updates, exact approval, verified activity and real two-Worker
recovery with synthetic service bindings. It is not a mocked Worker bundle test.

## Web acceptance coverage

- All 19 specified routes render one H1; all primary route DOMs and a confirmation
  dialog have zero serious/critical findings in the enabled axe rules.
- Invitation → masked display → user-entered email/proof → native-adapter Passkey
  creation → Home, plus sign-in success/cancel/unknown behavior.
- Allow/deny require the existing exact step-up contract, explicit confirmation and
  authoritative re-query. Missing details disable Allow once; no batch controls.
- Device addition requires exact word matching; first-device confirmation is
  explicit. Removal is shown only after server readback. Existing-device signatures
  and expiry/replay are covered by actual workerd tests.
- Earlier versions preserve current deletion and previous versions; restore waits
  for a device-created signed request. The browser never manufactures an operation.
- Activity filters/detail and persistent verification warnings; account metadata,
  recovery stages, independent cancellation confirmation, locked terminal/activation
  states, session cache clearing, language parity, link preservation, keyboard focus
  trap/restore and no technical terminology in rendered primary screens.
- CSS contract checks cover responsive tracks/wrapping, 44px targets and reduced
  motion; six actual text/background palette pairs meet WCAG AA contrast numerically.

## Browser acceptance and remaining limits

The controller measurements below are historical. This final repair session had
no Codex built-in Chrome/DevTools capability and did not rerun browser checks.
No external Chrome or Hermes browser adapter was used.

- Controller used the real local Chrome state through Kimi WebBridge. Desktop and
  375px sign-in/recovery rendered successfully; signed-in Home was rendered with a
  synthetic same-origin API read model solely for visual inspection. Desktop content
  filled the available area, 375px had no horizontal overflow, the public recovery
  link measured 44px after repair, mobile navigation targets measured 48px, and the
  More dialog opened with focus inside. English/Chinese switching and one-H1 page
  structure were verified. The favicon 404, undersized public link and ambiguous
  cross-device Passkey copy found during review were fixed and rechecked.
- Native/platform Passkey ceremonies, real email delivery and a real signed-in cloud
  account were not exercised. Synthetic fetch injection was not treated as backend or
  authentication evidence; it was used only to inspect signed-in layout states.
- JSDOM does not implement layout/canvas contrast. axe's color-contrast rule is
  disabled in DOM tests; numeric palette tests are separate. These are not a claim
  that full rendered WCAG/browser acceptance has passed.
- Device progress is a report from an authenticated device, not independent proof
  of local persistence. Migration 0012 records successful pull time and the input
  processed cursor, never the newly delivered suffix. Freshness lasts 300 seconds;
  Phase 4 periodic client pulls remain unimplemented. No timer fabricates progress.
- Existing operation types without safe review details remain non-approvable in
  the Web. Restore requires a real pending device request. Cancellation needs an
  independently signed confirmation; the browser cannot manufacture one. Enrolled
  device/account metadata lists are bounded to 100, recovery summaries to 20.
- Verification bootstrap responses are indistinguishable for known, unknown and
  failed-proof attempts. Only a real independently verified account with the exact
  eligible package can start a real case; decoy attempts never show fake success.
- Production email/trusted-ingress/recovery authority bindings, live cloud setup,
  physical devices, persistent local-client handoff integration (Phase 4), independent
  review of the new code and deployment/release approval remain separate gates.
  No production configuration was invented to conceal those boundaries.

修复代码与已执行的自动化验证保留在完整未提交工作区供审查。当前任务的真实浏览器
验收仍受阻，根目录依赖审计有上述发现；不得据此宣称整项验收完成、无 Bug、已部署
或生产可用。原生平台 Passkey 与后续阶段边界继续保留。


## Independent-review repair pass

### Public recovery authorization

- Removed the direct `{email,proof,target}` branch entirely. The only public
  verification schema is `{email,proof,requestRef}`; mixed bodies are rejected.
  References must resolve to an unexpired target record.
- Added `/v1/devices/recovery-target-challenge`: validates the target signature,
  seals a random possession challenge to the exact wrapping key, stores only a
  digest of the challenge/reference, and expires it after five minutes.
  `/recovery-target` consumes the exact target-bound proof once before issuing
  the 48-hour reference. Signature over target binds signing/wrapping public keys;
  challenge decryption independently proves the wrapping private key.
- Device recovery transport rejects Cookie, Origin and Fetch Metadata headers.
  Signed target transport remains required for status/release/finish. This
  isolates browser requests; it is not hardware attestation or proof of which
  program generated a key. A non-browser client is still subject to independent
  recovery authorization and two-party release. Claims here concern the public
  restricted recovery contract; existing Phase 2 repository contracts remain.
- Migration `0011` invalidates pre-repair handoffs and restricted recovery
  sessions that could have used direct targets. Normal sessions are preserved.
  It was run only against synthetic local workerd databases.
- Workerd negatives exercise complete browser-generated keypairs, direct and
  mixed target bodies, unknown/expired references, browser headers, wrong
  possession proof and replay, foreign accounts, foreign delivery signatures,
  inability to decrypt either target share, and failure to unwrap a VDK with a
  guessed second share. Positive control decrypts both target shares and the
  exact synthetic VDK, then finishes with target proof. Browser responses remain
  only acceptance/case/state/review metadata.

### State and screen repairs

- Home, Requests, Activity and Event Detail preserve failure during pending/error
  responses and clear it after a later verified response. Failed/pending/verified
  messaging no longer contradicts itself. Transition regressions cover all four.
- Session-expired clears query cache and account Risk.failed before navigation;
  API expiry also resets the in-memory activity receipt. Different-account login
  regression verifies a pending account does not inherit the previous warning.
- Requests retains visible Needs your attention / Recent controls with tab roles,
  selected styling and view-switch regression. Devices renders Needs attention,
  Active devices and Removed devices. Attention is active + stale/waiting/paused/
  unavailable status. Attention and Active never duplicate a device. Backend
  authenticated pull observations now supply last-seen and processed-cursor state;
  no new delivery is treated as acknowledgement.
- Account projects at most 20 persisted account/tenant-scoped recovery notification
  events and timestamps; tests include 25 records and a foreign-account row.
  The section is labelled Notification status, states delivery status is unavailable,
  links to Activity, and offers no nonexistent notification settings.
- Recursive sensitive-field guard runs before Web data reaches components.
  All 12 query views and four public recovery contracts have nested-array/object
  negative coverage for 43 spelling variants, including private/public/signing/wrapping/recovery/raw keys, key material,
  shares, VDK, plaintext, ciphertext, envelopes, signatures, tokens and digests.
  Workerd assertions also cover all real query projections, with populated
  request/device/history/activity/event/recovery/account records.
- Preserved public 44px link styling, mobile 48px navigation, explanatory Passkey
  copy, no external resources and the data favicon. Existing route/axe/design,
  approval, signature, replay, isolation and bundle tests remain in place.

### TDD observations

- UI transition/session/tab/device regressions: **7 failed / 51 passed** before
  changes; that earlier Web suite had **71 passed** (superseded below).
- Direct-target regression against pre-repair code: **1 failed / 1 passed /
  245 skipped**; the failing request was wrongly accepted with HTTP 200.
- Resource ownership test first failed because `shared/rpc-data.ts` did not exist.
- Expanded sensitive-key variants first produced **12 security failures**; the
  normalized recursive guard now rejects all variants on every query view.
- Migration regression first observed `revoked=0` for an old restricted session;
  migration now revokes it and preserves the normal browser session.

### RPC disposal investigation and containment

The reproduced message was the native **host workerd RPC result lifetime** warning,
not an application `console.warn`, and not the expected rejected-RPC exceptions.
The host does not report an allocation backtrace with this message. Prior full
recovery output contained it; an isolated initial two-flow check did not, so that
check alone was not treated as proof of full cleanup.

`shared/rpc-data.ts` now owns data-only RPC results: await, copy, and dispose via
`Symbol.dispose` in `finally`. API recovery calls and custodian key/rewrap calls
use it. Response-loss test adapters also release successful results before throwing
synthetic exceptions. A focused ownership regression proves cleanup after copying,
a later exception and copy failure. No RPC capability is retained in copied data.

`tests/recovery-resources.mjs` captures the child process host stdout/stderr, checks
that actual tests ran, and fails on an undisposed-resource warning. It covers seven
success/retry/resource cases, including real two-Worker recovery, delayed recovery,
public target handoff, partial RPC response loss and activation retry. Final full
backend and generated-artifact logs also contain no such warning. Expected negative
RPC error diagnostics remain visible; no stderr suppression was added.

### Controller browser acceptance

The implementation worker had no browser tool. Controller subsequently used Kimi
WebBridge against a local Vite server; no production account, Vault/Keychain or real
Passkey was used.

| Required actual browser check | Result |
| --- | --- |
| Desktop sign-in and recovery geometry | PASS |
| 375px sign-in and recovery, no horizontal overflow | PASS |
| Desktop and 375px synthetic signed-in Home geometry | PASS for visual/layout only |
| Rendered 44px public/control and 48px mobile target measurements | PASS |
| Mobile More dialog | PASS; focus entered dialog; keyboard trap/restore remains covered by DOM regression |
| Native/platform Passkey ceremony | Not performed; remains a platform acceptance limit |

CSS/JSDOM/axe checks and actual browser measurements are both recorded; neither is
presented as native Passkey or production-account acceptance.

## Final Phase 3 repair (2026-11-06 Asia/Shanghai)

- Normal account `recovery/start/status/cancel` return 401; legacy
  `recovery/detail/release/finish/notifications/review` return 404. Eight explicit
  normal-session route regressions assert these failures and safe error responses.
  Account status/notifications/review/cancel use only web query/action contracts.
- Restricted email recovery binds the possession-verified, target-signed requestRef.
  Start accepts only `{}`; direct targets and signed cancel authorization bodies
  are rejected. Cancel accepts an opaque same-account confirmation reference.
  Step-up remains mandatory for normal-account cancellation; regression covers
  missing/wrong reference, missing step-up, success and safe persisted readback.
- Generated bundle recovery uses `recovery-target-challenge`, `recovery-target`,
  `recovery-target-status/release/finish`. Only the synthetic target decrypts and
  signs proof; browser responses pass the recursive safe-view guard. A test-only
  workerd device transport avoids Node/Undici's injected Fetch Metadata; production
  target routes continue rejecting browser headers. Normal browser review then
  uses web options/verify/execute, without a recovery canonical or digest response.
- Recursive response checks now include proof, challenge, authorization,
  cancelAuthorization, completionSignature, canonical, wrappedVDK/wrapped_vdk,
  share/apiShare/custodianShare, sealed/encrypted/ciphertext and public/private/
  ephemeral key names. Authentication WebAuthn options remain a separate contract.
- The real API client's GET `/v1/auth/session` 401 now resets receipt/cache and
  dispatches expiry; the mounted application clears its actual query client and
  Risk.failed before redirect. The regression triggers a fetch 401, never manually
  dispatches expiry, and then signs in with a different account and pending state.
  The generated Worker test separately verifies real backend session revocation.
- Failed activity verification persists through pending responses and clears on
  verified. Fresh pending is not failed on Home, Requests, Activity and Event.
- Device states derive from account/tenant/vault-scoped backend progress: current
  (recent and at head), updating (recent and behind), waiting (no observations),
  stale (older than 300 seconds), paused (disabled vault membership), unavailable
  (missing/inconsistent state), removed (inactive device). Backend transition and
  pull acknowledgement tests plus seven UI partition cases cover these states.
- Requests attention/recent tabs and notification delivery disclaimers remain;
  44px public targets, cross-device Passkey wording and data favicon are preserved.
- Initial final-repair Web RED: 13 failed / 62 passed. Final counts in the table
  above supersede earlier historical passes. Root dependencies/overrides and
  bun.lock were not edited in this repair. All changes remain dirty/uncommitted;
  no commit, push, deploy or production operation occurred.

Final browser audit limit: no fresh Chrome DevTools or native Passkey run was
possible with this session's tools. DOM axe checks (19 routes + dialog) exclude
layout/canvas contrast; historical controller geometry is not final-repair browser
acceptance. Production identity/email/recovery adapters and Phase 4 integration
remain outside this local repair. No zero-bug or production acceptance claim.
