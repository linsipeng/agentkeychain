# Phase 2B repair evidence / 复审修复记录

Date: 2026-11-05. Branch: `feat/managed-cloud-v0.7`; HEAD:
`4bae5cf2775fcb6985e1e3023d3f51be0c441ae3`.
This repair **started with the dirty Phase 2B implementation**, not a clean tree.
The existing code, prior evidence/audit, `TECH_PLAN_MANAGED_CLOUD_COMPLETE.md`, and
both Managed Cloud PRDs were read. Frozen plans/PRDs and legacy `worker/` remain
unchanged. All work remains uncommitted. No deploy, Cloudflare account, real email,
real browser/passkey, Vault/Keychain, sync.json, .env or production data was used.

本记录替代上一轮 83 测试、完整审计失败的验收状态；旧依赖审计保留在
[审计 JSON](./MANAGED_CLOUD_PHASE2B_AUDIT.json) 的 `previousAudit` 中。
本次为本地修复与验证，不代表独立复审通过或上线授权。

## Exact files

| Files | Repair/result |
| --- | --- |
| `managed-cloud/api-worker/webauthn.ts` | Required resident/discoverable creation, legacy requireResidentKey=true, explicit negative credProps rejection; existing cryptographic checks retained |
| `managed-cloud/api-worker/browser-auth.ts` | Both invitation and verifier paths settle before combining results; required validated trusted source, redacted failures, explicit CryptoKey purpose checks, bounded cleanup on unsafe requests |
| `managed-cloud/api-worker/browser-bindings.ts` | Mandatory verifier/source, canonical 32-byte key decoding, pairwise material separation, all configuration/provider failures redacted |
| `managed-cloud/api-worker/browser-repository.ts` | Conditional INSERT RETURNING requires exactly one verification; bounded atomic retention sweep including dependent acceptance ledger |
| `managed-cloud/api-worker/migrations/0003_auth_retention.sql` | Indexed expiry lookups; only rejected audit events older than 30 days can be deleted |
| `managed-cloud/api-worker/wrangler.toml` | Existing checked-in nodejs_compat/date retained; exact named email/source service bindings added, no real resources/secrets |
| `managed-cloud/tests/browser-auth.spec.ts`, `virtual-authenticator.ts` | 96 auth cases, actual Ed25519/ES256 signatures, provider barriers and D1 races, independent UP/topOrigin, malformed attestation, retention and flood checks |
| `managed-cloud/tests/generated-bundle.mjs` | Standalone generated-module execution using Wrangler manifests, synthetic RPC adapters, local D1, blocked outbound fetch and guaranteed disposal |
| `managed-cloud/package.json`, `package-lock.json` | Reviewed exact toolchain pins, complete transitive integrity and test:bundle command |
| `managed-cloud/vitest.config.ts`, `tsconfig.json`, `tests/env.d.ts` | Official renamed Workers Vitest plugin imports/types |
| `README.md`, `README.zh-CN.md`, `docs/SYNC_GUIDE.md`, `managed-cloud/README.md` | Synchronized repaired behavior, retention, binding requirements and limits |
| This file, `docs/MANAGED_CLOUD_PHASE2B_AUDIT.json` | Current results, previous audit preserved, exact version and execution evidence |

Already-dirty Phase 2B foundation files retained: `api-worker/index.ts`,
`api-worker/package.json`, `api-worker/migrations/0002_browser_auth.sql`,
`shared/contracts.ts`, and `build.mjs`, all under `managed-cloud/`.

## TDD and security evidence

- First regression run could not listen on loopback in the sandbox (EPERM). With
  local-listening permission the actual workerd run was **RED: 23 failed / 60 passed**.
  Failures included resident options, nonresident hint, both invitation races,
  verifier invocation differences, missing/malformed/equal/source bindings and
  wrong-purpose keys. Fixes then produced **83/83**.
- Cleanup and post-crypto authentication tests preceded cleanup implementation:
  **RED: 2 failed / 88 passed**, specifically the missing cleanup method. The
  implementation and additional adversarial tests produced **130/130** overall:
  **96 auth + all 34 Phase 2A tests**.
- Registration uses `residentKey: required` and `requireResidentKey: true`.
  The standards-based capability test refuses creation on a nonresident-only
  authenticator before producing a credential; a resident-capable client succeeds.
  An actual registration with `credProps.rk=false` is rejected. The extension is
  unsigned and optional: none attestation cannot prove malicious-client storage.
  The enforcement guarantee is the conforming client's required creation policy,
  not an invented resident flag in signed authenticatorData.
- Provider barriers suspend email verification, then D1 consumes or expires the
  invitation. Both reject without inserting a verification or returning a phantom
  ID. Another test completes a competing **real registration HTTP ceremony** while
  verification is suspended and observes the same rejection. INSERT RETURNING
  linearizes eligibility at insertion; later consumption is rechecked at registration.
- Invalid invitation, wrong email, wrong proof and valid proof each invoke the
  verifier exactly once after unchanged source/identity rate gates. Lookup and
  verification run concurrently via allSettled, including verifier exceptions.
  This proves invocation equivalence, not wall-clock constant-time network service.
- Missing source/verifier, empty/non-string/space/uppercase/Unicode/oversized source,
  thrown source, inconsistent repeated source results, malformed/short keys and
  each equal-key pair return generic 503. The canonical source grammar is
  `[a-z0-9][a-z0-9._:-]{0,127}`. Both resolutions must agree for the same request;
  cross-request stability/authenticity remains a trusted ingress contract.
- Direct composition rejects AES/HMAC wrong-purpose CryptoKeys. A bootstrap signed
  using the lookup HMAC cannot authenticate. Production imports decoded key bytes
  into fixed algorithm/usages and rejects identical material before composition.
- Independent UP=false/UV=true and topOrigin-present/crossOrigin=false vectors
  reject in registration and assertions. Actual CBOR packed attestation and malformed
  bytes traverse the production adapter and reject. Existing RP/Origin/challenge,
  signature, UV, userHandle, replay, counter-risk and account-isolation tests remain.
- workerd's Headers API joins duplicate Origin, Content-Type and X-CSRF-Token with
  commas. Tests confirm normalization, reject appended duplicates and comma forms
  with/without spaces, and preserve the session. Raw wire multiplicity is not exposed.
- Post-crypto login races mutate membership, email identity, passkey, consumed
  anonymous session or anonymous expiry before the D1 acceptance batch. Each rolls
  back without a new session/acceptance/audit success. Step-up also covers revoked
  session, idle expiry, changed email, revoked membership/key and expired challenge.
- Logout audit insertion fault returns generic failure and leaves the original
  session usable. Existing registration audit-fault rollback, atomic acceptance,
  session/CSRF rotation and step-up absolute lifetime remain covered.
- Cleanup seeds 65 old rows per artifact table and old rejected events. One sweep
  removes exactly 32 per table including acceptance children; repeated sweeps drain
  eligible rows. Live session/challenge/replay state, referenced verifications, recent
  rejection and old successful forensic events survive. Recent audit deletion fails.
  Retention is 24h after artifact expiry and 30d for rejected audit only. No successful
  or privilege/counter event deletion is allowed. Each POST past the source rate gate
  runs one sweep; safe methods never write, and no idle/background reclamation is claimed.
- A 160-request bad-proof flood produces 30 credential denials and 130 rate denials,
  exactly 30 verifier calls, 2 bounded rate rows, at most 120 recent rejected audit
  rows, and no account/credential/challenge/verification/session state.

Standards consulted: [W3C WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/),
including required resident credentials and unsigned credProps;
[official Workers test configuration](https://developers.cloudflare.com/workers/testing/vitest-integration/configuration/).
Upstream package source/types were inspected for registration option semantics,
Wrangler manifest conversion, Miniflare 5's converter and public fetch dispatch.
This is implementation self-review, not independent certification.

## Toolchain and generated-bundle execution

Exact pins: `@cloudflare/vitest-plugin@1.6.0`, `vitest@4.1.12`, `vite@8.1.6`,
`wrangler@4.158.0`, `miniflare@5.20261104.0-beta`,
`@cloudflare/workers-types@5.20261104.1`, `esbuild@0.28.2`, `typescript@5.9.3`.
Runtime SimpleWebAuthn stays `14.0.3`.

The obsolete pool package's latest metadata still depended on vulnerable Zod;
its official replacement supports Vitest 4 and depends on the patched Zod 4.6.6,
Wrangler/Miniflare pair. Vitest and Vite remain on their existing major versions.
Miniflare 5 is an explicit reviewed upgrade (upstream beta pin), not a forced
transitive override. Its exported `convertV4MiniflareOptions` accepts Wrangler's
v4-shaped manifest output. The locked patched transitive versions are recorded in
the audit JSON. No `--force`, `--legacy-peer-deps`, audit exclusions or install hooks.

npm 10.9.8 crashed in Arborist (`edgesOut`) even with a fresh generated tree.
Ephemeral npm 12.2.2 on Node 22.22.3 correctly reported the Workers-types peer
constraint; matching its exact version allowed installation with `--ignore-scripts`.
Original generated dependencies/lock were preserved in /tmp during repair. No
system/global package upgrade was performed.

Reproduction (from repository root, loopback listening required):

```sh
cd managed-cloud
npm exec --yes --package=npm@12.2.2 -- npm ci --ignore-scripts
CI=1 WRANGLER_SEND_METRICS=false npm test
npm run typecheck
npm run test:bundle
npm audit --json
npm audit --omit=dev --json
```

The bundle harness calls build, then loads **dist/api-worker/index.js** and
**dist/recovery-worker/index.js** in standalone Miniflare/workerd, without Vitest's
loader/extra flags. It reads dates, nodejs_compat, worker names, D1 and service
entrypoints from checked-in Wrangler manifests. Only Wrangler's asserted default
source scanner rules are removed because input is already bundled; generated
modules use dist as their module root. Missing module roots originally caused
startup failure; this was corrected in the harness. Public dispatch avoids the
internal `/cdn-cgi` proxy's unrelated Origin policy; application Origin checks stay.

All D1 migrations run locally. Exact EMAIL_VERIFIER/TRUSTED_AUTH_SOURCE entrypoints
use synthetic in-memory RPC implementations; keys/proofs are fresh random values,
never checked in or printed. Worker outbound fetch is blocked. The generated API
passes ES256 registration, session read, bad-signature denial, login, action-bound
step-up, logout/revocation and device/browser route separation. Custodian default
HTTP remains 404. No production adapters, real email or remote bindings are used.

## Final gates

| Command / gate | Result |
| --- | --- |
| `CI=1 WRANGLER_SEND_METRICS=false npm test --prefix managed-cloud` | PASS: 131 tests / 4 files; 97 auth + 34 Phase 2A |
| `npm run typecheck --prefix managed-cloud` | PASS |
| `npm run build --prefix managed-cloud` | PASS (also executed by test:bundle) |
| `CI=1 WRANGLER_SEND_METRICS=false npm run test:bundle --prefix managed-cloud` | PASS: generated API + Custodian in standalone workerd, exact manifest compatibility/bindings |
| `bun run lint` | PASS |
| `bun run typecheck` | PASS |
| `bun test` | PASS: 111 tests, 509 assertions, 25 files |
| `bun run build` | PASS: 325 modules, ignored local binary |
| managed `npm audit --json` | PASS: 0 vulnerabilities including dev |
| managed `npm audit --omit=dev --json` | PASS: 0 vulnerabilities |
| `git diff --check` and new-file whitespace check | PASS |
| Changed-file secret/debug scan | PASS: no credential literal/private key/debugger/application logging; synthetic fixture keys only generated in memory |

## Limits and handoff

- No built-in Chrome/DevTools capability was exposed; no browser automation or
  real browser/platform passkey is claimed. The forbidden Hermes adapter was not used.
- Trusted adapters must be implemented/provisioned and independently reviewed before
  deployment. Grammar and same-request consistency cannot authenticate a malicious
  upstream or guarantee cross-request fairness. Real domain/RP/key provisioning is deferred.
- No wall-clock timing claim, physical storage guarantee, load/SLO, power-loss,
  replication failover or cross-D1 atomicity claim. Cleanup bounds deletions and
  retention, not a global storage quota or archival service.
- None-attestation resident behavior is enforced through standards-conforming client
  options; no unsigned property can prove physical authenticator residency.
- No UI, real email, enrollment, sync client, recovery release, audit checkpoints or
  production resources. Step-up remains a short-lived action-bound session fact;
  Phase 2D must consume approvals atomically with protected operations.
- Local gates are complete; independent re-review and any future deployment/release
  approval remain separate. The worktree is intentionally dirty and uncommitted.
