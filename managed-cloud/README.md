# Managed Cloud Phases 2A–2B

Local-testable backend foundation. This package is separate from the frozen legacy
`worker/`. Phase 2B adds invitation-only Passkey accounts and browser sessions. It does not
enroll devices, operate on a local Vault, or enable production recovery. No production resource identifiers are configured.

The public Worker has `MAIN` and a private `RECOVERY` Service Binding. The Custodian
Worker has only `CUSTODIAN`. Both public/default Custodian HTTP and its named RPC
entrypoint's `fetch` return 404. `describe()` is metadata-only and reports
`recoveryEnabled: false`; there is no release, decrypt, key-share, or recovery-case
mutation method. Main and Custodian migrations run in separate Workers test projects.

## Local development

Pinned dependencies and `package-lock.json` belong to this independent npm workspace.
With dependencies available locally:

```sh
cd managed-cloud
CI=1 WRANGLER_SEND_METRICS=false npm test
npm run typecheck
npm run build
npm run test:bundle
npm audit --json
npm audit --omit=dev --json
```

Tests use the official `@cloudflare/vitest-plugin` integration and workerd,
with disposable D1 and real Service Binding RPC. They require loopback listening.
`remoteBindings` is false. `build` is an esbuild bundle, not a Wrangler deploy.
Wrangler manifests use all-zero placeholder resource IDs, disable public workers.dev
and preview URLs, and set D1 `remote = false`. They are not deployment authorization.

Root `bun test` is explicitly scoped to `tests/`; Workers suites run separately.
Root lint includes both packages. Shared canonical protocol implementation is reused
from `src/cloud/protocol.ts`; its explicit `node:buffer` import works in workerd's
`nodejs_compat` mode without changing wire bytes. Device signatures use native
WebCrypto Ed25519 against the stored immutable public key.

## HTTP contract

The device sync routes below are unchanged; successful responses are 200 JSON with `Cache-Control:
no-store`. All errors are exactly `{"error":{"code":"..."}}`, also no-store, with
no SQL, exception, request content, token, or signature in the response or logs.
No application logger is present.

| Route | Request | Response |
| --- | --- | --- |
| `POST /v1/vaults/:vaultId/sync/push` | Exact `{canonical,signature}` JSON; no query parameters | Slice 1 `PushReceipt`: `{vaultId,deviceId,operationId,serverSequence}` |
| `GET /v1/vaults/:vaultId/sync/pull?cursor=...&limit=...` | No body; cursor optional; limit integer 1–100, default 100; duplicate/unknown query fields rejected | `{versions:[{signed:{canonical,signature},serverSequence}],nextCursor,hasMore}` |

Body bytes are capped at **384 KiB**, before JSON parsing, auth lookup, or signature
verification. Both declared Content-Length and actual streamed bytes are checked;
chunked bodies cannot bypass the limit. UTF-8 is strict; compressed bodies are not
accepted. Push Content-Type is `application/json` (optional `charset=utf-8`).
The decoded encrypted envelope (24-byte nonce plus ciphertext) is at most **256 KiB**.
Canonical field validation, signature encoding and envelope limits precede DB work.
Pull is capped at 100 versions and **512 KiB** serialized response; a SQL running byte
budget also bounds materialized results, with framing/escaping overhead reserved.

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Invalid JSON, canonical shape, encoding, query, cursor, UTF-8, or future cursor |
| 401 | `unauthorized` | Missing/malformed device session or proof headers |
| 401 | `invalid_signature` | Invalid request proof or operation signature |
| 403 | `approval_required` | Missing required reference, expired/consumed/mismatched in-scope grant, or forbidden grant on put |
| 404 | `not_found` | Unknown route or inaccessible session/vault/device/approval/cursor scope, including cross-tenant resources |
| 405 | `method_not_allowed` | Wrong method on a sync route |
| 409 | `idempotency_conflict` | Same operation identity with different canonical bytes/signature |
| 409 | `invalid_transition` | Generation/tombstone/keyEpoch violation |
| 409 | `replayed_request` | Reused session nonce |
| 413 | `payload_too_large` | Request/envelope limit exceeded |
| 415 | `unsupported_media_type` | Unsupported JSON Content-Type or Content-Encoding |
| 500 | `internal_error` | Redacted storage failure or broken history invariant |

A foreign approval reference is indistinguishable from a nonexistent in-scope
reference (404). A known in-scope grant with an invalid binding/expiry is 403.
Unknown routes return 404 before attempting to read their bodies.

## Device authentication and retry contract

Phase 2A can consume pre-provisioned, short-lived **device** sessions. No public device-session issuer or enrollment endpoint exists. Fixtures provision
device metadata directly in disposable D1. Browser authentication uses the isolated
`/v1/auth/` routes documented below and never authorizes these device sync routes.

Headers: `Authorization: Bearer <session-token>`, `X-Device-Nonce` (1–128 ASCII
identifier characters), and `X-Device-Proof` (canonical base64 Ed25519 signature).
D1 stores only SHA-256 session digests. The request proof signs UTF-8 bytes of:

```text
JSON.stringify([1, method, pathname + search, SHA256_HEX(exactBody), nonce, SHA256_HEX(sessionToken)])
```

The token identifies an account/tenant/vault/device tuple; none is taken from an
account/tenant body, query, or header. The route vault must match the stored tuple.
The device public key is pinned; updates, deletes and SQLite REPLACE cannot change
it. Both device signature and request proof are required for push; pull requires
request proof. Session expiry, revocation and active membership are checked again
inside the acceptance transaction. Token possession alone is insufficient.

An operation retry retains identical `canonical` and `signature` but uses a **fresh
request nonce/proof**. It returns the original receipt, without a new version,
sequence, approval consumption or audit event. Replaying the entire HTTP proof is
rejected with 409. This distinguishes operation idempotency from request replay.
The nonce ledger currently has no cleanup job; bounded expiry-aware cleanup belongs
to operational follow-up, and must never remove live-session replay protection.

Cursor is base64 JSON `[tenantId,vaultId,deviceId,sequence]`. It is an authorization
scope marker, not a signed checkpoint or secret capability. Every pull authenticates
and rechecks the tuple; editing the cursor cannot grant access. Current request
proof binds the exact URL/query. Clients must URL-encode the cursor. No checkpoints
are returned or implied in this phase.

## Durable acceptance and its exact limit

No JavaScript `BEGIN`/callback transaction is claimed. D1 `batch` submits:

1. Insert nonce: a BEFORE INSERT trigger rechecks live session, account membership,
   device and vault-device status, and rejects nonce replay.
2. Insert into the write-only `accept_operation` view. Its INSTEAD OF INSERT trigger
   decides exact idempotency, validates head transitions and approval bindings,
   increments the vault sequence, appends the immutable version, updates head,
   consumes approval (using the Slice 1 `SHA256("AgentKeychain-approval-v1\0" + canonical)` digest), stores the exact receipt, and appends redacted audit metadata.
3. Select that receipt using tenant/vault/device/operation identity.

A single SQLite/D1 transaction contains all these effects; no approval state lives
in a separate service store. Exact retries use `RAISE(IGNORE)` only to skip command
execution, while authorization/nonce acceptance still runs. Abort at any later
trigger rolls the entire batch back. The failure-injection test aborts audit insertion
and observes unchanged nonce count, sequence, head, version, approval and audit;
retrying the same pre-authenticated request then succeeds after removing the fault.
Concurrent identical/distinct pushes and conflicting retries execute against real D1.

Signature verification occurs before the transaction, using the immutable key;
mutable authorization is rechecked inside it. A revocation committed before that
check wins; one committed after an accepted write does not retroactively undo it.
No cross-D1 transaction, multi-region staging behavior, power-loss simulation,
replication failover, throughput/SLO or production deployment is proven here.

The SQL adapter is a trusted boundary: D1 has no RLS, and a compromised Worker with
a raw binding can issue arbitrary SQL. Application services receive only a scoped
`SyncRepository`, never arbitrary SQL/table/transaction callbacks. Auth composition
and repository factories own the raw D1 handles. DB triggers protect invariants,
not against an administrator who can alter/drop the schema.

## Isolation coverage

| Tables | Runtime access and negative evidence |
| --- | --- |
| `accounts`, `tenants` | Root identities; no CRUD/read API; ownership represented by membership. Unknown identity routes 404. |
| `memberships`, `vaults`, `devices`, `vault_devices` | Composite tenant keys; auth joins plus transactional recheck; cross-tenant relationship inserts fail; inactive memberships/devices/vault memberships reject writes and pulls. |
| `device_sessions`, `device_nonces` | Digest selects stored account/tenant/vault/device; composite FKs; forged principal relationships fail; missing proof, expired/revoked sessions, nonce replay and foreign vaults rejected. |
| `versions`, `heads`, `idempotency` | Every runtime query includes tenant/vault, identity lookup also device; foreign FKs fail; identical IDs in two tenants retain independent histories/receipts; cross-vault sequences independent. |
| `approvals` | Scoped ID plus account, device, action, object, digest, expiry and unused state; foreign tenant/vault grants fail; consumed/expired/tampered grants cannot authorize. |
| `audit` | Transactional metadata-only append; composite FK; no read API; UPDATE/DELETE/REPLACE rejected. |
| `checkpoints` | Schema only; no runtime signing/read API; cross-tenant audit FK and append-only guards. |
| `recovery_cases`, `recovery_events` | Orchestration metadata schema only; no runtime API; composite tenant/vault relationships reject foreign cases/targets. |
| Custodian `custodian_cases`, `release_evidence` | Separate database/Worker with no data RPC; cross-tenant case references reject; evidence cannot update/delete/replace. |

No universal service `get(table,id)` exists. Pull tests cover tenant/vault/device
cursor binding, future/gap rejection, byte limits, and pagination without gaps.

## Deferred boundaries

- Account/passkey/browser sessions and action-bound step-up: implemented in Phase 2B
  below; no real email provider or browser UI.
- Device enrollment, session issuance/refresh, wrapping keys/packages, durable client
  queue and signed checkpoint chains: Phase 2C and client phases.
- Approval issuance/UI, richer risk classification (including rotation/overwrite),
  two-party cryptographic recovery, notifications, cooldown/release saga: Phase 2D.
  This backend preserves Slice 1 put/delete/restore semantics; it does not claim all
  V1 high-risk policies are enforced yet.
- Checkpoint rows are schema only. Audit is append-only/redacted, not cryptographically
  checkpointed. Restore is a signed device operation with a pre-provisioned bound
  approval; browser authorization alone cannot generate a restore signature.
- No real user data, Vault keys, private device keys, production accounts, Cloudflare
  resources, deployment, migration of existing local data or legacy Worker changes.
- No UI was added. No built-in Chrome/DevTools tool is exposed in this session;
  browser validation was unavailable, not replaced with the prohibited Hermes adapter.

## Phase 2B browser authentication

Evidence: [Phase 2B](../docs/MANAGED_CLOUD_PHASE2B_EVIDENCE.md). This is a backend
contract, with no ordinary-user UI. `@simplewebauthn/server` is pinned to **14.0.3**;
its production adapter runs in workerd, with no fake verification or hand-written
CBOR/COSE verifier. Tests generate Ed25519 and ES256 virtual-authenticator keys only
in memory. Attestation `none` is required and other formats are rejected using the
library decoder **before** its certificate/metadata verification code can execute.

### Configuration and fail-closed boundaries

`browser-bindings.ts` requires `AUTH_ORIGIN` (exact HTTPS origin), `AUTH_RP_ID` (exact
host), and three independent base64url 32-byte keys: `AUTH_BOOTSTRAP_KEY` (HMAC),
`AUTH_EMAIL_KEY` (AES-GCM), `AUTH_LOOKUP_KEY` (HMAC). These are future secret bindings,
not checked-in values or environment files. Keys must use canonical unpadded base64url;
decoded key material must be pairwise distinct. Missing/malformed configuration returns 503;
no manifest enables auth by default. Real provisioning/key rotation is deferred.
`EMAIL_VERIFIER.verify(email, proof)` is a mandatory trusted service-binding interface;
absence returns 503 before any ceremony. Well-formed invalid invitation, wrong email
and wrong proof requests all invoke it exactly once after the same rate gates,
concurrently with invitation lookup; both results settle before acceptance. Tests inject a synthetic, single-test verifier.
There is no public invitation issuer, email sender, or production bypass.

`TRUSTED_AUTH_SOURCE.resolve(request)` is mandatory. Its output must be a canonical
opaque lowercase ASCII identifier matching `[a-z0-9][a-z0-9._:-]{0,127}` (1–128 bytes).
Empty, malformed, non-string, throwing or inconsistent same-request resolutions
return redacted 503. Two independent resolutions of cloned requests must match.
Cross-request stability and authenticated ingress attribution remain the trusted
adapter's contract; this check cannot prove a malicious provider trustworthy.
`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP` have no fallback
role. Direct test composition explicitly supplies a stable synthetic source.
The manifest declares the trusted email/source service entrypoints; real adapter
implementation, provisioning and review remain deployment gates. Neither adapter
may log or persist requests or proofs.

### HTTP contract

All routes below are under `/v1/auth/`; queries are rejected, responses are JSON
and no-store, request bodies have exact fields, and WebAuthn failures return exactly
`401 {"error":{"code":"unauthorized"}}`. Rate denial is 429 `rate_limited`.
Unexpected SQL/library/provider errors are never echoed or logged. Protocol errors
may return 404/405/413/415. Accepted bodies are limited to 32 KiB (the shared streaming
reader also enforces its 384 KiB hard ceiling).

| Method / suffix | Request | Successful response |
| --- | --- | --- |
| GET `bootstrap` | None | `{authenticated:false}` + 5-minute anonymous session and CSRF cookies |
| GET `session` | Session cookie | `{authenticated:false}` or account/tenant IDs, `authentication:"passkey"`, absolute expiry and step-up boolean; no email or credential data |
| POST `invitation/verify` | `{invitation,email,proof}` | `{verificationId}` |
| POST `registration/options` | `{verificationId}` | `{challengeId,userId,options}` |
| POST `registration/verify` | `{challengeId,userId,response}` | `{authenticated:true}` + new cookies |
| POST `authentication/options` | `{email}` | `{challengeId,options}`; no allowCredentials enumeration, same shape for unknown email |
| POST `authentication/verify` | `{challengeId,response}` | `{authenticated:true}` + new cookies |
| POST `step-up/options` | `{actionDigest}` | `{challengeId,options}` |
| POST `step-up/verify` | `{challengeId,actionDigest,response}` | `{authenticated:true}` + rotated cookies |
| POST `session/refresh` | `{}` | `{ok:true}`; advances idle time only |
| POST `logout` | `{}` | `{ok:true}`; server revocation and Max-Age=0 cookies |

**Every POST** needs an existing session, exact Origin, JSON Content-Type, CSRF
header `X-CSRF-Token` equal to the CSRF cookie, and a matching server-authenticated
CSRF digest. Duplicate cookie names fail. workerd normalizes repeated Origin, Content-Type and
X-CSRF-Token headers into comma-combined values; these and manually combined forms
are rejected. Raw wire multiplicity is unavailable to the handler. Device bearer
tokens cannot substitute.
Pre-login POSTs require the anonymous session; step-up/logout/refresh require an
authenticated session. Login from a different browser leaves other sessions active.

The bootstrap solves the pre-login CSRF boundary without a mutating GET: a random
anonymous session carries an HMAC-authenticated CSRF digest and 5-minute expiry.
It is stateless until successful registration/login records only its SHA-256 digest
as consumed. Thus cancelled/invalid registrations create **zero account, passkey or
browser-session rows**. This is an intentional distinction from authenticated D1
sessions, not a CSRF exception. GET/HEAD never write D1, refresh idle time, or consume
a challenge. Phase 3 should use the explicit POST refresh for user activity.

Cookies have no Domain:

- `__Host-akc_session=<random>; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=...`
- `__Host-akc_csrf=<random>; Secure; SameSite=Strict; Path=/; Max-Age=...`

Authenticated session and CSRF tokens are random 32-byte values; D1 stores only
SHA-256 digests. Idle expiry is 30 minutes, absolute expiry 12 hours. Step-up rotates
both cookies, revokes the old row, and **preserves** the original absolute deadline.
Logout and membership/passkey privilege changes revoke sessions server-side.

### Durable acceptance and identity isolation

Migration 0002 is additive. Encrypted email/lookup/verified status are in the 1:1
`account_emails` extension, preserving Phase 2A account insert contracts. Email
normalization lowercases the whole address without provider-specific alias folding;
invitation provisioning must use the same policy. Lookup is keyed HMAC-SHA-256,
email is AES-256-GCM with a fresh 12-byte nonce and lookup hash as associated data.
No endpoint returns stored email ciphertext or lookup hashes.

Challenges are random 32 bytes, stored as digests, expire after 5 minutes, bind
purpose, anonymous/authenticated session, identity and request digest. Step-up binds
a 64-character lowercase SHA-256 action digest; registration binds its future user
handle. Attempts are atomic and capped at five. RP ID, Origin, UP, UV, signature,
credential ownership and optional userHandle are verified. Iframe ceremonies fail.
Registration requires `residentKey: required` and `requireResidentKey: true`, because
login intentionally provides no credential list. Conforming nonresident-only
clients must fail creation; an explicit `credProps.rk: false` also rejects. The
unsigned extension is a hint, not an attested residency guarantee, and its absence
is compatible with conforming clients. None attestation cannot prove storage
behavior of a malicious client.

Invitation verification uses conditional `INSERT ... RETURNING` and requires
exactly one inserted row. Expiry/consumption while the verifier awaits yields 401,
with no phantom verification ID.

The first statement in a D1 batch inserts into `accept_browser_auth`. Its trigger
rechecks challenge lifetime, session lifetime, purpose, request binding, invitation
and email-verification eligibility, or active credential/account/session membership.
It consumes challenge/invitation/verification/anonymous session once. The same batch
creates account/tenant/membership/empty vault/passkey and browser session, or rotates
a session, updates the counter and appends audit. Failure rolls everything back;
failed attempt counts remain recorded outside the acceptance transaction. A single
D1 transaction is proven; multi-region/staging behavior is not.

Counter handling deliberately passes `counter:-1` to the reviewed library API so
its built-in counter policy cannot hard-lock an account. This does **not** skip
cryptographic verification. Only after a valid assertion does SQL compare the new
counter with the **current** stored high-water mark; a non-increase when either
counter is nonzero appends `counter_risk`, while retaining the maximum. Invalid
signatures never create a risk event or session.

Each unsafe request consumes a shared source budget of 120/minute; each identity
operation also consumes an independent 30/minute budget. Atomic D1 UPSERT counters
saturate at 1001. Per-call cleanup deletes at most 32 windows older than two minutes;
live windows are never deleted. These are fixed windows, not rolling-window SLOs.

Auth audit contains only integer ID, event enum and server timestamp; it has no
email, key/credential ID, session/challenge/token, arbitrary text or request payload.
UPDATE/REPLACE and deletion of recent or non-rejected events fail. Failed credential requests after the CSRF/source gate
append only `rejected`. Passkey ownership/key bytes are immutable. Raw D1 is confined
to the repository factory and composition boundaries, as in Phase 2A; this is not RLS.

### Remaining phase boundaries

Step-up records a five-minute action-bound fact on the rotated session. It is **not**
a reusable grant, an approval issuer, or a device signing capability. Phase 2D must
consume/validate it with the actual one-use approval action in its own durable
transaction; no protected-action endpoint exists yet. Recovery purposes are reserved
in the challenge schema; recovery ceremonies belong to Phase 2D.

No real email, domain/RP provisioning, browser hardware passkey, deployment, device
enrollment, React UI, cross-device sync client or cryptographic recovery is included.
Cleanup runs after the source rate gate on unsafe requests, never on GET/HEAD.
Each atomic sweep removes at most 32 rows per table: challenges (and their
acceptance ledger children), unreferenced account verifications, browser sessions
and consumed bootstraps retain 24 hours after expiry; rejected audit rows retain
30 days. Other audit events are retained indefinitely. Live challenges protect
referenced verifications. Live/idle-active sessions, unexpired replay protection,
recent forensic events, accounts and passkeys are never deleted. No background
scheduler or archival/checkpoint service is implied; reclamation needs traffic.

`npm run test:bundle` executes generated API and Custodian modules in standalone
Miniflare/workerd using the checked-in manifest's date, `nodejs_compat`, D1 and
service entrypoint bindings. It uses synthetic trusted adapters and fresh random
in-memory key bindings, blocks outbound fetch, applies local migrations, and runs
ES256 registration/login/step-up/logout. Source-only Vitest execution is a separate
gate. No built-in
Chrome/DevTools capability is exposed in this session, so the evidence is workerd/D1
and synthetic WebAuthn wire data, not a real-browser acceptance claim.

### Reviewed development toolchain

Exact pins: Workers Vitest plugin 1.6.0, Vitest 4.1.12, Vite 8.1.6, Wrangler
4.158.0, Miniflare 5.20261104.0-beta, Workers types 5.20261104.1, esbuild 0.28.2
and TypeScript 5.9.3. Miniflare 5 is the plugin/Wrangler dependency; its exported
v4-option converter is used for the manifest-based bundle harness. No forced peer
overrides are used. See the evidence for the npm 10 resolver failure and successful
installation using ephemeral npm 12.2.2 on Node 22.22.3 (`--ignore-scripts`). Both full
and runtime npm audit reports are clean as of the recorded local run.
