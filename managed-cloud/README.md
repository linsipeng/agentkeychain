# Managed Cloud Phases 2A–3

Local-testable Workers/D1 backend, separate from the frozen legacy `worker/`.
Phase 2C adds trusted device enrollment, 15-minute proof-bound device sessions,
immutable encrypted key packages, and service-signed sync checkpoints. Phase 2D adds
exact approval APIs, signed activity and two-party recovery. Phase 3 adds the local
React control center. Local Vault integration, deployment and production signer
provisioning remain separate gates.
The Slice 1 in-memory client is unchanged. A separate durable Phase 4 client now exists under `src/cloud`; current evidence and unfinished integration are recorded in `docs/MANAGED_CLOUD_PHASE4_BLOCKERS.md`.

## Local verification

```sh
cd managed-cloud
CI=1 WRANGLER_SEND_METRICS=false npm test
npm run typecheck
npm run build
npm run test:bundle
npm audit --json
npm audit --omit=dev --json
```

Tests require loopback listening, use disposable real workerd/D1, and generate synthetic
keys only in memory. No remote bindings or outbound services are used by runtime tests.
The npm audit commands require explicitly authorized public-registry access; current
full/runtime Phase 2D reports both contain zero vulnerabilities. Dependency versions
and lockfile are unchanged from the reviewed Phase 2B baseline. See
[Phase 2D evidence](../docs/MANAGED_CLOUD_PHASE2D_EVIDENCE.md).

## Device HTTP contracts

All responses are JSON with `Cache-Control: no-store`; errors use
`{"error":{"code":"..."}}` without exceptions, SQL or payloads. Device control routes
reject cookies, query parameters, unknown fields and unsupported content types. Bodies
are capped while streaming at 8 KiB (384 KiB for signed approval submissions), before
JSON parsing, DB access or crypto. Trusted
source attribution is required and source limits are 120/minute. Status/challenge requests
also use an independent 30/minute identity limit. No public route accepts account, tenant
or vault identifiers as authorization.

| Method / path | Request | Response |
| --- | --- | --- |
| POST `/v1/devices/authorize` | `{signingKey,wrappingKey,platform,proof}`; platform is macos/linux/windows/other | `{requestId,deviceId,deviceCode,verificationUri,verificationCode,phrase,expiresIn:600,interval:5}` |
| POST `/v1/devices/status` | `{deviceCode}` | `{state}`; approved result additionally includes deviceId, vaultId, requestId and consumes the code |
| POST `/v1/devices/challenge` | `{deviceId}` | `{challengeId,challenge,deviceId,vaultId,expiresAt}` |
| POST `/v1/devices/token` | `{challengeId,signature}` | `{token,tokenType:"DeviceProof",expiresIn:900,deviceId,vaultId}` |
| POST `/v1/devices/enroll` | `{canonical,signature}` key package, authenticated device request | `{accepted:true}` |
| GET `/v1/devices/key-packages` | No body; authenticated device request | Own current `{canonical,signature}` package, or 404 |

Codes are independent random 256-bit values stored only as SHA-256 digests. The six-word
phrase is for comparison, never an authorization capability. The verification URI is
`/v1/auth/devices/verification`: an authenticated, read-only GET returning the JSON
landing contract `{authentication:"passkey",verificationCodeRequired:true,submitUri}`.
Its submitUri is `/v1/auth/devices/pending`, which accepts the separate verification code. Expired, unknown, already delivered and too-fast
polls fail closed with the same 401 response. Denial prevents approval; consumed pairing
codes are unnecessary for later session reissuance. Challenges last 60 seconds, permit at
most five signature attempts, and are consumed atomically with session issuance.

Authorize proof signs `JSON.stringify(["AgentKeychain-device-authorize-v1",signingKey,
wrappingKey,platform])`. Keys use canonical base64; signing is Ed25519, wrapping is X25519.
Only public keys are submitted. Challenge proof signs
`JSON.stringify(["AgentKeychain-device-challenge-v1",challengeId,SHA256(challenge),deviceId,
vaultId,expiresAt])`. Possession of a code, device ID, challenge or session token alone
cannot authenticate. Refresh is a new challenge/proof; there is no bearer refresh bypass.

### Browser approval and revocation

These POST routes reuse the complete Phase 2B session, exact Origin, JSON, double-submit
CSRF, source/account rate limits and real Passkey step-up pipeline. They never issue a
device session using a browser cookie. Approval, denial and revocation require `confirmed:true`, a fresh
step-up over its returned digest, and atomic one-use consumption at acceptance.

| `/v1/auth/` suffix | Exact request | Response |
| --- | --- | --- |
| `devices/pending` | `{verificationCode,issuerDeviceId}` (null only for bootstrap) | `{requestId,deviceId,platform,phrase,canonical,actionDigest,denyActionDigest}` |
| `devices/approve` | `{canonical,signature,confirmed:true}` (signature null only for bootstrap) | `{approved:true,deviceId}` |
| `devices/deny` | `{requestId,confirmed:true}` | `{denied:true}` |
| `devices/list` | `{}` | `{devices:[{id,active,lastDevice,recoveryReady,canRemove,revocationComplete,revokeActionDigest}]}` |
| `devices/revoke` | `{deviceId,confirmed:true}` | `{revoked:false,enforced:true,witnessPending:true}` |

Pending binds the request to the authenticated account/tenant and its sole vault. An
ambiguous multi-vault account fails closed instead of accepting a caller-selected vault.
First device bootstrap is allowed only when the tenant has **no historical device**.
Revoking every device never reopens bootstrap; Phase 2D recovery below is the separate path.

The exact canonical enrollment grant has ordered fields:
`version,requestId,accountId,tenantId,vaultId,deviceId,signingKey,wrappingKey,issuerDeviceId,
keyEpoch,expiresAt`. Version is 1. A subsequent device requires an existing active device
of the same account/vault to sign those exact UTF-8 bytes, plus browser step-up. Server
records supply the expected fields; supplied IDs cannot change authorization. Action
digest is SHA-256 of `JSON.stringify(["AgentKeychain-device-action-v1",action,canonical])`.
Deny uses requestId as canonical; revoke uses the JSON array
`[tenantId,accountId,deviceId,signingKey,wrappingKey]`. The target and authorizer are
rechecked inside the D1 action trigger. Concurrent revocation wins if committed first.

### Device request proof

Every authenticated request carries `Authorization: Bearer <token>`, `X-Device-Nonce`,
`X-Device-Timestamp` (integer Unix seconds), and canonical base64 `X-Device-Proof`.
Proof signs the UTF-8 JSON array:

```text
["AgentKeychain-device-request-v1", method, normalizedPathAndQuery,
 SHA256_HEX(exactBody), timestamp, nonce, SHA256_HEX(sessionToken)]
```

Normalization uses URL pathname and sorted URLSearchParams serialization. Duplicate or
unknown query fields are rejected by sync routes. The timestamp may differ by at most
300 seconds, checked both at authentication and inside nonce acceptance. Session tokens
are random 256-bit values; only digests reach D1. Each `(session digest,nonce)` is one-use.
An expired session needs a new signing-key proof. Revocation atomically disables every
device session and vault membership, while both historical public keys remain immutable
under UPDATE, DELETE and INSERT OR REPLACE. Cleanup deletes at most 64 nonces per device
control request, only after session expiry plus the full skew window. Challenge cleanup
is bounded at 32 after a 24-hour retention period. Successful audit evidence is retained.

### Key packages

Canonical package fields in order: `version,vaultId,targetDeviceId,keyEpoch,wrappedVDK,
issuerDeviceId,grantId`. Version is 1; wrappedVDK is canonical base64 encrypted bytes
(48-byte minimum, 2048 encoded character maximum). The issuer signs exact canonical bytes.
The server verifies the active trusted issuer, authenticated request, accepted enrollment
grant, target, vault and epoch; it never decrypts the package. First-device packages are
self-issued against the bootstrap grant. Later packages require that grant's authorizer.
Epoch is currently 1 for enrollment; rotation is outside this phase. An accepted package
is immutable; only an exact signed retry succeeds. Fetch has no target/vault parameters
and can return only the authenticated device's own package while that device is active.

## Durable sync and checkpoints

| Route | Contract |
| --- | --- |
| POST `/v1/vaults/:vaultId/sync/push` | Exact `{canonical,signature}`; no query. Returns Slice 1 receipt plus `checkpoint:{canonical,signature}` |
| GET `/v1/vaults/:vaultId/sync/pull?cursor=...&limit=...` | No body; limit 1–100. Returns `{versions,nextCursor,hasMore,checkpoint,pageCheckpoint}` |

Sync requests retain the 384 KiB canonical request / 256 KiB encrypted-envelope limits.
Pull pages are capped at 100 versions and 512 KiB with reserved checkpoint framing space.
The route vault must match the authenticated session's stored vault. Cursor is base64 JSON
`[tenantId,vaultId,deviceId,sequence]`; it is a scope marker, not an authorization capability.
Exact operation retries require a fresh request nonce and return the original receipt and
checkpoint without allocating another sequence or consuming another approval.

The mandatory `CHECKPOINT_SIGNER` private Service Binding exposes `key()` (keyId/publicKey)
and `sign(canonical)`. It owns the Ed25519 private key; the API/D1 only receive signatures
and public metadata. There is no checked-in production key or fallback signer. Key ID is
SHA-256 of canonical base64 publicKey; D1 pins the service key immutably. Substitution or
missing configuration fails closed. Key rotation needs a separately reviewed trust-root
migration; it is not silently accepted. Local tests inject ephemeral signer Workers.

Checkpoint fields in order: `version,tenantId,vaultId,keyId,sequence,root,previousRoot,
operationDigest`. Version is 1. The signature covers exactly that canonical JSON.

```text
genesis = SHA256(JSON.stringify(["AgentKeychain-sync-genesis-v1",tenantId,vaultId]))
opDigest = SHA256(JSON.stringify(["AgentKeychain-signed-operation-v1",canonical,signature]))
root = SHA256(JSON.stringify(["AgentKeychain-sync-chain-v1",previousRoot,sequence,opDigest]))
```

For each accepted version, one D1 batch rechecks live authorization/nonce/time, decides
idempotency, validates transition and approval, allocates sequence, appends version, updates
head, consumes approval, appends audit, and inserts its checkpoint. A stale predecessor
aborts the entire batch and retries with the new root (at most 32 attempts). Signatures
computed for aborted candidates are never published or stored. No transaction is held
open across a service RPC. A genesis root is independently initialized at sequence zero;
nonempty historical vaults without a checkpoint fail closed and require an explicit
migration. This task does not backfill or alter existing production history.

Pull reads its versions, current signed head, and signed page-end root in one D1 batch.
Clients must verify the independently pinned service key, device operation signatures,
contiguous chain, page-end root, high-water sequence and hasMore consistency.
`verifyCheckpointPage` supplies the checkpoint/chain portion; Slice 1 operation signature
validation remains separate. Persist the returned root/sequence and requiredThrough
atomically with applied history. Known rollback, hidden suffix below an authenticated
head, key substitution and altered pages are rejected. A wholly replayed old valid
snapshot cannot prove its own staleness without a separately retained trusted anchor;
this cryptographic limit is not claimed solved by a signature alone.

The old Phase 2A `checkpoints` table remains reserved; Phase 2C uses `checkpoint_key`
and `sync_checkpoints`. Device grants, browser actions, public keys, packages and device
audit have immutable guards. Audit contains event names and opaque principal IDs only,
never codes, tokens, signatures, public keys or package ciphertext. Raw D1 access remains
a trusted repository boundary, not an RLS claim against a compromised administrator.

## Remaining product and release boundaries

- Phase 2D JSON approval, activity and two-party recovery contracts are implemented below.
- Phase 3: local ordinary-user Web UI, with `/app/devices`; see the current evidence for controller browser acceptance limits.
- Phase 4: secure local key storage, persistent client queue, checkpoint anchors and daemon.
- Real trusted ingress/email/checkpoint services, domains, keys, independent security review,
  online vulnerability audit, staging, remote migrations and deployment require their own gates.
- No real keys, Vault, Keychain, sync.json, Cloudflare account or user data was accessed.

## Phase 2B browser authentication

Evidence: [Phase 2B](../docs/MANAGED_CLOUD_PHASE2B_EVIDENCE.md). This is a backend
contract; the ordinary-user UI is implemented in Phase 3 below. `@simplewebauthn/server` is pinned to **14.0.3**;
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
a reusable grant or a device signing capability. Phase 2C consumes it atomically for device actions; Phase 2D now
consumes/validates it with the actual one-use approval action in its own durable
transaction for sync-operation approvals. Recovery purposes are reserved
in the challenge schema; recovery ceremonies belong to Phase 2D.

No real email, domain/RP provisioning, browser hardware passkey, deployment
or persistent cross-device sync client is included. The React UI is implemented in Phase 3. Device enrollment and cryptographic
recovery are implemented in the subsequent backend sections.
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

## Phase 2D JSON contracts

Current implementation/evidence: [Phase 2D](../docs/MANAGED_CLOUD_PHASE2D_EVIDENCE.md).
These local backend contracts supersede the earlier phase-specific deferral notes.
Phase 3 supplies the local UI; no deployment or production provider is enabled.

All browser routes below are POST `/v1/auth/<suffix>` with the existing Session,
Origin, JSON, double-submit CSRF, trusted-source and account-rate checks. Unknown
fields (including batch/permanent authorization and account/tenant selectors) fail.
Foreign resources return 404. All successful responses are JSON/no-store.

| Suffix | Exact body | Result |
| --- | --- | --- |
| `approvals/list`, `approvals/pending`, `approvals/recent` | `{after,limit}` | `{requests,nextCursor}`; limit 1–100; pending excludes expiry, recent descends |
| `approvals/detail` | `{id}` | Bound metadata, summary digest, approve/deny/cancel action digests |
| `approvals/approve`, `approvals/deny`, `approvals/cancel` | `{id,confirmed:true}` | Decision metadata; exact action-bound Passkey step-up consumed once |
| `activity/list` | `{after,limit,minimum}` | Events, cursor, signed checkpoint, through, `verification` |
| `activity/detail` | `{id,minimum}` | One event and explicit checkpoint verification |

The old normal-session recovery start/detail/release/finish/notifications/review/
cancel routes are removed or denied. Account browsers use `web/query` (`recovery`
and `account`) for safe state, notification and review/cancel references, followed
by `web/options`, `web/verify`, `web/execute` for exact step-up actions. Cancellation
also requires a same-account, unexpired device-issued `confirmationRef`. No account
browser may submit target keys or receive recovery cryptographic material.
Restricted public recovery alone permits `recovery/start {}`, `recovery/status {id}`
and `recovery/cancel {id,confirmed:true,confirmationRef}` after email verification
bound to the signed target device's requestRef. Direct target/authorization bodies
are rejected. See the target-device handoff contract below.

Device POST routes retain timestamped signing-key proof, no cookies, and stored
account/tenant/vault authority:

- `/v1/devices/approvals`: `{operation:{canonical,signature},expiresIn}` with optional
  `summary:{nonce,ciphertext,signature}`. TTL is 30–900 seconds. The signed operation
  must already contain its unique approvalRef. Maximum request size is 384 KiB.
- `/v1/devices/recovery-keys`: `{}` returns separate operator public key IDs/keys.
- `/v1/devices/recovery-package`: `{canonical,signature}` uploads the signed manifest.
- `/v1/devices/recovery-cancel`: `{id,authorization}` requires an active same-account device and independent signed cancel authorization.
- `/v1/devices/recovery-notifications`: `{after}` reads bounded notifications.

An initial credential put remains automatic and cannot request approval. Every put
against an existing head, delete and restore needs the exact unexpired grant. Thus
updates, encrypted scope changes and key-epoch rotations cannot bypass approval by
using `put`. Scope content stays encrypted; the backend does not interpret it.
Device enrollment/revocation retain their Phase 2C exact, one-use browser actions
and D1 transaction, rather than adding device commands to the sync wire protocol.
Agents use the authenticated device principal; this phase introduces no separate
cloud delegated-agent identity or broad reusable authorization.

Grant consumption, live device/session membership, idempotency, sequence, version,
head, legacy and normalized audit append, and signed sync checkpoint remain one
D1 batch. An exact accepted retry returns the original receipt/checkpoint. Changed
operation bytes need a new request. Approval metadata and optional summaries are
immutable; denial/cancellation are terminal; expiry is derived from database time.
Encrypted human-readable summaries are signed over
`["AgentKeychain-approval-summary-v1",operationDigest,ttl,nonce,ciphertext]` and
excluded from browser list/detail. Browser metadata contains only action and opaque
credential/device references. Decision digests include the optional summary digest. Creation retries with a fresh
transport nonce return the same request when signed operation, TTL and encrypted
summary are identical; changed content under the same request ID conflicts. The
original expiry is retained, never extended by retry.

Activity events have fixed columns, a fixed event vocabulary and no arbitrary
metadata object. Auth, account, device, sync, approval and recovery transitions
append through D1 triggers in the mutation's transaction. Anonymous auth/device
failures remain unscoped forensic records and are not exposed as another tenant's
activity. Old auth retention does not delete the normalized immutable copy.
Browser list/detail and checkpoints are scoped to both tenant and account until
a team-role policy exists. Public event IDs, `after`, `nextCursor`, `minimum` and
`through` use random opaque 128-bit IDs (zero means the initial boundary). IDs from
another account are not found. Global database ordinals are never serialized,
including inside signed checkpoint canonical bytes. Cumulative counts describe
only this account. Signed per-account checkpoints use the mandatory private `CHECKPOINT_SIGNER`, pin
its public key, and bind previous event boundary, through ID, cumulative count and
chain root. Read requests checkpoint at most 100 new events, verify existing signed
history, and return `verified`, `pending` or `failed`; they never label an unsigned
backlog verified. Verification failures cannot be hidden by list/detail. Corrupt
non-redacted rows are withheld with explicit failure. Existing-history verification
currently scans that account's retained checkpoints/history; this is not an SLO or
constant-cost archival design. `minimum` is the caller's retained high-water ID;
unknown newer history cannot be inferred from an old valid signature alone.

Recovery uses separate `MAIN` and `CUSTODIAN` D1 databases and private Service Binding
RPC; public Custodian HTTP is always 404. Manifests bind package/account/tenant/vault,
epoch, policy, issuing device, both operator key IDs, encrypted shares and wrapped
VDK. Device helpers generate a random 256-bit recovery key, XOR split it into two
uniform 2-of-2 shares, and wrap each share using ephemeral X25519, HKDF-SHA-256 and
AES-256-GCM with context-bound AAD. A separate AES-GCM envelope wraps the VDK.
Neither service gets the VDK or complete recovery key. Each encrypted package may
contain both sealed boxes, but neither operator key can decrypt the other's box.
`recovery-keyring.ts` accepts explicitly provisioned CryptoKeys, supports an active
key ID plus retained old decrypt keys, and has no generated production fallback.

Both operators independently invoke `recovery-authorization.ts` through separately
provisioned `RECOVERY_AUTH` bindings. Each resolves its own current trusted-device
or account-verification key; an API permit is not Custodian evidence. Device fast
path signs `["AgentKeychain-recovery-confirm-v1",caseCanonical]`, including the exact
target signing/wrapping keys. No-device evidence is an independently verified
signature on `["AgentKeychain-recovery-account-verified-v1",caseCanonical]`, checked
only after at least 24 hours. Local tests supply synthetic account/email verifier
keys, never real email. A registry implementation must recheck device revocation
on each authorization call; production identity/provider provisioning is a gate.

The Main saga is `prepared → confirmed → released → activating → completed`.
The legacy pre-activation `proven` state is accepted for local compatibility.
Cancellation is permitted only before `activating`. A conditional Main transaction
validates the persisted proof digest after target-signature verification, both
releases, current epoch, expiry, membership, active confirmer and target uniqueness.
That transaction records the activation intent and creates device/key/request rows;
any activation-trigger error rolls the entire transaction back. New targets must
be absent from devices, device_keys, vault_devices, device_requests, legacy recovery
cases and all other recovery sagas, including historical/cancelled records. These
checks run at start and again in the activation transaction.

After Main commits `activating`, the private Custodian completion RPC independently
validates the target-signed proof. It idempotently transitions released → completed.
Main then idempotently transitions activating → completed, revokes browser sessions,
and retains the required device-review flag. Main cancellation after activation
returns `{cancelled:false,state:"activating"|"completed"}` without a cancellation RPC.
The Main transaction serializes concurrent finish/cancel decisions. Custodian keeps
its separate prepared/released/completed/cancelled ledger; no cross-D1 atomicity is
claimed. Neither service exposes its private RPC as a public recovery endpoint.

Completion response loss is resumable from `activating`, including after Custodian
has completed and before Main's final transition. Expiry does not undo a committed
activation intent. Before activation, expired/revoked/stale-epoch cases remain
fail-closed; transient activation errors are retryable only while eligibility still
holds. This is not an unconditional guarantee for every partial recovery failure.
The target device retries with the same target proof via its signed target-device
transport. After completion, the account browser signs in again to review safe
metadata. Recovery never issues a normal account session.

Cancel authorization is `{action:"cancel",nonce,expiresAt,deviceId,signature}`.
A currently trusted device, or the independent account verifier when `deviceId` is
null, signs `["AgentKeychain-recovery-cancel-v1",caseCanonical,"cancel",nonce,
expiresAt,deviceId]`. Admission requires an unexpired authorization no more than
600 seconds in the future. Both authorization services validate it independently.
Main persists the signed authorization with its cancellation decision before RPC.
Custodian atomically consumes the nonce and records the exact case/digest receipt
with the cancellation/tombstone. Exact committed retries return the receipt, while
nonce reuse for different content/cases fails. Missing/wrong/expired authorization
cannot create a tombstone. If delivery never committed and the authorization
expired, supply a new independently signed authorization to resume cancellation;
Main's durable cancelled state never reopens. A tombstone blocks delayed prepare.

Target proof decrypts a random challenge using the wrapping private key and signs
`["AgentKeychain-recovery-proof-v1",caseCanonical,proof]` using the target signing
key. Activation requires both releases and both target-key proofs. Cancellation
cannot erase plaintext a target already reconstructed from released shares; it
blocks activation only before the durable activation boundary and stops subsequent
release. Deployment must not promise revocation of already learned key material.

Private binding names in the manifests are deployment contracts only. Their local
bundle implementations are synthetic and generated only from `tests/`. Production
operator separation, trust-registry/email adapters, key custody/rotation ceremony,
remote migrations and deployment require independent review and approval. The
React control center is implemented in Phase 3 below; the persistent local client/daemon remains Phase 4.

## Phase 3 Web control center / Web 控制中心

`web/` is a separately typechecked Vite/React/Router/TanStack Query app. The API
Worker serves its built static assets, including SPA deep links, with no-store,
CSP, no-referrer and nosniff headers. Source maps/source paths are rejected.
`npm run build` builds both the SPA and Workers; `npm run test:bundle` exercises
those exact artifacts in local workerd. Run Web checks with
`npm test --prefix web` and `npm run typecheck --prefix web` from this directory.
No production bindings or deployment are created by these commands.

The Web uses `/v1/auth/web/{query,pairing,options,verify,execute}`. Query views
cover Home, requests, devices, activity, contextual history, account and recovery
review. References for actions and pagination are account/tenant scoped, expire
in five minutes, and resolve server-side. Passkey step-up still authorizes the
original exact Phase 2 transaction; denial also retains its existing step-up gate.
The Web reads back removal, decisions and recovery states. It never signs a
restore: a device-created restore request must exist before the user can allow it.
Updates without durable fresh device acknowledgements remain “Not recently
checked”; an empty device list means “Waiting for a device”. Lists are bounded;
requests, activity and versions have continuation controls. Device/account metadata
is limited to 100 records, recovery summaries to 20. Activity verification receipts
are retained in memory and sent back to detect known rollback within the session.

本地 Web 提供完整中英文路由、确认界面和控制面数据投影。页面不接收凭证正文、
加密载荷或恢复分片。旧 CLI 的持久化和本机设备交接集成仍属于 Phase 4；没有部署
云服务，也不会访问真实账号、Vault 或 Keychain。

### Invitation provisioning

Migration `0009` adds `invitations.encrypted_email`. The local provisioning helper
`seedInvitation` uses the existing auth email AES-GCM key and HMAC lookup key;
tokens remain digest-only. `invitation/detail` accepts only the complete capability
under bootstrap cookie + Origin + CSRF, and returns `{maskedEmail,status,expiresAt}`.
Missing, expired, consumed, corrupted and legacy hash-only display metadata fail
closed with generic unauthorized. Legacy records are not guessed or backfilled;
reissue locally with the helper when the address is available through an authorized
provisioning boundary. Verification still requires the user's full email and an
independent EMAIL_VERIFIER proof matching the invitation's lookup exactly.

### Public recovery and device handoff

1. A new device prepares public target keys and posts `recovery-target-challenge`
   to the device API with a signature over `['AgentKeychain-recovery-target-v1',target]`.
   It decrypts the returned challenge using its wrapping private key, then posts
   `{target,signature,challengeRef,proof}` to `recovery-target`. The challenge is
   target-bound, one-use and expires in five minutes. Only after both proofs
   succeed is a 48-hour `requestRef` issued; only its digest is stored. The target includes
   the recovery package, case, target device, two independent public keys and nonce.
2. The browser submits `{email,proof,requestRef}` to `recovery/verify` using its
   five-minute bootstrap + CSRF. Direct target objects (including mixed target +
   reference bodies), unknown references and expired references are rejected.
   Both known and unknown/failed-proof verification
   attempts perform the same verifier/query/token/batch shape and return
   `{accepted:true}` with identical cookie attributes. Unknown/failed attempts
   create only unprivileged decoy rows, never accounts, normal sessions or cases.
3. Real verification creates a ten-minute `r.` recovery cookie, with only token,
   CSRF and independent-proof digests retained. Account/tenant/vault come from the
   verified stored lookup. The exact target and request digest are immutable.
   Bootstrap/proof reservation is atomic and single-use. Restrictions are checked
   before routing: only start/status/cancel are possible, with independent source
   and restricted-session rate limits. This cookie cannot authenticate a passkey,
   become a normal session, or access devices, requests, activity, sync or releases.
4. `recovery/start {}` uses the exact verified target. `recovery/status {id}`
   returns only case/state/review metadata. Case substitution fails. Verification
   alone never means recovery succeeded. Reverification with a fresh independent
   proof is needed after the restricted session expires, including long cooldowns.
5. Only the target device calls `recovery-target-status/release/finish`. Every call
   requires the target capability and signature over
   `['AgentKeychain-recovery-target-call-v1',route,bodyWithoutSignature]`, with an
   exact request-digest match against the stored case. Device recovery transports
   reject Cookie, Origin and browser Fetch Metadata headers. These are browser
   isolation checks, not hardware attestation: a non-browser client can generate
   keys but must prove both private keys and satisfy independent recovery authorization. Existing two-party evidence, cooldown, release and target
   proof transactions remain authoritative; the browser never receives their data.
6. An enrolled device may prepare `recovery-cancel-confirmation {id,authorization}`
   using its normal signed device session and independently verified cancellation
   authorization. Its short-lived opaque reference is accepted by browser cancel
   with explicit confirmation; normal sessions additionally require exact Passkey
   step-up. Restricted cancellation stays retryable after partial custody failure.
   Activation locks cancellation. Completion revokes both normal and restricted
   sessions; the user must sign in normally and review devices.

Pairing now produces a 12-character, 72-bit code and three independent words from
an exact-pinned 2048-word list (33 comparison bits). The old complete 43-character
codes remain accepted. Enrolled devices obtain a scoped `pairing-detail`, sign
its exact grant and submit `pairing-confirm`; only the server retains the signed
grant. Web confirmation requires phrase matching and a Passkey, then uses the
original device transaction. First-device initialization remains explicit.

Independent email verification, recovery authorities and platform passkeys still
need their separately provisioned production adapters. The checked-in tests use
synthetic local bindings only. Evidence and acceptance limits:
[Phase 3 evidence](../docs/MANAGED_CLOUD_PHASE3_EVIDENCE.md).

### Phase 3 review repairs

Requests has visible attention/recent tabs. Devices lists Needs attention, Active
devices and Removed devices: active devices with stale/waiting/paused/unavailable
status need attention and appear only in that section. Fresh current/updating
devices appear in Active devices; removed devices appear only in Removed devices.
Migration `0012` stores successful authenticated pull observations. The input cursor
reports processed history; newly delivered data does not count as acknowledgement.
Within 300 seconds, a device at the vault head is current and a device behind it is
updating. Older observations are stale; no observation is waiting; disabled vault
membership is paused; missing/inconsistent observations are unavailable. All device
vaults contribute to status. This is a device report, not proof of local disk writes.
Phase 4 must supply periodic pulls for continued freshness. Account
shows at most 20 stored recovery notification records, scoped to account and tenant;
these records are not evidence of delivery. Activity links remain available.
Activity verification failures persist through pending/error responses and clear
on a later verified response. Session expiry clears account risk, queries and
receipt state before reauthentication. All Web data responses undergo recursive
sensitive-field checks, including alternate casing/separators.

Migration `0011` adds digest-only wrapping-possession challenges and invalidates
older local recovery handoff references and restricted recovery sessions that
lacked that proof; normal sessions are preserved. No existing Vault
is touched. Recovery RPC data results are copied and explicitly disposed; run
`npm run test:recovery-resources` for captured host workerd diagnostics.

The recursive safe-view guard rejects recovery proof/challenge/authorization,
cancelAuthorization, completionSignature, signatures, canonical payloads,
wrappedVDK/wrapped_vdk, shares, sealed/ciphertext/encrypted and private/public key
fields, including spelling variants in nested objects and arrays. WebAuthn options
are a separate authentication contract; their passkey challenge is not recovery
material. Real GET `/v1/auth/session` 401 clears queries, activity receipts and the
account risk warning before redirect; a different-account regression covers it.


## Current Phase 4/5 client work

The development branch includes signed-release endpoint policy, sealed and SAS-bound
trusted enrollment, private-pipe native secure storage, CSK-encrypted SQLite tables,
atomic mutation/apply, proof-bound HTTP, durable retries, checkpoint anchors, daemon
leases/IPC and additive CLI/MCP controls. Migrations `0013` and `0014` add immutable
opaque trust delivery and signed safe approval intents. `rotate` and `scope` intent
labels are authenticated against the exact signed operation; unknown `put` requests
remain unavailable for browser approval. No credential values enter browser views.

The compiled-process harness uses the real CLI entrypoint with a separate synthetic
build composition, real HTTP API/repositories and persistent SQLite with the actual
migrations. Passkey approval is represented by a test authority; existing workerd
bundle tests separately exercise virtual WebAuthn. It is not native-browser acceptance.
Ordinary binaries cannot select the synthetic endpoint or secure store via environment.

Production requires a release-build verified manifest; the repository's default is
`cloud_unavailable_not_provisioned`. The final local issuer/daemon interruption,
protected enrollment-anchor recovery and directory-relative export matrices pass.
Signed-roster propagation and local recovery activation are implemented. Migrations
`0015` and `0016` retain immutable retry/expiry and exact export authorization guards.
Only external provisioning, native-platform/browser acceptance and release/deployment
gates remain. See [final local evidence](../docs/PHASE45_FINAL_CONTINUATION.md).

中文：最终三项内部缺口已完成本地实现及验收；现仅保留外部生产配置、原生平台/浏览器
验收及发布部署门槛。未提交、部署或使用真实 Vault、Keychain、凭证和生产资源。

Signed roster storage, possession-only revoked-device fetch, issuer publication and revocation sequence boundaries are implemented by migration `0017` and `roster-repository.ts`. Browser device lists contain no keys or signed roster data. See [contract and acceptance evidence](../docs/SIGNED_ROSTER.md).

The native-only `recovery-target-delivery` route adds independent API/Custodian
release signatures. Each Worker requires its own `RECOVERY_RELEASE_SIGNER` binding;
public signing pins belong to the signed release manifest `recoveryServices` roles.
Existing unsigned release contracts are preserved. The prior incomplete native activation record is superseded by
[completed local recovery activation evidence](../docs/LOCAL_RECOVERY_ACTIVATION.md).

Recovery activation adds `0018_recovery_evidence.sql`, `0019_recovery_refresh.sql`
and Custodian `0003_recovery_trust.sql`. Target-only `evidence`, `trust` and `readback`
endpoints complete the native flow. `recovery-confirm` accepts an enrolled device's
exact case signature; the private account attester supplies the delayed-path assertion
after public email verification. The Custodian requires independent
`RECOVERY_TRUST_SIGNER` and `RECOVERY_TRUST_POLICY` bindings. The API requires
`RECOVERY_ACCOUNT_ATTESTER` for delayed recovery. Missing bindings fail closed.
The authority signs a target-encrypted refresh credential; D1 retains only its digest.
`recovery-refresh` requires the target signature, checks live membership/revocation,
and converges retries to the same proof-bound session. These are local contracts;
no production binding, domain or key has been provisioned.

Run `npm run test:recovery-process` for compiled synthetic recovery acceptance.

Final local security repair and upgrade semantics: [repair record](../docs/FINAL_SECURITY_REPAIR.md), [migration/rollback runbook](../docs/SECURITY_REPAIR_MIGRATION_RUNBOOK.md). Local verification does not authorize release or deployment.


### Final review repair — local verification complete

Device list responses never contain signing or wrapping keys. The Web safe view
contains `id`, `active`, `status`, `lastDevice`, `recoveryReady`,
`revocationComplete`, and an opaque `removeRef` (null when removal is unavailable).
The final trusted issuer for each affected vault cannot be removed without a
current, non-revoked recovery readiness record for the latest package/key epoch.
Readiness expires after 30 days and is renewed only after both services accept the
package. Existing installations must re-confirm package readiness; migration 0022
does not infer it. The transaction rechecks readiness, active issuers and the exact
step-up action. Last-device actions explicitly bind “Access will require recovery”
and preserve the package/action record. Device/session enforcement is immediate;
`revocationComplete` requires the independently witnessed successor roster.

Last-device recovery requires an independently authorized revocation receipt in
Custodian (`RECOVERY_AUTH.rosterRevocation`), tied to the exact action, recovery
package and checkpoint boundary. Main cannot manufacture that authorization. A
missing provider or authorization leaves the witness pending and fails closed.
Recovery retries deliver the exact revocation event for independent authorization;
the pinned recovery authority then signs the successor carrying that boundary and
the new target. Operators must provision the independent action registry before
advertising last-device recovery readiness.

Activation v2 signs a canonical `TrustActivationBinding`: case and immutable receipt
version, exact signed and sealed bundle digests, refresh digest, checkpoint
sequence/root/key/digest, witness event/revision/receipt digest, roster revision/digest,
target signing and wrapping keys, epoch and expiry. The encrypted authority-signed
bundle also contains its receipt version. Main and Custodian independently compare
all fields to the selected immutable version. The client verifies the same binding
before activation writes; unchanged roster digests cannot authorize substituted
checkpoint, refresh or witness evidence.

Witness pages contain at most 128 rosters and 128 checkpoints, including the exact
stored anchors, plus the previous independent receipt. Roster and checkpoint heads
advance independently and atomically. Main fetches bounded suffixes, catches up
checkpoints before advancing rosters, and retries concurrent head conflicts. No
256-roster or 10,000-checkpoint lifetime ceiling applies. Genesis still requires
independent provisioning; upgrade anchors retain the migration runbook boundary.

Final gates and exact source/artifact evidence: [last final review](../docs/LAST_FINAL_REVIEW.md).

Recovery delivery uses the latest independently witnessed roster anchor and, when needed, its recovery-authority successor. It does not seal full roster history; existing local anchor checks still fail closed if their bridge is unavailable.
