# Managed Cloud Phases 2A–2C

Local-testable Workers/D1 backend, separate from the frozen legacy `worker/`.
Phase 2C adds trusted device enrollment, 15-minute proof-bound device sessions,
immutable encrypted key packages, and service-signed sync checkpoints. No ordinary-user
React UI, local Vault integration, deployment or production signer provisioning is included.
The Slice 1 in-memory client is unchanged; its production persistence/transport belongs to Phase 4.

## Local verification

```sh
cd managed-cloud
CI=1 WRANGLER_SEND_METRICS=false npm test
npm run typecheck
npm run build
npm run test:bundle
npm audit --offline --json
npm audit --offline --omit=dev --json
```

Tests require loopback listening, use disposable real workerd/D1, and generate synthetic
keys only in memory. No remote bindings or outbound services are used. Offline npm audit
output does **not** establish current advisory coverage. Dependency versions and lockfile
are unchanged from the reviewed Phase 2B baseline. A fresh online audit remains a release
gate when network access is authorized. See [Phase 2C evidence](../docs/MANAGED_CLOUD_PHASE2C_EVIDENCE.md).

## Device HTTP contracts

All responses are JSON with `Cache-Control: no-store`; errors use
`{"error":{"code":"..."}}` without exceptions, SQL or payloads. Device control routes
reject cookies, query parameters, unknown fields and unsupported content types. Bodies
are capped while streaming at 8 KiB, before JSON parsing, DB access or crypto. Trusted
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
| `devices/list` | `{}` | `{devices:[{id,public_key,wrapping_key,active,revokeActionDigest}]}` |
| `devices/revoke` | `{deviceId,confirmed:true}` | `{revoked:true}` |

Pending binds the request to the authenticated account/tenant and its sole vault. An
ambiguous multi-vault account fails closed instead of accepting a caller-selected vault.
First device bootstrap is allowed only when the tenant has **no historical device**.
Revoking every device never reopens bootstrap; recovery is a later phase.

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

- Phase 2D: broader operation risk approvals, checkpointed audit stream and two-party recovery.
- Phase 3: ordinary-user UI including `/device`; no UI or real browser test is claimed.
- Phase 4: secure local key storage, persistent client queue, checkpoint anchors and daemon.
- Real trusted ingress/email/checkpoint services, domains, keys, independent security review,
  online vulnerability audit, staging, remote migrations and deployment require their own gates.
- No real keys, Vault, Keychain, sync.json, Cloudflare account or user data was accessed.

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
a reusable grant or a device signing capability. Phase 2C consumes it atomically for device actions; Phase 2D must
consume/validate it with the actual one-use approval action in its own durable
transaction for sync-operation approvals. Recovery purposes are reserved
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
