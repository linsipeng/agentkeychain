# Managed Cloud Phase 2A

Local-testable backend foundation. This package is separate from the frozen legacy
`worker/`. It does not provision accounts, enroll devices, operate on a local Vault,
or enable production recovery. No production resource identifiers are configured.

The public Worker has `MAIN` and a private `RECOVERY` Service Binding. The Custodian
Worker has only `CUSTODIAN`. Both public/default Custodian HTTP and its named RPC
entrypoint's `fetch` return 404. `describe()` is metadata-only and reports
`recoveryEnabled: false`; there is no release, decrypt, key-share, or recovery-case
mutation method. The two D1 migrations run in separate Workers test projects.

## Local development

Pinned dependencies and `package-lock.json` belong to this independent npm workspace.
With dependencies available locally:

```sh
cd managed-cloud
CI=1 WRANGLER_SEND_METRICS=false npm test
npm run typecheck
npm run build
```

Tests use the official `@cloudflare/vitest-pool-workers` integration and workerd,
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

Only these routes exist; successful responses are 200 JSON with `Cache-Control:
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

Phase 2A can consume pre-provisioned, short-lived **device** sessions. No public
session issuer, account login, passkey, browser cookie, enrollment or registration
endpoint exists. Fixtures provision metadata directly in disposable D1. A Phase 2B
`AccountPrincipal` interface is a placeholder, not an authentication implementation.

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

- Real account/passkey/browser sessions and step-up: Phase 2B.
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
