# AgentKeychain Managed Cloud V1 — Complete Implementation Plan

## Delivery order

1. Phase 2A — Managed Cloud backend foundation
2. Phase 2B — Passkey account and browser sessions
3. Phase 2C — Device enrollment and durable sync
4. Phase 2D — Approvals, audit and two-party recovery
5. Phase 3 — Ordinary-user Web control center
6. Phase 4 — Local client persistence, daemon and Vault integration
7. Phase 5 — Cross-layer real-process E2E and release gates
8. Phase 6 — Staging deployment and production release approval

## Phase 2A: Backend foundation

Create `managed-cloud/` as an independent workspace:

```text
managed-cloud/
  shared/
  api-worker/
  recovery-worker/
  web/
```

Use Cloudflare Workers, D1, Service Binding and Workers Vitest integration. The existing `worker/` remains frozen legacy code.

First implementation slice must deliver:

- exact HTTP/error contracts;
- typed authenticated contexts;
- Main D1 and Custodian D1 migrations;
- account/tenant/vault/device/sync/approval/audit/recovery tables;
- typed repositories without service-facing raw SQL;
- D1 durable push transaction and pull pagination;
- tenant isolation matrix;
- service-bound private recovery Worker skeleton;
- local workerd tests only.

## Transaction contracts

One D1 transaction must include:

- revocation and membership recheck;
- exact idempotency decision;
- sequence allocation;
- generation/tombstone/keyEpoch transition;
- approval validation/consumption;
- version append;
- head update;
- audit append.

Approval and repository state may not live in separate transactions in production.

## Phase 2B: Passkey auth

- `@simplewebauthn/server`, exact pinned version.
- Invite-only account creation.
- Single-use 5-minute registration/login/step-up/recovery challenges.
- UV required, exact Origin and RP ID.
- `__Host-` session and CSRF cookies.
- 30-minute idle, 12-hour absolute session.
- Strict Origin + JSON + double-submit CSRF for every unsafe browser method.
- Per-account and per-source shared D1 rate limits.
- Passkey counter regressions are risk signals, not automatic account loss.

## Phase 2C: Devices and sync

- Existing-device-signed enrollment grants.
- Independent signing and wrapping keys.
- Short-lived device Session + request signature proof.
- Device Key Packages signed by issuing device.
- Production payload limit: 256 KiB encrypted envelope, 384 KiB canonical request.
- Pull pages: max 100 versions and bounded serialized size.
- Service-signed append-only checkpoint chain.
- Device revocation invalidates sessions but retains historical public key.

## Phase 2D: approvals/audit/recovery

- Browser step-up produces one-use approval.
- Approval mutation and operation acceptance share D1 transaction.
- Audit is append-only, redacted and checkpointed.
- Recovery uses separate Worker, D1, secrets and Service Binding.
- 2-party release, cooldown, cancellation, idempotent saga and target-device encryption.
- Neither Worker alone can output usable recovery material.

## Phase 3: Web product

Stack: Vite + React + TypeScript + React Router + TanStack Query; Worker-served static assets. No SSR required.

Routes:

- `/sign-in`, `/join/:invite`, `/create-passkey`, `/recovery`
- `/app`, `/app/requests`, `/app/devices`, `/app/activity`, `/app/account`
- contextual update status, device detail, request detail, history and restore pages

UI rules:

- no secret values or decryption keys;
- no Worker/D1/scope/nonce/digest/sequence/ciphertext terminology;
- high-risk request has only “Don’t allow” and “Allow once”;
- no batch approval;
- Web restore only authorizes; enrolled device signs actual restore;
- full keyboard/mobile/accessibility coverage;
- user-visible process reflects real persisted state.

## Phase 4: Local client

- Fixed official endpoint; no custom URL flags.
- Browser device authorization.
- Generic secure-store abstraction for macOS/Linux/test.
- Private keys and refresh credentials never in argv or files.
- VDK, CSK and per-device signing/wrapping keys.
- Additive cloud tables inside vault.db.
- Local mutation + encrypted outbox in one transaction.
- Remote page + Vault apply + cursor/checkpoint in one transaction.
- Automatic daemon with singleton lease, wake-up IPC and exponential retry.
- Reconciler catches modifications made by older local binaries.
- CLI: cloud login/status/sync-now/logout/devices/service install/start/stop/status.
- MCP adds metadata-only cloud status and local approval request without changing existing tool names.

## Phase 5: cross-layer E2E

Build the actual binary and run two isolated OS processes against a loopback HTTP service with SQLite/D1-compatible persistence:

- device auth and enrollment;
- Secure Capture create;
- auto sync to second device;
- MCP retrieval on second device;
- offline queue survives restart;
- accepted response lost creates one version;
- pull crash does not advance partial cursor;
- approval rotation/delete/restore;
- tombstone cannot be resurrected;
- revoked device stops writes;
- checkpoint/pin/snapshot restart validation;
- migration keeps existing v0.6.2 rows byte-identical.

## Phase boundaries

Allowed without further approval:

- local code, migrations, tests, docs, builds and local commits in the feature worktree.

Separate approval gates remain for:

- production Cloudflare resources;
- custom domain/RP ID;
- real email provider;
- remote D1 migration;
- public deployment;
- GitHub push/PR/merge;
- formal Release and local upgrade.
