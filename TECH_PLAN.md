# TECH_PLAN — AgentKeychain Managed Cloud v0.7, Slice 1

## 1. Goal and definition of done

Deliver one independently working, local-only managed-cloud synchronization slice on branch `feat/managed-cloud-v0.7`:

- two isolated synthetic clients have independent device identities;
- signed encrypted operations are accepted by a managed-service core;
- server assigns monotonic sequence numbers and retains immutable history;
- idempotent retry creates one version;
- server receive order selects the current head;
- tombstones propagate and stale writes cannot resurrect deleted objects;
- revoked devices and tampered signatures are rejected;
- pull uses sequence cursors and pagination;
- legacy BYO sync is not used by the new path;
- no production deployment, account provider, Vault migration, Keychain access or release.

Done means focused and full repository gates pass, and a real two-client integration test exercises create → sync → concurrent offline update → retry → delete → stale-write rejection → approved restore → revoked-device rejection.

## 2. Current-state evidence

- Existing v0.3 sync is in `src/sync.ts`, `src/cli/sync.ts`, `worker/src/index.ts`, and `worker/schema.sql`.
- It uses shared bearer auth, client timestamps and manual push/pull, so it must remain legacy compatibility only.
- Existing cryptography in `src/crypto/keys.ts` and `src/crypto/xchacha.ts` is reusable.
- Existing Vault schema and ciphertext must not be rewritten.
- Existing worker `fetch` seam and `tests/worker.test.ts` can be extended, but FakeD1 behavioral imitation is not sufficient evidence for v2 transactional behavior.

## 3. Architecture

### 3.1 Protocol objects

Add `src/cloud/protocol.ts` with canonical, versioned contracts:

- `ManagedOperation`
- `SignedManagedOperation`
- `PushReceipt`
- `PullPage`
- `ManagedVersion`
- `DeviceRecord`
- `DeviceKeyPackage` interface only

Signed bytes bind at minimum:

- protocol version;
- vault id;
- object id;
- device id;
- operation id/idempotency key;
- operation kind (`put`, `delete`, `restore`);
- generation;
- key epoch;
- encrypted envelope;
- approval reference when required.

Canonical serialization must be deterministic and reject unknown/invalid fields.

### 3.2 Device identity

Add `src/cloud/device.ts`:

- create Ed25519 device identity;
- derive public registration record;
- sign canonical operations;
- verify signatures;
- private keys exist only in test memory for this slice and must never be logged.

### 3.3 Service core

Add `src/cloud/service.ts` as a deterministic managed-service domain core with an injected repository. It must:

- register and revoke devices;
- validate vault/device membership and signature;
- enforce unique `(vaultId, deviceId, operationId)`;
- allocate monotonic per-vault `serverSequence`;
- append immutable versions;
- maintain current head by server acceptance order;
- retain tombstone generation barriers;
- reject stale-generation live writes after delete;
- allow restore only as explicit `restore` into a newer generation;
- page versions after a sequence cursor.

Add an in-memory repository for deterministic tests. Worker/D1 persistence is a later slice; do not fake claims of production transactional proof.

### 3.4 Client engine

Add `src/cloud/engine.ts` and `src/cloud/transport.ts`:

- durable-operation shape, but in-memory queue implementation for this slice;
- sign once and preserve identical signed bytes across retries;
- push until acknowledged;
- pull by server cursor with continuation;
- apply server head deterministically;
- expose state `idle | syncing | backoff | revoked`;
- remote apply never emits an echo operation.

The integration test may use encrypted synthetic envelopes and must not interact with real Vault or Keychain.

### 3.5 Approval contract

Add `src/auth/approval.ts` with a pure contract/classifier:

- automatic: scoped read, metadata/status, sync;
- confirmation required: publish, payment/purchase/transfer, delete, permission/scope/device/member changes, export, restore, rotate;
- approval request binds agent id, action, credential reference, canonical request digest, expiry and one-time nonce;
- tampering changes the digest and invalidates approval.

This slice defines and tests the contract; it does not add UI or production approval storage.

### 3.6 Compatibility

Add `src/cloud/legacy.ts`:

- detect existing v0.3 `sync.json` shape without returning or logging token;
- classify it as `legacy_byo_cloudflare`;
- provide a safe migration status message;
- never contact old endpoint, delete config or upload automatically.

Fix sync config path isolation so tests with custom `AGENTKEYCHAIN_HOME` cannot fall back to the real home directory.

## 4. Files and ownership

Expected new files:

- `src/cloud/protocol.ts`
- `src/cloud/device.ts`
- `src/cloud/service.ts`
- `src/cloud/transport.ts`
- `src/cloud/engine.ts`
- `src/cloud/legacy.ts`
- `src/auth/approval.ts`
- `tests/cloud-protocol.test.ts`
- `tests/cloud-service.test.ts`
- `tests/cloud-integration.test.ts`
- `tests/cloud-compat.test.ts`
- `tests/approval.test.ts`

Expected existing edits:

- `src/sync.ts` only for safe config path reuse/export and legacy compatibility boundary;
- `src/cli/sync.ts` to deprecate `init/connect/push/pull` as ordinary-user paths without exposing stored URL/token;
- `README.md`, `README.zh-CN.md`, `docs/SYNC_GUIDE.md`, `docs/AI_INSTALL.md`, `docs/AI_INSTALL.zh-CN.md`;
- `eslint.config.js` or package lint script only if needed to include new source paths.

Forbidden:

- production Vault/Keychain reads or writes;
- `.env`, real tokens, real account ids, private keys or user data;
- production deployment, Cloudflare mutation, GitHub push/PR/Release;
- deleting v0.3 implementation before compatibility behavior is tested;
- changing current local secret ciphertext format.

## 5. TDD work packages

1. Protocol canonicalization and signature RED/GREEN.
2. Service sequence, idempotency, history, tombstone generation and revocation RED/GREEN.
3. Two-client engine with dropped-response retry, pagination and no echo RED/GREEN.
4. Approval classifier/digest tamper RED/GREEN.
5. Legacy config detection and path isolation RED/GREEN.
6. Bilingual docs and legacy CLI messaging.
7. Full gates and independent review.

## 6. Acceptance matrix

- Deterministic canonical bytes → same logical operation produces same bytes; reordered/unknown fields rejected.
- Signature binding → any field mutation fails verification.
- Idempotency → same signed operation retried twice returns same receipt and one history version.
- Receive order → later accepted update becomes head regardless of client timestamp.
- History → both concurrent versions remain retrievable.
- Delete barrier → stale generation put cannot resurrect tombstone.
- Restore → explicit approved restore into newer generation becomes head and preserves history.
- Revocation → revoked device cannot write; historical signatures remain verifiable.
- Pagination → more than one page is retrieved without gaps/duplicates.
- Retry → dropped first response and restart do not duplicate version.
- No echo → pulled operation does not enter local outgoing queue.
- Approval → high-risk actions require valid bound approval; read/status/sync do not.
- Legacy safety → v0.3 token is never printed, old endpoint is never contacted, config is not deleted.
- Isolation → custom home tests never read/write actual `~/.agentkeychain` or host Keychain.

## 7. Commands

Focused:

```bash
bun test tests/cloud-protocol.test.ts tests/cloud-service.test.ts tests/cloud-integration.test.ts tests/cloud-compat.test.ts tests/approval.test.ts tests/vault-isolation.test.ts
```

Broad:

```bash
bun run lint
bun run typecheck
bun test
bun run build
```

Repository proof:

```bash
git diff --check
git status --short
```

## 8. Security and recovery

- Synthetic test keys and encrypted payloads only.
- No test may call macOS `security`, production AgentKeychain CLI, real network endpoints or Cloudflare.
- Signatures cover every state-changing field.
- Tombstone generation cannot decrease.
- Device revocation is checked at write acceptance.
- Legacy config parsing redacts token by construction.
- Recovery interfaces remain design-only in this slice; do not claim account recovery is implemented.

## 9. Release boundary

Authorized: edit/test/commit locally in the isolated worktree.

Not authorized: push, PR creation, merge, deployment, account/provider setup, database creation, production migration or Release publication.
