# AgentKeychain — development handoff / 开发交接

Prepared: 2026-11-21 (local clock). The enrollment/debugging events below occurred on 2026-11-06–07; they are historical evidence, NOT a fresh production health check.

## Read this first / 先读这里

- Product repository: `linsipeng/agentkeychain` (PUBLIC).
- Baseline commit: `37d9eb9387d2bee60c4531266cf42d13cccde3ca`.
- Development worktree: `/Users/mac/Projects/agentkeychain-managed-cloud-v07`, branch `feat/managed-cloud-v0.7`.
- Branch `handoff/managed-cloud-ai-20261121` now contains the complete WIP source snapshot as well as these documents. Clone/check out this branch directly; no ZIP or patch application is required.
- The source repairs are preserved for takeover, **not independently reviewed or release-ready**. Compare with the baseline above and rerun acceptance. On this same Mac, preserve the existing dirty development worktree; do not apply the changes twice.
- Existing production/local credentials and cloud provisioning outputs are deliberately NOT included. A clean clone cannot deploy or access the real Vault using this handoff.
- Next-agent prompt: [AI_TAKEOVER_PROMPT.md](AI_TAKEOVER_PROMPT.md).

## Product target / 目标

Official managed cloud for individual/small-team AI-agent users. Ordinary users must not provision Cloudflare, install Wrangler or paste sync tokens. Separate account verification, device trust, scoped credential use, exact one-use approval and independently controlled recovery. Existing BYO sync is legacy compatibility only. Do not restore older BYO-first strategy from obsolete notes.

The user-facing promise is that an agent can safely use a credential without taking a long-lived secret. Plaintext legacy CLI/MCP retrieval alone does not fulfill that promise. No production-ready claim until real enrollment, sync, approval, revocation and recovery acceptance is complete.

## Actual delivery state / 实际状态

v0.6.2 is the last recorded stable local installation. Managed Cloud v0.7 remains unfinished staging work. Package version remaining 0.6.2 is not proof that v0.7 shipped.

Historical staging endpoints:
- Web: `https://agentkeychain.soupsam.com`
- API: `https://api.agentkeychain.soupsam.com`

Recorded deployment consists of API/Web, Custodian, auth-trust, API-trust and custody-trust Workers; separate Main/Custodian/Auth D1 databases; email verification; an offline-root-signed release manifest. Re-verify live versions and bindings safely before relying on them. Generated deployment configs are ignored and host-specific.

### Completed historically, but not a complete end-to-end acceptance

1. Account and Passkey registration succeeded. Preserve them.
2. Dual-origin signed release contract repaired: signed `apiOrigin` for HTTP device traffic and signed `webOrigin` for browser handoff, canonical HTTPS with strict hostname relationship. Never simply relax origin checks.
3. CLI pairing phrase is now displayed before browser approval (`showPhrase`). Browser and CLI phrase equality was observed. A previous assertion of phrase mismatch was erroneous (DOM timing/result-unwrapping); do not treat it as a confirmed cryptographic flaw.
4. Browser approval reached `web/options`, `web/verify`, `web/execute` = 200; cloud device was created in that historical attempt.
5. Approval failed afterward at `/v1/devices/roster-put`: 500, safe diagnostic `witness_untrusted_genesis`.
6. `web/options` 503 was traced to recursive synthetic Request construction losing trusted ingress metadata. `browser-auth.ts` now handles Web step-up using already-validated request/session context; a regression was added. Review parity with ordinary step-up carefully.
7. Genesis witness had consulted Custody Trust before it had any device registry. Repair adds `GENESIS_AUTH` routed to API Trust, leaving recovery authorization routed to Custody Trust. **This is an unreviewed trust-boundary change**, not proof of operator independence; audit actual RPC surface, key ownership and compromise model before accepting.
8. Sam explicitly approved cleanup of one failed staging enrollment. A Main D1 export and an atomic `D1.batch()` cleanup were executed. Readback at that point: device/grant/roster/witness saga = 0; account/Passkey/membership/Vault = 1; five deletion-protection triggers restored; Custodian witness/recovery rows = 0; no cloud Vault ciphertext/key packages/recovery packages. This is historical state, not a current guarantee.
9. Temporary cleanup endpoint `/__admin/enrollment-cleanup` was removed from code and redeployed; POST returned 404; temporary Worker secret was deleted. Do not recreate it as a permanent admin backdoor.
10. Local unfinished cloud secure-store accounts and empty cloud tables were cleared in that approved cleanup. Later login attempts recreated pending cloud state. At the end the waiting CLI was stopped, local pending request rows cleared, health marked configured, browser automation session closed. Protected pending keys may still exist. Do NOT interpret configured as enrolled.

### Final unresolved state

No cloud enrollment end-to-end success was verified after the genesis-binding fix. No real successful Vault sync, approval roundtrip, second-device enrollment, recovery or release was verified. The last CLI was stopped at Sam's request after repeated failed user interaction. Do not resume an old waiting process or use old pairing phrases/URLs.

The previous assistant asserted that the valid session was in Safari. **This was not proven by a Safari inspection**; only Chrome 401 responses and D1 session existence were observed. Treat browser/profile mismatch, session loss and cookie/bootstrap behavior as hypotheses needing evidence. Do not repeat that assertion as fact.

Sam will not cooperate with repeated login/Passkey attempts. First complete synthetic end-to-end acceptance and diagnose session/request lifetime safely. Never bypass, forge or automate OS biometric/Passkey user verification.

## Priority backlog / 未完成事项（按顺序）

### P0 — preserve safety and make the failure reproducible

- Inspect repo rules, dirty diff, test isolation and generated artifacts; preserve other agents' changes.
- Audit pending-state handling: approved remote device must survive local retry/expiry without replacing its request ID or VDK, orphaning devices, or generating phantom second devices. Historical retries overwrote pending state after expiry.
- Test resume after browser approval, Worker/response failures, process restart, grant expiry, denied requests and lost ACK; no automatic destructive cleanup.
- Expired-enrollment reconciliation is read-only: the original device signs a short-lived check tied to its request, device and original keys. A retained expired request can be classified as previously approved, never approved, or ambiguous. Missing rows and uncertain evidence never authorize replacement or automatic retry. A separate, purpose-signed retirement can atomically mark an expired, never-approved request terminal and return the same retained decision after response loss. Reapproval for approved identities and idempotent allocation of a successor remain unfinished.
- 过期请求对账只读：原设备用原密钥签名查询。服务端记录可区分“已批准”“未批准”“不确定”；找不到记录不能当作未批准。不会自动替换原请求，也不会延长原授权。独立签名的终止操作可以原子终止过期且未批准的请求，丢响应后仍可读取同一结果。已批准设备的重新批准及后继请求的幂等创建仍待实现。
- Investigate why browser `/session` becomes 401 after successful login. Correlate actual same browser/profile/tab and response body with bootstrap/session cookie lifecycle; deployment alone is not a proven cause. No cookie/token logging.
- Fix expiry/poll error handling and frontend generic "request changed" error masking 503/401/Passkey cancellation. Do not send users through a click loop.

### P0 — security review of new fixes

- Review Web step-up reuse: action digest, account/tenant/session binding, membership recheck, attempts, CSRF, rate limits, session rotation and atomic consumption; compare to normal step-up route.
- Review `GENESIS_AUTH`: the local repair replaces access to full `RecoveryAuthority` with a dedicated `RosterGenesisAuthority` entrypoint. This only narrows the RPC surface; it still relies on Main D1 enrollment. Independent genesis evidence is an unresolved release gate. Do not widen recovery authority based on Main DB claims.
- Review dual-origin canonical/signature verification, retained pins/operator ownership, manifest/root pairing, actual release policy and local compiled binary/helper coherence.
- Replace error-message regex logging with a fixed safe allowlist if arbitrary error names/messages could reveal metadata. Do not output request bodies, signatures or identifiers.

### P1 — full local and compiled acceptance

Run current focused/full tests, typechecks, lint, builds, dependency audits, real Worker bundle and support-service graph tests. Update **all** fixtures/configs for `GENESIS_AUTH` (including recovery-process/support-bundle and generated configs), not just Vitest. Old evidence hashes are invalid for the dirty tree.

### P1 — real staging only after local proof

Only if an authorized session already exists, inspect it with background DOM/CDP. Do not ask Sam to repeatedly authenticate. If actual Passkey verification is unavoidable, leave one precise documented blocker rather than pretending completion or bypassing it. Do not modify production Vault to make a cloud test pass.

### P2 — finish managed product/release gates

- Real two-device enrollment and secure trust transfer.
- Real encrypted sync with conflict/retry/pagination/delete/restore barriers and scoped approval.
- Independent recovery enrollment/release/activation, rollback/substitution rejection and last-device safety.
- Native secure-store/packaging/update rollback, daemon restart/lease checks.
- Independent security review, updated evidence, CI, release approval, versioned install distribution and bilingual docs. Do not merge/release/deploy under the documentation-handoff authorization.

## Files to inspect / 关键文件

- `docs/PRD_MANAGED_CLOUD_V0.7.md`, `docs/PRD_MANAGED_CLOUD_V1.md`, `docs/MANAGED_CLOUD_WEB_SPEC.md` — reconcile current scope, do not assume every older design is authoritative.
- `src/cloud/config.ts`, `src/cloud/release.generated.ts`, `managed-cloud/shared/release-origins.*` — signed contract/public artifact.
- `src/cloud/login.ts`, `src/cloud/enrollment-intent.ts`, `src/cloud/http.ts`, `src/cli/cloud.ts` — enrollment/retry/secure intent.
- `managed-cloud/api-worker/browser-auth.ts`, `web-repository.ts`, `device-http.ts`, `device-repository.ts` — browser action and enrollment.
- `managed-cloud/recovery-worker/index.ts`, `shared/trust-runtime.ts`, `api-worker/roster-witness.ts`, `shared/roster-witness.ts`, `provisioning/render.mjs` — trust boundary and graph.
- `managed-cloud/web/src/App.tsx`, `api.ts` — UI/error/session flow.
- `docs/DUAL_ORIGIN_REPAIR_2026-11-06.md` — worker's historical handoff; its statements that signing/deployment had not happened were superseded by controller staging work. Not current final evidence.
- `docs/LAST_FINAL_REVIEW*`, `docs/FINAL_SECURITY_REPAIR*`, `docs/MANAGED_CLOUD_SUPPORT_WORKERS*` — historical audit evidence; rerun and regenerate after changes.

## Verification / 核验口径

Fresh handoff-only checks on 2026-11-21: root lint/typecheck, backend/Web typechecks and `git diff --check` passed. No fresh full tests, build, cloud login or production health probe was performed for this handoff.

Historical results (not final-tree acceptance): dual-origin worker reported root 193/backend 316/Web 95/recovery 49; focused browser auth 140 passed after step-up fix; focused recovery/transaction/trust 92 passed after genesis binding; earlier CLI process tests passed before later trust changes. Do not combine those counts into a current all-green claim.

Commands from current package scripts (test isolation must be checked before executing):

```sh
bun run lint
bun run typecheck
bun test
bun run build
npm test --prefix managed-cloud
npm run typecheck --prefix managed-cloud
npm test --prefix managed-cloud/web
npm run typecheck --prefix managed-cloud/web
npm run test:bundle --prefix managed-cloud
npm run test:support-bundle --prefix managed-cloud
npm run test:recovery-process --prefix managed-cloud
npm run test:recovery-resources --prefix managed-cloud
git diff --check
```

## Non-negotiable safety / 不可突破

Never print/store secret values, master passwords, tokens, cookies, private keys, Vault contents or raw credential/audit lists. Never use the real macOS Keychain/Vault in tests. A historical test overwrote the production unlock password; preserve the v0.6.2 fail-closed test guard.

No `.env`, database/export, logs with user data, generated provisioning config or private material in Git/patches. `release.generated.ts` contains a PUBLIC signed artifact, not the offline private root. Never add an unsigned field to a signed manifest.

Delete/rotate/overwrite/migrate/restore/scope expansion/delegation/merge/release/third-party account change require explicit approval. Historical approval for a specific cleanup is exhausted, not ongoing permission. This handoff authorizes documentation and preservation only.

Local operations evidence remains outside the repository under a private cleanup backup directory from 2026-11-07; those exports contain sensitive control-plane data and must NOT be copied into Git or sent to another AI. Steward rules live at `/Users/mac/.hermes/agentkeychain-steward`. Do not run its Collector blindly: it may run quality tests on source changes. Check its actual behavior first.
