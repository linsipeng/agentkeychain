# Phase 2A local backend evidence / 本地后端验收

Branch: `feat/managed-cloud-v0.7`; starting HEAD: `b749df3`; security-reviewed Slice 1
baseline: `ac58879`. No commit, push, PR, deployment, release, Cloudflare account,
external service, real Vault/Keychain/config/token or production-data access.

独立 `managed-cloud/` workspace 已实现本地可测后端基础；旧 `worker/` 未修改。
本记录仅证明本地 workerd/D1 行为，不表示可上线，也不表示分钥恢复已经完成。

Detailed HTTP/error/authentication/transaction contracts, per-table isolation matrix
and deferred phase boundaries: [managed-cloud/README.md](../managed-cloud/README.md).

## TDD and findings / 测试驱动与发现

- Initial workerd RED: oversized POST returned 404 instead of required 413.
- Initial transaction suite RED: scoped repository module did not exist. Tests were
  written before migrations, authentication and acceptance implementation.
- Real D1 GREEN covers concurrent identical and conflicting retries, independent
  vault sequences, membership/session revocation after authentication, immutable
  device keys, tombstone/restore/keyEpoch, bound one-use approvals, audit failure
  rollback, bounded pagination, and separate Service Binding RPC.
- Additional RED reproduced SQLite `INSERT OR REPLACE` bypassing ordinary UPDATE /
  DELETE immutability triggers. BEFORE INSERT collision guards fixed it. The original
  failure was an actual resolved D1 write, not a FakeD1 imitation.
- Approval digest compatibility had its own RED test before adding the existing
  `AgentKeychain-approval-v1\0` domain separator to durable approval validation.
- Extra coverage exercises identical vault/device/operation IDs in distinct tenants,
  concurrent distinct writes, real HTTP authentication/push/pull/error responses,
  foreign approvals/cursors/IDs, and composite FK negatives across dependent tables.

数据库故障注入在审计插入时中止，确认 nonce、sequence、head、version、approval、audit
全部回滚；去掉故障后，同一请求可成功提交。公钥不可变还覆盖 SQLite REPLACE 绕过。
API/Custodian 使用不同 Worker 和不同 D1；测试项目也不交叉绑定数据库。

## Environment / 环境

Official Workers integration `0.18.5`, Vitest `4.1.10`, Wrangler `4.111.0`, TypeScript
`5.9.3`. Packages were already installed elsewhere on this machine and copied locally;
no registry/network download occurred. The workspace lockfile was generated with
`npm install --package-lock-only --offline --ignore-scripts --no-audit --no-fund`.
This does not constitute an online dependency vulnerability audit.

Sandbox-only execution denied loopback listening (`EPERM` for Vitest; `EADDRINUSE`
for 11 existing Bun listener tests). Approved local-listening execution used the same
code and isolation guards. Root preload removes inherited credentials and requires
Keychain stubs/temp homes. No secret-reading installation verification was performed.

没有可用的内置 Chrome/DevTools 工具，因此没有浏览器验收；没有调用被禁止的 Hermes
浏览器适配器。此阶段没有 UI，HTTP、流式请求与数据库契约由真实 workerd 验证。

## Gates / 验证结果

| Gate | Result |
| --- | --- |
| `CI=1 WRANGLER_SEND_METRICS=false npm test --prefix managed-cloud` | 34 pass, 0 fail, 3 files; real workerd/D1 |
| Slice 1 focused suite (7 files, including engine security and Vault isolation) | 24 pass, 0 fail, 217 assertions |
| `bun run lint` | Pass; includes managed-cloud |
| `bun run typecheck` | Pass |
| `bun test` | 111 pass, 0 fail, 509 assertions, 25 files |
| `bun run build` | Pass; 325 modules, ignored local binary |
| `npm run typecheck --prefix managed-cloud` | Pass |
| `npm run build --prefix managed-cloud` | Pass; two local esbuild bundles, no deploy |
| `git diff --check` | Pass |

Final inspection found no private key blocks, plaintext credentials, application
logging/debug statements, real resource identifiers or unexpected outbound calls.
The only request URLs in source are intercepted `https://local.invalid` test requests.
No built output or database is tracked.
Generated bundles, node_modules and disposable databases are ignored, not deliverables.

## Limits / 限制

No account/passkey/browser auth, device/session issuance, enrollment, checkpoint
signing, approval issuance/UI, cryptographic split-key recovery, production data,
remote resources or staging failure testing. Device sessions and approvals are
provisioned only through synthetic test setup. Metadata-only recovery RPC never
returns key material. SQL atomicity is the tested single-D1 batch/trigger contract,
not a claim about cross-D1 recovery or an interactive JS transaction API.

生产账号、设备注册、签名检查点、审批 UI、分钥恢复与部署均属于后续阶段。
目前是实现自查与本地测试证据，不是新的独立安全审查批准。
