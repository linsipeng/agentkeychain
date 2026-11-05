# Managed Cloud Slice 1 repair evidence / 修复验收记录

Scope: repair the existing dirty Slice 1 implementation, local synthetic verification
only. No commit, push, PR, release, deployment, Cloudflare, external service, real
Vault, real Keychain or real legacy configuration access. Existing v0.6.2 tests are
preserved. Concept, technical plan and PRD were read and not modified.

范围：修复已有未提交 Slice 1 实现，仅本地合成验证。没有提交、推送、PR、发布、部署、
Cloudflare、外部服务、真实 Vault/Keychain 或真实旧同步配置访问。保留 v0.6.2 既有测试，
已阅读且未修改 Concept、技术计划和 PRD。

## Repairs / 修复

- Engine construction is now asynchronous `CloudEngine.create`, requiring a separate
  explicit trusted enrollment list. Pins are copied privately. Transport `device()`
  is removed; pulled signatures cannot select their own verification keys.
- Each page validates contiguous sequences, signatures, device/operation uniqueness,
  generation/keyEpoch transitions, tombstone barriers and signed approval references
  before changing heads/cursor. Exact signed replays at a new sequence are rejected.
- Snapshots retain complete signed history (identities and exact signed bytes), heads,
  pending operations, cursor and a required sequence lower bound. Restart verifies
  history signatures against pins, reconstructs heads, validates transitions and
  verifies every pending signature against the local identity. Duplicate identities,
  duplicate/mismatched heads and inconsistent sequence/cursor states fail closed.
- Pagination checks page bounds, gaps, duplicate sequences/operations, continuation
  types/cursors, empty promised pages and premature termination below known receipts
  or continuation promises. The lower bound survives retries and restart.
- Service tests cover two-vault sequence isolation, device-scoped operation IDs,
  conflicts, revocation after signature verification at the repository acceptance
  seam, approval expiry and cross-operation nonce reuse.
- Managed Cloud never opens legacy config contents. Status only detects a safe regular
  file and preserves it; direct legacy config loading is disabled. Tests cover both a
  final-component symlink and parent-directory replacement after path validation.
- `ManagedService.transactionScope` and repository API comments explicitly expose
  the production requirement for one durable transaction spanning approvals and
  repository acceptance. No claim that separate in-memory stores solve it.

引擎通过独立受信注册列表固定公钥，不再使用同步传输返回的公钥。每页原子校验签名、
唯一操作身份、连续序列、generation/keyEpoch、删除屏障及签名审批引用。快照保留完整
签名历史，重启重建 head、验签并拒绝重复和无效状态。已知续页下限跨重试及重启保留。
服务测试覆盖双 Vault 隔离、设备级幂等、接受时吊销竞态、审批过期及跨操作 nonce 重用。
Managed Cloud 不打开旧配置内容，只检测安全普通文件并保留；直接加载旧配置已禁用。测试覆盖
最终文件符号链接和路径校验后的父目录替换。API 与文档明确生产审批/仓库必须共用持久化事务。

## TDD / 测试驱动记录

New engine security tests first failed because the trusted async construction API
was absent, then passed after implementation. The legacy symlink regression first
reproduced an outside-root classification, then passed after the read boundary fix.
A later continuation retry regression first proved that a rejected empty promised
page was accepted on the next sync; persisting the minimum expected sequence fixed
both retry and restart. Extra service tests confirmed existing acceptance checks.

引擎安全测试先因缺少受信异步构造入口失败，再通过实现变绿。符号链接测试先复现越界读取，
修复边界后通过。续页重试测试先复现失败后下一次同步错误成功，持久保留已知下限后重试和
重启均正确拒绝。服务附加测试验证了已有接受检查。

## Final gates / 最终验证

| Command | Result |
| --- | --- |
| `bun test tests/cloud-protocol.test.ts tests/cloud-service.test.ts tests/cloud-integration.test.ts tests/cloud-engine-security.test.ts tests/cloud-compat.test.ts tests/approval.test.ts tests/vault-isolation.test.ts` | 24 pass, 0 fail, 217 assertions, 7 files |
| `bun run lint` | Pass |
| `bun run typecheck` | Pass |
| `bun test` | 111 pass, 0 fail, 509 assertions, 25 files |
| `bun run build` | Pass; 325 modules; ignored local binary |
| `git diff --check` | Pass |

The initial sandboxed full run (before the final added tests) had 98 pass and 11
failures, all existing local form listeners reporting `EADDRINUSE` on port 0.
The final full run above used approved local-listening execution with unchanged
preload Keychain stubs and temporary-home guards. Only local test traffic was used.
No browser UI was changed; verification exercised the protocol, CLI and local form
contracts directly. Final tracked diff and new source/test files were inspected for
secret material, debug statements and unexpected IO; no such residue was found.

首次沙箱全量运行（最终新增测试前）98 通过、11 失败，均为既有本地表单端口 0 的
`EADDRINUSE`。最终获准本地监听运行 110 全通过，未改变 Keychain stub 或临时目录保护，
仅使用本地测试流量。无浏览器界面修改，直接验证协议、CLI 和本地表单契约。已检查最终
差异及新增源码/测试，未发现真实敏感数据、调试语句或意外 IO。

## Limits / 限制

This is a local in-memory slice, not a production adapter. Approval lookup and
consumption, revocation checks, idempotency, sequence allocation and version append
must share a durable transaction in production. The current separate MemoryApprovals
and repository seam do not prove crash-safe atomicity or production concurrency.

Clients verify signed approval references; actual grant validity is enforced by the
service. References alone do not prove human confirmation. Without authenticated
log checkpoints, unknown hidden suffixes and rollback of an entire valid snapshot
cannot be detected. Full-history snapshots are unbounded; persistence, compaction,
account/enrollment authentication, key distribution, approval UI, recovery and
production transport remain outside Slice 1. Existing CLI/MCP plaintext delivery
and approval behavior are unchanged. This repair is implementation self-review,
not independent security approval.

本阶段仅内存实现；生产审批消费、吊销、幂等、序列及版本追加须共用持久化事务，当前接口
不证明崩溃原子性或生产并发安全。客户端验证签名审批引用，实际授权由服务端检查，引用
本身不能证明用户确认。没有认证日志检查点，无法检测未知尾部隐藏或整个合法快照回滚。
完整历史无容量上限；持久化、压缩、账号/注册认证、密钥分发、审批 UI、恢复和生产传输
尚未实现。既有 CLI/MCP 明文交付及审批行为不变。本记录是实现自查，不是独立安全批准。

Status: repaired and verified locally; left uncommitted for review.
状态：已本地修复验证，保持未提交以供审查。
