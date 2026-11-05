# Managed Cloud v0.7 — Slice 1 / 托管云 Slice 1

## English

AgentKeychain has one planned cloud product mode: the official managed service.
Users will sign in and synchronize encrypted credentials across approved devices.
This branch contains only a local, in-memory protocol/service/client implementation.
There is no cloud deployment or account connection command to run yet.

Implemented and tested:

- Canonical protocol v2 operations signed by independent Ed25519 devices. Signatures
  bind the vault, object, device, operation ID, kind, generation, key epoch,
  encrypted envelope and approval reference. Noncanonical wire bytes are rejected.
- Per-vault server sequences, immutable ciphertext history and receive-order heads.
  Identical retries return the same receipt; conflicting idempotency keys fail.
- Sequence pagination, a sign-once memory queue with restart snapshots, and explicit
  sync states. Callers invoke `sync()` again after backoff; no scheduler or disk
  persistence is included. A rejected queued operation remains pending for diagnosis.
- Signed tombstones block stale writes. Explicit restore requires a newer generation
  and a valid bound approval. Revocation blocks writes, including retries; historical
  signatures remain verifiable.
- A pure risk classifier and an in-memory trusted confirmation seam. Scoped reads,
  metadata/status and sync are automatic; publish, payment/purchase/transfer,
  deletion, permission/scope/device/member changes, export, restore and rotation
  require confirmation. Unknown actions fail closed. Approval binds agent, action,
  credential reference, request digest, expiry and one-time nonce. Delete/restore
  acceptance enforces that contract in the test service.

`agentkeychain sync status` detects old configuration without displaying its URL or
credential and without opening the Vault or contacting any endpoint. Legacy sync
`init`, `connect`, `push`, `pull` and `disconnect` are deprecated and disabled.
Configuration is preserved; nothing is automatically uploaded, migrated or deleted.
The old implementation remains in the source for compatibility review, outside the
managed path. Custom `AGENTKEYCHAIN_HOME` uses the Vault's isolation guard.

Limitations: this is not a production API. Device administration, key discovery and
pull are trusted in-process seams, not authenticated public endpoints. The test
approval issuer is a trusted harness, not a user confirmation interface. Existing
v0.6.2 Vault schema/ciphertext and CLI/MCP behavior remain unchanged; local secret
reads still return plaintext to trusted clients. The new classifier is not wired
into those legacy commands. Account recovery, device key delivery, production D1
transactions, persistent approvals/queue, scheduling and history retention policy
are deferred. `DeviceKeyPackage` is an interface only. No account-recovery claim is made.

## 中文

AgentKeychain 只规划一种云产品模式：官方托管服务。目标体验是登录后，在获批设备间
同步加密凭证。本分支只有本地内存协议、服务和客户端实现；尚无云部署或账号连接命令。

已实现并测试：

- 规范化 v2 操作和独立 Ed25519 设备签名，绑定 Vault、对象、设备、操作 ID、类型、
  generation、key epoch、密文信封与审批引用。拒绝非规范化传输字节。
- 每个 Vault 的服务器序列、不可变密文历史、按服务器接收顺序选择当前版本。
  相同重试返回原回执，幂等键冲突被拒绝。
- 序列分页、只签名一次的内存队列、重启快照和同步状态。退避后由调用方再次调用
  `sync()`；没有调度器或磁盘持久化。被拒绝的队列操作会保留以供诊断。
- 签名 tombstone 阻止旧写入复活对象；显式恢复须使用更高 generation 和有效绑定审批。
  吊销后拒绝写入及重试，但历史签名仍可验证。
- 纯风险分类器及内存受信确认入口。已授权 scope 内读取、元数据/状态和同步可自动执行；
  发布、付款/购买/转账、删除、权限/scope/设备/成员变更、导出、恢复和轮换必须确认。
  未知动作默认要求确认。审批绑定 Agent、动作、凭证引用、请求摘要、有效期和一次性 nonce。
  测试服务在接受删除和恢复时强制执行该契约。

`agentkeychain sync status` 检测旧配置，不显示 URL 或凭证，不打开 Vault，不访问端点。
旧同步 `init/connect/push/pull/disconnect` 命令已弃用并禁用。配置原样保留，不自动上传、
迁移或删除。旧实现保留于源码供兼容审查，不进入托管路径。自定义 `AGENTKEYCHAIN_HOME`
复用 Vault 隔离保护。

限制：这不是生产 API。设备管理、密钥发现和拉取属于进程内受信入口，并非认证后的公开端点。
测试审批签发器是受信测试工具，不是用户确认界面。v0.6.2 Vault schema/密文和 CLI/MCP
行为保持不变，本地读取仍向受信客户端返回明文；新分类器尚未接入这些旧命令。
账号恢复、设备密钥交付、生产 D1 事务、持久化审批/队列、调度及历史保留策略均留待后续阶段。
`DeviceKeyPackage` 仅为接口，不代表已实现账号恢复。

## Slice 1 trust and restart contract / 信任与重启契约

`CloudEngine.create` requires a separate trusted enrollment list and validates the
snapshot asynchronously before exposing the engine. Sync transport cannot supply
verification keys. Full contiguous signed history retains device/operation identities
and signed bytes; restart reconstructs heads and checks pending signatures. Every
page validates signatures, unique identities, generation/key-epoch transitions and
approval references before applying. Delete/restore approval references are signed;
the service validates actual grants. A client alone cannot prove user confirmation
from a reference. Pending offline writes may be stale and are checked at acceptance.

Pagination rejects gaps, duplicates, oversized pages, invalid continuation, an empty
page after promised continuation and termination below an acknowledged sequence.
Without an authenticated log checkpoint it cannot detect a server hiding an unknown
suffix or rolling back an entire otherwise valid snapshot. Full-history storage is
unbounded in this local slice; durable storage/compaction is not implemented.

`ManagedService.transactionScope` explicitly identifies a local-memory-only contract.
Production approval lookup/consumption, device revocation check, idempotency, sequence
allocation and version append must commit or roll back in one durable transaction.
The injected repository and separate MemoryApprovals do not establish this production
guarantee. Managed Cloud never opens legacy `sync.json`; status only detects a safe
regular-file presence and preserves it for a future explicit migration flow.

`CloudEngine.create` 必须接收独立受信注册列表，并在返回引擎前异步校验快照。
同步传输不能提供验签公钥。连续完整签名历史保留设备/操作身份与签名字节；
重启时重建 head 并检查待发送签名。每页应用前校验签名、身份唯一性、generation、
keyEpoch 转移及审批引用。删除/恢复的审批引用纳入签名，实际授权由服务端验证；
客户端无法仅凭引用证明用户确已确认。离线待发送操作可能过期，由接受端检查。

分页拒绝缺口、重复、超大页、无效续页、承诺续页后返回空页，以及在已确认 sequence
之前结束。没有经过认证的日志检查点时，无法检测服务端隐藏未知尾部或回滚整个合法快照。
本阶段完整历史无容量上限，尚无持久化或压缩实现。

`ManagedService.transactionScope` 明确标识仅内存契约。生产审批读取/消费、设备吊销检查、
幂等检查、序列分配与版本追加必须在同一个持久化事务内提交或回滚。注入仓库与独立
MemoryApprovals 不提供此生产保证。Managed Cloud 不打开旧 `sync.json`，状态命令只检测
安全普通文件是否存在，并原样保留给未来显式迁移流程。

## Phase 2A backend foundation / 后端基础

The independent `managed-cloud/` workspace now tests atomic D1 acceptance, device-authenticated push/pull, isolation and a private Custodian skeleton on local workerd. This does not turn the Slice 1 client into a production client. Account login, enrollment, signed checkpoints and split-key recovery remain deferred. See [contracts](../managed-cloud/README.md) and [evidence](./MANAGED_CLOUD_PHASE2A_EVIDENCE.md).

独立 `managed-cloud/` 已通过本地 workerd 验证 D1 原子接受、设备认证同步、隔离及私有 Custodian 骨架。Slice 1 客户端仍不是生产客户端；账号登录、设备注册、签名检查点与分钥恢复仍属于后续阶段。
