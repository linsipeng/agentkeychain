# Managed Cloud v0.7 — Slice 1 / 托管云 Slice 1

## English

AgentKeychain has one planned cloud product mode: the official managed service.
Users will sign in and synchronize encrypted credentials across approved devices.
The original Slice 1 implements the local in-memory protocol/service/client.
The separate `managed-cloud/` workspace now includes locally tested Phase 2
Workers and the Phase 3 bilingual Web control center, without production deployment.
See [Phase 3 evidence](./MANAGED_CLOUD_PHASE3_EVIDENCE.md); persistent local-client
integration and native browser acceptance remain separate gates.
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

Historical Slice 1 limitations (superseded by the durable client and security repair below): this was not a production API. Device administration, key discovery and
pull are trusted in-process seams, not authenticated public endpoints. The test
approval issuer is a trusted harness, not a user confirmation interface. Existing
v0.6.2 Vault schema/ciphertext and CLI/MCP behavior remain unchanged; local secret
reads still return plaintext to trusted clients. The new classifier is not wired
into those legacy commands. Account recovery, device key delivery, production D1
transactions, persistent approvals/queue, scheduling and history retention policy
are deferred. `DeviceKeyPackage` is an interface only. No account-recovery claim is made.

## 中文

AgentKeychain 只规划一种云产品模式：官方托管服务。目标体验是登录后，在获批设备间
同步加密凭证。早期 Slice 1 只有本地内存协议；当前已有持久客户端及账号连接命令，仍未部署生产服务。

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
unbounded in the historical memory-only slice. The current client persists encrypted history and secure anchors; history compaction remains deferred.

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

The independent `managed-cloud/` workspace now tests atomic D1 acceptance, device-authenticated push/pull, isolation and a private Custodian skeleton on local workerd. This does not turn the Slice 1 client into a production client. Account login arrived in Phase 2B; enrollment and signed checkpoints arrived in Phase 2C below. Split-key recovery now has a local Phase 2D backend; see the current section below. See [contracts](../managed-cloud/README.md) and [evidence](./MANAGED_CLOUD_PHASE2A_EVIDENCE.md).

独立 `managed-cloud/` 已通过本地 workerd 验证 D1 原子接受、设备认证同步、隔离及私有 Custodian 骨架。Slice 1 客户端仍不是生产客户端；账号登录已在 Phase 2B 实现，设备注册与签名检查点已在下文 Phase 2C 实现；分钥恢复现已实现本地可测的 Phase 2D 后端，见下文。

## Phase 2B account backend / 账号后端

Phase 2B adds locally tested invitation-only Passkey registration/login, encrypted
verified email, browser sessions, CSRF, action-bound step-up and shared D1 rate limits.
Review repairs require discoverable credentials and trusted source bindings, reject
verification races, add bounded retention, and execute the generated bundle locally.
It uses the real pinned SimpleWebAuthn adapter in workerd with synthetic Ed25519 and
ES256 authenticators. The React UI and device enrollment are implemented in later
sections below; real email delivery and deployment remain separate gates. See [HTTP contracts](../managed-cloud/README.md#phase-2b-browser-authentication)
and [test evidence and limitations](./MANAGED_CLOUD_PHASE2B_EVIDENCE.md).

Phase 2B 已实现本地可测的邀请制 Passkey 注册/登录、加密已验证邮箱、浏览器会话、CSRF、
动作绑定 step-up 与 D1 共享限流。复审修复要求可发现凭证及可信来源绑定，拒绝验证竞态，
加入有界清理，并本地执行生成 bundle。使用固定版本的真实 SimpleWebAuthn 适配器及合成
Ed25519/ES256 认证器，在 workerd 中验签；设备注册及 React UI 见后续阶段章节，仍无真实邮件或部署。
验收范围与限制见上方契约和证据链接。


## Phase 2C devices and checkpoints / 设备与检查点

The managed backend now implements browser-approved trusted-device grants, first-device
bootstrap, 15-minute sessions requiring request signatures, immutable encrypted key
packages, atomic revocation, and signed per-vault sync chains. Browser approval requires
Passkey step-up over the exact action digest and explicit confirmation. Account/vault
scope comes from authenticated records; the server never receives a private device key
or VDK. The generated workerd bundle exercises the complete synthetic JSON flow.

托管后端已实现浏览器批准的受信设备授权、首设备初始化、15 分钟请求签名会话、不可变加密
密钥包、原子吊销与每 Vault 签名同步链。浏览器批准需要绑定完整动作摘要的 Passkey
step-up 和显式确认；账号/Vault 范围来自认证记录，服务端不接收设备私钥或 VDK。
生成的 workerd bundle 已验证完整合成 JSON 流程。

The historical Slice 1 implementation remains as a protocol fixture. The current durable client
persists checkpoints and independent witness receipts; the web application implements the ordinary-user `/app/devices` UI. A retained
trusted anchor is necessary to reject an entirely replayed old signed snapshot. No online
audit or real browser/platform-authenticator validation is claimed under this task's
no-network constraint and unavailable built-in browser tools.

上文 Slice 1 限制属于历史记录；当前持久客户端已保存检查点，设备界面已实现。原计划属于
后续阶段。拒绝整个旧签名快照的回放需要独立保存的可信锚点。本任务禁止网络，且未提供内置
浏览器工具，因此不声称完成在线漏洞审计或真实浏览器/平台认证器验收。

See [current backend contracts](../managed-cloud/README.md) and
[Phase 2C evidence](./MANAGED_CLOUD_PHASE2C_EVIDENCE.md).


## Phase 2D approvals, activity and recovery / 审批、活动与恢复

The local backend now implements pending/recent exact one-use approvals, atomic
approval consumption for existing-object updates/delete/restore, normalized
append-only activity with signed checkpoints, and a two-Worker/two-D1 recovery
saga. Recovery has independent operator authorization, a 24-hour no-device
cooldown, device confirmation/cancellation, target-only encrypted share release,
private-key proof, session revocation and device review state. Scope/rotation
changes carried in encrypted updates require the same exact approval. Device
control retains its exact transactional action authorization. No cross-D1
atomicity is claimed. No production service, ordinary-user UI, or persistent
client integration is delivered by this backend phase.

本地后端现已实现待办/最近一次性精确审批、更新/删除/恢复的事务内消费、
统一追加式脱敏活动与签名检查点，以及双 Worker/双 D1 恢复状态机。
恢复包含独立授权、无设备路径至少 24 小时冷却、设备确认/取消、仅向目标设备
加密释放份额、持钥证明、浏览器会话撤销与设备复核状态。加密更新携带的 scope
或密钥轮换同样要求精确审批；设备控制沿用事务内动作授权。不存在跨 D1 原子
事务保证。本阶段不交付生产服务、普通用户界面或持久化客户端集成。

See [JSON contracts](../managed-cloud/README.md#phase-2d-json-contracts) and
[actual local evidence and deployment limits](./MANAGED_CLOUD_PHASE2D_EVIDENCE.md).

Phase 2D review repair: browser activity and signed checkpoint counts are account-scoped;
public event IDs/cursors are opaque and contain no global database ordinals. Recovery
rejects existing/historical targets at start and activation. Main atomically records
`activating` with local activation before idempotent Custodian completion; cancellation
cannot cross that boundary. Cancel requires a separate exact signed authorization,
independently verified by Custodian with nonce replay protection. An undelivered,
expired cancel authorization needs a fresh signature. Pre-activation eligibility
failures remain fail-closed; there is no unconditional partial-failure resume claim.

Phase 2D 复审修复：浏览器活动及签名检查点计数按账号隔离，公开事件 ID/游标不暴露
全局数据库序号。恢复在开始和激活时均拒绝已存在或历史设备身份。Main 将
`activating` 意图与本地激活原子提交，再幂等完成 Custodian；取消不能越过该边界。
取消需要独立精确签名、Custodian 独立验签和 nonce 防重放；未投递成功且已过期
的取消授权需要重新签名。激活前资格失效仍拒绝执行，不再笼统承诺部分失败均可续跑。

## Phase 3 本地实现补充

独立 managed-cloud 工作区已提供本地测试的双语 Web 控制中心及邀请显示、受限恢复
前置契约。没有部署服务、自动迁移或真实数据访问；Phase 4 本地客户端集成及原生浏览器
验收仍需单独完成。[证据与限制](./MANAGED_CLOUD_PHASE3_EVIDENCE.md)。


### Phase 3 review boundary / 复审边界

Public recovery accepts only `{email,proof,requestRef}`. The target device first
signs its exact target and decrypts a five-minute one-use wrapping-key challenge;
only then does the device API issue the handoff reference. Direct browser target
objects are rejected. Browser email proof authorizes recovery but never creates
target keys or delivers shares. See the [current evidence](./MANAGED_CLOUD_PHASE3_EVIDENCE.md)
for local test counts and outstanding controller/native Passkey acceptance.

公开恢复仅接受设备完成签名及包装私钥持有证明后取得的 `requestRef`，不接受浏览器
直接提交目标公钥。通知页面展示有界的真实恢复记录，不声称通知已送达；活动验证
成功后解除警告，登录过期时清空账号风险和查询缓存。没有部署或使用真实数据。

## Final Phase 3 recovery boundary / 最终恢复边界

Normal account browsers use safe web query/action contracts for recovery metadata,
notifications, review and cancellation only. They cannot start recovery, submit
target keys, obtain cryptographic recovery material or finish activation. Restricted
public recovery verifies a target-device-signed requestRef, then permits only
start/status/cancel. The target-device endpoints perform all cryptographic steps.
Cancellation carries an opaque device-issued confirmation reference, never a signed
authorization body. Device status follows authenticated pull time and reported
processed cursors, with a 300-second freshness window; delivery alone is not an ack.

普通账号浏览器只通过安全 web 合约查看元数据、通知、复核及取消，不可启动恢复、
提交目标密钥、取得恢复材料或完成激活。受限公开恢复绑定目标设备签名的 requestRef，
仅允许启动、状态及取消；所有密码学步骤走目标设备接口。取消只传设备签发的引用，
不传签名授权正文。设备状态来自认证拉取时间和已处理游标，时效窗口为 300 秒；
服务器发送数据不等于设备已确认。尚未部署，原生浏览器/Passkey 验收仍有限制。


## Current client implementation / 当前客户端实现

The separate durable client now persists encrypted outbox/history, validates release
and enrollment trust, retains an independent checkpoint anchor, and supplies background
sync plus CLI/MCP controls. These supersede the historical Phase 4 deferrals above.
`cloud status` in an ordinary unprovisioned build reports
`cloud_unavailable_not_provisioned`; no URL/token override exists. The legacy `sync`
commands remain disabled and legacy configuration is never imported automatically.

Compiled synthetic acceptance covers issuer intent/SAS/package/receipt interruptions,
terminal and replacement requests, concurrent delivery, local/outbox atomicity,
push/pull/cursor/anchor crashes, daemon leases, revocation and reconciliation decisions.
Enrollment resumes only from exact protected signed/encrypted evidence; unknown or
conflicting anchors fail closed. Export uses exclusive POSIX directory-relative
publication with a durable inode receipt, exact staging cleanup, and tested parent
rename/symlink/fsync failures. Existing Vault rows remain unchanged during enrollment.
Use `cloud request-export <path>` before `export --out <path>` and
`cloud reconcile [name]` to inspect or stage older-client edits.
See [final local acceptance](PHASE45_FINAL_CONTINUATION.md).

中文：最终三项内部缺口已完成本地实现及验收：签发端/守护进程中断与并发、部分注册锚
恢复、目录描述符相对导出。恢复仅使用受保护的原始密钥和已验证信任证据；未知或冲突锚
保持隔离。现仅保留外部生产配置、原生平台/浏览器验收及发布部署门槛。未使用真实数据。

Signed roster/revocation contracts and freshness limits remain documented in
[SIGNED_ROSTER.md](SIGNED_ROSTER.md). Completed local recovery activation is documented
in [LOCAL_RECOVERY_ACTIVATION.md](LOCAL_RECOVERY_ACTIVATION.md).

### Native recovery activation

The development CLI now implements `cloud recover <packageId>` and journal resume
with `cloud recover`. Use `--no-open` to print the safe verification URL, or
`--restart` with a package ID to replace only a key-free terminal receipt. Recovery
requires the existing locally initialized vault/private password boundary.
Independent release signatures, an authority-encrypted trust bundle, protected
refresh credentials and final server/local readback gate activation. See
[local recovery implementation and acceptance](LOCAL_RECOVERY_ACTIVATION.md).
Production endpoint/key provisioning remains fail-closed; this does not change the
pinned public installation release or authorize real-vault migration.

Latest local continuation: [crash delivery and reconciliation evidence](PHASE45_FINAL_CONTINUATION.md). Denied, cancelled, expired and stale legacy requests are retired locally; `cloud reconcile` reports the terminal request and an explicit new request is required.

Current security lifecycle: Main acceptance → pending witness saga → independently
verified Custodian receipt → client trust/activation. Revocation enforcement can precede
its witnessed completion; the UI/API must not equate the two. Recovery refresh creates
a new immutable receipt version before target-signed activation; committed history is
retained. Managed imports commit an entire batch or nothing. See
[final security repair](FINAL_SECURITY_REPAIR.md) and the
[migration rollback runbook](SECURITY_REPAIR_MIGRATION_RUNBOOK.md).

中文：当前生命周期为 Main 接受、独立见证待确认、Custodian 签名回执、客户端信任/激活。
吊销执行不等于见证完成；激活前可刷新回执版本，激活后保留不可变历史。托管导入全批次
提交或全部回滚。旧阶段计数是历史证据，最新验收以安全修复记录为准。

精确恢复版本绑定、最后设备移除保护与无限历史的增量见证，以[最终复审契约及验收记录](LAST_FINAL_REVIEW.md)为准。

Private support Workers, email-code requests and deterministic staging configuration are documented in [English](MANAGED_CLOUD_SUPPORT_WORKERS.md) / [中文](MANAGED_CLOUD_SUPPORT_WORKERS.zh-CN.md). No real resources or deployment are enabled / 未启用真实资源或部署。
