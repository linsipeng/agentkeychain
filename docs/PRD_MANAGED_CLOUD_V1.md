# AgentKeychain Managed Cloud V1 PRD

- 状态：开发中
- 产品形态：唯一官方托管云
- 首发用户：已经使用 AI Agent、担心凭证泄露和越权的个人与小团队
- 产品承诺：Agent 可以安全使用凭证，但看不到、带不走长期秘密
- 基线：Managed Cloud v0.7 Slice 1，提交 `ac58879`

## 1. V1 完整结果

用户安装 AgentKeychain 后，只需：

1. 用 Passkey 登录官方账号；
2. 在浏览器确认添加设备；
3. 继续像现在一样通过本地私密页面保存凭证；
4. 多台设备自动同步，无需 push/pull；
5. 普通读取在最小权限内自动完成；
6. 发布、付款、删除、改权限、导出、恢复和轮换必须“允许一次”；
7. 丢失所有设备时，可通过平台账号验证、冷静期和独立恢复服务恢复访问。

用户不需要理解 Worker、D1、scope、sequence、设备密钥、Token 或 Cloudflare。

## 2. 产品组成

### 2.1 官方云服务

- Public API Worker：账号、Passkey、会话、设备、同步、历史、审批、审计和恢复编排。
- Recovery Custodian Worker：独立私有服务，只持有恢复边界的一部分，不拥有账号、会话或 Vault 历史读取权。
- Main D1：账号、租户、设备、同步历史、审批、审计。
- Custodian D1：独立恢复状态与一次性释放证据。

### 2.2 Web 控制台

普通用户页面：

- 登录 / 加入邀请；
- 首页；
- 待确认请求；
- 设备；
- 更新状态；
- 活动；
- 早期版本和恢复；
- 账号与恢复。

浏览器是账号控制面，不接收 Vault 解密密钥，不显示或复制凭证值。

### 2.3 本地客户端

- 浏览器设备授权；
- 独立设备签名密钥和包装密钥；
- 操作系统安全存储；
- 持久化加密队列、cursor、设备 pin 和日志检查点；
- 自动同步后台进程；
- 接入 Vault、Secure Capture、CLI 和 MCP；
- 本地写入与 cloud outbox 原子提交；
- 远端应用不产生 echo。

## 3. 安全红线

以下任一成立即否决发布：

- 云端、浏览器、日志或审计出现明文 secret、master password、Vault Key、设备私钥或长期 KEK；
- 同步服务可以替换设备公钥并伪造操作；
- 重放旧写入可以复活 tombstone；
- 同一设备或操作幂等键可以产生多个历史版本；
- 删除、恢复、轮换、导出或权限变化绕过确认；
- 账号服务单独即可解密或恢复 Vault；
- 跨账号/租户读取设备、历史、审批、活动或恢复记录；
- 浏览器能够直接制造恢复操作；
- 测试访问生产 Vault、Keychain、旧 sync.json 或外部服务；
- 普通用户仍需部署 Cloudflare、复制 URL/Token 或执行 push/pull；
- 老 v0.6.2 Vault 密文被迁移、重写或破坏。

## 4. 账号与登录

- 邀请制注册；本阶段不做公开注册、计费或订阅。
- Passkey 为唯一登录方式；无账号密码回退。
- Passkey 注册和认证使用严格 RP ID、Origin、challenge、UV 和单次消费校验。
- 浏览器会话使用 `__Host-` Cookie、HttpOnly、Secure、SameSite 和服务端 digest。
- 所有浏览器写操作必须同时通过 Session、严格 Origin、JSON Content-Type 和双提交 CSRF。
- 登录、恢复、审批和设备变化具备账号 + 来源独立限流。

## 5. 设备

- 每台设备拥有独立 Ed25519 签名密钥和 X25519 包装密钥。
- 添加设备需要账号验证和现有受信设备签名授权；首台设备是例外初始化流程。
- 浏览器只批准设备，不接收 Vault Data Key。
- 设备可单独移除；移除后所有设备 Session 失效，旧公钥保留用于历史验签。
- 设备请求同时使用短期 Session Token 和设备签名证明，Token 被盗不能单独使用。

## 6. 同步

- 服务端为每个 Vault 分配单调递增 sequence。
- 所有写入是设备签名的规范操作。
- 同一 `(vault, device, operation)` 精确重试返回原 receipt；不同内容冲突返回 409。
- tombstone、generation、key epoch、审批消费、head 更新、审计和 sequence 分配处于同一持久事务。
- 当前版本由服务器接收顺序决定；历史至少保留 30 天。
- Pull 以 sequence cursor 分页，并返回签名日志 checkpoint。
- 客户端独立验证公钥 pin、签名、sequence、幂等、状态机和 checkpoint；不盲信服务端。

## 7. 风险审批

自动：

- 已授权 scope 内读取；
- 非敏感元数据和状态；
- 后台同步；
- 新建一条全新凭证。

必须“允许一次”：

- 覆盖或轮换；
- 删除；
- 恢复；
- 导出；
- scope/权限变化；
- 添加或移除设备；
- 成员/Agent 权限变化；
- 账号恢复；
- AgentKeychain 自有连接器内的发布、付款和转账。

审批绑定 Agent、设备、动作、目标、完整请求 digest、过期时间和一次性 nonce。审批内容变化后必须重新确认。

## 8. 恢复

- 恢复由 Public API Worker 与 Recovery Custodian Worker 两方共同完成。
- 任一服务单独不能产生可用 Vault Key。
- 账号验证后创建恢复 Case，通知所有现有设备和邮箱。
- 有受信设备确认时可快速恢复；没有设备时进入至少 24 小时冷静期。
- 冷静期内任一现有设备可取消。
- 两方只输出加密给目标设备包装公钥的恢复材料。
- 新设备必须证明私钥持有后才能激活。
- 恢复完成后撤销浏览器会话、要求检查设备并生成完整审计。

## 9. 普通用户 Web 页面

固定导航：

- 首页
- 请求
- 设备
- 活动
- 账号

不建立全局明文凭证目录；没有安全标签时统一显示“Saved credential / 已保存的凭证”。

高风险请求页必须明确显示：会发生什么、谁请求、来自哪台设备、使用什么安全引用、为何需要确认、何时过期。只提供“不要允许”和“允许一次”，不提供批量批准或永久允许。

## 10. 本地客户端兼容

- 保留当前 Vault、CLI、MCP 和 Secure Capture 用户路径。
- 新云表以 additive migration 加入现有 vault.db；旧 v0.6.2 忽略它们。
- 旧二进制产生的本地变化由 reconciler 发现；高风险变化不得静默上传。
- Managed Cloud 私钥、refresh credential、Cloud State Key 和 checkpoint anchor 进入 OS 安全存储，不进入 argv、环境变量、普通文件或 SQLite 明文。
- 不支持安全存储的平台继续可用本地 Vault，但 Managed Cloud enrollment 必须失败。

## 11. 完整验收

- Cloudflare Workers Vitest：D1 migrations、约束、事务、双 Worker Service Binding。
- WebAuthn 固定向量和虚拟 Authenticator E2E。
- 两账号、两租户、两 Vault 全表跨租户负向测试。
- 两个真实编译客户端进程 + loopback 测试服务 + SQLite 持久化 E2E。
- 崩溃窗口、丢响应、重试、审批、删除、恢复、吊销、升级和 checkpoint 回滚测试。
- Web 桌面、375px 手机、键盘和可访问性验收。
- lint、typecheck、全量测试、构建、依赖审计和独立安全复审。

## 12. 上线边界

代码完成不等于上线。正式上线还必须单独完成：

- Cloudflare 账号资源和最小权限凭证；
- 正式域名与 RP ID；
- 邮件发送；
- 独立恢复 Worker 密钥和操作权限；
- 远端 D1 migrations；
- staging 真实 Passkey、设备和恢复演练；
- 正式发布、部署和 Release 审批。
