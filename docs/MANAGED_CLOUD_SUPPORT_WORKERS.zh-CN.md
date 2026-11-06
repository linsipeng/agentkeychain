# Managed Cloud 支持 Worker 与 staging 配置

本实现从 `feat/managed-cloud-v0.7` 的 `afc0186` 开始，新增私有 Auth Trust、
API Trust、Custody Trust Worker、独立邮件 D1、验证码请求与消费、双语发送按钮，
以及五个 Worker / 三个 D1 的确定性配置生成器。没有部署、提交、创建真实凭证、
访问 Cloudflare 账号或发送真实邮件；公开安装版本不变。

完整接口、密钥格式、数据表和验证细节见
[英文运行说明](MANAGED_CLOUD_SUPPORT_WORKERS.md)。非敏感拓扑保存在
`managed-cloud/provisioning/plan.json`：Web/RP 为 `agentkeychain.soupsam.com`，
API 为 `api.agentkeychain.soupsam.com`。仅 API Worker 设置域名路由，其余 Worker
均为私有服务并返回 HTTP 404。Custody 必须具备独立的密钥、操作人员和资源权限。

`provisioning/examples/*.json.example` 不含真实资源 ID 或密钥。生成器只从受保护
运行环境接收三个独立 D1 ID、域名、发件地址、发布公钥 pin 和双方全部公钥；缺失、
重复、占位符或错误格式均拒绝。`checkpointKeys` 与 API recovery service pin 必须属于
API 操作方；`witnessKeys`、`recoveryAuthorities` 与 Custodian recovery service pin 必须
属于 Custody 操作方，生成器和 Custody 运行时双重校验。输出位于忽略目录
`provisioning/generated/`，目录权限 0700、文件权限 0600。未签名发布清单不等于正式发布。

业务凭证继续由 AgentKeychain 管理，受限加载器在获批后注入 Worker secrets。
双方各用途密钥必须独立；活动密钥唯一，旧签名密钥可以仅保留公钥，旧包装密钥
可用于解密历史包。密钥 ID 为规范 base64 公钥的 SHA-256。禁止导出私钥、任意
签名及任意重包裹；重包裹必须匹配持久化恢复请求、最新包、当前授权、目标公钥
和对应操作方。取消、撤销或篡改后拒绝。RPC 辅助函数采用模块私有边界。

独立控制面须审核并写入 `trust_devices` 初始锚点、`trust_accounts` 账号验证公钥
和 `trust_revocations` 精确撤销摘要。没有公开写入接口或默认放行规则；空注册表
会拒绝相关操作。新增 migration 仅包含 schema，不包含用户数据。

验证码使用密码学随机数生成，六位、十分钟有效、最多五次尝试，原子单次消费；
同邮箱跨用途每小时最多发送五次、两次间隔至少六十秒。数据库与审计不保存邮箱、
验证码或 IP 明文。私有 EMAIL 绑定必须具备真实可用的发送能力；测试仅替换为
内存邮件箱，检查接口只返回收件人掩码。来源限流只接受 Cloudflare 入口覆盖的
连接 IP 元数据，输出 HMAC 化标识，无客户端头回退。

浏览器请求接口先验证 bootstrap/session、Origin、JSON、CSRF 及来源/身份限流。
请求与消费绑定同一邀请或恢复 requestRef；返回结果与账号/邀请是否存在无关。
发送按钮先获取 bootstrap，成功响应到达后才开始六十秒重发倒计时；失败可重试，
没有伪造的进度。

本地验证包括真实五 Worker 构建、三 D1、staging Service Binding 拓扑、邀请及
恢复验证码请求/消费/重放、私有 HTTP、签名拒绝、双方独立授权与重包裹、撤销和
取消。计数与命令见 `MANAGED_CLOUD_SUPPORT_WORKERS_AUDIT.json`。

实测结果：根目录 190 测试 / 1,804 断言 / 46 文件（包含真实编译进程测试），
后端 316 测试 / 11 文件，Web 95 测试 / 4 文件，编译恢复 52 场景，资源诊断
8 测试且没有未释放 RPC 警告。最后的严格邮箱边界修改另通过 147 个认证测试。
两套构建产物验收、五份配置及八种拒绝场景、lint、三套 typecheck、CLI/原生工具/
Worker/Web 构建均通过；Bun 与完整/运行时 npm 审计均为零漏洞。

尚需外部门禁：真实资源、独立权限及信任元数据审批、受保护的密钥生成与安装、
实际公钥收集与发布签名、发件域名与真实投递、远端 migration、DNS、自定义域名、
真实 Passkey 与延迟恢复演练、Chrome 可访问性/视觉验收，以及明确部署/发布批准。
本轮没有可用的 Codex 内置 Chrome 接口，也没有接管外部 Chrome 或使用 Hermes
浏览器适配器。
