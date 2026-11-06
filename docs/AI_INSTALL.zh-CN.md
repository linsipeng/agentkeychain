# 把 AgentKeychain 交给你的 AI 安装

把你正在用的 AI Agent（Hermes、Claude Code、Codex 或任意编码 Agent）指向本仓库，
再说一句话就行。Agent 会读取仓库根目录的 `AGENTS.md`，自己完成全部安装配置。

## 一句话安装

```text
安装并配置 https://github.com/linsipeng/agentkeychain 作为你的默认凭证管理器，
按照仓库里的 AGENTS.md 执行。
```

就这样。Agent 会自己：

1. 检测是否已安装兼容版本的 AgentKeychain，已兼容则原样保留。
2. 用一键安装脚本装 CLI，带 SHA256 校验。
3. 把 AgentKeychain Skill 装进 Hermes——以后涉及凭证的任务会自动走保险箱。
4. 在 Hermes 注册 AgentKeychain MCP server。
5. 只在（且仅在）本机还没有保险箱时，通过本地私密输入问你要一次 master 密码。
6. 验证 CLI、Skill、MCP 和保险箱元数据访问——安装验证期间不读取、不打印、不存储任何 secret 值。

## Agent 不会做的事

- 不会把 secret 值、token、密码或私钥打印到聊天、日志或文件里。
- 不会覆盖、导入、迁移或重置已有保险箱。
- 不会替你选 master 密码，也不会记录它。
- 未经你确认，不会执行删除、轮换、扩大 scope 或签发委托 token。

## 手动安装兜底（没有 Agent 可用的时候）

```bash
curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/v0.6.2/install.sh | sh -s -- --version v0.6.2
agentkeychain init
```

可选参数：`--version vX.Y.Z`（锁版本）、`--dir <路径>`、`--uninstall`。
支持：macOS（Apple Silicon 和 Intel）、Linux（x64 和 arm64）。

## 验证安装

```bash
agentkeychain --version      # 打印版本
agentkeychain status --json  # 只读检查，不创建或修改保险箱
agentkeychain list           # 只显示元数据，绝不显示值
hermes skills list           # 能看到 agentkeychain
hermes mcp test agentkeychain
```

Skill 和 MCP 的变更在新 Hermes 会话生效（或在当前会话执行
`/reload-skills` + `/reload-mcp`）。

## Managed Cloud 状态

安装器仍安装固定的 v0.6.2 本地 CLI。Managed Cloud v0.7 Slice 1 仅为本地测试实现，
并非已上线的云服务或账号设置流程。唯一规划的云模式是官方托管服务；用户无需部署
基础设施或提供共享同步凭证。在此开发分支中，`agentkeychain sync status` 安全检测旧配置；
旧同步命令已禁用，配置原样保留且不连接端点。本阶段没有旧同步自动迁移或已部署云服务；账号恢复与审批界面已完成本地测试。
审批契约不改变现有 CLI/MCP 向受信任客户端交付明文的行为。

## 相关文档

本分支已实现原生安全存储辅助程序、发行清单验签构建、仅元数据兼容检查及可执行文件原子
替换；仅对原已安装且运行中的托管服务尝试重启。macOS 辅助程序与 CLI 同目录构建，发行
时须提供校验和；主密码仍使用原钥匙串 tuple，改为 stdin 传入，不进入 argv。未知云表
版本会停用云集成，本地旧表仍可使用。公开安装协议仍固定 v0.6.2；开发验收不得升级已有
安装或安装宿主机服务。生产云组合在缺少编译内置的已验签发行清单时关闭。托管导出已接入确切云审批；
最终签发端/守护进程中断、受保护注册锚恢复及目录描述符相对导出矩阵已通过本地验收。
仅保留外部生产配置、原生平台/浏览器验收及发布部署门槛，见[最终证据](./PHASE45_FINAL_CONTINUATION.md)。

- 托管云范围与兼容性：[SYNC_GUIDE.md](./SYNC_GUIDE.md)
- English install guide: [AI_INSTALL.md](./AI_INSTALL.md)

Phase 2A 已新增独立的 Workers/D1 本地可测后端；它不改变安装流程，也未启用账号登录、设备注册或分钥恢复。详见 [Phase 2A 验收记录](./MANAGED_CLOUD_PHASE2A_EVIDENCE.md)。

目标设备在浏览器批准后可使用原密钥签名续接注册；签发端保留密封字节及本地短语确认以重试。恢复激活、过期请求清理及新请求不复用旧短语已有本地验收。

开发中的签名名单与撤销传播见 [SIGNED_ROSTER.md](SIGNED_ROSTER.md)。这不改变公开安装的固定版本，也不授权迁移真实凭证库。

开发中的 `cloud recover [packageId]` 已接入安全存储恢复日志、独立签名份额、
权威签名的目标加密信任包，以及服务端和本地状态读回后激活。编译产物使用合成数据
验收快速、延迟和崩溃/替换路径。详见[恢复证据](LOCAL_RECOVERY_ACTIVATION.md)。

最终开发分支安全契约及迁移语义见 [FINAL_SECURITY_REPAIR.md](FINAL_SECURITY_REPAIR.md)。公开固定安装版本未变；部署与原生平台验收仍是独立门槛。

私有支持 Worker 和 staging 配置仅为开发成果，不改变固定版本安装流程。详见[运行说明与外部门禁](MANAGED_CLOUD_SUPPORT_WORKERS.zh-CN.md)。
