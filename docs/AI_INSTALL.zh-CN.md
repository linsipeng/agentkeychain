# 把 AgentKeychain 交给你的 AI 安装

把你正在用的 AI Agent（Hermes、Claude Code、Codex 或任意编码 Agent）指向本仓库，
再说一句话就行。Agent 会读取仓库根目录的 `AGENTS.md`，自己完成全部安装配置。

## 一句话安装

```text
安装并配置 https://github.com/linsipeng/agentkeychain 作为你的默认凭证管理器，
按照仓库里的 AGENTS.md 执行。
```

就这样。Agent 会自己：

1. 检测是否已安装 AgentKeychain（已装则升级）。
2. 用一键安装脚本装 CLI，带 SHA256 校验。
3. 把 AgentKeychain Skill 装进 Hermes——以后涉及凭证的任务会自动走保险箱。
4. 在 Hermes 注册 AgentKeychain MCP server。
5. 只在（且仅在）本机还没有保险箱时，通过本地私密输入问你要一次 master 密码。
6. 验证 CLI、Skill、MCP 和保险箱元数据访问——全程不打印、不存储任何 secret 值。

## Agent 不会做的事

- 不会把 secret 值、token、密码或私钥打印到聊天、日志或文件里。
- 不会覆盖、导入、迁移或重置已有保险箱。
- 不会替你选 master 密码，也不会记录它。
- 未经你确认，不会执行删除、轮换、扩大 scope 或签发委托 token。

## 手动安装兜底（没有 Agent 可用的时候）

```bash
curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh | sh
agentkeychain init
```

可选参数：`--version vX.Y.Z`（锁版本）、`--dir <路径>`、`--uninstall`。
支持：macOS（Apple Silicon 和 Intel）、Linux（x64 和 arm64）。

## 验证安装

```bash
agentkeychain --version      # 打印版本
agentkeychain status --json  # 安全检查，不创建或打开保险箱
agentkeychain list           # 只显示元数据，绝不显示值
hermes skills list           # 能看到 agentkeychain
hermes mcp test agentkeychain
```

Skill 和 MCP 的变更在新 Hermes 会话生效（或在当前会话执行
`/reload-skills` + `/reload-mcp`）。

## 相关文档

- 多机云同步：[SYNC_GUIDE.md](./SYNC_GUIDE.md)
- English install guide: [AI_INSTALL.md](./AI_INSTALL.md)
