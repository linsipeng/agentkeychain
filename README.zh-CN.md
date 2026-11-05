# agentkeychain

> 为 AI Agent 设计的零知识凭证保险箱。CLI + MCP Server，单文件二进制。
> **只输一次密码。再也不用把 API key 贴到聊天里。**

[![CI](https://github.com/linsipeng/agentkeychain/actions/workflows/ci.yml/badge.svg)](https://github.com/linsipeng/agentkeychain/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![English](https://img.shields.io/badge/lang-English-blue.svg)](./README.md)

---

## 把链接发给你的 AI

只需把本仓库发给你的 AI Agent，再说一句：

```text
安装并配置 https://github.com/linsipeng/agentkeychain 作为你的默认凭证管理器，
按照仓库里的 AGENTS.md 执行。
```

AI 会自己完成 CLI 安装、AgentKeychain Skill 安装、Hermes MCP 注册、
保险箱安全初始化和最终验证。你不需要复制一串命令，已有保险箱也绝不会被覆盖。

[完整 AI 安装协议](./docs/AI_INSTALL.zh-CN.md)

## 给人类看的（你只需要这一节）

**你不需要记命令，也不需要编写权限 scope。** 只要告诉本机 AI Agent
你要存什么凭证、准备拿它做什么：

```text
帮我保存 OpenAI 凭证，用于模型调用。
```

AgentKeychain 会在本机浏览器打开一次性安全表单。把凭证粘贴到表单，
不要贴进聊天。页面只显示“仅允许用于 OpenAI 模型调用”这类自然语言权限；
底层最小权限由系统自动推断。

如果想确认自己记住的主密码是否正确，只需告诉 Agent“验证我的主密码”。
系统会打开另一个一次性本地表单，最多允许 10 次只读校验，10 次都不正确才失效。
密码不会进入聊天或 MCP 参数，也不会修改 Vault 或 macOS 钥匙串。

### 真实使用场景

```bash
# 第 1 步：初始化（每台电脑只做一次）
$ agentkeychain init
Master password (min 8 chars): ********
✓ vault initialized
✓ master password saved to OS keychain

#     👆 之后 agentkeychain 就把密码存到 macOS Keychain 了。
#     **你再也不需要输第二遍。你的 AI Agent 会帮你处理。**

# 第 2 步：告诉 Agent 要保存什么凭证、用于什么。
# 系统打开一次性本地表单；凭证值和原始 scope 都不会进入聊天。

# 第 3 步：需要时取出来（密码从 Keychain 自动取，不弹窗）
$ agentkeychain get openai
sk-proj-xxxxxxxxxxxx...

# 第 4 步：看存了什么
$ agentkeychain list
NAME      VERSION  SCOPES       UPDATED
openai    1        openai:chat  2026-07-06 04:56:24

# 删除旧的
$ agentkeychain delete test-key --yes
✓ deleted: test-key
```

### 跟你的 Agent 说就行了

**你连命令都不用记。** 直接跟你的 AI 助手说：

| 你说 | Agent 静默执行 |
|---|---|
| “帮我保存 OpenAI 凭证，用于模型调用” | 打开一次性本地表单，并自动推断最小权限 |
| “验证我记住的主密码” | 打开一次性本地表单，只读校验密码，不修改任何数据 |
| "帮我查一下 Cloudflare 的 token" | `agentkeychain get cloudflare-token` |
| "用 openai 帮我写段代码" | `agentkeychain get openai-key` → 调 API → 干活 |
| "告诉我存了哪些 key" | `agentkeychain list` |
| "把旧的 XX 删掉" | `agentkeychain delete xxx --yes` |

**你的 Agent 找保险箱要 key，不用再问你。你全程不用参与。**

### Managed Cloud v0.7（Slice 1：仅本地测试）

AgentKeychain 正在转向唯一的官方托管云模式。目标体验是登录账号后，在获批设备间
自动同步加密凭证。Slice 1 通过内存服务与客户端实现并测试协议、独立设备签名、
服务器接收顺序与历史、幂等重试、分页、删除屏障以及明确批准后的恢复。

本阶段没有已部署的云服务、账号登录、账号恢复、审批界面或持久化同步队列。
v0.6.2 本地 Vault 行为保持不变；现有 CLI/MCP 读取仍会向受信任的本地调用方返回明文。
新的审批契约尚未接入现有 CLI/MCP 操作。

`agentkeychain sync status` 只在本地报告安全兼容状态。旧同步
`init/connect/push/pull/disconnect` 命令已禁用；已有配置原样保留，不连接旧端点，
也不上传数据。本阶段不自动迁移。详见[托管云指南](./docs/SYNC_GUIDE.md)。

### 换新 Mac（或第二台电脑）怎么迁移

```bash
# ── 旧机器 ──────────────────────────────────────────
agentkeychain export
# ✓ exported 42 secret(s) → ./agentkeychain-export-20260903-120000.akcbundle

# 把这一个文件传到新机器（AirDrop / scp / U 盘都行）。

# ── 新机器 ──────────────────────────────────────────
# 1. 先安装（见下面的「安装」——一条命令）
# 2. 用【和旧机器相同】的 master 密码初始化：
agentkeychain init
# 3. 导入 bundle：
agentkeychain import ~/Downloads/agentkeychain-export-*.akcbundle
# ✓ imported 42 secret(s)
agentkeychain list   # 检查一下，都在
```

- bundle 是**完全加密**的（和保险箱同一套 Argon2id + XChaCha20）——
  没有你的 master 密码，谁拿到都只是密文。导入完删掉即可。
- 同名条目默认跳过；想覆盖就加 `--overwrite`。
- Agent 身份不会迁移（身份属于各自的保险箱）。没关系，
  新机器保留自己的 `default` 身份。
- 两台机器都需要 v0.2.0+。**不要**直接拷贝 `vault.db`——
  每个保险箱有自己的 salt，拷过去的文件解不开。

### 你永远不要做的事

- ❌ 把 API key 贴到聊天消息、邮件、README、或者会 commit 的 `.env` 文件里
- ❌ 在代码注释里写 key
- ❌ 截屏发 key
- ❌ 同一个 key 在 50 个工具里重复输入
- ❌ 说"密码是多少来着"——在保险箱里，你的 Agent 知道怎么取

如果你发现自己在复制粘贴一个 key，停下来，说一句：**"存一下这个 key"**。

---

## 给开发者看的

### 功能

| | |
|---|---|
| **CLI** | `init / capture / verify-password / store / get / list / delete / audit / export / import / sync / issue-token / serve` |
| **MCP Server** | 7 个工具，包含私密密码校验和安全凭证录入，stdio 传输 |
| **跨 Agent 委托** | Ed25519 签名的限时、限定作用域的代理令牌 |
| **审计链** | 每次操作都有防篡改的 Ed25519 签名链 |
| **零知识同步** | 密码、KEK 和明文凭证绝不上云；可由系统钥匙串保存密码以供本机 Agent 自动解锁 |
| **单文件二进制** | `bun build --compile` → 62 MB 自包含可执行文件 |

### 安装（macOS 和 Linux，一条命令）

```bash
curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh | sh
```

- 自动识别你的系统和架构，从最新 Release 下载对应二进制，
  **校验 SHA256**，安装到 `~/.local/bin`。
- 想先审查脚本再运行？`curl -fsSLO .../install.sh && less install.sh && sh install.sh`
- 可选参数：`--version v0.3.0`（锁版本）、`--dir <路径>`、`--uninstall`。
- 如果 `~/.local/bin` 不在你的 PATH 里，安装器会打印需要添加的那一行。
- 支持：macOS（Apple Silicon 和 Intel）、Linux（x64 和 arm64）。也可以用 `bun` 从源码构建。

### 首次设置

```bash
agentkeychain init
# Master password: ********      （≥8 位，永不落盘）
# → vault initialized at ~/.agentkeychain/
# → default identity: ak_xxx ("default")
# → ✓ master password saved to OS keychain（以后再也不会问你要密码）
```

**这是你唯一一次输入密码。** 之后所有的 `store / get / list / delete / audit` 都会自动从 macOS Keychain 读取密码。

每个自定义 `AGENTKEYCHAIN_HOME` 都绑定独立的、按路径隔离的系统钥匙串
条目，因此临时 vault 与生产 vault 不能再互相覆盖主密码。默认
`~/.agentkeychain` 继续兼容原有条目。旧版自定义 vault 升级后运行
`agentkeychain setup` 时，只有旧条目经验证确实能解锁当前 vault，才会
自动复制到新的隔离条目。

### CLI 命令参考

| 命令 | 说明 |
|---|---|
| `agentkeychain init` | 初始化保险箱，设置 master 密码，创建默认身份 |
| `agentkeychain verify-password` | 打开一次性本地表单，只读校验记住的主密码，不修改保险箱或钥匙串 |
| `agentkeychain store <name> --value <v> --scopes "..."` | 加密并存储凭证 |
| `agentkeychain get <name> [--json]` | 解密并返回凭证 |
| `agentkeychain list [--json]` | 列出所有凭证（仅元数据） |
| `agentkeychain delete <name> [--yes]` | 删除凭证（加 `--yes` 跳过确认，Agent 调用时有用） |
| `agentkeychain audit [--since 24h]` | 查看审计日志 |
| `agentkeychain export [--out <path>]` | 导出全部凭证到加密 bundle（迁移到另一台机器用） |
| `agentkeychain import <bundle> [--overwrite]` | 从 bundle 导入凭证（需要相同的 master 密码） |
| `agentkeychain sync status` | 本地兼容状态；Managed Cloud Slice 1 仅供测试——见 [docs/SYNC_GUIDE.md](./docs/SYNC_GUIDE.md) |
| `agentkeychain serve` | 启动 MCP 服务器（stdio 传输） |
| `agentkeychain issue-token --sub <id> --scopes "..." [--ttl 1h]` | 签发跨 Agent 委托令牌 |
| `agentkeychain status [--json]` | 安全报告版本、保险箱初始化状态和密码通道状态，不读取凭证 |
| `agentkeychain --version` | 打印版本 |

### 迁移到新机器

```bash
# 旧机器：
agentkeychain export
# → ✓ exported 42 secret(s) → ./agentkeychain-export-20260903-120000.akcbundle

# 把 bundle 传过去（AirDrop / U 盘 / scp），然后在新机器上：
agentkeychain init          # 用【同一个】master 密码
agentkeychain import ~/Downloads/agentkeychain-export-*.akcbundle
# → ✓ imported 42 secret(s)
```

bundle 完全加密（与保险箱相同的 Argon2id + XChaCha20）——没有你的 master 密码，
谁拿到的都只是密文。导入完成后请删除 bundle。
注意：agent 身份属于各自的保险箱，不会随 bundle 迁移；新机器保留自己的
`default` 身份（那边的审计由它签名）。

### 作为 MCP Server 使用

在任何支持 MCP 的客户端（Claude Desktop、Hermes、Codex、IDE 插件等）的配置中添加：

```json
{
  "mcpServers": {
    "agentkeychain": {
      "command": "/home/you/.local/bin/agentkeychain",
      "args": ["serve"]
    }
  }
}
```

服务器暴露 7 个工具：

| 工具 | 说明 |
|---|---|
| `akc_request_store` | 默认人工录入路径：打开一次性本地表单并自动推断权限；凭证值不进入 MCP 参数 |
| `akc_request_password_check` | 打开一次性本地只读校验表单；主密码不进入 MCP 参数 |
| `akc_store` | 高级兼容路径：加密存储可信 MCP 客户端提供的值 |
| `akc_get` | 解密并返回凭证（作用域检查） |
| `akc_list` | 列出凭证名（不返回值） |
| `akc_delete` | 删除凭证（作用域检查） |
| `akc_audit` | 读取审计日志（不含凭证信息） |

**MCP 信任边界：**`akc_get` 会把明文返回给 MCP 客户端，调用它的 Agent 才能实际使用。
只应注册可信的本地客户端；如果客户端没有关闭留存，其模型上下文、会话记录或工具日志
可能保留该结果，AgentKeychain 无法清除客户端持有的副本。

### 安全模型

- **Argon2id**（内存=64 MB，迭代=3）从 master 密码导出 KEK
- **XChaCha20-Poly1305** AEAD 独立加密每个凭证
- **Ed25519** 为审计条目和委托令牌签名（离线可验证）
- **纯客户端**——无托管服务、不向外部上传凭证；安全录入仅使用一次性 127.0.0.1 本地回环表单
- **零知识**——master 密码永不写入磁盘

详细威胁模型和竞品对比见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

---

## 开发

```bash
bun install         # 安装依赖
bun test            # 运行全部测试
bun run lint        # eslint
bun run build       # 编译为单文件二进制到 bin/agentkeychain-bin
bun run typecheck   # tsc --noEmit
```

每次推送到 `main` 都会自动跑 CI——详见 [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)。

---

## 许可证

MIT——见 [LICENSE](./LICENSE)。

## 状态

v0.6.2 —— 紧急安全版本：测试默认禁止访问宿主机钥匙串与生产 Vault；自定义
Vault 使用按路径隔离的钥匙串条目；`setup` 在任何覆盖前必须先验证密码。
v1.0 前仍可能有破坏性变更。

Managed Cloud Slice 1 使用独立受信注册入口固定的设备公钥校验拉取及重启历史，
并实施重放检查和删除屏障。快照保留完整签名历史；持久化存储及回滚保护尚未实现。
生产审批消费与版本接受必须共用一个持久化事务；内存服务并非生产适配器。
