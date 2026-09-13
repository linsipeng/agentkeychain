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

**你只需要记 4 个命令。** 下面都是给 AI Agent 和开发者看的。

```bash
agentkeychain init      # 一次性：设一个 master 密码（≥8 位，记好！）
agentkeychain store     # 存一个 key——跟着提示输入：名字？值？作用域？
agentkeychain get NAME  # 取出来
agentkeychain list      # 看存了哪些（只显示名字，绝不显示值）
```

**⬆️ 就这些。剩下的都是给 AI Agent 和开发者准备的。**

### 真实使用场景

```bash
# 第 1 步：初始化（每台电脑只做一次）
$ agentkeychain init
Master password (min 8 chars): ********
✓ vault initialized
✓ master password saved to OS keychain

#     👆 之后 agentkeychain 就把密码存到 macOS Keychain 了。
#     **你再也不需要输第二遍。你的 AI Agent 会帮你处理。**

# 第 2 步：存入第一个 key
$ agentkeychain store
Name: openai
Value: ***[粘贴你的 key]*     （输入时不可见）
Scope: openai:chat
✓ encrypted and stored: openai

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
| "存一下这个 OpenAI key：sk-xxxxx" | `agentkeychain store openai-key --value sk-xxxxx` |
| "帮我查一下 Cloudflare 的 token" | `agentkeychain get cloudflare-token` |
| "用 openai 帮我写段代码" | `agentkeychain get openai-key` → 调 API → 干活 |
| "告诉我存了哪些 key" | `agentkeychain list` |
| "把旧的 XX 删掉" | `agentkeychain delete xxx --yes` |

**你的 Agent 找保险箱要 key，不用再问你。你全程不用参与。**

### 多台机器云同步（v0.3，BYO Cloudflare——用你自己的 CF 账号）

通过**你自己的** Cloudflare 账号自动同步（免费额度绰绰有余——云端只存密文）：

```bash
# 一次性（在主机器上）：
agentkeychain sync init      # 部署一个极小 Worker + D1 到你自己的 CF 账号
# → 输出 Sync URL + Token

agentkeychain sync connect   # 粘贴 URL + Token
agentkeychain sync push      # 上传密钥（加密）

# 在其他机器上：
agentkeychain sync connect   # 同样的 URL + Token
agentkeychain sync pull      # 下载——完成，所有密钥都在了

# 日常：改完 push，其他机器 pull。
agentkeychain sync status    # 健康状态 + 行数对账
```

- **零知识依然成立**：云端只存密文信封 + 不可逆的条目名哈希（BLAKE2b-256）——
  没有明文名字，没有值。
- 冲突按 **last-write-wins** 解决；所有操作本地审计留痕。
- 费用：**$0**——单人使用远在 Cloudflare 免费额度之内。
- Worker + D1 跑在**你自己的**账号里：随时可以在 CF 控制台删除。

> 📖 **完整同步指南**（设置、冲突、安全模型、故障排查、彻底移除）：
> [docs/SYNC_GUIDE.md](./docs/SYNC_GUIDE.md)

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
| **CLI** | `init / store / get / list / delete / audit / export / import / sync / issue-token / serve` |
| **MCP Server** | 5 个工具（`akc_store`, `akc_get`, `akc_list`, `akc_delete`, `akc_audit`），stdio 传输 |
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

### CLI 命令参考

| 命令 | 说明 |
|---|---|
| `agentkeychain init` | 初始化保险箱，设置 master 密码，创建默认身份 |
| `agentkeychain store <name> --value <v> --scopes "..."` | 加密并存储凭证 |
| `agentkeychain get <name> [--json]` | 解密并返回凭证 |
| `agentkeychain list [--json]` | 列出所有凭证（仅元数据） |
| `agentkeychain delete <name> [--yes]` | 删除凭证（加 `--yes` 跳过确认，Agent 调用时有用） |
| `agentkeychain audit [--since 24h]` | 查看审计日志 |
| `agentkeychain export [--out <path>]` | 导出全部凭证到加密 bundle（迁移到另一台机器用） |
| `agentkeychain import <bundle> [--overwrite]` | 从 bundle 导入凭证（需要相同的 master 密码） |
| `agentkeychain sync init/connect/push/pull/status/disconnect` | 云同步（用你自己的 Cloudflare 账号）——见 [docs/SYNC_GUIDE.md](./docs/SYNC_GUIDE.md) |
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

服务器暴露 5 个工具：

| 工具 | 说明 |
|---|---|
| `akc_store` | 加密并持久化凭证（返回 id，绝不返回值） |
| `akc_get` | 解密并返回凭证（作用域检查） |
| `akc_list` | 列出凭证名（不返回值） |
| `akc_delete` | 删除凭证（作用域检查） |
| `akc_audit` | 读取审计日志（不含凭证信息） |

### 安全模型

- **Argon2id**（内存=64 MB，迭代=3）从 master 密码导出 KEK
- **XChaCha20-Poly1305** AEAD 独立加密每个凭证
- **Ed25519** 为审计条目和委托令牌签名（离线可验证）
- **纯客户端**——无服务器，无网络调用；保险箱文件完全加密
- **零知识**——master 密码永不写入磁盘

详细威胁模型和竞品对比见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

---

## 开发

```bash
bun install         # 安装依赖
bun test            # 运行所有测试（41 个）
bun run lint        # eslint
bun run build       # 编译为单文件二进制到 bin/agentkeychain-bin
bun run typecheck   # tsc --noEmit
```

每次推送到 `main` 都会自动跑 CI——详见 [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)。

---

## 许可证

MIT——见 [LICENSE](./LICENSE)。

## 状态

v0.1.0 —— 公开 alpha 版。单文件二进制端到端可用。v1.0 前可能会有破坏性变更。
