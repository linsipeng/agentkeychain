# Sync Guide — 多台机器云同步完整指南

> English | [中文版见下方](#中文版)

Complete guide to syncing your agentkeychain vault across machines using the
built-in BYO Cloudflare sync (v0.3.0+).

---

## English

### How it works (30-second version)

```
┌─────────────┐   push (ciphertext)   ┌──────────────────────────────┐
│  Machine A  │ ────────────────────► │  YOUR Cloudflare account     │
│             │                       │  Worker + D1                 │
│  Machine B  │ ◄──────────────────── │  (free tier, $0/mo)          │
└─────────────┘   pull (ciphertext)   └──────────────────────────────┘
```

- The cloud stores **only**: ciphertext envelopes + irreversible BLAKE2b-256
  name hashes. No plaintext names, no values, ever.
- Your master password never leaves your machines. The cloud cannot decrypt
  anything even if fully compromised.
- The Worker + D1 database live in **your own** Cloudflare account — you can
  inspect or delete them anytime from the CF dashboard.

### Prerequisites

- agentkeychain **v0.3.0+** on every machine ([install](../README.md#install-mac))
- A (free) Cloudflare account
- On the machine running `sync init` only:
  - [wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-debug/) CLI
  - A Cloudflare API token with **Workers + D1 edit** permissions,
    exported as `CLOUDFLARE_API_TOKEN`

### One-time setup (main machine)

```bash
# 1. Deploy the sync endpoint to YOUR Cloudflare account
export CLOUDFLARE_API_TOKEN=cf_xxx   # your CF API token
agentkeychain sync init
```

Output:

```
Deploying sync worker to YOUR Cloudflare account…
✓ D1 database: agentkeychain-sync (3c6918ac-…)
✓ D1 schema applied
✓ worker deployed: https://agentkeychain-sync.<your-subdomain>.workers.dev
✓ SYNC_TOKEN injected

════════════════════════════════════════════════
Sync endpoint ready.

  URL:   https://agentkeychain-sync.<you>.workers.dev
  Token: AurrIWj4Ve1xO_…（64 chars）
════════════════════════════════════════════════
```

`sync init` is **idempotent** — safe to re-run; it reuses the existing D1
database and self-heals its config.

```bash
# 2. Bind this machine
agentkeychain sync connect
# Sync URL: https://agentkeychain-sync.<you>.workers.dev
# Sync token: <paste>

# 3. Upload everything
agentkeychain sync push
# ✓ pushed 42 row(s) (42 written to cloud)
```

The binding is stored in `~/.agentkeychain/sync.json` (mode 0600).

### Every other machine

```bash
agentkeychain sync connect   # same URL + token
agentkeychain sync pull      # ✓ pulled 42 row(s): 42 applied
agentkeychain list           # verify
```

Each machine gets its own random `deviceId` at connect time.

### Day-to-day

| Action | Command |
|---|---|
| After adding/changing secrets | `agentkeychain sync push` |
| Bring other machines up to date | `agentkeychain sync pull` |
| Check health + row counts | `agentkeychain sync status` |
| Unbind this machine (cloud data untouched) | `agentkeychain sync disconnect` |

A common rhythm: `push` on the machine where you changed something, `pull`
everywhere else. Pushing unchanged rows is harmless (server-side LWW dedupes).

### Conflict handling

Conflicts are resolved **last-write-wins** by per-secret `updated_at`:

- If two machines change the same secret offline, the later write wins.
- The losing value is not kept (v0.4 may add version history).
- Every push/pull is recorded in the **local** audit chain
  (`sync_push` / `sync_pull` actions) — the audit chain itself never leaves
  your machine, so there are no merge conflicts to worry about.

### Deleting a secret

`agentkeychain delete <name>` removes it locally. The cloud copy is not
touched in v0.3 (tombstones exist in the schema but delete-propagation ships
in v0.4). To fully remove a secret everywhere: delete locally on each machine,
or reset the cloud (below).

### Removing the sync backend entirely

```bash
# In the Cloudflare dashboard (your account):
#   Workers & Pages → agentkeychain-sync → Delete
#   Storage & Databases → D1 → agentkeychain-sync → Delete
agentkeychain sync disconnect   # on each bound machine
```

### Security model

| Threat | Protection |
|---|---|
| Cloud DB leaked | Only ciphertext + name hashes (BLAKE2b-256, keyed). Undecryptable without your master password. |
| Sync token stolen | It only reads/writes ciphertext. Attacker gains nothing readable. Rotate via `wrangler secret put SYNC_TOKEN`. |
| Man-in-the-middle | HTTPS (workers.dev TLS) + bearer token. |
| Malicious cloud | Cannot decrypt, cannot correlate names (hashes are keyed, irreversible). |

### Troubleshooting

| Symptom | Fix |
|---|---|
| `sync auth failed (401)` | Token mismatch — re-run `sync connect` with the token from `sync init`. |
| `endpoint /v1/health did not return ok` | Wrong URL, or the Worker was deleted. Re-run `sync init`. |
| `cannot decrypt cloud row — master password mismatch?` | Machines use different master passwords. All machines must share the SAME master password. |
| Push says `0 written` | Rows unchanged since last push — nothing to do. |
| Need a fresh start | `sync disconnect` everywhere → delete Worker + D1 in CF dashboard → `sync init` again. |

### Cost

$0. A single user makes a few dozen requests/day at a few KB each — far
inside Cloudflare's free tier (100k requests/day, 5GB D1).

---

## 中文版

### 工作原理（30 秒版）

```
┌─────────────┐   push（密文）   ┌──────────────────────────────┐
│  机器 A      │ ──────────────► │  你自己的 Cloudflare 账号      │
│             │                 │  Worker + D1                 │
│  机器 B      │ ◄────────────── │  （免费额度，$0/月）           │
└─────────────┘   pull（密文）   └──────────────────────────────┘
```

- 云端**只存**：密文信封 + 不可逆的 BLAKE2b-256 条目名哈希。永远没有明文名字和值。
- master 密码从不离开你的机器。云端即使被完整拖库也解不开任何东西。
- Worker + D1 跑在**你自己的** Cloudflare 账号里——随时可以在 CF 控制台查看或删除。

### 前置条件

- 每台机器都要 agentkeychain **v0.3.0+**（[安装](../README.zh-CN.md#安装mac)）
- 一个（免费的）Cloudflare 账号
- 只在跑 `sync init` 的那台机器上需要：
  - [wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-debug/) CLI
  - 有 **Workers + D1 编辑**权限的 Cloudflare API Token，导出为 `CLOUDFLARE_API_TOKEN`

### 一次性设置（主机器）

```bash
# 1. 把同步端点部署到你自己的 CF 账号
export CLOUDFLARE_API_TOKEN=cf_xxx   # 你的 CF API Token
agentkeychain sync init
```

输出：

```
Deploying sync worker to YOUR Cloudflare account…
✓ D1 database: agentkeychain-sync (3c6918ac-…)
✓ D1 schema applied
✓ worker deployed: https://agentkeychain-sync.<你的子域>.workers.dev
✓ SYNC_TOKEN injected

════════════════════════════════════════════════
Sync endpoint ready.

  URL:   https://agentkeychain-sync.<你>.workers.dev
  Token: AurrIWj4Ve1xO_…（64 字符）
════════════════════════════════════════════════
```

`sync init` 是**幂等**的——可以放心重跑；会复用已有 D1 数据库并自愈配置。

```bash
# 2. 绑定这台机器
agentkeychain sync connect
# Sync URL: https://agentkeychain-sync.<你>.workers.dev
# Sync token: <粘贴>

# 3. 上传全部
agentkeychain sync push
# ✓ pushed 42 row(s) (42 written to cloud)
```

绑定信息存在 `~/.agentkeychain/sync.json`（权限 0600）。

### 其他每台机器

```bash
agentkeychain sync connect   # 同样的 URL + Token
agentkeychain sync pull      # ✓ pulled 42 row(s): 42 applied
agentkeychain list           # 验证
```

每台机器连接时会获得自己的随机 `deviceId`。

### 日常使用

| 操作 | 命令 |
|---|---|
| 增改密钥之后 | `agentkeychain sync push` |
| 让其他机器跟上 | `agentkeychain sync pull` |
| 检查健康状态 + 行数 | `agentkeychain sync status` |
| 解绑这台机器（云端数据不动） | `agentkeychain sync disconnect` |

常见节奏：在哪台机器改了就 `push`，其他机器 `pull`。重复 push 没有副作用
（服务端 LWW 会去重）。

### 冲突处理

按每条密钥的 `updated_at` 做 **last-write-wins**：

- 两台机器离线改了同一条，后写的赢。
- 输掉的旧值不保留（v0.4 可能加版本历史）。
- 每次 push/pull 都记入**本地**审计链（`sync_push` / `sync_pull`）——
  审计链本身从不出你的机器，所以不存在审计链合并冲突。

### 删除一条密钥

`agentkeychain delete <name>` 只删本地。v0.3 暂不传播删除到云端
（schema 里已有 tombstone，删除传播 v0.4 发布）。要彻底清掉一条：
每台机器本地各删一遍，或重置云端（见下）。

### 彻底移除同步后端

```bash
# 在 Cloudflare 控制台（你自己的账号）：
#   Workers & Pages → agentkeychain-sync → Delete
#   Storage & Databases → D1 → agentkeychain-sync → Delete
agentkeychain sync disconnect   # 每台绑定的机器各跑一次
```

### 安全模型

| 威胁 | 防护 |
|---|---|
| 云端数据库泄漏 | 只有密文 + 名称哈希（BLAKE2b-256，带密钥）。没有 master 密码解不开。 |
| 同步 Token 被盗 | 只能读写密文，偷到也看不到任何明文。轮换：`wrangler secret put SYNC_TOKEN`。 |
| 中间人 | HTTPS（workers.dev TLS）+ Bearer Token。 |
| 恶意云端 | 解不开，也无法对应条目名（哈希带密钥、不可逆）。 |

### 故障排查

| 症状 | 处理 |
|---|---|
| `sync auth failed (401)` | Token 不匹配——用 `sync init` 输出的 Token 重新 `sync connect`。 |
| `endpoint /v1/health did not return ok` | URL 错了，或 Worker 被删了。重跑 `sync init`。 |
| `cannot decrypt cloud row — master password mismatch?` | 机器间 master 密码不一致。所有机器必须用**同一个** master 密码。 |
| push 显示 `0 written` | 自上次 push 后没有变化——无需处理。 |
| 想推倒重来 | 各机 `sync disconnect` → CF 控制台删 Worker + D1 → 重新 `sync init`。 |

### 费用

$0。单人每天几十次请求、每次几 KB——远在 Cloudflare 免费额度之内
（10 万请求/天、D1 5GB）。

---

## Related / 相关

- [迁移到新机器（export/import）](../README.md#moving-to-a-new-mac-or-a-second-machine)
- [主 README](../README.md) | [中文主 README](../README.zh-CN.md)
