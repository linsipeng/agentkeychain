# agentkeychain

> Agent-native zero-knowledge credential vault. CLI + MCP Server, single binary.
> **Type your password ONCE. Never paste a key into chat again.**

[![CI](https://github.com/linsipeng/agentkeychain/actions/workflows/ci.yml/badge.svg)](https://github.com/linsipeng/agentkeychain/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

---

## For Humans (the only section you need)

**You only need 4 commands.** Everything else is for agents and developers.

```bash
agentkeychain init      # One-time: set a master password (≥8 chars, remember it!)
agentkeychain store     # Add a new secret — it asks you: name? value? scope?
agentkeychain get NAME  # Retrieve a secret
agentkeychain list      # See all stored secrets (metadata only, NEVER values)
```

**⬆️ That's it. That's all you need to remember. Everything below is for AI agents, developers, and power users.**

### Real-world usage

```bash
# Step 1: Initialize (do this ONE TIME per machine)
$ agentkeychain init
Master password (min 8 chars): ********
✓ vault initialized
✓ master password saved to OS keychain

#     👆 After this, agentkeychain remembers your password in macOS Keychain.
#     You will NEVER be asked to type it again. Your AI agent handles it.

# Step 2: Store your first secret
$ agentkeychain store
Name: openai
Value: ***[paste your key]*     (hidden while typing)
Scope: openai:chat
✓ encrypted and stored: openai

# Step 3: Retrieve it when you need it (password auto-resolved from Keychain)
$ agentkeychain get openai
sk-proj-xxxxxxxxxxxx...

# Step 4: See what you have
$ agentkeychain list
NAME      VERSION  SCOPES       UPDATED
openai    1        openai:chat  2026-07-06 04:56:24

# Delete old stuff
$ agentkeychain delete test-key --yes
✓ deleted: test-key
```

### Talk to your agent instead

**You don't even need to remember the commands.** Just tell your AI assistant:

| You say | Agent does (silently) |
|---|---|
| "存一下这个 OpenAI key：sk-xxxxx" | `agentkeychain store openai-key --value sk-xxxxx` |
| "帮我查一下 Cloudflare 的 token" | `agentkeychain get cloudflare-token` |
| "用 openai 帮我写段代码" | `agentkeychain get openai-key` → call API → do the work |
| "告诉我存了哪些 key" | `agentkeychain list` |
| "把旧的 XX 删掉" | `agentkeychain delete xxx --yes` |

**Your agent asks the vault, not you. You stay out of the loop.**

### What you NEVER do

- ❌ Paste API keys into chat messages, emails, READMEs, or `.env` files you commit
- ❌ Write keys in code comments
- ❌ Screenshot a key and send it
- ❌ Re-type the same key 50 times across different tools
- ❌ Say "密码是多少来着" — it's in the vault, your agent knows how to get it

If you find yourself about to paste a key anywhere, stop and say: **"存一下这个 key"**.

---

## For Developers

### What it does

| | |
|---|---|
| **CLI** | `init / store / get / list / delete / audit / issue-token / serve` |
| **MCP Server** | 5 tools (`akc_store`, `akc_get`, `akc_list`, `akc_delete`, `akc_audit`) over stdio |
| **Cross-agent delegate** | Ed25519-signed time-limited scope-bounded tokens |
| **Audit chain** | Tamper-evident Ed25519 signature chain over every operation |
| **Zero-knowledge** | Master password never persisted; KEK derived via Argon2id on demand |
| **Single binary** | `bun build --compile` → 62 MB self-contained executable |

### Install (Mac)

```bash
curl -L https://github.com/linsipeng/agentkeychain/releases/latest/download/agentkeychain-darwin-arm64 \
  -o ~/.local/bin/agentkeychain
chmod +x ~/.local/bin/agentkeychain
agentkeychain --version
```

**No `sudo` needed.** `~/.local/bin` is already in PATH on macOS.

For Linux x64, replace `darwin-arm64` with `linux-x64` (or build from source).

### First-time setup

```bash
agentkeychain init
# Master password: ********      (≥8 chars, never stored)
# → vault initialized at ~/.agentkeychain/
# → default identity: ak_xxx ("default")
# → ✓ master password saved to OS keychain (you'll never be asked again)
```

**That's the only time you type the password.** Every subsequent `store / get / list / delete / audit` reads the password automatically from macOS Keychain.

### CLI reference

| Command | Description |
|---|---|
| `agentkeychain init` | Initialize vault, set master password, create default identity |
| `agentkeychain store <name> --value <v> --scopes "..."` | Encrypt and store a credential |
| `agentkeychain get <name> [--json]` | Decrypt and return a credential |
| `agentkeychain list [--json]` | List all credentials (metadata only) |
| `agentkeychain delete <name> [--yes]` | Delete a credential (add `--yes` to skip confirmation — useful for agents) |
| `agentkeychain audit [--since 24h]` | Show audit log |
| `agentkeychain serve` | Start MCP server (stdio transport) |
| `agentkeychain issue-token --sub <id> --scopes "..." [--ttl 1h]` | Issue a cross-agent delegate token |
| `agentkeychain --version` | Print version |

### Use as MCP Server

Add to any MCP-compatible client (Claude Desktop, Hermes, Codex, IDE plugins):

```json
{
  "mcpServers": {
    "agentkeychain": {
      "command": "/usr/local/bin/agentkeychain",
      "args": ["serve"]
    }
  }
}
```

The server exposes 5 tools:

| Tool | Description |
|---|---|
| `akc_store` | Encrypt + persist a secret (returns id, never the value) |
| `akc_get` | Decrypt + return a secret (scope-checked) |
| `akc_list` | List secret names (no values) |
| `akc_delete` | Remove a secret (scope-checked) |
| `akc_audit` | Read the audit log (no secret material) |

### Security model

- **Argon2id** (memory=64 MB, iterations=3) derives a KEK from master password
- **XChaCha20-Poly1305** AEAD encrypts each secret independently
- **Ed25519** signs audit entries + delegate tokens (offline-verifiable)
- **Client-side only** — no server, no network call; vault file is fully encrypted
- **Zero-knowledge** — master password is never written to disk

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full threat model and competitor comparison.

---

## Development

```bash
bun install         # install deps
bun test            # run all tests (41 tests)
bun run lint        # eslint
bun run build       # single-binary compile to bin/agentkeychain-bin
bun run typecheck   # tsc --noEmit
```

CI runs on every push to `main` — see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

---

## License

MIT — see [LICENSE](./LICENSE).

## Status

v0.1.0 — public alpha. Single binary works end-to-end. Breaking changes possible before v1.0.
