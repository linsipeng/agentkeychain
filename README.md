# agentkeychain

> Agent-native zero-knowledge credential vault. CLI + MCP Server, single binary.
> **Type your password ONCE. Never paste a key into chat again.**

[![CI](https://github.com/linsipeng/agentkeychain/actions/workflows/ci.yml/badge.svg)](https://github.com/linsipeng/agentkeychain/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![中文版](https://img.shields.io/badge/lang-中文-red.svg)](./README.zh-CN.md)

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

### Cloud sync across your machines (v0.3, bring-your-own Cloudflare)

Sync automatically via **your own** Cloudflare account (free plan is plenty —
the cloud only ever holds ciphertext):

```bash
# One-time (on your main machine):
agentkeychain sync init      # deploys a tiny Worker + D1 to YOUR CF account
# → prints a Sync URL + Token

agentkeychain sync connect   # paste that URL + token here
agentkeychain sync push      # upload your secrets (encrypted)

# On your other machine(s):
agentkeychain sync connect   # same URL + token
agentkeychain sync pull      # download — done, everything's here

# Day-to-day: push after changes, pull on other machines.
agentkeychain sync status    # health + row counts
```

- **Zero knowledge holds**: the cloud stores only ciphertext envelopes +
  irreversible name hashes (BLAKE2b-256) — no plaintext names, no values.
- Conflicts resolve **last-write-wins**; everything is audit-logged locally.
- Cost: **$0** — a single user stays far inside Cloudflare's free tier.
- The Worker + D1 live in **your** account: you can delete them anytime.

> 📖 **Full sync guide** (setup, conflicts, security model, troubleshooting,
> teardown): [docs/SYNC_GUIDE.md](./docs/SYNC_GUIDE.md)

### Moving to a new Mac (or a second machine)

```bash
# ── Old machine ──────────────────────────────────────────
agentkeychain export
# ✓ exported 42 secret(s) → ./agentkeychain-export-20260903-120000.akcbundle

# Send that ONE file to the new machine (AirDrop / scp / USB).

# ── New machine ──────────────────────────────────────────
# 1. Install (see "Install" below — one command)
# 2. Initialize with the SAME master password as the old machine:
agentkeychain init
# 3. Import the bundle:
agentkeychain import ~/Downloads/agentkeychain-export-*.akcbundle
# ✓ imported 42 secret(s)
agentkeychain list   # verify — everything is there
```

- The bundle is **fully encrypted** (same Argon2id + XChaCha20 as the vault) —
  without your master password it's just ciphertext. Delete it after importing.
- Same-name secrets are skipped by default; add `--overwrite` to replace them.
- Agent identities are NOT transferred (they're per-vault). That's fine —
  the new machine keeps its own `default` identity.
- Requires v0.2.0+ on **both** machines. Never copy `vault.db` directly —
  each vault has its own salt, the copied file won't decrypt.

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
| **CLI** | `init / store / get / list / delete / audit / export / import / sync / issue-token / serve` |
| **MCP Server** | 5 tools (`akc_store`, `akc_get`, `akc_list`, `akc_delete`, `akc_audit`) over stdio |
| **Cross-agent delegate** | Ed25519-signed time-limited scope-bounded tokens |
| **Audit chain** | Tamper-evident Ed25519 signature chain over every operation |
| **Zero-knowledge** | Master password never persisted; KEK derived via Argon2id on demand |
| **Single binary** | `bun build --compile` → 62 MB self-contained executable |

### Install (macOS & Linux, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh | sh
```

- Detects your OS + architecture, downloads the right binary from the latest
  release, **verifies its SHA256 checksum**, and installs to `~/.local/bin`.
- Prefer to review before running? `curl -fsSLO .../install.sh && less install.sh && sh install.sh`
- Options: `--version v0.3.0` (pin), `--dir <path>`, `--uninstall`.
- If `~/.local/bin` is not on your PATH, the installer prints the exact line to add.
- Supported: macOS (Apple Silicon & Intel), Linux (x64 & arm64). Or build from source with `bun`.

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
| `agentkeychain export [--out <path>]` | Export all secrets to an encrypted bundle (for moving to another machine) |
| `agentkeychain import <bundle> [--overwrite]` | Import secrets from an export bundle (same master password required) |
| `agentkeychain sync init/connect/push/pull/status/disconnect` | Cloud sync via your own Cloudflare account — see [docs/SYNC_GUIDE.md](./docs/SYNC_GUIDE.md) |
| `agentkeychain serve` | Start MCP server (stdio transport) |
| `agentkeychain issue-token --sub <id> --scopes "..." [--ttl 1h]` | Issue a cross-agent delegate token |
| `agentkeychain --version` | Print version |

### Moving to a new machine

```bash
# Old machine:
agentkeychain export
# → ✓ exported 42 secret(s) → ./agentkeychain-export-20260903-120000.akcbundle

# Copy the bundle over (AirDrop / USB / scp), then on the NEW machine:
agentkeychain init          # use the SAME master password
agentkeychain import ~/Downloads/agentkeychain-export-*.akcbundle
# → ✓ imported 42 secret(s)
```

The bundle is fully encrypted (same Argon2id + XChaCha20 as the vault) — anyone
without your master password sees only ciphertext. Delete it after importing.
Note: agent identities are per-vault and are NOT transferred; the new machine
keeps its own `default` identity (audit entries there are signed by it).

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
