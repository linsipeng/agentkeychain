# agentkeychain

> Agent-native zero-knowledge credential vault. CLI + MCP Server, single binary.

**AI Agents need credentials. Users shouldn't be asked for API keys 50 times.**
agentkeychain treats agents as **first-class identities** with their own scopes,
delegation, and tamper-evident audit — built on Argon2id, XChaCha20-Poly1305,
and Ed25519.

[![CI](https://github.com/linsipeng/agentkeychain/actions/workflows/ci.yml/badge.svg)](https://github.com/linsipeng/agentkeychain/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

---

## For Humans (the only section you need)

**You only need 4 commands.** Everything else is for agents and power users.

```bash
agentkeychain init      # One-time: set a master password (8+ chars, remember it!)
agentkeychain store     # Add a new secret (it asks you: name? value? scope?)
agentkeychain get NAME  # Retrieve a secret (prompts for master password)
agentkeychain list      # See all stored secrets (metadata only, NEVER values)
```

That's it. Everything below is optional.

### Real-world usage

```bash
# Step 1: Initialize (do this ONCE per machine)
$ agentkeychain init
Master password (min 8 chars): ********
✓ vault initialized

# Step 2: Store your first secret (just follow the prompts)
$ agentkeychain store
Name: openai
Value: ***(paste your key, input is hidden in real terminals)
Scope: openai:chat
✓ encrypted and stored: openai

# Step 3: Retrieve it when you need it
$ agentkeychain get openai
Master password: ********
***your key appears here***

# Step 4: See what you have
$ agentkeychain list
NAME      VERSION  SCOPES       UPDATED
openai    1        openai:chat  2026-07-06 04:56:24
```

### Talk to your agent instead

**You don't even need to remember the commands.** Just tell your agent:

- "I want to save this OpenAI key" → agent runs `agentkeychain store` for you
- "Get my Cloudflare token" → agent runs `agentkeychain get cloudflare`
- "Show me all my stored keys" → agent runs `agentkeychain list`
- "Delete the old GitHub token" → agent runs `agentkeychain delete github`

When the agent needs a credential to do work, it asks the vault, not you. You
stay out of the loop.

### What you NEVER do

- ❌ Paste API keys into chat messages, emails, READMEs, or `.env` files you commit
- ❌ Write keys in code comments
- ❌ Screenshot a key and send it
- ❌ Re-type the same key 50 times across different tools

If you find yourself pasting a key anywhere, stop and run `agentkeychain store`.

---

## What it does

| | |
|---|---|
| **CLI** | `agentkeychain init / store / get / list / delete / audit / issue-token / serve` |
| **MCP Server** | 5 tools (`akc_store`, `akc_get`, `akc_list`, `akc_delete`, `akc_audit`) over stdio |
| **Cross-agent delegate** | Ed25519-signed time-limited scope-bounded tokens |
| **Audit chain** | Tamper-evident Ed25519 signature chain over every operation |
| **Zero-knowledge** | Master password never persisted; KEK derived via Argon2id on demand |
| **Single binary** | `bun build --compile` → 62 MB self-contained executable |

---

## 5-Minute Quickstart

### Install

```bash
# Option 1: download single binary (Linux x64)
curl -L https://github.com/linsipeng/agentkeychain/releases/latest/download/agentkeychain-linux-x64 -o akc
chmod +x akc
mv akc /usr/local/bin/agentkeychain

# Option 2: from source
git clone https://github.com/linsipeng/agentkeychain.git
cd agentkeychain
bun install
bun run build   # produces bin/agentkeychain-bin
```

### First-time setup

```bash
agentkeychain init
# Master password: ********      (≥8 chars, never stored)
# Confirm: ********
# → vault initialized at ~/.agentkeychain/
# → default identity: ak_xxx ("default")
```

### Use the CLI

```bash
# Store an API key
agentkeychain store openai-key --value "sk-..." --scopes "openai:chat"

# Retrieve (decrypts on demand, prompted for master password)
agentkeychain get openai-key

# List (metadata only, never values)
agentkeychain list

# View audit log (Ed25519-signed entries, tamper-evident)
agentkeychain audit
```

### Issue a delegate token (cross-agent)

```bash
# Main agent issues a time-limited, scope-bounded token for a sub-agent
agentkeychain issue-token \
  --sub ak_subagent_xxx \
  --scopes "openai:read,cloudflare:read" \
  --ttl 1h

# Output: base64url-encoded JSON to stdout — pass via env var or pipe to sub-agent
TOKEN=$(agentkeychain issue-token --sub ak_sub --scopes openai:read --ttl 30m)
```

The sub-agent presents the token as the `delegate_token` argument when calling
MCP tools — verified offline against the issuer's Ed25519 public key without
touching the vault.

---

## Use as MCP Server

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
| `akc_delete` | Remove a secret |
| `akc_audit` | Read the audit log (no secret material) |

Example from an agent:

```typescript
// Store
await callTool("akc_store", {
  name: "openai-key",
  value: "sk-...",
  scope: ["openai:write"],
});

// Retrieve later (scope-checked)
const result = await callTool("akc_get", { name: "openai-key" });
```

---

## Commands

| Command | Description |
|---|---|
| `agentkeychain init` | Initialize vault, set master password, create default identity |
| `agentkeychain store <name> --value <v> --scopes "..."` | Encrypt and store a credential |
| `agentkeychain get <name> [--json]` | Decrypt and return a credential |
| `agentkeychain list [--json]` | List all credentials (metadata only) |
| `agentkeychain delete <name>` | Soft-delete a credential |
| `agentkeychain audit [--since 24h]` | Show audit log |
| `agentkeychain serve` | Start MCP server (stdio transport) |
| `agentkeychain issue-token --sub <id> --scopes "..." [--ttl 1h]` | Issue a cross-agent delegate token |
| `agentkeychain --version` | Print version |

---

## Security model

- **Argon2id** (memory=64 MB, iterations=3) derives a KEK from master password
- **XChaCha20-Poly1305** AEAD encrypts each secret independently
- **Ed25519** signs audit entries + delegate tokens (offline-verifiable)
- **Client-side only** — server never sees plaintext; vault file is fully encrypted
- **Zero-knowledge** — master password is never written to disk

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full threat model and
competitor comparison (vs 1Password / Bitwarden / Infisical agent-vault).

---

## Development

```bash
bun install         # install deps
bun test            # run all tests (33 tests)
bun run lint        # eslint
bun run build       # single-binary compile to bin/agentkeychain-bin
bun run typecheck   # tsc --noEmit
```

CI runs on every push to `main` — see
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

---

## Roadmap

- [ ] Apply to MCP Registry (Claude Desktop / Hermes / Codex)
- [ ] TPM-backed KEK unlock (hardware-bound master key)
- [ ] `agentkeychain shell` — REPL for multi-command workflows
- [ ] Cloud sync (end-to-end encrypted, optional)
- [ ] Team / enterprise: SSO + role delegation

---

## License

MIT — see [LICENSE](./LICENSE).

## Status

v0.1.0 — public alpha. Single binary works end-to-end. Breaking changes possible
before v1.0.