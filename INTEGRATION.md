# Integration Guide

How to wire agentkeychain into your agent framework (Hermes, Claude Desktop,
Codex, custom agents).

## Architecture in 30 seconds

```
┌──────────────┐                  ┌────────────────────┐
│ Human User   │                  │ Vault file         │
│ (master pwd) │                  │ ~/.agentkeychain/  │
└──────┬───────┘                  └────────┬───────────┘
       │ Argon2id                         │
       │ deriveKEK(pwd)                   │ encrypted
       ▼                                  │
┌──────────────┐  unlock + sign           │
│ Hermes       │ ───────────────────────► │
│ (main agent) │                          │
│ Ed25519 key  │                          │
└──────┬───────┘                          │
       │ issue-token (Ed25519 signed)     │
       ▼                                  │
┌──────────────┐  verify (Ed25519)        │
│ Sub-agent    │ ───────────────────────► │ (NO DB read needed)
│ (delegated)  │  akc_get { delegate_token }
└──────────────┘
```

**Key insight:** Sub-agent verification is purely cryptographic. The main agent
does not need to be online; the delegate token is self-contained.

---

## Wire into Hermes (one-time setup)

### Step 1: Build + install

```bash
git clone https://github.com/linsipeng/agentkeychain.git ~/projects/agentkeychain
cd ~/projects/agentkeychain
bun install
bun run build
ln -sf "$(pwd)/bin/agentkeychain-bin" /usr/local/bin/agentkeychain
```

### Step 2: Initialize vault

```bash
agentkeychain init
# Master password: ********
# Confirm: ********
```

### Step 3: Register the MCP server with Hermes

Add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  agentkeychain:
    command: /usr/local/bin/agentkeychain
    args: ["serve"]
    env:
      AGENTKEYCHAIN_HOME: ~/.agentkeychain
```

Restart Hermes. The 5 `akc_*` tools will appear in Hermes' tool list.

### Step 4: Use from a Hermes session

Hermes can now call:

```
akc_store  name="openai-key"  value="sk-..."  scope=["openai:chat"]
akc_get    name="openai-key"
akc_list
akc_audit
```

Hermes will prompt for the master password the first time per session (via
`AKC_KEK_HEX` env or a `shell` unlock command in a future version).

---

## Delegate to a sub-agent (Hermes → codex / claude-code / etc.)

When you delegate a task to a sub-agent (Codex CLI, Claude Code, etc.) and it
needs scoped access to specific secrets:

```bash
# In Hermes:
TOKEN=*** agentkeychain issue-token \
  --sub ak_subagent_$(uuidgen) \
  --scopes "openai:read,cloudflare:read" \
  --ttl 30m)

# Pass token to sub-agent via env var or stdin
codex --prompt "fix the cloudflare worker" --env "AKC_DELEGATE_TOKEN=$TOKEN"
```

The sub-agent verifies the token's Ed25519 signature against the main agent's
public key (stored in the vault at `~/.agentkeychain/vault.db`) — no network
call, no shared secret.

---

## Use from Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agentkeychain": {
      "command": "/usr/local/bin/agentkeychain",
      "args": ["serve"],
      "env": {
        "AGENTKEYCHAIN_HOME": "/Users/you/.agentkeychain"
      }
    }
  }
}
```

Restart Claude Desktop. Tools appear as `mcp__agentkeychain__akc_*`.

---

## Use from a custom agent (programmatic)

```typescript
import { createServer } from "agentkeychain/src/mcp/server.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "/usr/local/bin/agentkeychain",
  args: ["serve"],
});
const client = new Client({ name: "my-agent", version: "1.0.0" }, { capabilities: {} });
await client.connect(transport);

const result = await client.callTool({
  name: "akc_get",
  arguments: { name: "openai-key" },
});
console.log(result.content);
```

---

## Threat model summary

| Attacker | Can read secret? | Notes |
|---|---|---|
| Network eavesdropper | ❌ No | TLS + end-to-end encryption |
| Compromised sub-agent | ⚠️ Only if scopes match | Scope-bounded delegate tokens |
| Compromised main agent | ✅ Yes | Master password unlocks everything — use hardware unlock |
| Disk thief (vault file only) | ❌ No | Argon2id KEK + XChaCha20-Poly1305 |
| Insider with shell access | ✅ Yes | Same as compromised main agent |
| Backdoored libsodium binary | ⚠️ Yes | Mitigate via reproducible builds + binary verification |

See [ARCHITECTURE.md § Threat Model](./ARCHITECTURE.md) for the full breakdown.

---

## FAQ

### Why not just use 1Password CLI?
1Password treats agents as **proxies for humans** — single identity, all-or-nothing
access, no per-agent audit. agentkeychain treats agents as **first-class identities**
with their own scopes, delegation, and signature-verifiable audit chain.

### Why not Infisical / Doppler / Vault?
Those are **secret managers for human teams**. agentkeychain is the **IAM layer
for agents**: agent identities, scope-bounded delegation, offline token verification.
Different problem, different solution.

### What's the threat model?
- Server compromise: cannot read secrets (zero-knowledge, client-side encryption)
- Agent compromise: bounded by scopes (e.g. read-only token for a sub-agent)
- Insider with shell access: full access (same as any secret manager on your machine)

### Is the master password stored?
**No.** It's used to derive an Argon2id KEK, which is held in process memory
only. The vault stores only a hash of the KEK + the encrypted data.

### What about MFA / 2FA?
Not in v0.1. Roadmap item. For now, the master password is the only factor.

### Can multiple agents share a vault?
Yes — but each gets its own Ed25519 identity. The vault stores all identities
with their scopes. Sub-agents can be issued delegate tokens scoped to specific
operations.