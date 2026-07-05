# agentkeychain

> Agent-native zero-knowledge credential vault. CLI + MCP Server, single binary.

## Why

AI Agents need credentials. Users shouldn't be asked for API keys 50 times. Existing tools (1Password, Infisical agent-vault) treat agents as proxies or users — **agentkeychain** treats agents as first-class identities with their own scopes, delegation, and audit.

## Install

```bash
bun install
bun run build
```

## Quickstart

```bash
# 1. Initialize vault (creates ~/.agentkeychain/)
./bin/agentkeychain init

# 2. Store a credential (encrypted with Argon2id-derived key)
./bin/agentkeychain store openai --value "sk-..." --scopes "openai:chat"

# 3. Retrieve (human-readable)
./bin/agentkeychain get openai

# 4. List all credentials (metadata only, no values)
./bin/agentkeychain list

# 5. View audit log
./bin/agentkeychain audit --since 24h

# 6. Start MCP server (for Agent access)
./bin/agentkeychain serve
```

## Commands

| Command | Description |
|---|---|
| `agentkeychain init` | Initialize vault, set master password, create default Agent Identity |
| `agentkeychain store <name> --value <value> --scopes "..."` | Encrypt and store a credential |
| `agentkeychain get <name> [--json]` | Decrypt and return a credential |
| `agentkeychain list` | List all credentials (metadata only) |
| `agentkeychain delete <name>` | Soft-delete a credential |
| `agentkeychain audit [--since 24h]` | Show audit log |
| `agentkeychain serve` | Start MCP server (stdio transport) |
| `agentkeychain delegate <agent> --scopes "..." --ttl 3600` | Issue delegate token |
| `agentkeychain revoke <agent-id>` | Revoke an agent identity |

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for threat model, tech rationale, and competitor comparison.

See [PRD](~/projects/product-docs-templates/产品定义-agentkeychain.md) for full spec.

## Status

v0.1 in development. PRD locked.

## License

MIT
