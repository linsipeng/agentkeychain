# agentkeychain

> Agent-native zero-knowledge credential vault. CLI + MCP Server, single binary.

## Quickstart

```bash
bun install
bun run build
./bin/agentkeychain init
./bin/agentkeychain store openai --value "sk-..." --scopes "openai:chat"
./bin/agentkeychain get openai
./bin/agentkeychain serve  # starts MCP server
```

See [PRD](../product-docs-templates/产品定义-agentkeychain.md) for full spec.

## Why

AI Agents need credentials. Users shouldn't be asked for API keys 50 times. Existing tools (1Password, Infisical agent-vault) treat agents as proxies or users — we treat agents as first-class identities with their own scopes, delegation, and audit.

## Status

v0.1 in development. PRD locked.