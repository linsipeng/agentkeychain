# Installing AgentKeychain with your AI agent

Send your AI agent (Hermes, Claude Code, Codex, or any coding agent) this
repository link and one sentence. The agent reads `AGENTS.md` at the repo
root and completes the entire setup itself.

## The one-liner

```text
Install and configure https://github.com/linsipeng/agentkeychain as your
default credential manager. Follow AGENTS.md in the repository.
```

That's it. The agent will:

1. Detect whether AgentKeychain is already installed (and upgrade if needed).
2. Install the CLI via the one-command installer, with SHA256 verification.
3. Install the AgentKeychain skill into Hermes, so credential tasks route
   through the vault automatically from now on.
4. Register the AgentKeychain MCP server in Hermes.
5. Ask you for a master password exactly once, through a private local
   prompt — if (and only if) this machine has no vault yet.
6. Verify CLI, skill, MCP, and metadata-only vault access, without ever
   printing or storing any secret value.

## What the agent will NOT do

- It will not print a secret value, token, password, or private key into
  chat, logs, or files.
- It will not overwrite, import into, migrate, or reset an existing vault.
- It will not choose a master password for you or record it anywhere.
- It will not perform deletions, rotation, scope expansion, or delegation
  without asking you first.

## Manual fallback (no agent available)

```bash
curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh | sh
agentkeychain init
```

Options: `--version vX.Y.Z` (pin), `--dir <path>`, `--uninstall`.
Supported: macOS (Apple Silicon & Intel), Linux (x64 & arm64).

## Verifying the setup

```bash
agentkeychain --version      # prints the installed version
agentkeychain status --json  # safe readiness probe; does not create/open a vault
agentkeychain list           # metadata only — never values
hermes skills list           # shows agentkeychain installed
hermes mcp test agentkeychain
```

Skill and MCP changes take effect in a new Hermes session (or
`/reload-skills` + `/reload-mcp` in the current one).

## Related docs

- Cloud sync between machines: [SYNC_GUIDE.md](./SYNC_GUIDE.md)
- 中文版安装指南: [AI_INSTALL.zh-CN.md](./AI_INSTALL.zh-CN.md)
