# Agent instructions for AgentKeychain

AgentKeychain is an AI-first credential vault. A user should be able to send an AI agent only this repository URL and ask it to install and configure AgentKeychain as the default credential manager.

## When the user asks you to install or configure this repository

Own the full outcome. Do not hand the user a checklist of shell commands.

### Required outcome

- The correct AgentKeychain binary is installed and on PATH.
- The public AgentKeychain skill is installed in Hermes when Hermes is available.
- The AgentKeychain MCP server is registered in Hermes when Hermes supports MCP.
- An existing vault is preserved exactly as-is. Do not overwrite, import into, migrate, or reset it.
- A new vault is initialized only after the user enters a master password at a local, private input boundary.
- CLI, skill, MCP, and metadata-only vault access are verified.
- No secret value, token, password, private key, raw credential list, vault content, or raw KEK is printed or persisted.

### Installation protocol

1. Discover before installing:

   ```bash
   command -v agentkeychain || true
   agentkeychain --version 2>/dev/null || true
   command -v hermes || true
   ```

2. If a working CLI is already present, preserve it. Do not overwrite or upgrade
   an existing binary unless the user explicitly asked for an upgrade. If the
   CLI is absent, install it with the repository installer:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh | sh
   ```

   Resolve the installed binary by absolute path. Do not modify global PATH without need.

3. If Hermes is present, inspect `hermes skills list`. Preserve any existing
   `agentkeychain` skill; do not force-overwrite it. Only when absent, install
   the repository skill non-interactively:

   ```bash
   hermes skills install --yes https://raw.githubusercontent.com/linsipeng/agentkeychain/main/skills/agentkeychain/SKILL.md
   ```

4. If Hermes supports MCP, inspect `hermes mcp list`. If `agentkeychain`
   already exists, preserve its configuration and run only the test command.
   If absent, register the verified absolute binary path non-interactively:

   ```bash
   hermes mcp list
   printf 'y\n' | hermes mcp add agentkeychain --command /absolute/path/to/agentkeychain --args serve
   hermes mcp test agentkeychain
   ```

   `hermes mcp add` asks whether to enable discovered tools. The piped `y`
   accepts all five in non-interactive agent runs; without it, EOF cancels the
   installation and nothing is saved.

5. Preserve vault state:

   - Run `agentkeychain status --json` first; unlike `list`, this probe never creates or opens a vault.
   - If `vaultInitialized` is true, the vault already exists. Do not run `init`, import, overwrite, migrate, or reset.
   - If `vaultInitialized` is true but `passwordAvailable` is false, run `agentkeychain setup` and let the user enter the existing master password locally.
   - If `vaultInitialized` is false, run `agentkeychain init` and stop at the private password-input boundary. Never choose, record, or display the master password for the user.
   - Never use `list` or any vault-opening command to decide whether a vault exists — on a fresh machine they create an empty database and report success, which would wrongly skip `init`. `status` is the only safe existence probe.

6. Verify without reading secret values:

   ```bash
   agentkeychain --version
   agentkeychain status --json
   agentkeychain list --json
   hermes skills list
   hermes mcp test agentkeychain
   ```

   Report only versions, presence, health, and metadata counts. Do not call `get` merely to prove installation.

7. Skill changes take effect in a new Hermes session or after `/reload-skills`. MCP configuration may require `/reload-mcp` or a gateway restart, depending on the active Hermes runtime.

### Stop conditions

Stop and ask the user only when:

- local master-password input is required;
- initialization would overwrite or conflict with an existing vault;
- migration, restore, credential rotation, deletion, scope expansion, or delegation-token issuance is required;
- the platform has no supported OS keychain and a plaintext workaround would be necessary.

## Development rules

- Use test-driven development for behavior changes.
- Run `bun run lint`, `bun run typecheck`, and `bun test` before committing.
- Keep `README.md`, `README.zh-CN.md`, and the matching files under `docs/` synchronized.
- Never commit `.env`, `vault.db`, `sync.json`, credentials, tokens, master passwords, raw KEKs, cookies, private keys, or user data.
- Publishing a release is a separate approval boundary.
