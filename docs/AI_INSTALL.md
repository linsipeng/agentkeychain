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

1. Detect whether a compatible AgentKeychain is already installed and preserve it.
2. Install the CLI via the one-command installer, with SHA256 verification.
3. Install the AgentKeychain skill into Hermes, so credential tasks route
   through the vault automatically from now on.
4. Register the AgentKeychain MCP server in Hermes.
5. Ask you for a master password exactly once, through a private local
   prompt — if (and only if) this machine has no vault yet.
6. Verify CLI, skill, MCP, and metadata-only vault access without retrieving,
   printing, or storing any secret value during setup.

## What the agent will NOT do

- It will not print a secret value, token, password, or private key into
  chat, logs, or files.
- It will not overwrite, import into, migrate, or reset an existing vault.
- It will not choose a master password for you or record it anywhere.
- It will not perform deletions, rotation, scope expansion, or delegation
  without asking you first.

## Manual fallback (no agent available)

```bash
curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/v0.6.2/install.sh | sh -s -- --version v0.6.2
agentkeychain init
```

Options: `--version vX.Y.Z` (pin), `--dir <path>`, `--uninstall`.
Supported: macOS (Apple Silicon & Intel), Linux (x64 & arm64).

## Verifying the setup

```bash
agentkeychain --version      # prints the installed version
agentkeychain status --json  # read-only readiness probe; never creates/mutates a vault
agentkeychain list           # metadata only — never values
hermes skills list           # shows agentkeychain installed
hermes mcp test agentkeychain
```

Skill and MCP changes take effect in a new Hermes session (or
`/reload-skills` + `/reload-mcp` in the current one).

## Managed Cloud status

The installer still installs the pinned v0.6.2 local CLI. Managed Cloud v0.7 Slice 1
is a local/test-only implementation, not a hosted service or an account setup flow.
The only planned cloud mode is the official managed service; users do not deploy
infrastructure or supply shared sync credentials. In this development branch,
`agentkeychain sync status` safely detects legacy configuration; old sync commands
are disabled, and configuration is preserved without contacting an endpoint.
No automatic legacy migration or deployed cloud is available; the account recovery/approval UI is locally tested. The approval
contract does not change existing CLI/MCP plaintext delivery to trusted clients.

## Related docs

This branch implements native secure-store helpers, signed-manifest build checks,
metadata-only compatibility reporting and atomic executable replacement. Managed
service restart is attempted only for a previously installed, running service.
The macOS helper is built beside the binary and must be shipped with its checksum;
master-password storage preserves the existing tuple and uses stdin, not secret argv.
Unknown cloud schemas disable cloud integration while legacy local tables remain usable.
The public installation protocol stays pinned to v0.6.2; do not upgrade an existing
installation or install a host service during development acceptance. Production
cloud composition fails closed until a verified release manifest is built in.
Target enrollment can resume after browser approval using its original keys. Issuer
delivery now retries its persisted sealed bytes and local phrase confirmation. Managed
export requires exact cloud approval. The final local issuer/daemon interruption,
protected enrollment-anchor recovery and directory-relative export matrices pass.
Only external provisioning, native-platform/browser acceptance and release/deployment
gates remain; see [final evidence](./PHASE45_FINAL_CONTINUATION.md).

- Managed Cloud scope and compatibility: [SYNC_GUIDE.md](./SYNC_GUIDE.md)
- 中文版安装指南: [AI_INSTALL.zh-CN.md](./AI_INSTALL.zh-CN.md)

Phase 2A now has an independent locally tested Workers/D1 backend; it does not change installation or enable account login, enrollment or split-key recovery. See [Phase 2A evidence](./MANAGED_CLOUD_PHASE2A_EVIDENCE.md).

Development-only signed roster/revocation propagation is described in [SIGNED_ROSTER.md](SIGNED_ROSTER.md). It does not change the pinned public installation release or permit real-vault migration.

The development `cloud recover [packageId]` command now resumes secure-store-backed
recovery, validates independent releases and authority-encrypted trust, and publishes
local cloud state only after server and secure-store readback. Compiled synthetic
recovery acceptance covers fast/delayed paths and crash/substitution cases. See [local recovery evidence](LOCAL_RECOVERY_ACTIVATION.md).

Final development security contracts and migration semantics are recorded in [FINAL_SECURITY_REPAIR.md](FINAL_SECURITY_REPAIR.md). The public pinned installation release is unchanged; deployment and platform acceptance remain separate gates.
