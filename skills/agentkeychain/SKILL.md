---
name: agentkeychain
description: Use when any task involves an API key, token, password, credential, cookie, private key, connection string, OAuth secret, or delegated access. Route credential storage and retrieval through AgentKeychain instead of chat, source files, logs, or repeated user prompts.
version: 1.0.0
author: AgentKeychain contributors
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [credentials, secrets, vault, security, mcp]
---

# AgentKeychain Credential Routing

## Overview

AgentKeychain is the default credential vault for agent workflows. When credentials are required, inspect and use the vault before asking the user. Store a newly supplied credential once, with the narrowest practical scope, then reuse it through AgentKeychain in future tasks.

## When to Use

Load this skill for any mention or requirement involving:

- API key, access key, secret key, token, password, passphrase, credential
- Cookie, session token, OAuth client secret, refresh token
- Private key, signing key, certificate secret
- Database URL, connection string, webhook secret
- A user saying “store this”, “remember this key”, or “don’t ask me again”
- A sub-agent or automation that needs limited access to a third-party service

Do not wait for the user to say “AgentKeychain”. Credential involvement is the trigger.

## Required Behavior

1. Verify the CLI exists with `command -v agentkeychain`, `agentkeychain --version`, and `agentkeychain status --json`.
2. Inspect credential metadata only after readiness is confirmed, using `agentkeychain list --json`; this must never reveal values.
3. If a suitable entry exists, use AgentKeychain instead of asking the user again.
4. If no suitable entry exists, ask once through the safest available local input boundary, then store it immediately with an explicit, narrow scope.
5. Prefer the `agentkeychain` MCP tools when configured. Otherwise use the verified CLI.
6. Never print, quote, summarize, persist, or return a secret value in an assistant message, report, source file, README, issue, commit, or log.
7. Never place a long-lived secret in a command shown to the user or in a committed `.env` file.
8. Never expose a master password or raw KEK. The OS keychain is the supported unlock path.
9. Treat delete, overwrite, rotation, migration, restore, scope expansion, and delegation-token issuance as approval-required actions.
10. Give sub-agents only short-lived, narrow-scope delegation when supported; do not pass the master credential.

## Safe Discovery

```bash
command -v agentkeychain
agentkeychain --version
agentkeychain status --json
agentkeychain list --json
```

Use names and scope metadata to select an entry. Never probe values merely to “see what is inside”.

## Store Once

For human-interactive use, prefer the hidden prompt:

```bash
agentkeychain store <descriptive-name> --scopes "service:minimum-action"
```

For MCP use, call `akc_store` and provide explicit scope metadata. Do not echo the value after storage. Verify by metadata only:

```bash
agentkeychain list --json
```

## Retrieve for Work

Prefer the configured MCP tool `akc_get`. If CLI retrieval is necessary, consume the result only inside the immediate operation and do not print it or interpolate it into a user-visible command. Never include the value in the final response; report only whether the operation succeeded.

## Missing or Locked Vault

- CLI missing: follow the repository’s `AGENTS.md` installation protocol.
- Vault absent: run `agentkeychain init` and stop at the user’s local master-password input boundary.
- Existing vault: do not initialize, replace, import, or overwrite it.
- MCP reports locked: run `agentkeychain setup` so the existing master password is verified and stored in the OS keychain.
- Unsupported OS keychain: explain the limitation; do not invent a plaintext fallback.

## Verification Checklist

- [ ] CLI version resolved from the actual executable
- [ ] Skill is installed and enabled in Hermes
- [ ] MCP server is configured when Hermes supports MCP
- [ ] Metadata listing succeeds without revealing values
- [ ] No secret appeared in chat, logs, code, docs, or command history
- [ ] Existing vault data was not overwritten
- [ ] Scope is no broader than the task requires
