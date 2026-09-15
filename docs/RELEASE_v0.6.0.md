# AgentKeychain v0.6.0 — Private master-password verification

AgentKeychain v0.6.0 lets users verify the master password they remember without placing it in chat, MCP arguments, command-line arguments, logs, or persistent files.

## Highlights

- New zero-argument MCP tool `akc_request_password_check` opens a one-time local password-check form.
- New CLI entry `agentkeychain verify-password` launches the same private browser flow.
- Verification is read-only against existing KEK metadata; it does not read credential rows, modify the Vault, or update the OS keychain.
- Results distinguish `correct`, `incorrect`, `expired`, and `cancelled`; incomplete checks are never reported as wrong passwords.
- MCP schema and runtime both reject all arguments without reflecting supplied content.
- Loopback-only listener, cryptographically random one-time URL, five-minute expiry, request limits, security headers, and a concurrent-submission lock.

## Compatibility

- Existing vaults require no migration.
- Existing CLI and MCP commands remain available.
- The encrypted vault format is unchanged.

## Verification

- 85 tests, lint, typecheck, build, and compiled-binary correct/incorrect password E2E passed before release.
- Independent security and logic re-review passed with no blockers.
- GitHub CI passed on the feature PR and merged `main` commit.