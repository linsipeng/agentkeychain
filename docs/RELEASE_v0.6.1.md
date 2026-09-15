# AgentKeychain v0.6.1 — Ten password-check attempts

AgentKeychain v0.6.1 improves the private master-password verification experience introduced in v0.6.0.

## Change

- A one-time local password-check session now allows up to ten incorrect candidates.
- After each of the first nine incorrect attempts, the same private form remains active and shows the remaining count.
- Failed submissions use POST/Redirect/GET so refreshing the page does not accidentally consume another attempt.
- A correct candidate ends the session immediately.
- The session expires only after the tenth incorrect candidate, manual cancellation, or the existing five-minute timeout.
- Concurrent submissions remain locked so only one candidate is verified at a time.

## Security and compatibility

- Verification remains read-only and does not modify the Vault or OS keychain.
- Passwords still never enter chat, MCP arguments, command-line arguments, logs, or persistent files.
- No vault migration is required; CLI and MCP interfaces are unchanged.

## Verification

- The ten-attempt behavior is covered by an end-to-end loopback-server regression test.
- The complete test suite, lint, typecheck, and compiled-binary build passed before release.