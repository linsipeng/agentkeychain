# AgentKeychain v0.6.2 — Production Keychain isolation

AgentKeychain v0.6.2 is an emergency safety release that prevents development
and end-to-end tests from reaching the host OS keychain or the default
production Vault.

## Security fixes

- Every `bun test` run preloads a fail-closed test mode.
- Test-mode keychain access requires an explicitly injected executable inside
  an explicitly declared isolated stub directory; inherited command overrides
  and normal `PATH` discovery cannot reach the host keychain.
- Test mode refuses the default Vault and any Vault path outside the system
  temporary directory.
- Non-default `AGENTKEYCHAIN_HOME` values use deterministic path-scoped
  keychain service names instead of sharing the production service tuple.
- `agentkeychain setup` verifies the supplied password against the existing
  Vault before writing or replacing a keychain entry.
- Legacy keychain entries are migrated to a custom Vault only after proving
  that the legacy password unlocks that Vault.

## Compatibility

- The default production Vault retains the existing keychain service name.
- No Vault migration, credential rotation, or secret rewrite is performed by
  this release.
- The private master-password check from v0.6.1 remains available with up to
  ten attempts per local session.

## Verification

- Exact-candidate independent security review passed with no blocking security
  or logic findings.
- Lint, TypeScript typecheck, 90 tests, compiled-binary build, and diff checks
  passed on macOS.
- Production Keychain metadata was identical before and after the local test
  run; no password value was read or logged.
- PR and post-merge `main` CI completed successfully before tagging.