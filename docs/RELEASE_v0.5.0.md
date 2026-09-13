# AgentKeychain v0.5.0 — Secure local credential capture

AgentKeychain v0.5.0 removes CLI syntax and raw scope strings from the normal human credential-entry path.

## Highlights

- New MCP tool `akc_request_store(name, purpose)` opens a one-time local secure-entry form. The credential value never enters chat or MCP arguments.
- New CLI fallback `agentkeychain capture <name> --purpose <text>` launches the same form for agent-driven workflows.
- Automatic least-privilege scope inference for common providers, with a non-universal `service:use` fallback.
- Plain-language permission display; raw scope strings remain advanced metadata.
- Loopback-only listener, cryptographically random one-time URL, five-minute expiry, single submission, strict request limits, and no-store/CSP/no-referrer headers.
- Existing secrets cannot be overwritten through secure capture; rotation and overwrite remain explicit approval boundaries.

## Compatibility

- Existing vaults require no migration.
- The original `akc_store` MCP tool remains available as an advanced compatibility path for trusted clients.
- Existing CLI commands and encrypted vault formats are unchanged.

## Verification

- 76 tests, lint, typecheck, build, and compiled-binary secure-capture E2E passed before release.
