# Secure Capture v0.5 Specification

## Goal

A user can ask a trusted local AI agent to store a credential without typing a CLI command, pasting the credential into chat, or inventing raw scope strings.

## Required user path

1. The AI calls the MCP tool `akc_request_store` with a secret name and natural-language purpose. No secret value or raw scope is accepted by this tool.
2. AgentKeychain infers a narrow internal scope and a human-readable permission sentence.
3. AgentKeychain opens a one-time form in the local default browser. The one-time URL is not returned to the MCP client.
4. The form shows the secret name, purpose, and natural-language permission. It never displays the raw scope.
5. The user enters the value locally and presses “Encrypt and save”. The value is POSTed only to a loopback listener and is never logged or returned to MCP.
6. The listener encrypts and stores the value, stops after one successful submission, and expires after five minutes.

## Security contracts

- Bind only to `127.0.0.1`.
- Use a cryptographically random one-time path token.
- Reject a missing/wrong token, non-form content types, oversized bodies, empty values, expired requests, and second submissions.
- Send `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and a restrictive CSP.
- Never return or log the credential value.
- Refuse to overwrite an existing live secret; rotation/overwrite remains an explicit approval boundary.
- Raw scope override is not part of the novice MCP tool. Existing `akc_store` remains an advanced compatibility tool.

## Scope inference

- Recognize common providers from the name and purpose.
- Choose a deterministic least-privilege scope for known usage, with a service-level `use` fallback rather than universal `*`.
- Return human-readable permission text to the form and MCP acknowledgement; raw scope remains metadata/advanced output.

## Interfaces

- MCP: `akc_request_store(name, purpose)` opens the secure local form and returns only a safe acknowledgement plus natural-language permission.
- CLI fallback for automation/testing: `agentkeychain capture <name> --purpose <text>`; `--no-open --json` may print the local one-time URL only to the invoking local terminal.

## Acceptance

- Unit tests cover scope inference and all HTTP rejection paths.
- Integration test submits a synthetic value and verifies encrypted-at-rest storage and correct inferred scope.
- Existing tests remain green.
- `bun run lint`, `bun run typecheck`, `bun test`, and `bun run build` pass.
- Compiled binary completes the secure-capture integration path in an isolated vault.
