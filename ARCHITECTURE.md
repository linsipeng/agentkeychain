# Architecture

> See `产品定义-agentkeychain.md` for full PRD. This file explains *why*, not *what*.

## Threat Model

**T1: Local disk theft** — Attacker reads `~/.agentkeychain/vault.db`. We mitigate with Argon2id master-password-derived KEK (memory=64MB, iterations=3, parallelism=4). Disk-only attacker without master password cannot decrypt secrets.

**T2: Memory dump** — Attacker dumps process memory while `get` is executing. We mitigate by (a) zeroing plaintext buffers immediately after use, (b) keeping decrypted plaintext in stack-allocated arrays only.

**T3: Prompt injection on Agent** — Attacker tricks the Agent into leaking credentials via crafted user input. We mitigate with (a) Scope-by-agent enforcement (Agent X cannot read secret Y unless X has scope), (b) full audit log of every read.

**T4: Compromised sub-agent** — Attacker controls a delegated sub-agent token. We mitigate with (a) TTL on all delegate tokens, (b) scopes cannot escalate, (c) audit chain detects unusual access patterns.

**T5: Audit log tampering** — Attacker modifies audit_log to hide their tracks. We mitigate with (a) Ed25519 signature on every row, (b) prev_hash chaining (modifying row N requires rewriting N+1..M), (c) integrity verified on every startup.

## Tech Choices

**Why Bun**: MCP official SDK is first-class in Bun/Node. Faster cold start than Node. Built-in SQLite (`bun:sqlite`) eliminates a dependency.

**Why libsodium-wrappers**: Battle-tested cryptography. Used by 1Password, Bitwarden, Signal. Argon2id is OWASP-recommended for password-based KDF. XChaCha20-Poly1305 is AEAD mainstream (extended nonce prevents reuse). Ed25519 is fast and small.

**Why local SQLite first**: Zero dependencies, zero cloud lock-in for v0.1. Cloud sync is v0.2 (CF D1 + E2EE).

**Why no Web UI**: Scope creep. CLI + MCP is enough for Agent + developer. Web UI doubles the attack surface and maintenance burden.

## vs Competitors

| Dimension | 1Password | Bitwarden | Infisical agent-vault | **agentkeychain** |
|---|---|---|---|---|
| Target user | Human | Human | Agent (proxy mode) | **Agent (identity mode)** |
| Agent gets plaintext key | N/A | N/A | ❌ never | ✅ with scope |
| Agent identity | ❌ | ❌ | ❌ | ✅ Ed25519 per vault |
| Scope-by-agent | ❌ | ❌ | ⚠️ egress filter | ✅ JSON scopes |
| Cross-agent delegation | ❌ | ❌ | ❌ | ✅ signed tokens + TTL |
| MCP native | ❌ | ❌ | ⚠️ partial | ✅ from v0.1 |
| Audit log | ⚠️ paid | ⚠️ paid | ✅ | ✅ signed chain |
| Open source | ❌ | ✅ AGPL | ✅ MIT | ✅ MIT |
| Cloud dependency | ✅ | optional | ✅ required | ❌ local-first |

## File Layout

```
agentkeychain/
├── src/
│   ├── cli/                   # init / store / get / list / delete / audit / serve / issue-token / setup
│   ├── crypto/                # argon2, xchacha, ed25519 wrappers (libsodium-sumo)
│   ├── auth/                  # scope parsing, delegate token issue + verify
│   ├── mcp/                   # MCP server (5 tools via stdio transport)
│   ├── db/                    # SQLite schema + migration
│   ├── util/                  # prompt, keychain (macOS/Linux), redact
│   ├── audit.ts               # append-only tamper-evident audit chain
│   ├── identity.ts            # Ed25519 agent identity gen + load
│   ├── secrets.ts             # store / get / list / delete logic
│   ├── vault.ts               # sqlite3 DB bootstrap, openDb, vaultExists
│   └── index.ts               # main exports, version
├── tests/                     # 41 tests (bun:test)
├── package.json
├── tsconfig.json
├── eslint.config.js
├── README.md
├── INTEGRATION.md
└── ARCHITECTURE.md
```