# Phase 4/5 final local implementation acceptance

2026-11-06. The three requested local implementation gaps are complete in the dirty
working tree. Nothing was committed, deployed, provisioned or tested with real data.
Historical counts in other phase records describe their original runs; this record
and PHASE45_FINAL_CONTINUATION_AUDIT.json describe the final continuation.

## Interruption and concurrency matrix

The synthetic build compiles the real CLI entrypoint. It runs separate processes,
real HTTP, persistent SQLite with the production migrations, and an isolated secure
store authority. Crash hooks exist only in the test build plugin, not in production
configuration. Expiry is injected using the test composition's clock; OS secure-store
and browser behavior are separate native-platform acceptance gates.

| Area | Exercised boundaries and outcomes |
| --- | --- |
| Issuer | Request fetch before/after; intent before/uncommitted/committed; pairing confirmation; trust accepted with response lost; phrase pending and durably confirmed; package before/after acceptance; receipt and cleanup. Restarts preserve the exact randomized trust/package. Concurrent issuers converge to the durable receipt or a fenced conflict; canonical server rows remain byte-identical. |
| Terminal requests | Denial before restart clears request-specific state; expired issuer intent becomes a terminal receipt; replacement request has different ciphertext and SAS; revoked issuer cannot deliver. A terminal conflict never regenerates a delivery for the old request. |
| Local mutations | Process exits before mutation, between local row and outbox, and after outbox before transaction completion leave neither a partial local row nor a lost queue. |
| Sync | Lease acquisition; push before/after response; receipt verification; lease renewal; pull before/after response; verified page; apply; cursor; SQLite commit before secure checkpoint update. Retries preserve exact queue bytes until verified pull commits, and verified history repairs a lagging checkpoint anchor. |
| Actions | Compiled interruption sequences cover creation, rotation, deletion, resurrection, scope and legacy metadata/version reconciliation. Denied/cancelled/replaced approvals also crash between retirement and queue removal, then resume to terminal status and a fresh exact approval. |
| Daemon/roster | Real service processes crash at lease acquisition, renewal and page commit; socket/lease restart converges. Revocation crashes before/after roster-anchor writes; verified history catches the secure anchor up. Revoked queues remain byte-identical and historical signatures remain verifiable. |

A concurrent-process regression exposed SQLite busy handling in the read-only vault
existence probe. `vaultExists` and `openDb` now establish a busy timeout before their
first schema/metadata work, avoiding a spurious `vault_not_initialized` result.

## Explicit enrollment transaction

`enrollment-intent` in the protected secure store precedes individual signing,
wrapping and CSK slot writes. It retains the original key material for exact retries;
resume does not choose new keys. Accepted activation extends that protected intent
with the exact grant, key package, encrypted trust bundle, confirmed phrase,
authenticated acceptance time, signed roster and profile. SQLite holds the matching
CSK-encrypted journal.

Resume verifies signatures, bindings, release pins, target keys and the original key
package before repairing missing SQLite state. A stale roster can advance only through
the exact secure-anchored successor after the full existing signed history verifies.
Unrelated profiles, conflicting journals, forks, missing protected evidence and unknown
secure-ahead state fail closed. Runtime stays isolated while activation intent remains;
no server data is used to reconstruct missing local trust. SQLite-ahead catch-up needs
verified signed history/checkpoints. Completed profile/cursor/pins commit atomically,
then protected intent is removed. Denial/expiry replacement clears request-specific
packages and SAS state without regenerating the protected device keys.

Compiled processes crash before and after the intent, signing, wrapping, CSK,
activation-intent, roster-anchor and checkpoint-anchor writes, final SQLite commit
and protected-intent removal. Focused tests remove the SQLite journal/profile while
retaining protected evidence, test stale signed history, and reject conflicts. Existing
legacy Vault rows remain byte-identical through enrollment; additive cloud tables are
expected to change the SQLite file itself.

## Directory-relative exclusive export

`native/relative-directory.c` supplies fixed-ABI wrappers around `openat`, `linkat`
and `unlinkat`; `src/platform/relative-directory.ts` binds them to the already-opened
destination directory descriptor. The wrapper avoids the ARM64 variadic `openat` ABI
pitfall. Its embedded, non-secret C source is compiled locally by Bun's bundled C
compiler with no SDK headers and removed from its private temporary directory.
Bundle bytes stay in the process and are written to the opened descriptor; no bundle,
credential or key is passed in command arguments or environment variables.

The opened directory inode is checked against the approved output commitment.
Every subsequent file open, link and unlink uses that descriptor and a single basename.
Files are no-follow, exclusively created at mode 0600, ownership/type/link/content
checked and fsynced. Final publication is exclusive and never overwrites a name.
The encrypted journal records the published device/inode in a separate durable
transaction before staging cleanup. An unrelated existing file is rejected even if
it contains identical ciphertext. Cleanup requires the exact journal-bound staging
name, content and inode; startup never scans arbitrary matching names. Linked staging
without a durable publication receipt is retained for exact recovery.

The process matrix includes bundle preparation, consume/journal/publication/cleanup
crashes, after-completion restart, failure at every file/directory fsync, and injected
I/O errors. Parent directory rename/replacement and symlink substitution at creation,
staging fsync, link, output fsync, cleanup and completion do not redirect publication
or delete the replacement directory's unrelated file. Recovery preserves already
published ciphertext exactly. Tests also reject symlinks, extra hardlinks, unsafe
modes and plaintext bundles. Windows publication fails closed; it has no path fallback.

## Final validation

Historical baseline: root **170 tests / 1,527 assertions / 44 files**; backend **280 tests**; Web **90
tests**; separate compiled-process acceptance **692 assertions**; compiled recovery
**51 scenarios**; resource diagnostics **8 tests**. All passed. Artifact-scan assertion
counts can vary with the presence of transient SQLite WAL/SHM files.

Root/backend/Web typechecks, lint, root/native/backend/Web builds, signed synthetic
release and absent-manifest tests, generated Worker bundle acceptance, resource
lifecycle diagnostics, whitespace checks and dependency audits passed. Bun and npm
full/runtime audits reported no vulnerabilities. The bounded changed-source scan
found no high-confidence credential/private-key/raw-KEK patterns. Compiled acceptance
recursively scans synthetic fixture artifacts and export outputs for plaintext test
credentials. This is reproducible local evidence, not an independent security audit.

## External gates only

- Independently provisioned production domains, release/signing roots, operator,
  account-attester, recovery-service and secure-store bindings.
- Native-platform acceptance: actual macOS Keychain/Linux Secret Service prompts,
  launchd/systemd lifecycle, cross-platform packaging/signing and Linux execution.
  macOS ARM64 directory-relative primitives were exercised locally. Windows export
  remains intentionally disabled until a reviewed native implementation exists.
- Built-in Chrome/DevTools and native Passkey acceptance. No such browser tool was
  available in this session; external Chrome and the Hermes adapter were not used.
- Explicit release/deployment approval, production rollout and production acceptance.

No internal implementation blocker remains for these three requested gaps. Existing
protocol limits remain explicit: no implicit key/pin rotation. The subsequent
[final security repair](FINAL_SECURITY_REPAIR.md) adds an independent Custodian
witness and latest-head activation fencing; its evidence supersedes these historical
counts and the earlier signed-expiry-only recovery freshness limitation.
