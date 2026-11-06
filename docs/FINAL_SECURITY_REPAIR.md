> Historical evidence below is superseded by the [last final-review repair](LAST_FINAL_REVIEW.md).
> Current counts and source digests are in the linked final-review record.

# Final local security repair

This record and [machine-readable acceptance evidence](FINAL_SECURITY_REPAIR_AUDIT.json)
supersede earlier local acceptance conclusions after the final A–G repairs passed. Work is dirty and uncommitted. No deployment,
production database, credential retrieval or host secure-store operation is authorized
or used by the disposable tests.

Custodian now owns an append-only roster/checkpoint witness in its separate D1. The
witness has a separate signing binding and release-pinned public keys distinct from
checkpoint and recovery-authority keys. Main supplies signed chains, never a head
setter. A recovery revision is reserved in Main before the independent call; competing
writers cannot occupy it while an acknowledgment is pending. Concurrent roster fetches
retry until the fetched head and witness agree, or return a retryable failure. Genesis needs independently provisioned authorization; upgraded inventories
need the separately reviewed migration anchor. Historical prefixes, forks, omitted
revoked identities and stale checkpoint roots fail verification. A Main roster row
starts a pending saga; only a Custodian acknowledgment makes it deliverable. Revocation
enforcement is immediate, while its API reports `witnessPending` until a complete signed
roster is acknowledged. Device metadata reports `revocationComplete` separately.
Roster fetches, enrollment delivery, recovery trust and managed push acknowledgments
carry witness receipts. Production release builds require witness pins.

Recovery trust versions retain exact request digests, including revocations and target
case bytes. Changed retries conflict. Custodian requires the latest witnessed roster
and checkpoint; a pending witnessed successor can resume after response loss without
re-signing a conflicting chain. A newer witnessed head requires a new receipt version
for the same case. The target signs its exact activation version and roster digest;
Custodian commits only while that witness event remains current. Committed activation
history is immutable. The client verifies refreshed chains against staged anchors,
replaces only uncommitted trust slots, and resumes committed activation from its original
receipt. Neither Main nor Custodian claims a transaction spanning both D1 databases.

Migration 0017 backfills immutable conservative revocation boundaries. See the
[backup, failure and rollback runbook](SECURITY_REPAIR_MIGRATION_RUNBOOK.md).
Tests restore every 0001–0016 prefix into disposable databases, preserve devices,
approvals and recovery state, roll back an injected migration failure, then accept a
complete signed roster through 0017–0019.

Managed bundle import validates the bundle before selecting mutations. The coordinator
prepares every operation under one SQLite writer transaction, then writes local rows,
shadow state, outbox and encrypted import audit together. Existing entries requiring
approval, tombstones, cloud history whose local row was deleted, invalid entries,
duplicate names and injected writes cannot leave
partial batch state. Reconciliation rows share that database transaction boundary.

Daemon startup probes live IPC before lease replacement and again after acquisition.
The probe waits for acknowledgment without half-closing its socket. Listener setup,
renewal and all exits share cleanup; cleanup removes only the owned inode and lease.
Installer downloads, checksums and probes both members before stopping a service. It
retains versioned pairs and backups, publishes through one directory pointer, records
helper ABI/version compatibility, and restores the old pair/service on stop, rename or
restart failure. Failed rollback retains its backup and reports repair required.

Public recovery resolves a verified email against the target-signed package's exact
account/tenant/vault authorization. Extra vaults and memberships do not make a valid
target ambiguous; unknown/foreign targets retain the generic decoy response.

Windows cloud and export entrypoints reject before opening the vault, resolving a
password or creating output. Unit tests and a compiled CLI with code-injected `win32`
exercise that exact branch against an empty disposable home. This is **not** native
Windows executable acceptance: The Windows x86-64 PE cross-compile also succeeded and its header was verified, but no
Windows executor is installed on this macOS host. Native Windows execution, supported service
integration and secure-store acceptance remain external release gates. macOS/Linux
secure-store transports use stubs in tests; ABI metadata probing touches no host store.
The built-in Chrome/DevTools tools are absent in this session, so native browser and
Passkey acceptance remains external. The disabled external Chrome extension was not
changed or used.

## Final disposable verification — 2026-11-06

Root **185 tests / 1678 assertions / 46 files**, backend **282**, Web **90**,
compiled process **695 assertions**, compiled recovery **51 scenarios**, and resource
diagnostics **8 tests / zero undisposed-resource warnings** passed. The original
170/280/90/692/51 gates are preserved. Lint, all typechecks, client/native-helper,
Worker and Web builds, generated bundle acceptance, production fault-selector scans
and whitespace checks passed. Root and managed Bun audits plus full/runtime npm
audits reported zero vulnerabilities. Bounded changed-source credential scans found
no high-confidence patterns; compiled tests recursively scan synthetic artifacts.
Windows x86-64 PE compilation and header validation passed; platform-injected
unit and compiled entrypoint tests verified fail-closed behavior without key, database
or output creation. Native Windows execution remains external. No commit, deployment,
real data or host secure-store use occurred. See the JSON record for source digests
and the remaining external acceptance gates.
