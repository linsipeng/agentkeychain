# Signed device roster and revocation propagation

Implemented in the uncommitted Phase 4 tree, 2026-11-06. No production service,
keys, real Vault/Keychain, deployment or release was used.

## Trust contract

`managed-cloud/shared/roster.ts` defines the exact canonical `TrustedDeviceRoster`:
account, tenant, vault, revision, previous signed-roster digest, key epoch, active
and permanently revoked devices with immutable signing/wrapping keys, issuer,
issued/expiry times, checkpoint key IDs/pins and recovery authority IDs/pins.
Revocations include their revision and the exact signed acceptance checkpoint.
Device/key/pin duplicates, overlap, unknown fields, noncanonical ordering and
oversized rosters fail closed. At most 1,000 devices and 16 pins of each type are
allowed, with a 512 KiB canonical limit and a maximum 30-day validity period.

Successors increment revision by exactly one and commit to the complete prior
signed object. Every historical device and revocation must remain present.
Key replacement, resurrection, epoch changes and pin changes are rejected; this
version deliberately has no implicit rotation policy. The issuer must have been
active in the preceding roster. Recovery issuance instead requires a release-pinned
independent authority and its signed completed-case certificate binding account,
tenant, vault, target keys, revision and previous digest. `issueRecoveryRoster`
validates that evidence and the entire transition before requesting a signature.
The API additionally requires the corresponding recovery saga to be completed.
Compiled-client recovery activation is implemented, including authenticated local
share reconstruction and authority-bound trust. See the recovery continuation
evidence linked below.

Release manifests may explicitly include `recoveryAuthorities`. Omission means
recovery roster issuance is disabled. These public pins are authenticated by the
existing release root, never an environment variable or server response. There are
no embedded production keys or newly provisioned services.

## Bootstrap and persistence

Every enrollment bundle now requires `signedRoster`. SAS commits to those exact
bytes alongside the target grant, issuer and release pins. The target verifies the
sealed bundle and the signed roster before activation. First-device anchoring uses
its own key, the approved grant and the verified release manifest. A verified
recovery bundle binds its completed case and independently pinned authority.
A fetched server roster is never a bootstrap source. Existing experimental cloud
state without this anchor fails closed; it is not silently migrated or re-anchored.

`RosterStore` stores the signed baseline, each successor and current roster under
CSK row encryption. A separate `roster-anchor` secure-store account retains revision
and signed digest. Anchor-ahead, missing-anchor and same-revision fork cases fail
closed. An advertised higher head is retained across pages and restarts; a later
response cannot silently retract its promised suffix. SQLite-ahead repair requires a cryptographically validated continuous
history containing the exact old anchor. Initial activation writes the anchor first;
only the identical authenticated bundle can resume an interrupted activation.
A separate fenced SQLite lease serializes roster anchor validation/repair/updates;
issuer delivery also holds the existing sync lease. A killed issuer must wait for
lease expiry before another process resumes its exact journal.

## Backend and runtime

Migration `0017_signed_rosters.sql` adds immutable revisions and revocation sequence
boundaries. Exact retries return the original logical acceptance; competing revisions
cannot both commit. Transaction triggers recheck active issuer status, roster revision,
complete device count, revoked-device state and acceptance boundary. Existing browser
revocation still immediately disables sessions and device writes. A trusted online
issuer then signs and publishes the successor from the immutable boundary.
Signed revisions also enter the existing device audit stream.

Native-only device routes are `roster-put`, `roster-pending` and `roster-fetch`.
Publication/pending work uses active authenticated device contexts. Fetch uses a
short-lived signed possession request bound to account/tenant/vault/device and cursor,
so a revoked device can still read its signed revocation without obtaining a session
or write privileges. Browser device lists expose only status, IDs and the opaque
step-up action digest, never public keys, signatures or canonical roster data.

Before syncing, clients fetch and validate the roster chain, then publish pending
revocations when authorized. An issuer renews a roster within the last day of its
validity. Revocation removes active trust, preserves historical public keys, clears
the local HTTP session and persists terminal `revoked` health. The daemon exits;
new local managed mutations are blocked, and encrypted queued rows remain unchanged.
Restart reads the persisted roster and secure anchor before constructing a writer.

An operation signed by a currently revoked device is acceptable only at or before
its signed acceptance boundary. The exact checkpoint root must occur in the verified
operation chain. Pages needing a later boundary are buffered until that proof is
complete; a missing suffix cannot commit a partial page. Later operations, forked
checkpoint roots and truncated proofs are security errors.

## Freshness and operational boundaries

An untrusted server cannot create signatures, change a pinned history, remove known
revocations or supply an inconsistent advertised suffix. As with any offline signed
snapshot, a server can withhold an *entire previously unseen* newer revision while
replaying a still-valid old head. This protocol bounds that window by signed expiry;
it does not claim an independent global latest-head witness. Publication requires an
online active issuer, or completed recovery with a provisioned authority. Revoking
all available issuers still blocks server writes immediately, but cannot cause the
API itself to manufacture a signed successor. No implicit authority/pin rotation or
recovery bypass is enabled to address that availability condition.

## Acceptance evidence (original roster run)

- Root: 147 tests, 787 assertions, 41 files; zero failures.
- Backend: 278 tests, nine files; Web: 90 tests, three files; zero failures.
- Compiled two-client acceptance: 84 assertions. A receives signed revocation, B's
  daemon exits revoked, restart blocks writes, and encrypted pending rows remain
  byte-identical. A verifies B's previously accepted signatures after its own restart.
- Focused tests cover canonical/schema rejection, signature/issuer substitution,
  duplicate devices, hidden revoked devices, rollback/fork, key/pin replacement,
  reactivation, recovery certificates, encrypted persistence and anchor crash rules,
  concurrent server issuers, immutable storage, revocation race, revoked-only fetch,
  and historical-operation checkpoint/suffix rejection.
- Root/backend/Web lint/typecheck/build gates, native helper build, signed synthetic
  release/absent-manifest gates, generated bundle acceptance and recovery resource
  diagnostics passed. Audits reported zero vulnerabilities. The bounded changed-source scan inspected
  76 files with zero high-confidence embedded credential/private-key/raw-KEK findings;
  machine-readable audit evidence is in [SIGNED_ROSTER_AUDIT.json](SIGNED_ROSTER_AUDIT.json).
- Built-in Chrome/DevTools was unavailable. Existing protocol/Web tests were run;
  no native browser/Passkey or real Keychain/service acceptance is claimed.

## Local recovery continuation

Independent signed target releases, local share reconstruction, secure-first recovery
journaling, CLI activation and completed-case trust integration are implemented.
The compiled two-Worker matrix covers 51 scenarios. See
[LOCAL_RECOVERY_ACTIVATION.md](LOCAL_RECOVERY_ACTIVATION.md).

The final issuer/export/reconciliation and protected enrollment continuation is locally
complete; current counts and external gates are in
[PHASE45_FINAL_CONTINUATION.md](PHASE45_FINAL_CONTINUATION.md). Earlier counts here
remain historical evidence.

The final independent Custodian witness, immutable trust refresh versions and revocation completion semantics supersede earlier freshness limitations here. See [FINAL_SECURITY_REPAIR.md](FINAL_SECURITY_REPAIR.md).
